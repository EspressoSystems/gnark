//go:build icicle

package bw6761

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/backend/accelerated/icicle/internal/devicemutex"
	"github.com/consensys/gnark/logger"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bw6761 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bw6761"
	icicle_msm "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bw6761/msm"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

var isProfileMode bool
var isDebugMode bool

var (
	msmChunkCapOnce sync.Once
	msmChunkCap     int
)

var (
	msmMaxWindowOnce sync.Once
	msmMaxWindow     int
)

func init() {
	_, isProfileMode = os.LookupEnv("ICICLE_STEP_PROFILE")
	_, isDebugMode = os.LookupEnv("ICICLE_DEBUG")
}

// getDeviceMutex returns the process-wide per-device exclusive mutex for GPU
// operations, shared by ALL plonk curve packages (internal/devicemutex) —
// NOT per-curve-package state: concurrent plonk Proves of different curves
// on one device (e.g. recursive aggregation) serialize per GPU operation
// (SRS upload, every MSM; DESIGN.md §8). It also makes the non-atomic
// free-VRAM reads of the MSM tuner safe. Per-call granularity is correct
// here only because this package owns no NTT-domain state — see doc.go. The
// groth16 backend keeps its own mutexes: groth16∥plonk on one device remains
// unsupported (doc.go point 2).
// lifted from groth16/bw6-761/icicle.go (getDeviceProveMutex), then hoisted
func getDeviceMutex(deviceID int32) *sync.Mutex {
	return devicemutex.Get(deviceID)
}

// lifted from groth16/bw6-761/icicle.go (projectiveToGnarkAffine, g1ProjectiveToG1Jac)
func projectiveToGnarkAffine(p icicle_bw6761.Projective) *curve.G1Affine {
	px, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.X.ToBytesLittleEndian()))
	py, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Y.ToBytesLittleEndian()))
	pz, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Z.ToBytesLittleEndian()))

	var x, y, zInv fp.Element

	zInv.Inverse(&pz)
	x.Mul(&px, &zInv)
	y.Mul(&py, &zInv)

	return &curve.G1Affine{X: x, Y: y}
}

func g1ProjectiveToG1Jac(p icicle_bw6761.Projective) curve.G1Jac {
	var p1 curve.G1Jac
	p1.FromAffine(projectiveToGnarkAffine(p))

	return p1
}

// loadG1 loads a G1 vector from host to device with Montgomery→Standard conversion.
// Used for: Kzg and KzgLagrange SRS vectors (MSM config has AreBasesMontgomeryForm=false).
// The conversion happens on device only — the host slice is never written to.
// lifted from groth16/bw6-761/icicle.go (loadG1), with the allocation made
// explicit: CopyToDevice(_, true) discards the Malloc status, so a VRAM OOM
// would only surface as a CheckDevice panic inside the copy — Malloc first
// and turn the failure into a Go error instead.
func loadG1(hostSlice icicle_core.HostSlice[curve.G1Affine]) (icicle_core.DeviceSlice, error) {
	var deviceSlice icicle_core.DeviceSlice
	if _, err := deviceSlice.Malloc(hostSlice.SizeOfElement(), hostSlice.Len()); err != icicle_runtime.Success {
		return icicle_core.DeviceSlice{}, fmt.Errorf("device malloc for %d G1 points (%d bytes): %s",
			hostSlice.Len(), hostSlice.Len()*hostSlice.SizeOfElement(), err.AsString())
	}
	hostSlice.CopyToDevice(&deviceSlice, false)
	if err := icicle_bw6761.AffineFromMontgomery(deviceSlice); err != icicle_runtime.Success {
		deviceSlice.Free() // Free GPU memory before returning error
		return icicle_core.DeviceSlice{}, fmt.Errorf("convert from Montgomery: %s", err.AsString())
	}
	if isDebugMode {
		log := logger.Logger()
		log.Debug().Int("size", deviceSlice.Len()).Msg("Loaded G1 vector (with Montgomery conversion)")
	}
	return deviceSlice, nil
}

// lifted from groth16/bw6-761/icicle.go (msmChunkedG1)
// msmChunkedG1 runs an MSM in progressively smaller chunks until it fits in GPU memory, accumulating the result.
func msmChunkedG1(scalars icicle_core.DeviceSlice, bases icicle_core.DeviceSlice, cfg icicle_core.MSMConfig) (curve.G1Jac, int, error) {
	size := scalars.Len()
	if size == 0 {
		return curve.G1Jac{}, 0, nil
	}

	chunks := configureMSM(
		&cfg,
		size,
		scalars,
		bases,
		fr.Bits,
		int(unsafe.Sizeof(fr.Element{})),
		int(unsafe.Sizeof(icicle_bw6761.Affine{})),
		int(unsafe.Sizeof(icicle_bw6761.Projective{})),
	)

	// Force C++ to NOT chunk internally, as we handle it here
	cfg.Ext = nil

	var totalG1 curve.G1Jac
	chunkSize := (size + chunks - 1) / chunks

	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > size {
			end = size
		}

		// Create views for the current chunk
		subScalars := scalars.Range(start, end, false)
		subBases := bases.Range(start, end, false)

		res := make(icicle_core.HostSlice[icicle_bw6761.Projective], 1)
		err := icicle_msm.Msm(subScalars, subBases, &cfg, res)
		if err != icicle_runtime.Success {
			return curve.G1Jac{}, chunks, fmt.Errorf("icicle MSM chunk %d/%d: %s", i, chunks, err.AsString())
		}

		var chunkRes curve.G1Jac
		chunkRes = g1ProjectiveToG1Jac(res[0])

		if i == 0 {
			totalG1 = chunkRes
		} else {
			totalG1.AddAssign(&chunkRes)
		}
	}

	return totalG1, chunks, nil
}

// lifted from groth16/bw6-761/icicle.go (configureMSM, chunkCountFromCap,
// getConfiguredMSMChunkCap, getConfiguredMSMMaxWindow, computeMinMSMChunks,
// computeRequiredMSMMemory)
func configureMSM(cfg *icicle_core.MSMConfig, msmSize int, scalars, bases icicle_core.DeviceSlice, bitsize int, scalarFallback, affineFallback, projectiveBytes int) int {
	if msmSize <= 0 {
		return 1
	}

	freeMem := 0.0
	if mem, err := icicle_runtime.GetAvailableMemory(); err == icicle_runtime.Success && mem != nil {
		freeMem = float64(mem.Free)
	}

	maxWindow := getConfiguredMSMMaxWindow()
	selectedC := int(cfg.C)
	if selectedC <= 0 || selectedC > maxWindow {
		selectedC = maxWindow
	}
	if cfg.Bitsize > 0 && int(cfg.Bitsize) < bitsize {
		bitsize = int(cfg.Bitsize)
	}
	if selectedC > bitsize {
		selectedC = bitsize
	}
	if selectedC < 4 {
		selectedC = 4
	}

	scalarBytes := scalarFallback
	if l := scalars.Len(); l > 0 {
		if sz := scalars.SizeOfElement(); sz > 0 {
			scalarBytes = sz
		}
	}
	affineBytes := affineFallback
	if l := bases.Len(); l > 0 {
		if sz := bases.SizeOfElement(); sz > 0 {
			affineBytes = sz
		}
	}

	precompute := int(cfg.PrecomputeFactor)
	if precompute <= 0 {
		precompute = 1
	}
	batchSize := int(cfg.BatchSize)
	if batchSize <= 0 {
		batchSize = 1
	}

	scalarsOnDevice := scalars.Len() > 0
	basesOnDevice := bases.Len() > 0

	minChunks, tunedC, tunedBatch := computeMinMSMChunks(
		msmSize,
		bitsize,
		selectedC,
		precompute,
		batchSize,
		cfg.ArePointsSharedInBatch,
		scalarBytes,
		affineBytes,
		projectiveBytes,
		freeMem,
		scalarsOnDevice,
		basesOnDevice,
	)

	cfg.C = int32(tunedC)
	cfg.BatchSize = int32(tunedBatch)

	chunkCount := minChunks
	if chunkCount <= 1 && (!scalarsOnDevice || !basesOnDevice) {
		chunkCount = 4
	}
	if chunkCount < 1 {
		chunkCount = 1
	}

	capChunks := chunkCountFromCap(msmSize, scalarBytes, affineBytes, freeMem)
	if capChunks > chunkCount {
		chunkCount = capChunks
	}
	if chunkCount > msmSize {
		chunkCount = msmSize
	}
	return chunkCount
}

func chunkCountFromCap(size int, scalarBytes, baseBytes int, freeMem float64) int {
	cap := getConfiguredMSMChunkCap()
	if cap <= 0 {
		return 1
	}
	if size <= cap {
		return 1
	}

	perElem := scalarBytes + baseBytes + 128
	if perElem > 0 && freeMem > 0 {
		capByMem := int((freeMem * 0.7) / float64(perElem))
		if capByMem > 0 && capByMem < cap {
			cap = capByMem
		}
	}
	if cap < 1 {
		return size
	}
	return (size + cap - 1) / cap
}

func getConfiguredMSMChunkCap() int {
	msmChunkCapOnce.Do(func() {
		// Hardcoded safe upper bound for MSM chunk size to prevent backend crashes on large curves (e.g. BLS12-377 G2)
		// This value (2^18) is empirically verified to be stable.
		msmChunkCap = 1 << 18
	})
	return msmChunkCap
}

func getConfiguredMSMMaxWindow() int {
	msmMaxWindowOnce.Do(func() {
		const defaultWindow = 16
		maxWindow := defaultWindow
		if val := os.Getenv("ICICLE_MSM_MAX_WINDOW"); val != "" {
			if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 && parsed < 30 {
				maxWindow = parsed
			}
		}
		msmMaxWindow = maxWindow
	})
	return msmMaxWindow
}

func computeMinMSMChunks(msmSize, bitsize, initialC, precompute, batchSize int, sharedPoints bool, scalarBytes, affineBytes, projectiveBytes int, freeMem float64, scalarsOnDevice, basesOnDevice bool) (int, int, int) {
	if msmSize <= 0 {
		return 1, initialC, batchSize
	}
	currentC := initialC
	if currentC < 4 {
		currentC = 4
	}
	if currentC > bitsize {
		currentC = bitsize
	}

	effectiveBatch := batchSize
	if effectiveBatch < 1 {
		effectiveBatch = 1
	}
	if precompute < 1 {
		precompute = 1
	}

	for {
		nofBmsAfter, scalarsMem, indicesMem, pointsMem, bucketsMem, reduced := computeRequiredMSMMemory(
			msmSize,
			currentC,
			effectiveBatch,
			bitsize,
			precompute,
			sharedPoints,
			scalarBytes,
			affineBytes,
			projectiveBytes,
			freeMem,
			scalarsOnDevice,
			basesOnDevice,
		)

		minChunks := 1

		if effectiveBatch > 1 {
			var lowerBound float64
			if sharedPoints {
				if pointsMem*2 > reduced {
					minChunks = 0
				} else {
					denom := reduced - 2*pointsMem
					if denom <= 0 {
						minChunks = 0
					} else {
						lowerBound = (2*(scalarsMem+indicesMem) + bucketsMem) / denom
						minChunks = int(math.Floor(lowerBound)) + 1
					}
				}
			} else {
				if reduced <= 0 {
					minChunks = 0
				} else {
					lowerBound = (2*(scalarsMem+pointsMem+indicesMem) + bucketsMem) / reduced
					minChunks = int(math.Floor(lowerBound)) + 1
				}
			}
			if minChunks == 0 || minChunks > effectiveBatch {
				effectiveBatch = 1
				continue
			}
		}

		if effectiveBatch < 2 {
			for bucketsMem > reduced && currentC > 4 {
				if isDebugMode {
					fmt.Printf("DEBUG: computeMinMSMChunks loop: bucketsMem=%.0f reduced=%.0f currentC=%d\n", bucketsMem, reduced, currentC)
				}
				denom := float64(3) * float64(projectiveBytes) * float64(nofBmsAfter)
				if denom <= 0 || reduced <= 0 {
					currentC = 4
					break
				}
				nextC := int(math.Floor(math.Log2(reduced / denom)))
				if nextC < 4 {
					nextC = 4
				}
				if nextC >= currentC {
					nextC = currentC - 1
				}
				if nextC < 4 {
					nextC = 4
				}
				if nextC == currentC {
					break
				}
				currentC = nextC
				nofBmsAfter, scalarsMem, indicesMem, pointsMem, bucketsMem, reduced = computeRequiredMSMMemory(
					msmSize,
					currentC,
					1,
					bitsize,
					precompute,
					sharedPoints,
					scalarBytes,
					affineBytes,
					projectiveBytes,
					freeMem,
					scalarsOnDevice,
					basesOnDevice,
				)
			}
			denom := reduced - bucketsMem
			if denom <= 0 {
				minChunks = msmSize
			} else {
				lowerBound := (2 * (scalarsMem + pointsMem + indicesMem)) / denom
				minChunks = int(math.Floor(lowerBound)) + 1
				if minChunks < 1 {
					minChunks = 1
				}
			}
		}

		if minChunks > msmSize {
			minChunks = msmSize
		}
		if currentC > bitsize {
			currentC = bitsize
		}
		if currentC < 4 {
			currentC = 4
		}

		return minChunks, currentC, effectiveBatch
	}
}

func computeRequiredMSMMemory(
	msmSize,
	c,
	batchSize,
	bitsize,
	precompute int,
	sharedPoints bool,
	scalarBytes,
	affineBytes,
	projectiveBytes int,
	freeMem float64,
	scalarsOnDevice,
	basesOnDevice bool,
) (int, float64, float64, float64, float64, float64) {
	if msmSize <= 0 {
		return 1, 0, 0, 0, 0, freeMem
	}

	nofBms := (bitsize + c - 1) / c
	if nofBms < 1 {
		nofBms = 1
	}
	nofBmsAfter := (nofBms + precompute - 1) / precompute
	if nofBmsAfter < 1 {
		nofBmsAfter = 1
	}

	scalarsMem := float64(scalarBytes) * float64(msmSize*batchSize)
	indicesMem := float64(4*unsafe.Sizeof(uint32(0))) * float64(msmSize*batchSize*nofBms)
	pointsMem := float64(affineBytes) * float64(msmSize*precompute)
	if !sharedPoints {
		pointsMem *= float64(batchSize)
	}

	var bucketFactor float64 = 4
	bucketsMem := bucketFactor * float64(projectiveBytes) * float64(uint64(1)<<uint(c)) * float64(batchSize*nofBmsAfter)

	available := freeMem
	if freeMem <= 0 {
		available = 0
	}
	if basesOnDevice {
		available += pointsMem
	}
	if scalarsOnDevice {
		available += scalarsMem
	}

	reduced := available * 0.7
	return nofBmsAfter, scalarsMem, indicesMem, pointsMem, bucketsMem, reduced
}

// gpuMsmFloor is the size below which an MSM runs on the CPU: tiny windows are
// launch-overhead-dominated, and the floor check happens before any
// DeviceSlice.Range call (Range panics on end <= start), which makes
// degenerate geometries (e.g. offset == nbPublic) safe by construction.
const gpuMsmFloor = 64

// forceCPUMSM reports whether ICICLE_PLONK_FORCE_CPU_MSM=1 is set: gpuMsm then
// computes via curve MultiExp — the determinism oracle's CPU leg. Read per
// call (not cached) so tests can toggle it; inert when unset.
func forceCPUMSM() bool {
	return os.Getenv("ICICLE_PLONK_FORCE_CPU_MSM") == "1"
}

// debugMSM reports whether ICICLE_PLONK_DEBUG_MSM=1 is set: gpuMsm then
// shadow-compares the GPU result against curve MultiExp on identical inputs
// and errors on mismatch. Read per call (not cached) so tests can toggle it;
// inert when unset.
func debugMSM() bool {
	return os.Getenv("ICICLE_PLONK_DEBUG_MSM") == "1"
}

// cpuMsm is the CPU leg of gpuMsm: gnark-crypto MultiExp on the host window.
func cpuMsm(scalars []fr.Element, bases []curve.G1Affine) (curve.G1Affine, error) {
	var res curve.G1Affine
	if _, err := res.MultiExp(bases, scalars, ecc.MultiExpConfig{}); err != nil {
		return curve.G1Affine{}, fmt.Errorf("cpu MultiExp: %w", err)
	}
	return res, nil
}

// gpuMsm is the single synchronous chokepoint through which every PLONK GPU
// MSM flows (DESIGN.md §2). It computes sum_i scalars[i]·bases[start+i] over
// the window [start, start+len(scalars)) — the window length is always
// derived from len(scalars), never hard-coded.
//
//   - deviceBases is the device-resident SRS vector (standard form, converted
//     once at load by loadG1; every call sets AreBasesMontgomeryForm=false).
//   - hostBases is the matching host SRS vector (Montgomery form), used by the
//     CPU legs (size floor, ICICLE_PLONK_FORCE_CPU_MSM, ICICLE_PLONK_DEBUG_MSM).
//   - scalars are uploaded raw in Montgomery form (AreScalarsMontgomeryForm=true,
//     no conversion kernel) and freed immediately after the MSM.
//
// The call runs inside icicle_runtime.RunOnDevice and under the per-device
// mutex. A fresh MSMConfig is taken per call because MsmCheck mutates it.
func gpuMsm(device *icicle_runtime.Device, scalars []fr.Element, hostBases []curve.G1Affine, deviceBases icicle_core.DeviceSlice, start int) (curve.G1Affine, error) {
	n := len(scalars)
	if n == 0 {
		// MSM over the empty window is the point at infinity.
		return curve.G1Affine{}, nil
	}
	end := start + n
	if start < 0 || end > len(hostBases) || deviceBases.Len() != len(hostBases) {
		return curve.G1Affine{}, fmt.Errorf("gpuMsm: window [%d:%d] out of bounds (host bases %d, device bases %d)", start, end, len(hostBases), deviceBases.Len())
	}
	hostWindow := hostBases[start:end]

	// CPU legs: size floor (checked before any Range call) and the
	// determinism oracle.
	if n < gpuMsmFloor || forceCPUMSM() {
		return cpuMsm(scalars, hostWindow)
	}

	var res curve.G1Affine
	var msmErr error
	startTime := time.Now()
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)

		mu := getDeviceMutex(device.Id)
		mu.Lock()
		defer mu.Unlock()

		// fresh config per call — MsmCheck mutates it
		cfg := icicle_msm.GetDefaultMSMConfig()
		cfg.AreScalarsMontgomeryForm = true // raw Montgomery upload, no conversion kernel
		cfg.AreBasesMontgomeryForm = false  // bases pre-converted at load (loadG1)

		// explicit Malloc so a VRAM OOM surfaces as a Go error, not a later
		// CheckDevice panic (CopyToDevice(_, true) discards the Malloc status)
		hostScalars := (icicle_core.HostSlice[fr.Element])(scalars)
		var scalarsDevice icicle_core.DeviceSlice
		if _, mallocErr := scalarsDevice.Malloc(hostScalars.SizeOfElement(), hostScalars.Len()); mallocErr != icicle_runtime.Success {
			msmErr = fmt.Errorf("gpu msm (size %d): scalar buffer malloc (%d bytes): %s",
				n, hostScalars.Len()*hostScalars.SizeOfElement(), mallocErr.AsString())
			return
		}
		defer scalarsDevice.Free()
		hostScalars.CopyToDevice(&scalarsDevice, false)

		window := deviceBases.Range(start, end, false)
		jac, chunks, err := msmChunkedG1(scalarsDevice, window, cfg)
		if err != nil {
			msmErr = fmt.Errorf("gpu msm (size %d, window [%d:%d]): %w", n, start, end, err)
			return
		}
		res.FromJacobian(&jac)

		if isProfileMode {
			log := logger.Logger()
			evt := log.Debug().Dur("took", time.Since(startTime)).Int("size", n)
			if chunks > 1 {
				evt = evt.Int("chunks", chunks)
			}
			evt.Msg("PLONK GPU MSM")
		}
	})
	<-done
	runtime.KeepAlive(scalars) // host scalars must survive until CUDA finishes copying
	if msmErr != nil {
		return curve.G1Affine{}, msmErr
	}

	if debugMSM() {
		cpuRes, err := cpuMsm(scalars, hostWindow)
		if err != nil {
			return curve.G1Affine{}, fmt.Errorf("debug shadow msm: %w", err)
		}
		if !res.Equal(&cpuRes) {
			return curve.G1Affine{}, fmt.Errorf("ICICLE_PLONK_DEBUG_MSM mismatch (size %d, window [%d:%d]): gpu %s != cpu %s", n, start, end, res.String(), cpuRes.String())
		}
	}

	return res, nil
}
