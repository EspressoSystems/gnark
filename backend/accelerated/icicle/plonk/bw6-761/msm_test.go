//go:build icicle

package bw6761

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	"github.com/consensys/gnark/backend/accelerated/icicle/internal/gpuinit"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

// testDevice warms up the ICICLE backend (process-wide, once) and returns the
// default test device.
func testDevice(t *testing.T) *icicle_runtime.Device {
	t.Helper()
	cfg, err := icicle.NewConfig()
	if err != nil {
		t.Fatalf("new config: %v", err)
	}
	gpuinit.WarmUpOnce(cfg)
	device := icicle_runtime.CreateDevice(cfg.Backend.String(), cfg.DeviceID)
	return &device
}

// randomFr returns n random scalars (Montgomery form, as fr.Element always is
// internally — the form gpuMsm uploads raw).
func randomFr(t *testing.T, n int) []fr.Element {
	t.Helper()
	scalars := make([]fr.Element, n)
	for i := range scalars {
		if _, err := scalars[i].SetRandom(); err != nil {
			t.Fatalf("rand scalar: %v", err)
		}
	}
	return scalars
}

// randomBases returns n distinct random G1 points (SRS-shaped: no repeated
// generator, no points at infinity).
func randomBases(t *testing.T, n int) []curve.G1Affine {
	t.Helper()
	_, _, g1GenAff, _ := curve.Generators()
	return curve.BatchScalarMultiplicationG1(&g1GenAff, randomFr(t, n))
}

// loadBases uploads bases to the device via loadG1 (Montgomery→standard on
// device) and registers a cleanup that frees them.
func loadBases(t *testing.T, device *icicle_runtime.Device, bases []curve.G1Affine) icicle_core.DeviceSlice {
	t.Helper()
	var devBases icicle_core.DeviceSlice
	var loadErr error
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)
		mu := getDeviceMutex(device.Id)
		mu.Lock()
		defer mu.Unlock()
		devBases, loadErr = loadG1((icicle_core.HostSlice[curve.G1Affine])(bases))
	})
	<-done
	if loadErr != nil {
		t.Fatalf("loadG1: %v", loadErr)
	}
	t.Cleanup(func() {
		freed := make(chan struct{})
		icicle_runtime.RunOnDevice(device, func(args ...any) {
			defer close(freed)
			devBases.Free()
		})
		<-freed
	})
	return devBases
}

// assertMsmParity checks gpuMsm against gnark-crypto MultiExp on the same
// window of bases with fresh random scalars.
func assertMsmParity(t *testing.T, device *icicle_runtime.Device, hostBases []curve.G1Affine, devBases icicle_core.DeviceSlice, start, size int) {
	t.Helper()
	scalars := randomFr(t, size)

	got, err := gpuMsm(device, scalars, hostBases, devBases, start)
	if err != nil {
		t.Fatalf("gpuMsm (start=%d size=%d): %v", start, size, err)
	}

	var want curve.G1Affine
	if _, err := want.MultiExp(hostBases[start:start+size], scalars, ecc.MultiExpConfig{}); err != nil {
		t.Fatalf("cpu MultiExp: %v", err)
	}
	if !got.Equal(&want) {
		t.Fatalf("MSM parity mismatch (start=%d size=%d): gpu=%s cpu=%s", start, size, got.String(), want.String())
	}
}

func TestGpuMsmParity(t *testing.T) {
	device := testDevice(t)

	const n = 1 << 14
	nbBases := n + 3 // canonical SRS shape: exactly n+3 points
	hostBases := randomBases(t, nbBases)
	devBases := loadBases(t, device, hostBases)

	// Windows starting at 0 (RangeTo shape — L wire, BSB22/Z commitments,
	// quotient shards, openings). Sizes span the CPU floor boundary
	// (63/64/65), odd sizes, powers of two, and the n+2/n+3 shard shapes.
	for _, size := range []int{17, 63, 64, 65, 100, 1024, n / 4, n, n + 2, n + 3} {
		t.Run(fmt.Sprintf("rangeTo/size=%d", size), func(t *testing.T) {
			assertMsmParity(t, device, hostBases, devBases, 0, size)
		})
	}

	// Interior windows (Range(a,b) shape — R/O wires over
	// [nbPublic:offset] with nbPublic in {1,5}).
	for _, w := range []struct{ start, size int }{
		{1, 63},          // below the floor, interior
		{1, 64},          // at the floor, interior
		{5, 65},          // above the floor, interior
		{1, 1024},        // power of two, interior
		{5, n/2 + 1},     // odd interior window
		{3, nbBases - 3}, // window reaching the last base point
	} {
		t.Run(fmt.Sprintf("range/start=%d/size=%d", w.start, w.size), func(t *testing.T) {
			assertMsmParity(t, device, hostBases, devBases, w.start, w.size)
		})
	}

	// Degenerate geometry: zero-length window (offset == nbPublic). Handled
	// by the floor before any Range call (Range panics on end <= start).
	t.Run("range/empty", func(t *testing.T) {
		got, err := gpuMsm(device, nil, hostBases, devBases, 5)
		if err != nil {
			t.Fatalf("empty window: %v", err)
		}
		var infinity curve.G1Affine
		if !got.Equal(&infinity) {
			t.Fatalf("empty window: expected point at infinity, got %s", got.String())
		}
	})

	// Out-of-bounds window must error, not panic.
	t.Run("range/outOfBounds", func(t *testing.T) {
		if _, err := gpuMsm(device, randomFr(t, 128), hostBases, devBases, nbBases-64); err == nil {
			t.Fatal("expected out-of-bounds error")
		}
	})
}

// TestGpuMsmChunkedParity covers the >2^18 path: msmChunkedG1 splits the MSM
// at the 2^18 chunk cap (getConfiguredMSMChunkCap), and the chunk sub-ranges
// compose with the windowed base views the prover uses (deviceBases.Range
// then per-chunk Range on the view). Exactly two cases to keep GPU runtime
// sane: a full-prefix window one element past the cap (2 uneven chunks) and a
// ~2^19 window at an interior start offset (2 full chunks, start≠0).
func TestGpuMsmChunkedParity(t *testing.T) {
	device := testDevice(t)

	chunkCap := getConfiguredMSMChunkCap() // 1<<18
	nbBases := 2*chunkCap + 9
	hostBases := randomBases(t, nbBases)
	devBases := loadBases(t, device, hostBases)

	t.Run(fmt.Sprintf("rangeTo/size=%d", chunkCap+1), func(t *testing.T) {
		assertMsmParity(t, device, hostBases, devBases, 0, chunkCap+1)
	})
	t.Run(fmt.Sprintf("range/start=9/size=%d", 2*chunkCap), func(t *testing.T) {
		assertMsmParity(t, device, hostBases, devBases, 9, 2*chunkCap)
	})
}

func TestGpuMsmForceCPU(t *testing.T) {
	device := testDevice(t)
	hostBases := randomBases(t, 512)
	devBases := loadBases(t, device, hostBases)

	t.Setenv("ICICLE_PLONK_FORCE_CPU_MSM", "1")
	assertMsmParity(t, device, hostBases, devBases, 0, 512) // above the floor: still must take the CPU leg
	assertMsmParity(t, device, hostBases, devBases, 3, 128) // interior window
}

func TestGpuMsmDebugShadow(t *testing.T) {
	device := testDevice(t)
	hostBases := randomBases(t, 512)
	devBases := loadBases(t, device, hostBases)

	t.Setenv("ICICLE_PLONK_DEBUG_MSM", "1")

	// Identical host/device inputs: the shadow compare must pass.
	assertMsmParity(t, device, hostBases, devBases, 0, 512)
	assertMsmParity(t, device, hostBases, devBases, 5, 256)

	// Corrupt one host base so host and device disagree: the shadow compare
	// must surface the mismatch as an error.
	corrupted := make([]curve.G1Affine, len(hostBases))
	copy(corrupted, hostBases)
	corrupted[7].Add(&corrupted[7], &corrupted[8])
	if _, err := gpuMsm(device, randomFr(t, 512), corrupted, devBases, 0); err == nil {
		t.Fatal("expected ICICLE_PLONK_DEBUG_MSM mismatch error")
	}
}
