//go:build icicle

package bn254

import (
	"fmt"
	"io"
	"sync"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/logger"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

// deviceInfo carries the device-resident dual SRS and its lifetime state.
// refs/pinned/pendingFree are guarded by ProvingKey.setupMu.
//
// Lifetime model (Phase 4 ports must replicate it):
//   - every Prove acquires a reference (acquireDeviceSRS, before spr.Solve)
//     and releases it via defer (releaseDeviceSRS) when it returns;
//   - the device slices are freed by the LAST release (refs==0) unless the
//     key is pinned. Pinning is a set-once promotion — either the user field
//     PinToGPU (set before the first Prove) or icicle.WithPinKeysToGPU on any
//     single Prove pins the key; Prove never unpins and never writes the
//     public PinToGPU field;
//   - FreeGPUResources while Proves are in flight marks pendingFree: the last
//     release then frees, pinned or not;
//   - the recorded device is the only device the SRS is resident on: an
//     acquire targeting a different device errors (no multi-device residency).
type deviceInfo struct {
	G1Device struct {
		Kzg         icicle_core.DeviceSlice // pk.Kzg.G1, n+3 canonical points, standard form
		KzgLagrange icicle_core.DeviceSlice // pk.KzgLagrange.G1, n Lagrange points, standard form
	}
	// device the slices were allocated on; frees must run from a goroutine
	// pinned to that device (DeviceSlice.Free checks the active device), and
	// every acquire checks identity against it.
	device icicle_runtime.Device

	refs        int  // in-flight Proves holding the device SRS
	pinned      bool // keep the SRS resident at refs==0 (set-once promotion, see above)
	pendingFree bool // FreeGPUResources was called while refs>0: last release frees

	// NO CosetGenerator, NO NTT state — MSM-only (coupling documented in doc.go)
}

// ProvingKey wraps the native PLONK proving key with device pointers for the
// dual SRS. The native key is embedded BY VALUE so that
// WriteTo/WriteRawTo/VerifyingKey are promoted and the serialization stays
// byte-identical to the native key; deviceInfo is never serialized.
// ReadFrom/UnsafeReadFrom are overridden (not promoted) to release any stale
// device-resident SRS before the host SRS is replaced.
type ProvingKey struct {
	plonk_bn254.ProvingKey
	*deviceInfo            // nil until first use
	setupMu     sync.Mutex // Protects deviceInfo and its refs/pinned/pendingFree state
	// PinToGPU keeps the SRS vectors in GPU memory across Prove calls
	// (default: false). Set it BEFORE the first Prove on this key and do not
	// modify it afterwards: Prove reads it (under the key's internal lock)
	// but never writes it. Per-call pinning is available via
	// icicle.WithPinKeysToGPU, which promotes the key to pinned set-once.
	PinToGPU bool
}

// NewProvingKey creates a new empty proving key for deserializing into.
func NewProvingKey() *ProvingKey {
	return &ProvingKey{}
}

// Setup prepares the public data associated to a circuit + public inputs.
// It wraps the native [plonk_bn254.Setup]; the returned proving key shares the
// native key's backing arrays (shallow copy: two slice headers + Vk pointer)
// and additionally carries device pointers for acceleration.
func Setup(spr *cs.SparseR1CS, srs, srsLagrange kzg.SRS) (*ProvingKey, *plonk_bn254.VerifyingKey, error) {
	nativePk, vk, err := plonk_bn254.Setup(spr, srs, srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	pk := &ProvingKey{}
	pk.ProvingKey = *nativePk
	return pk, vk, nil
}

// ReadFrom deserializes the proving key from r (native byte stream, subgroup
// checks on). Loading a new host SRS invalidates any device-resident bases
// uploaded from the previous one — silently stale device bases would produce
// invalid proofs — so the device state is released first. Deserializing while
// a Prove is in flight on this key is a usage error and fails without reading
// from r.
func (pk *ProvingKey) ReadFrom(r io.Reader) (int64, error) {
	if err := pk.releaseDeviceSRSForReload(); err != nil {
		return 0, fmt.Errorf("icicle proving key: %w", err)
	}
	return pk.ProvingKey.ReadFrom(r)
}

// UnsafeReadFrom is [ProvingKey.ReadFrom] without subgroup checks; it releases
// any device-resident SRS first for the same staleness reason. (ReadFrom and
// UnsafeReadFrom are the only native deserializers that replace the G1
// slices — the native plonk key has no ReadDump.)
func (pk *ProvingKey) UnsafeReadFrom(r io.Reader) (int64, error) {
	if err := pk.releaseDeviceSRSForReload(); err != nil {
		return 0, fmt.Errorf("icicle proving key: %w", err)
	}
	return pk.ProvingKey.UnsafeReadFrom(r)
}

// releaseDeviceSRSForReload frees the device-resident SRS ahead of a
// deserialization that replaces the host SRS. Errors when Proves are in
// flight (the device bases are in use and cannot be safely replaced).
func (pk *ProvingKey) releaseDeviceSRSForReload() error {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()

	if pk.deviceInfo == nil {
		return nil
	}
	if pk.deviceInfo.refs > 0 {
		return fmt.Errorf("cannot deserialize: %d Prove call(s) in flight on this key", pk.deviceInfo.refs)
	}
	pk.freeDeviceSRSLocked()
	return nil
}

// setupDevicePointers ensures the dual SRS (canonical + Lagrange G1) is
// resident on device, converting Montgomery→standard on device only — the
// host slices are never written to. It does NOT take a lifetime reference:
// Prove goes through acquireDeviceSRS/releaseDeviceSRS instead. Idempotent
// for the same device; errors if the SRS is already resident on a DIFFERENT
// device.
func (pk *ProvingKey) setupDevicePointers(device *icicle_runtime.Device) error {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()
	return pk.ensureDeviceSRSLocked(device)
}

// acquireDeviceSRS is the Prove entry point of the lifetime model: it ensures
// the dual SRS is resident on device and takes one reference. It must
// complete synchronously before spr.Solve runs — the BSB22 hint fires GPU
// MSMs inside the solver (DESIGN.md §5 ordering invariant). pin promotes the
// key to pinned for this and all future Proves (set-once; Prove never
// unpins). Every successful acquire must be paired with exactly one
// releaseDeviceSRS.
func (pk *ProvingKey) acquireDeviceSRS(device *icicle_runtime.Device, pin bool) error {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()

	if err := pk.ensureDeviceSRSLocked(device); err != nil {
		return err
	}
	pk.deviceInfo.refs++
	if pin || pk.PinToGPU {
		pk.deviceInfo.pinned = true
	}
	return nil
}

// releaseDeviceSRS drops one Prove's reference on the device SRS. The slices
// are freed when this was the last reference AND the key is not pinned (or a
// FreeGPUResources call is pending).
func (pk *ProvingKey) releaseDeviceSRS() {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()

	if pk.deviceInfo == nil {
		return // defensive: unpaired release
	}
	pk.deviceInfo.refs--
	if pk.deviceInfo.refs <= 0 && (pk.deviceInfo.pendingFree || !pk.deviceInfo.pinned) {
		pk.freeDeviceSRSLocked()
	}
}

// ensureDeviceSRSLocked lazily loads the dual SRS to device. Caller must hold
// setupMu. When the SRS is already resident it verifies device identity:
// reusing slices allocated on another device would feed foreign device
// pointers to the MSMs (CheckDevice panic at best, undefined behavior at
// worst), so a mismatch is a descriptive error — free the key from the
// original device (FreeGPUResources) or use one *ProvingKey per device.
func (pk *ProvingKey) ensureDeviceSRSLocked(device *icicle_runtime.Device) error {
	if pk.deviceInfo != nil {
		if pk.deviceInfo.device.Id != device.Id || pk.deviceInfo.device.GetDeviceType() != device.GetDeviceType() {
			return fmt.Errorf("device SRS is resident on %s:%d but this operation targets %s:%d — multi-device residency is unsupported; call FreeGPUResources() first or use one ProvingKey per device",
				pk.deviceInfo.device.GetDeviceType(), pk.deviceInfo.device.Id,
				device.GetDeviceType(), device.Id)
		}
		return nil
	}
	info := &deviceInfo{device: *device}

	var loadErr error
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)

		mu := getDeviceMutex(device.Id)
		mu.Lock()
		defer mu.Unlock()

		// Fail fast when the dual SRS clearly cannot fit in free VRAM — a
		// blind upload would surface much later as an allocation panic inside
		// a kernel call. Skipped when the backend cannot report memory (the
		// MSM tuner degrades the same way).
		required := uint64(len(pk.Kzg.G1)+len(pk.KzgLagrange.G1)) * uint64(unsafe.Sizeof(curve.G1Affine{}))
		if mem, memErr := icicle_runtime.GetAvailableMemory(); memErr == icicle_runtime.Success && mem != nil && uint64(mem.Free) < required {
			loadErr = fmt.Errorf("insufficient device memory for the dual SRS: need %d bytes (%d+%d G1 points), %d bytes free on %s:%d",
				required, len(pk.Kzg.G1), len(pk.KzgLagrange.G1), mem.Free, device.GetDeviceType(), device.Id)
			return
		}

		var err error
		info.G1Device.Kzg, err = loadG1((icicle_core.HostSlice[curve.G1Affine])(pk.Kzg.G1))
		if err != nil {
			loadErr = fmt.Errorf("load Kzg G1: %w", err)
			return
		}
		info.G1Device.KzgLagrange, err = loadG1((icicle_core.HostSlice[curve.G1Affine])(pk.KzgLagrange.G1))
		if err != nil {
			info.G1Device.Kzg.Free()
			loadErr = fmt.Errorf("load KzgLagrange G1: %w", err)
			return
		}
	})
	<-done
	if loadErr != nil {
		return loadErr
	}

	pk.deviceInfo = info
	return nil
}

// FreeGPUResources releases the device-resident SRS vectors. Call it when the
// ProvingKey is no longer needed, especially if the key is pinned. It is safe
// to call multiple times. If Prove calls are in flight the free is deferred:
// it returns immediately and the LAST in-flight Prove performs the actual
// free when it releases its reference (pinned or not).
func (pk *ProvingKey) FreeGPUResources() {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()

	if pk.deviceInfo == nil {
		return
	}
	if pk.deviceInfo.refs > 0 {
		pk.deviceInfo.pendingFree = true
		return
	}
	pk.freeDeviceSRSLocked()
}

// freeDeviceSRSLocked frees both device slices and nils deviceInfo. Caller
// must hold setupMu and have checked refs == 0. The free runs from a
// goroutine pinned to the recorded device (DeviceSlice.Free checks the active
// device).
func (pk *ProvingKey) freeDeviceSRSLocked() {
	log := logger.Logger()

	done := make(chan struct{})
	icicle_runtime.RunOnDevice(&pk.device, func(args ...any) {
		defer close(done)

		mu := getDeviceMutex(pk.device.Id)
		mu.Lock()
		defer mu.Unlock()

		if pk.G1Device.Kzg.AsUnsafePointer() != nil {
			pk.G1Device.Kzg.Free()
			log.Debug().Msg("Freed device Kzg G1")
		}
		if pk.G1Device.KzgLagrange.AsUnsafePointer() != nil {
			pk.G1Device.KzgLagrange.Free()
			log.Debug().Msg("Freed device KzgLagrange G1")
		}
	})
	<-done

	pk.deviceInfo = nil
}
