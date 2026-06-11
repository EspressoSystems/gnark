//go:build icicle

package bn254

import (
	"fmt"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/logger"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

type deviceInfo struct {
	G1Device struct {
		Kzg         icicle_core.DeviceSlice // pk.Kzg.G1, n+3 canonical points, standard form
		KzgLagrange icicle_core.DeviceSlice // pk.KzgLagrange.G1, n Lagrange points, standard form
	}
	// device the slices were allocated on; FreeGPUResources must free them
	// from a goroutine pinned to that device (DeviceSlice.Free checks the
	// active device).
	device icicle_runtime.Device
	// NO CosetGenerator, NO NTT state — MSM-only (coupling documented in doc.go)
}

// ProvingKey wraps the native PLONK proving key with device pointers for the
// dual SRS. The native key is embedded BY VALUE so that
// WriteTo/ReadFrom/WriteRawTo/UnsafeReadFrom/VerifyingKey are promoted and the
// serialization stays byte-identical to the native key; deviceInfo is never
// serialized.
type ProvingKey struct {
	plonk_bn254.ProvingKey
	*deviceInfo // nil until first use
	setupMu     sync.Mutex // Protects concurrent deviceInfo initialization
	PinToGPU    bool       // If true, keep the SRS vectors in GPU memory across Prove calls (default: false)
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

// setupDevicePointers loads the dual SRS (canonical + Lagrange G1) to the
// device, converting Montgomery→standard on device only — the host slices are
// never written to. It is idempotent (no-op when deviceInfo is already set)
// and must complete synchronously before spr.Solve runs: the BSB22 hint fires
// GPU MSMs inside the solver (DESIGN.md §5 ordering invariant).
func (pk *ProvingKey) setupDevicePointers(device *icicle_runtime.Device) error {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()

	if pk.deviceInfo != nil {
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

// FreeGPUResources releases the device-resident SRS vectors.
// This should be called when the ProvingKey is no longer needed, especially if PinToGPU was enabled.
// It is safe to call this multiple times.
func (pk *ProvingKey) FreeGPUResources() {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()

	if pk.deviceInfo == nil {
		return
	}

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
