//go:build icicle

package bn254

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"

	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

type pkTestCircuit struct {
	A, B frontend.Variable `gnark:",public"`
	Res  frontend.Variable
}

func (c *pkTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.Res)
	return nil
}

// setupTestPk compiles a small circuit, generates an unsafe SRS and runs the
// wrapper Setup.
func setupTestPk(t *testing.T) *ProvingKey {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &pkTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := Setup(ccs.(*cs.SparseR1CS), *srs.(*kzg_bn254.SRS), *srsLagrange.(*kzg_bn254.SRS))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if vk == nil || pk.Vk != vk {
		t.Fatal("wrapper Setup must return the native Vk embedded in the pk")
	}
	return pk
}

func deviceFreeMemory(t *testing.T, device *icicle_runtime.Device) uint64 {
	t.Helper()
	var free uint64
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)
		mem, err := icicle_runtime.GetAvailableMemory()
		if err != icicle_runtime.Success {
			panic("get available memory: " + err.AsString())
		}
		free = uint64(mem.Free)
	})
	<-done
	return free
}

func TestSetupDevicePointersRoundTrip(t *testing.T) {
	device := testDevice(t)
	pk := setupTestPk(t)

	// pk serialization bytes before any GPU interaction.
	var before bytes.Buffer
	if _, err := pk.WriteTo(&before); err != nil {
		t.Fatalf("pk WriteTo: %v", err)
	}

	if pk.deviceInfo != nil {
		t.Fatal("fresh pk must have nil deviceInfo")
	}
	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers: %v", err)
	}
	if pk.deviceInfo == nil {
		t.Fatal("deviceInfo must be set after setupDevicePointers")
	}
	// Dual SRS shapes: canonical n+3, Lagrange n (lengths derived from the
	// host slices).
	if got, want := pk.G1Device.Kzg.Len(), len(pk.Kzg.G1); got != want {
		t.Fatalf("device Kzg len %d, want %d", got, want)
	}
	if got, want := pk.G1Device.KzgLagrange.Len(), len(pk.KzgLagrange.G1); got != want {
		t.Fatalf("device KzgLagrange len %d, want %d", got, want)
	}
	if len(pk.Kzg.G1) != len(pk.KzgLagrange.G1)+3 {
		t.Fatalf("SRS shape: canonical %d, lagrange %d, want n+3 vs n", len(pk.Kzg.G1), len(pk.KzgLagrange.G1))
	}

	// Idempotency: second call is a no-op keeping the same device pointers.
	kzgPtr := pk.G1Device.Kzg.AsUnsafePointer()
	lagPtr := pk.G1Device.KzgLagrange.AsUnsafePointer()
	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers (2nd): %v", err)
	}
	if pk.G1Device.Kzg.AsUnsafePointer() != kzgPtr || pk.G1Device.KzgLagrange.AsUnsafePointer() != lagPtr {
		t.Fatal("second setupDevicePointers must keep the same device slices")
	}

	pk.FreeGPUResources()
	if pk.deviceInfo != nil {
		t.Fatal("deviceInfo must be nil after FreeGPUResources")
	}
	pk.FreeGPUResources() // double free is a safe no-op

	// Re-setup after free works.
	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers after free: %v", err)
	}
	pk.FreeGPUResources()

	// loadG1 converts on device only: the host SRS bytes (shared with the
	// native key's backing arrays) must be untouched.
	var after bytes.Buffer
	if _, err := pk.WriteTo(&after); err != nil {
		t.Fatalf("pk WriteTo: %v", err)
	}
	if !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatal("pk serialization changed across setupDevicePointers/FreeGPUResources")
	}
}

func TestSetupDevicePointersNoLeak(t *testing.T) {
	device := testDevice(t)
	pk := setupTestPk(t)

	// Warm cycle so one-time allocations (context growth) do not count.
	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers: %v", err)
	}
	pk.FreeGPUResources()

	free0 := deviceFreeMemory(t, device)
	for i := 0; i < 5; i++ {
		if err := pk.setupDevicePointers(device); err != nil {
			t.Fatalf("setupDevicePointers (cycle %d): %v", i, err)
		}
		pk.FreeGPUResources()
	}
	free1 := deviceFreeMemory(t, device)

	// Allow 1 MiB of jitter; a leak of the SRS slices would show up as a
	// monotonic drop per cycle.
	if free1+1<<20 < free0 {
		t.Fatalf("device memory leak across setup/free cycles: free before %d, after %d", free0, free1)
	}
}
