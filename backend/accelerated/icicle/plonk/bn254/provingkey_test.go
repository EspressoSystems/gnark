//go:build icicle

package bn254

import (
	"bytes"
	"strings"
	"sync"
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

// TestDeviceIdentityMismatch: once the SRS is resident on a device, ensuring
// or acquiring it for a DIFFERENT device must fail with a descriptive error —
// MSMs against slices allocated on another device would CheckDevice-panic or
// worse. The check fires before any device call, so a phantom device id is
// safe to use on a single-GPU box.
func TestDeviceIdentityMismatch(t *testing.T) {
	device := testDevice(t)
	pk := setupTestPk(t)

	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers: %v", err)
	}
	defer pk.FreeGPUResources()

	other := icicle_runtime.CreateDevice(device.GetDeviceType(), int(device.Id)+1)
	if err := pk.setupDevicePointers(&other); err == nil {
		t.Fatal("setupDevicePointers on a different device must error while the SRS is resident elsewhere")
	}
	if err := pk.acquireDeviceSRS(&other, false); err == nil {
		t.Fatal("acquireDeviceSRS on a different device must error while the SRS is resident elsewhere")
	}

	// The recorded device keeps working.
	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers on the original device: %v", err)
	}
}

// TestReadFromReleasesDeviceState: deserializing a new host SRS into the
// wrapper must release any device-resident bases (they were uploaded from the
// PREVIOUS host SRS — keeping them would silently produce invalid proofs),
// and must refuse to run while a Prove holds a reference.
func TestReadFromReleasesDeviceState(t *testing.T) {
	device := testDevice(t)
	pk := setupTestPk(t)

	var buf bytes.Buffer
	if _, err := pk.WriteTo(&buf); err != nil {
		t.Fatalf("pk WriteTo: %v", err)
	}
	stream := buf.Bytes()

	// ReadFrom releases the stale device SRS.
	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers: %v", err)
	}
	if _, err := pk.ReadFrom(bytes.NewReader(stream)); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if pk.deviceInfo != nil {
		t.Fatal("ReadFrom must release the device-resident SRS")
	}

	// UnsafeReadFrom too.
	if err := pk.setupDevicePointers(device); err != nil {
		t.Fatalf("setupDevicePointers: %v", err)
	}
	if _, err := pk.UnsafeReadFrom(bytes.NewReader(stream)); err != nil {
		t.Fatalf("UnsafeReadFrom: %v", err)
	}
	if pk.deviceInfo != nil {
		t.Fatal("UnsafeReadFrom must release the device-resident SRS")
	}

	// With an in-flight Prove reference, deserialization is a usage error and
	// must fail without touching the stream or the device state.
	if err := pk.acquireDeviceSRS(device, false); err != nil {
		t.Fatalf("acquireDeviceSRS: %v", err)
	}
	if _, err := pk.ReadFrom(bytes.NewReader(stream)); err == nil {
		t.Fatal("ReadFrom with an in-flight reference must error")
	}
	if _, err := pk.UnsafeReadFrom(bytes.NewReader(stream)); err == nil {
		t.Fatal("UnsafeReadFrom with an in-flight reference must error")
	}
	if pk.deviceInfo == nil {
		t.Fatal("failed deserialization must not free the in-use device SRS")
	}
	pk.releaseDeviceSRS() // last unpinned release frees
	if pk.deviceInfo != nil {
		t.Fatal("last unpinned release must free the device SRS")
	}
}

// TestReadFromAcquireRaceStress: ReadFrom/UnsafeReadFrom hold setupMu across
// the ENTIRE native deserialization, so a concurrent Prove-side acquire can
// neither data-race its host-SRS reads against the stream writes nor upload
// the OLD host SRS (which would then silently serve every future proof from
// stale bases). One goroutine loops acquire/release; another loops ReadFrom
// from a pre-serialized key. The in-flight usage-error path ("Prove call(s)
// in flight") is an expected contention outcome and tolerated; any other
// error fails the test. Run with -race: the assertion is freedom from data
// races plus a consistent post-state.
func TestReadFromAcquireRaceStress(t *testing.T) {
	device := testDevice(t)
	pk := setupTestPk(t)

	var buf bytes.Buffer
	if _, err := pk.WriteTo(&buf); err != nil {
		t.Fatalf("pk WriteTo: %v", err)
	}
	stream := buf.Bytes()

	const iters = 40
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			// Unpinned acquire/release cycle: upload + last-release free, the
			// same window a small Prove exercises.
			if err := pk.acquireDeviceSRS(device, false); err != nil {
				t.Errorf("acquireDeviceSRS (iter %d): %v", i, err)
				return
			}
			pk.releaseDeviceSRS()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if _, err := pk.ReadFrom(bytes.NewReader(stream)); err != nil {
				if strings.Contains(err.Error(), "in flight") {
					continue // expected contention: a reference was held
				}
				t.Errorf("ReadFrom (iter %d): %v", i, err)
				return
			}
		}
	}()
	wg.Wait()

	// Post-state consistency: no leaked references, and the key still
	// completes a full acquire/release cycle against the reloaded host SRS.
	pk.setupMu.Lock()
	if pk.deviceInfo != nil && pk.deviceInfo.refs != 0 {
		t.Errorf("leaked device-SRS references after stress: %d", pk.deviceInfo.refs)
	}
	pk.setupMu.Unlock()
	if err := pk.acquireDeviceSRS(device, false); err != nil {
		t.Fatalf("acquireDeviceSRS after stress: %v", err)
	}
	pk.releaseDeviceSRS()
	if pk.deviceInfo != nil {
		t.Fatal("last unpinned release must free the device SRS")
	}
}

// TestFreeGPUResourcesPendingWhileInFlight: FreeGPUResources called while a
// reference is held marks pending-free and returns; the LAST release performs
// the actual free even when the key is pinned.
func TestFreeGPUResourcesPendingWhileInFlight(t *testing.T) {
	device := testDevice(t)
	pk := setupTestPk(t)

	if err := pk.acquireDeviceSRS(device, true); err != nil { // pinned
		t.Fatalf("acquireDeviceSRS: %v", err)
	}
	pk.FreeGPUResources() // refs>0: deferred
	if pk.deviceInfo == nil {
		t.Fatal("FreeGPUResources with refs>0 must defer the free, not perform it")
	}
	pk.releaseDeviceSRS()
	if pk.deviceInfo != nil {
		t.Fatal("the last release must honor the pending free, pinned or not")
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
