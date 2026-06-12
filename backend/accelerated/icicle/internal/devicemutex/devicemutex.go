//go:build icicle

// Package devicemutex hosts the process-wide per-device mutexes shared by
// every ICICLE PLONK curve package. Each mutex serializes individual GPU
// operations (SRS upload, every MSM) on one device ACROSS curve packages:
// one process may run e.g. a bn254 inner Prove and a bw6-761 outer Prove
// concurrently on the same GPU (recursive aggregation), and per-curve-package
// mutex maps would share no lock between them — their MSM transients would
// sum and their adaptive MSM tuners would race the non-atomic free-VRAM
// reads. The groth16 backend keeps its own per-device mutexes: concurrent
// groth16 and plonk proving on one device remains unsupported (see the plonk
// curve packages' doc.go, point 2).
package devicemutex

import "sync"

var (
	deviceMu     = make(map[int32]*sync.Mutex)
	deviceMuLock sync.Mutex
)

// Get returns the process-wide exclusive mutex for GPU operations on the
// given device id, creating it on first use. Devices are keyed by id only —
// matching the per-package maps this replaces (one backend type per process).
func Get(deviceID int32) *sync.Mutex {
	deviceMuLock.Lock()
	defer deviceMuLock.Unlock()
	if _, exists := deviceMu[deviceID]; !exists {
		deviceMu[deviceID] = &sync.Mutex{}
	}
	return deviceMu[deviceID]
}
