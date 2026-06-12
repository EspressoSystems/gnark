//go:build icicle

// Package gpuinit hosts the process-wide one-time initialization of the
// ICICLE backend. It is shared by every accelerated proof system package
// (groth16, plonk) so that the backend library is loaded, the devices are
// created and warmed up exactly once per process, regardless of which prover
// runs first.
package gpuinit

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark/backend/accelerated/icicle"
	"github.com/consensys/gnark/logger"

	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

var once sync.Once

// WarmUpOnce performs one-time initialization of the ICICLE backend and warms up all available devices.
// This function is called at the beginning of the Prove function to ensure that the devices are ready for use.
// It is safe to call this function multiple times; the initialization will only occur once.
//
// It returns only after the warm-up of EVERY device has completed (stream
// synchronized and destroyed). The join matters: WarmUpDevice transiently
// allocates HALF of free VRAM (MallocAsync(mem.Free/2) + FreeAsync), so an
// unjoined warm-up races the first Prove's free-VRAM prechecks and SRS
// uploads — spurious "insufficient device memory" failures on a healthy box.
// Warm-up failures panic from WarmUpOnce itself (synchronously in the caller,
// not on a detached RunOnDevice goroutine), preserving the fail-fast
// behavior.
//
// lifted from groth16/groth16_icicle.go (warmUpDevice)
func WarmUpOnce(config *icicle.Config) {
	once.Do(func() {
		log := logger.Logger()
		if config.BackendLibs != "" {
			err := icicle_runtime.LoadBackend(config.BackendLibs, true)
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("custom ICICLE backend loading error: %s", err.AsString()))
			}
		} else {
			err := icicle_runtime.LoadBackendFromEnvOrDefault()
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("default ICICLE backend loading error: %s", err.AsString()))
			}
		}
		nbDev, err := icicle_runtime.GetDeviceCount()
		if err != icicle_runtime.Success {
			panic(fmt.Sprintf("ICICLE get device count error: %s", err.AsString()))
		}
		log.Debug().Int("nbDev", nbDev).Msg("ICICLE devices detected")
		// One buffered failure channel per device; a closure reports its
		// failure (if any) instead of panicking on its RunOnDevice goroutine,
		// and the join loop below re-panics it synchronously.
		failures := make([]chan string, nbDev)
		for id := 0; id < nbDev; id++ {
			device := icicle_runtime.CreateDevice(config.Backend.String(), id)
			log.Debug().Int32("id", device.Id).Str("type", device.GetDeviceType()).Msg("ICICLE device created")
			fail := make(chan string, 1)
			failures[id] = fail
			icicle_runtime.RunOnDevice(&device, func(args ...any) {
				defer close(fail)
				stream, err := icicle_runtime.CreateStream()
				if err != icicle_runtime.Success {
					fail <- fmt.Sprintf("ICICLE create stream error: %s", err.AsString())
					return
				}
				if err := icicle_runtime.WarmUpDevice(stream); err != icicle_runtime.Success {
					icicle_runtime.DestroyStream(stream)
					fail <- fmt.Sprintf("ICICLE device warmup error: %s", err.AsString())
					return
				}
				// Join the async warm-up transient (MallocAsync/FreeAsync are
				// queued on this stream) and destroy the stream — it would
				// leak otherwise.
				if err := icicle_runtime.SynchronizeStream(stream); err != icicle_runtime.Success {
					icicle_runtime.DestroyStream(stream)
					fail <- fmt.Sprintf("ICICLE warmup stream synchronize error: %s", err.AsString())
					return
				}
				if err := icicle_runtime.DestroyStream(stream); err != icicle_runtime.Success {
					fail <- fmt.Sprintf("ICICLE warmup stream destroy error: %s", err.AsString())
					return
				}
			})
		}
		for _, fail := range failures {
			// Blocks until the device's closure sent a failure or closed the
			// channel (success: zero-value receive from the closed channel).
			if msg := <-fail; msg != "" {
				panic(msg)
			}
		}
	})
}
