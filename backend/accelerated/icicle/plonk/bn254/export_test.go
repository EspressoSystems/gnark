//go:build icicle

package bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Test seams for the cloned prover (DESIGN.md §10.1, §10.2). These are the
// ONLY way to override the randFr / onStageCheckpoint package variables —
// the production API does not expose them.
//
// The seams are package-level, so overriding them while another Prove runs in
// the same process is racy; tests must not prove concurrently with a seam
// override in place (the GPU test suite runs sequentially anyway, see doc.go).

// SetRandFr replaces the randomness seam with f and returns a function that
// restores the previous seam. Passing nil restores the default
// fr.Element.SetRandom (crypto/rand) generator. See the randFr contract in
// prove.go for the (tag, index) domain-separation guarantees f can rely on.
func SetRandFr(f func(tag string, i int) (fr.Element, error)) (restore func()) {
	old := randFr
	if f == nil {
		f = defaultRandFr
	}
	randFr = f
	return func() { randFr = old }
}

// SetOnStageCheckpoint replaces the stage-checkpoint seam with f (nil disables
// it) and returns a function that restores the previous seam. f receives live
// prover buffers and must consume (hash/copy) them synchronously; it may be
// called from any of the prover's goroutines, so it must be safe for
// concurrent use.
func SetOnStageCheckpoint(f func(stage string, data []fr.Element)) (restore func()) {
	old := onStageCheckpoint
	onStageCheckpoint = f
	return func() { onStageCheckpoint = old }
}
