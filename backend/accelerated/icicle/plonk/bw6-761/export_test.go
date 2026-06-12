//go:build icicle

package bw6761

import (
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// Test seams for the cloned prover (DESIGN.md §10.1, §10.2). These are the
// ONLY way to override the randFr / onStageCheckpoint package variables —
// the production API does not expose them.
//
// The seams are package-level, so WRITING them (override or restore) while a
// Prove is in flight is racy and forbidden. Installing a seam before any
// Prove starts and restoring it after every Prove has returned is safe — the
// goroutine start/join edges order the writes — and the installed hook may
// then serve concurrent Proves, provided it is itself safe for concurrent
// use (the concurrency gate in prove_test.go does exactly this; the GPU test
// suite otherwise runs sequentially, see doc.go).

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
