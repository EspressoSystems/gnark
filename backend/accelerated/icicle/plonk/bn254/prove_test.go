//go:build icicle

package bn254

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// proveTestCircuit has two public inputs (>1) and one private witness — the
// same shape as the marshal-test circuit.
type proveTestCircuit struct {
	A, B frontend.Variable `gnark:",public"`
	Res  frontend.Variable
}

func (c *proveTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.Res)
	return nil
}

// deterministicRandFr is the seeded test generator for the randFr seam
// (DESIGN.md §10.1): sha256(seed ‖ tag ‖ uint32(i)) → SetBytes. It is
// domain-separated per (tag, index), hence independent of the prover's
// goroutine schedule.
func deterministicRandFr(seed []byte) func(tag string, i int) (fr.Element, error) {
	return func(tag string, i int) (fr.Element, error) {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte(tag))
		var idx [4]byte
		binary.BigEndian.PutUint32(idx[:], uint32(i))
		h.Write(idx[:])
		var r fr.Element
		r.SetBytes(h.Sum(nil))
		return r, nil
	}
}

// TestProveDeterministicSeededRandomness is the P3.5 determinism gate
// (DESIGN.md §11.4, isolated from GPU MSMs at this step): with the randFr
// seam overridden by a fixed deterministic generator, two icicle Prove runs
// on identical inputs must produce byte-identical proofs and byte-identical
// stage checkpoints — and the proof must still pass the unmodified native
// verifier.
func TestProveDeterministicSeededRandomness(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &proveTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spr := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := Setup(spr, *srs.(*kzg_bn254.SRS), *srsLagrange.(*kzg_bn254.SRS))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	assignment := proveTestCircuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pw, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	cfg, err := icicle.NewConfig()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	restoreRand := SetRandFr(deterministicRandFr([]byte("p3.5-determinism-seed")))
	defer restoreRand()

	// run proves once and returns the serialized proof plus the per-stage
	// checkpoint digests (hashed synchronously — the payloads alias live
	// prover buffers).
	run := func() ([]byte, map[string]string) {
		t.Helper()
		stages := make(map[string]string)
		var mu sync.Mutex
		restore := SetOnStageCheckpoint(func(stage string, data []fr.Element) {
			h := sha256.New()
			for i := range data {
				b := data[i].Bytes()
				h.Write(b[:])
			}
			digest := hex.EncodeToString(h.Sum(nil))
			mu.Lock()
			stages[stage] = digest
			mu.Unlock()
		})
		defer restore()

		proof, err := Prove(spr, pk, w, cfg)
		if err != nil {
			t.Fatalf("prove: %v", err)
		}
		if err := plonk_bn254.Verify(proof, vk, pw.Vector().(fr.Vector)); err != nil {
			t.Fatalf("native verify rejected the icicle proof: %v", err)
		}
		var buf bytes.Buffer
		if _, err := proof.WriteTo(&buf); err != nil {
			t.Fatalf("proof serialization: %v", err)
		}
		return buf.Bytes(), stages
	}

	proof1, stages1 := run()
	proof2, stages2 := run()

	if !bytes.Equal(proof1, proof2) {
		t.Fatal("seeded randomness: two Prove runs produced different proof bytes")
	}

	if len(stages1) == 0 {
		t.Fatal("no stage checkpoints fired — onStageCheckpoint seam not wired")
	}
	if len(stages1) != len(stages2) {
		t.Fatalf("stage checkpoint count differs between runs: %d vs %d", len(stages1), len(stages2))
	}
	for stage, digest := range stages1 {
		digest2, ok := stages2[stage]
		if !ok {
			t.Errorf("stage %q missing from second run", stage)
			continue
		}
		if digest != digest2 {
			t.Errorf("stage %q diverged between seeded runs", stage)
		}
	}
}

// TestProveUnseededVerifies is the companion unseeded gate (DESIGN.md §11.4):
// with the default crypto/rand randomness the proof must verify — this
// catches anything a seeded stub could mask.
func TestProveUnseededVerifies(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &proveTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spr := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := Setup(spr, *srs.(*kzg_bn254.SRS), *srsLagrange.(*kzg_bn254.SRS))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	assignment := proveTestCircuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pw, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	cfg, err := icicle.NewConfig()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	proof, err := Prove(spr, pk, w, cfg)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := plonk_bn254.Verify(proof, vk, pw.Vector().(fr.Vector)); err != nil {
		t.Fatalf("native verify rejected the icicle proof: %v", err)
	}
}
