//go:build icicle

package bw6761

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	plonk_bw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bw6-761"
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
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, &proveTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spr := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := Setup(spr, *srs.(*kzg_bw6761.SRS), *srsLagrange.(*kzg_bw6761.SRS))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	assignment := proveTestCircuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField())
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
		if err := plonk_bw6761.Verify(proof, vk, pw.Vector().(fr.Vector)); err != nil {
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
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, &proveTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spr := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := Setup(spr, *srs.(*kzg_bw6761.SRS), *srsLagrange.(*kzg_bw6761.SRS))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	assignment := proveTestCircuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField())
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
	if err := plonk_bw6761.Verify(proof, vk, pw.Vector().(fr.Vector)); err != nil {
		t.Fatalf("native verify rejected the icicle proof: %v", err)
	}
}

// ----------------------------------------------------------------------------
// P3.7 gates: the GPU-vs-forced-CPU determinism oracle and the circuit matrix
// (DESIGN.md §11.4/§11.5). Circuits are kept small enough for fast GPU runs
// but — except for the tiny one — large enough that the prover's MSMs clear
// the gpuMsmFloor (64) and actually execute on the device.
// ----------------------------------------------------------------------------

// midSizeCircuit is a chain of squarings: ~2 constraints per round, so
// n = domain0 cardinality is a few hundred — every §2 MSM row (windows
// [0:offset], [nbPublic:offset], n, n+2, n+3) is above the GPU floor.
type midSizeCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

const midSizeRounds = 200

func (c *midSizeCircuit) Define(api frontend.API) error {
	acc := c.X
	for i := 0; i < midSizeRounds; i++ {
		acc = api.Mul(acc, acc)
		acc = api.Add(acc, i)
	}
	api.AssertIsEqual(acc, c.Y)
	return nil
}

func midSizeAssignment() *midSizeCircuit {
	var acc, tmp fr.Element
	acc.SetUint64(3)
	for i := 0; i < midSizeRounds; i++ {
		acc.Square(&acc)
		tmp.SetUint64(uint64(i))
		acc.Add(&acc, &tmp)
	}
	return &midSizeCircuit{X: 3, Y: acc.BigInt(new(big.Int))}
}

// bsb22Circuit uses the PLONK BSB22 commitment API (frontend.Committer), so
// c ≥ 1 and the §2 row-4 MSM fires INSIDE spr.Solve via the overridden hint.
// The squaring chain pads n above the GPU floor so the size-n commitment MSM
// really runs on the device.
type bsb22Circuit struct {
	Public frontend.Variable `gnark:",public"`
	X      frontend.Variable
}

func (c *bsb22Circuit) Define(api frontend.API) error {
	acc := c.X
	for i := 0; i < 100; i++ {
		acc = api.Mul(acc, acc)
		acc = api.Add(acc, i)
	}
	cmt, err := api.(frontend.Committer).Commit(c.X, acc)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt, c.Public)
	return nil
}

// tinyCircuit has a single constraint: n is far below the gpuMsmFloor, so
// every MSM takes the CPU leg — gates the floor/degenerate-geometry path
// (no DeviceSlice.Range call may fire).
type tinyCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *tinyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

// compileSetup compiles the circuit and runs the icicle Setup over a fresh
// unsafe KZG SRS.
func compileSetup(t *testing.T, circuit frontend.Circuit) (*cs.SparseR1CS, *ProvingKey, *plonk_bw6761.VerifyingKey) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spr := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := Setup(spr, *srs.(*kzg_bw6761.SRS), *srsLagrange.(*kzg_bw6761.SRS))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	return spr, pk, vk
}

func witnessFor(t *testing.T, assignment frontend.Circuit) (witness.Witness, fr.Vector) {
	t.Helper()
	w, err := frontend.NewWitness(assignment, ecc.BW6_761.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pw, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	return w, pw.Vector().(fr.Vector)
}

// proveVerifySerialize runs one icicle Prove, checks it against the
// unmodified native verifier (the hard correctness gate) and returns the
// serialized proof bytes.
func proveVerifySerialize(t *testing.T, spr *cs.SparseR1CS, pk *ProvingKey, vk *plonk_bw6761.VerifyingKey, w witness.Witness, pubW fr.Vector, cfg *icicle.Config) []byte {
	t.Helper()
	proof, err := Prove(spr, pk, w, cfg)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := plonk_bw6761.Verify(proof, vk, pubW); err != nil {
		t.Fatalf("native verify rejected the icicle proof: %v", err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		t.Fatalf("proof serialization: %v", err)
	}
	return buf.Bytes()
}

// withEnv sets an environment variable for the duration of fn and restores
// the previous state afterwards. The GPU test suite is sequential (-p 1,
// doc.go), so toggling the gpuMsm env switches per test is safe.
func withEnv(t *testing.T, key, val string, fn func()) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Setenv(key, val); err != nil {
		t.Fatalf("setenv %s: %v", key, err)
	}
	defer func() {
		if had {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	}()
	fn()
}

// runSeededGPUvsForcedCPU is THE determinism oracle (DESIGN.md §10.2): with
// the randFr seam seeded, a default (GPU) Prove and an
// ICICLE_PLONK_FORCE_CPU_MSM=1 Prove on identical inputs must produce
// byte-identical proofs — every Fiat-Shamir challenge and all CPU stages
// match end-to-end, proving the GPU MSMs bit-exact. Both proofs must also
// pass the unmodified native verifier.
func runSeededGPUvsForcedCPU(t *testing.T, circuit, assignment frontend.Circuit, seed string, opts ...icicle.Option) {
	spr, pk, vk := compileSetup(t, circuit)
	w, pubW := witnessFor(t, assignment)
	cfg, err := icicle.NewConfig(opts...)
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	restore := SetRandFr(deterministicRandFr([]byte(seed)))
	defer restore()

	gpuProof := proveVerifySerialize(t, spr, pk, vk, w, pubW, cfg)

	var cpuProof []byte
	withEnv(t, "ICICLE_PLONK_FORCE_CPU_MSM", "1", func() {
		cpuProof = proveVerifySerialize(t, spr, pk, vk, w, pubW, cfg)
	})

	if !bytes.Equal(gpuProof, cpuProof) {
		t.Fatal("GPU and forced-CPU proofs differ byte-wise under seeded randomness — a GPU MSM is not bit-exact")
	}
}

// TestProveGPUvsForcedCPUMultiPublic: §11.5 matrix (a) — two public inputs,
// so rows 2/3 use the interior window [nbPublic:offset] with nbPublic = 2 and
// the correctionPoint identity is exercised.
func TestProveGPUvsForcedCPUMultiPublic(t *testing.T) {
	runSeededGPUvsForcedCPU(t, &proveTestCircuit{}, &proveTestCircuit{A: 3, B: 5, Res: 15}, "p3.7-multi-public")
}

// TestProveGPUvsForcedCPUMidSize: the determinism oracle on a circuit whose
// MSMs all clear the GPU floor — the strongest §11.4 gate.
func TestProveGPUvsForcedCPUMidSize(t *testing.T) {
	runSeededGPUvsForcedCPU(t, &midSizeCircuit{}, midSizeAssignment(), "p3.7-mid-size")
}

// TestProveGPUvsForcedCPUBSB22: §11.5 matrix (b) — c ≥ 1: the row-4 MSM runs
// inside the solver hint (ordering invariant §5) and the bsb22 randomness
// tags are exercised.
func TestProveGPUvsForcedCPUBSB22(t *testing.T) {
	runSeededGPUvsForcedCPU(t, &bsb22Circuit{}, &bsb22Circuit{Public: 1, X: 3}, "p3.7-bsb22")
}

// TestProveGPUvsForcedCPUStatisticalZK: §11.5 matrix (c) — h shards are
// n+3/n+3/n+2: exercises the len-derived windows and the qsr randomness seam.
func TestProveGPUvsForcedCPUStatisticalZK(t *testing.T) {
	runSeededGPUvsForcedCPU(t, &midSizeCircuit{}, midSizeAssignment(), "p3.7-statistical-zk",
		icicle.WithProverOptions(backend.WithStatisticalZeroKnowledge()))
}

// TestProveGPUvsForcedCPUTiny: §11.5 matrix (d) — n below the gpuMsmFloor:
// every MSM takes the pure CPU leg; the two runs must still agree (and not
// panic in any Range call).
func TestProveGPUvsForcedCPUTiny(t *testing.T) {
	runSeededGPUvsForcedCPU(t, &tinyCircuit{}, &tinyCircuit{X: 3, Y: 9}, "p3.7-tiny")
}

// ----------------------------------------------------------------------------
// Concurrency gates (DESIGN.md §11.6): two concurrent Proves on ONE proving
// key. Exercises the refcounted device-SRS lifetime (provingkey.go): both
// Proves acquire the device SRS before either releases, so the first to
// finish must NOT free it under the other one.
// ----------------------------------------------------------------------------

// concurrentProvePair runs two Proves on one shared *ProvingKey at the same
// time (pinFlags[i] is each call's opts.PinToGPU) and verifies both proofs
// with the unmodified native verifier. A barrier on the "bp-bl" checkpoint —
// the first errgroup stage, fired exactly once per Prove with no GPU
// dependency — guarantees the Proves overlap: neither proceeds until both
// have acquired the device SRS. It returns the refcount observed at the
// barrier (must be 2 — proves the refcount path, not a lucky serialization).
func concurrentProvePair(t *testing.T, spr *cs.SparseR1CS, pk *ProvingKey, vk *plonk_bw6761.VerifyingKey, w witness.Witness, pubW fr.Vector, pinFlags [2]bool) int {
	t.Helper()

	var barrier sync.WaitGroup
	barrier.Add(2)
	var barrierRefs int32
	restore := SetOnStageCheckpoint(func(stage string, data []fr.Element) {
		if stage != "bp-bl" {
			return
		}
		barrier.Done()
		barrier.Wait() // both Proves in flight before either proceeds
		pk.setupMu.Lock()
		if pk.deviceInfo != nil && int32(pk.deviceInfo.refs) > atomic.LoadInt32(&barrierRefs) {
			atomic.StoreInt32(&barrierRefs, int32(pk.deviceInfo.refs))
		}
		pk.setupMu.Unlock()
	})
	defer restore()

	var wg sync.WaitGroup
	var proofs [2]*plonk_bw6761.Proof
	var errs [2]error
	for i := 0; i < 2; i++ {
		cfg, err := icicle.NewConfig(icicle.WithPinKeysToGPU(pinFlags[i]))
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		wg.Add(1)
		go func(i int, cfg *icicle.Config) {
			defer wg.Done()
			proofs[i], errs[i] = Prove(spr, pk, w, cfg)
		}(i, cfg)
	}
	wg.Wait()

	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent prove %d: %v", i, errs[i])
		}
		if err := plonk_bw6761.Verify(proofs[i], vk, pubW); err != nil {
			t.Fatalf("native verify rejected concurrent proof %d: %v", i, err)
		}
	}
	return int(atomic.LoadInt32(&barrierRefs))
}

// deviceSRSResident reports whether pk currently holds a device-resident SRS.
func deviceSRSResident(pk *ProvingKey) bool {
	pk.setupMu.Lock()
	defer pk.setupMu.Unlock()
	return pk.deviceInfo != nil
}

// TestConcurrentProvesSharedPk: two concurrent unpinned Proves on one pk —
// the in-flight references must keep the device SRS alive until the LAST
// Prove releases it, and then it must be freed. Run under -race this also
// gates the unsynchronized pin-state write the pre-refcount code had.
func TestConcurrentProvesSharedPk(t *testing.T) {
	spr, pk, vk := compileSetup(t, &midSizeCircuit{})
	w, pubW := witnessFor(t, midSizeAssignment())

	refs := concurrentProvePair(t, spr, pk, vk, w, pubW, [2]bool{false, false})
	if refs != 2 {
		t.Fatalf("refcount path not exercised: %d refs at the barrier, want 2", refs)
	}
	if deviceSRSResident(pk) {
		t.Fatal("device SRS must be freed once the last unpinned Prove releases")
	}
}

// TestConcurrentProvesSharedPkPinned: pinned + unpinned concurrent Proves on
// one pk — the pin promotion is set-once, so the SRS must survive both
// releases; an explicit FreeGPUResources afterwards (no Prove in flight)
// must free it immediately.
func TestConcurrentProvesSharedPkPinned(t *testing.T) {
	spr, pk, vk := compileSetup(t, &midSizeCircuit{})
	w, pubW := witnessFor(t, midSizeAssignment())

	refs := concurrentProvePair(t, spr, pk, vk, w, pubW, [2]bool{true, false})
	if refs != 2 {
		t.Fatalf("refcount path not exercised: %d refs at the barrier, want 2", refs)
	}
	if !deviceSRSResident(pk) {
		t.Fatal("pin promotion: device SRS must stay resident after both Proves")
	}
	pk.FreeGPUResources()
	if deviceSRSResident(pk) {
		t.Fatal("FreeGPUResources with no Prove in flight must free immediately")
	}
}

// TestProveShadowCompareMidSize: §11.5 matrix (e) — ICICLE_PLONK_DEBUG_MSM=1
// shadow-compares every gpuMsm against curve MultiExp on identical inputs and
// errors on the first mismatch; the prove must complete with zero mismatches.
func TestProveShadowCompareMidSize(t *testing.T) {
	spr, pk, vk := compileSetup(t, &midSizeCircuit{})
	w, pubW := witnessFor(t, midSizeAssignment())
	cfg, err := icicle.NewConfig()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	withEnv(t, "ICICLE_PLONK_DEBUG_MSM", "1", func() {
		proveVerifySerialize(t, spr, pk, vk, w, pubW, cfg)
	})
}
