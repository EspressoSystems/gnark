//go:build icicle

package plonk_test

// Phase 6 benchmark harness: upstream CPU PLONK prover vs the ICICLE GPU
// prover (DESIGN.md §11.7, GPU_EXPERIMENT.md Phase 6).
//
// What is measured
//
//   - BenchmarkPlonkProveCPU/<curve>/2^<k>: the real upstream backend/plonk
//     Prove (NOT the icicle clone in ICICLE_PLONK_FORCE_CPU_MSM mode — the
//     baseline is what users run today).
//   - BenchmarkPlonkProveGPU/<curve>/2^<k>: icicle plonk Prove with the dual
//     SRS pinned to the GPU (icicle.WithPinKeysToGPU). Each benchmark
//     invocation does ONE UNTIMED WARM-UP PROVE before b.ResetTimer() so that
//     ICICLE backend loading (gpuinit Once), the SRS upload and the pin
//     promotion are never in the timed region: the reported number is the
//     PINNED STEADY-STATE prove. After the timed loop the device SRS is
//     released (FreeGPUResources) so VRAM does not accumulate across
//     sizes/curves within one `go test` invocation.
//
// Setup (frontend.Compile, unsafekzg SRS, plonk.Setup — PLONK has no
// DummySetup, a real 2^22 Setup takes minutes) runs OUTSIDE the timed region,
// exactly once per curve/size per process, via a lazy cache keyed by
// (curve, k). Any -bench regex therefore only pays for the sizes it selects,
// and the CPU and GPU legs of the same curve/size share one setup when both
// run in the same invocation. Both legs verify their proof once (untimed)
// with the unmodified plonk.Verify before anything is timed — we never
// benchmark garbage.
//
// Circuit: the backend/plonk/plonk_test.go referenceCircuit pattern (a chain
// of nbConstraints api.Mul(x,x) squarings) scaled per exponent, with the
// BenchmarkLargeProver X=1,Y=1 witness trick (1*1=1 fixed point) — the honest
// witness would need a big.Int Exp of 2^(2^k) which itself becomes the
// bottleneck at 2^21+.
//
// SRS cache: unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache()) caches under
// $HOME/.gnark/kzg as kzgsrs-<curve>-<size>, each file holding BOTH the
// canonical and the Lagrange SRS in raw (WriteRawTo) form, i.e. ≈ 2·2^k
// G1 points: 64 B/point bn254, 96 B bls12-377/-381, 192 B bw6-761.
// Expected cache for the full matrix below: bn254 ≈ 0.68 GiB (already on
// disk), bls12-377 ≈ 1.0 GiB, bls12-381 ≈ 1.0 GiB, bw6-761 ≈ 1.3 GiB —
// ≈ 4.2 GiB total. df -h (2026-06-11): 385 GiB free on / — plenty; the
// default cache dir is used.
//
// bw6-761 size choice: 16/18/20 plus 2^21. The disk argument against 2^21
// (0.8 GiB cache file) is void given 385 GiB free, and its pinned dual SRS
// (0.77 GiB) fits the 8 GiB card with the same headroom the design budgets
// for bls12 at 2^22. bw6 2^22 stays excluded — not for VRAM (1.5 GiB dual
// SRS fits) but to bound one-time SRS generation + Setup + per-prove wall
// time (~3-4× bn254 at twice the data; ≥30 extra minutes for one point).
// Revisit if the 2^21 numbers justify it.
//
// Full Phase 6 matrix — run SEQUENTIALLY under EXCLUSIVE GPU access, one
// curve per command so the in-process setup cache is shared between the CPU
// and GPU legs while host RAM stays bounded; -benchtime=3x for k≤20, 2x for
// k≥21; -timeout=0 because a single 2^22 leg exceeds any default timeout:
//
//	cd /home/work/repositories/gnark
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bn254/2\^(16|18|20)$'     -benchtime=3x ./backend/accelerated/icicle/plonk/ | tee bench-bn254-small.txt
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bn254/2\^22$'             -benchtime=2x ./backend/accelerated/icicle/plonk/ | tee bench-bn254-22.txt
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bls12_377/2\^(16|18|20)$' -benchtime=3x ./backend/accelerated/icicle/plonk/ | tee bench-bls12377-small.txt
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bls12_377/2\^22$'         -benchtime=2x ./backend/accelerated/icicle/plonk/ | tee bench-bls12377-22.txt
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bls12_381/2\^(16|18|20)$' -benchtime=3x ./backend/accelerated/icicle/plonk/ | tee bench-bls12381-small.txt
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bls12_381/2\^22$'         -benchtime=2x ./backend/accelerated/icicle/plonk/ | tee bench-bls12381-22.txt
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bw6_761/2\^(16|18|20)$'   -benchtime=3x ./backend/accelerated/icicle/plonk/ | tee bench-bw6761-small.txt
//	nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProve(CPU|GPU)/bw6_761/2\^21$'           -benchtime=2x ./backend/accelerated/icicle/plonk/ | tee bench-bw6761-21.txt
//
// Per-MSM/transfer breakdown pass (§11.7 deliverable — validates the
// ≤200 ms/2^22-MSM assumption and exposes any silent CPU-backend dispatch):
// rerun the largest GPU size per curve with the existing step-profile hook,
// e.g.
//
//	ICICLE_STEP_PROFILE=1 nix develop --command go test -tags=icicle -run NONE -p 1 -timeout 0 -bench 'PlonkProveGPU/bn254/2\^22$' -benchtime=1x ./backend/accelerated/icicle/plonk/ 2>&1 | tee bench-bn254-msmprofile.txt
//
// (and bls12_377/bls12_381 at 2^22, bw6_761 at 2^21 likewise).
//
// Estimated cost of the full matrix (RTX 3070, Phase-1 CPU profile bn254
// 0.47 s @2^16 / 8.6 s @2^20 / 36.4 s @2^22, bls12 ≈ 1.6×, bw6 ≈ 3.5×; Go
// runs every benchmark twice — an N=1 probe then the requested N — so a 3x
// leg proves 4 times plus warm-ups/sanity):
//   - proving time ≈ 6 min bn254, ~10 min per bls12 curve, ~13 min bw6;
//   - plus compiles (4M-constraint chain ≈ 1-2 min at 2^22), Setups
//     (minutes at 2^22) and one-time SRS generation for the three uncached
//     curves (minutes per 2^22 file);
//   - total ≈ 1.5-2 h with a warm SRS cache, ≈ 2.5-3 h on the first run.
//   - disk: ≈ +3.5 GiB SRS cache (≈ 4.2 GiB total in ~/.gnark/kzg).
//
// Everything is skipped under -short (CI safety; consistent with the
// repo-wide rule that no GPU code runs in CI).

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	icicle_plonk "github.com/consensys/gnark/backend/accelerated/icicle/plonk"
	icicle_bls12377 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bls12-377"
	icicle_bls12381 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bls12-381"
	icicle_bn254 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bn254"
	icicle_bw6761 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bw6-761"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	plonk_bw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// benchMatrix is the Phase 6 curve × size matrix. See the header comment for
// the bw6-761 size rationale.
var benchMatrix = []struct {
	curve ecc.ID
	sizes []int // domain exponents k (domain cardinality 2^k)
}{
	{ecc.BN254, []int{16, 18, 20, 22}},
	{ecc.BLS12_377, []int{16, 18, 20, 22}},
	{ecc.BLS12_381, []int{16, 18, 20, 22}},
	{ecc.BW6_761, []int{16, 18, 20, 21}},
}

// benchCircuit is the referenceCircuit pattern from backend/plonk/plonk_test.go:
// a chain of nbConstraints squarings. With the X=1 assignment the fixed point
// 1*1=1 makes Y=1 a valid public input at any chain length.
type benchCircuit struct {
	nbConstraints int
	X             frontend.Variable
	Y             frontend.Variable `gnark:",public"`
}

func (c *benchCircuit) Define(api frontend.API) error {
	x := c.X
	for i := 0; i < c.nbConstraints; i++ {
		x = api.Mul(x, x)
	}
	api.AssertIsEqual(x, c.Y)
	return nil
}

// benchSetup carries everything that must be built exactly once per
// (curve, k): compiled ccs, witnesses, the native pk/vk and (lazily) the
// icicle pk. cpuVerified/gpuVerified make the untimed proof-verification
// guard run once per process rather than once per benchmark invocation.
type benchSetup struct {
	ccs         constraint.ConstraintSystem
	fullWitness witness.Witness
	pubWitness  witness.Witness
	pk          native_plonk.ProvingKey // upstream native key — the CPU leg
	vk          native_plonk.VerifyingKey
	iciclePk    native_plonk.ProvingKey // lazy shallow wrap of pk (GPU leg)
	cpuVerified bool
	gpuVerified bool
}

// benchSetups is the lazy per-size setup cache. Benchmarks run sequentially
// (one goroutine), so a plain map is fine.
var benchSetups = map[string]*benchSetup{}

// getSetup compiles, builds/loads the SRS, runs the real plonk.Setup and
// builds the witnesses for (curve, 2^k) — once per process. All of this is
// outside any timed region.
func getSetup(b *testing.B, curveID ecc.ID, k int) *benchSetup {
	key := fmt.Sprintf("%s-%d", curveID, k)
	if s, ok := benchSetups[key]; ok {
		return s
	}

	// nbConstraints Muls + 1 AssertIsEqual + 1 public input = 2^k - 6 rows
	// → domain cardinality NextPowerOfTwo(...) = exactly 2^k.
	nbConstraints := (1 << k) - 8
	b.Logf("[setup] %s 2^%d: compiling %d-constraint chain", curveID, k, nbConstraints)
	ccs, err := frontend.Compile(curveID.ScalarField(), scs.NewBuilder,
		&benchCircuit{nbConstraints: nbConstraints}, frontend.WithCapacity(1<<k))
	if err != nil {
		b.Fatal(err)
	}

	b.Logf("[setup] %s 2^%d: SRS (unsafekzg, FS cache ~/.gnark/kzg)", curveID, k)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	if err != nil {
		b.Fatal(err)
	}

	b.Logf("[setup] %s 2^%d: plonk.Setup", curveID, k)
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		b.Fatal(err)
	}

	// X=1, Y=1 witness trick (BenchmarkLargeProver): valid at any size with
	// no big.Int Exp cost.
	fullWitness, err := frontend.NewWitness(&benchCircuit{X: 1, Y: 1}, curveID.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	pubWitness, err := fullWitness.Public()
	if err != nil {
		b.Fatal(err)
	}

	s := &benchSetup{
		ccs:         ccs,
		fullWitness: fullWitness,
		pubWitness:  pubWitness,
		pk:          pk,
		vk:          vk,
	}
	benchSetups[key] = s
	return s
}

// icicleProvingKey lazily wraps the cached native proving key into the
// per-curve ICICLE key, sharing the native key's backing arrays (the same
// shallow copy the icicle Setup performs; the prover never writes the host
// pk — the §11.3 byte-compare gates pin that invariant). This avoids a second
// multi-minute Setup (or a multi-GiB serialization round-trip) for the GPU
// leg at large sizes.
func (s *benchSetup) icicleProvingKey(b *testing.B, curveID ecc.ID) native_plonk.ProvingKey {
	if s.iciclePk != nil {
		return s.iciclePk
	}
	switch curveID {
	case ecc.BN254:
		pk := icicle_bn254.NewProvingKey()
		pk.ProvingKey = *(s.pk.(*plonk_bn254.ProvingKey))
		s.iciclePk = pk
	case ecc.BLS12_377:
		pk := icicle_bls12377.NewProvingKey()
		pk.ProvingKey = *(s.pk.(*plonk_bls12377.ProvingKey))
		s.iciclePk = pk
	case ecc.BLS12_381:
		pk := icicle_bls12381.NewProvingKey()
		pk.ProvingKey = *(s.pk.(*plonk_bls12381.ProvingKey))
		s.iciclePk = pk
	case ecc.BW6_761:
		pk := icicle_bw6761.NewProvingKey()
		pk.ProvingKey = *(s.pk.(*plonk_bw6761.ProvingKey))
		s.iciclePk = pk
	default:
		b.Fatalf("unsupported curve %s", curveID)
	}
	return s.iciclePk
}

// BenchmarkPlonkProveCPU measures the upstream backend/plonk prover — the
// baseline today's users run, NOT the icicle clone in forced-CPU mode.
func BenchmarkPlonkProveCPU(b *testing.B) {
	if testing.Short() {
		b.Skip("Phase 6 GPU benchmark harness skipped in -short mode")
	}
	for _, row := range benchMatrix {
		for _, k := range row.sizes {
			b.Run(fmt.Sprintf("%s/2^%d", row.curve, k), func(b *testing.B) {
				s := getSetup(b, row.curve, k)

				// Untimed sanity gate, once per process: the baseline proof
				// must verify.
				if !s.cpuVerified {
					proof, err := native_plonk.Prove(s.ccs, s.pk, s.fullWitness)
					if err != nil {
						b.Fatal(err)
					}
					if err := native_plonk.Verify(proof, s.vk, s.pubWitness); err != nil {
						b.Fatal(err)
					}
					s.cpuVerified = true
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := native_plonk.Prove(s.ccs, s.pk, s.fullWitness); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkPlonkProveGPU measures the ICICLE plonk prover in pinned
// steady-state: the dual SRS is uploaded and pinned by an untimed warm-up
// prove, so the timed iterations pay no backend load, no SRS upload and no
// device warm-up. The pinned device SRS is released after the timed loop.
func BenchmarkPlonkProveGPU(b *testing.B) {
	if testing.Short() {
		b.Skip("Phase 6 GPU benchmark harness skipped in -short mode")
	}
	for _, row := range benchMatrix {
		for _, k := range row.sizes {
			b.Run(fmt.Sprintf("%s/2^%d", row.curve, k), func(b *testing.B) {
				s := getSetup(b, row.curve, k)
				ipk := s.icicleProvingKey(b, row.curve)
				pin := icicle.WithPinKeysToGPU(true)

				// Untimed warm-up prove on EVERY benchmark invocation (the
				// harness calls this function more than once): loads the
				// ICICLE backend (gpuinit Once), uploads the dual SRS and
				// pins it, so the timed loop below is pinned steady-state.
				proof, err := icicle_plonk.Prove(s.ccs, ipk, s.fullWitness, pin)
				if err != nil {
					b.Fatal(err)
				}
				// Untimed sanity gate, once per process: the GPU proof must
				// pass the unmodified native verifier.
				if !s.gpuVerified {
					if err := native_plonk.Verify(proof, s.vk, s.pubWitness); err != nil {
						b.Fatal(err)
					}
					s.gpuVerified = true
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := icicle_plonk.Prove(s.ccs, ipk, s.fullWitness, pin); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()

				// Release the pinned device SRS so VRAM never accumulates
				// across sizes/curves in one invocation (8 GiB card). The
				// next invocation's warm-up prove re-uploads and re-pins.
				f, ok := ipk.(interface{ FreeGPUResources() })
				if !ok {
					b.Fatalf("icicle proving key %T does not expose FreeGPUResources", ipk)
				}
				f.FreeGPUResources()
			})
		}
	}
}
