//go:build icicle

package bls12377

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/polynomial"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

// kzgTestCircuit only exists to give test/unsafekzg a constraint system large
// enough that the resulting SRS engages the GPU path (n = 1024 >> gpuMsmFloor).
type kzgTestCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable
}

func (c *kzgTestCircuit) Define(api frontend.API) error {
	acc := c.X
	for i := 0; i < 700; i++ {
		acc = api.Mul(acc, acc)
	}
	api.AssertIsEqual(acc, c.Y)
	return nil
}

// kzgTestEnv carries a REAL dual SRS (test/unsafekzg) with both G1 vectors
// uploaded to the device: canonical (n+3 points, plus the kzg verifying key)
// and Lagrange (n points) — the two base shapes the prover commits against.
type kzgTestEnv struct {
	device    *icicle_runtime.Device
	canonical *kzg_bls12377.SRS
	lagrange  *kzg_bls12377.SRS
	devCan    icicle_core.DeviceSlice
	devLag    icicle_core.DeviceSlice
	n         int // Lagrange size; canonical is n+3
}

func setupKzgTest(t *testing.T) *kzgTestEnv {
	t.Helper()
	device := testDevice(t)

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &kzgTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	canonical := srs.(*kzg_bls12377.SRS)
	lagrange := srsLagrange.(*kzg_bls12377.SRS)

	n := len(lagrange.Pk.G1)
	if len(canonical.Pk.G1) != n+3 {
		t.Fatalf("SRS shape: canonical %d, lagrange %d, want n+3 vs n", len(canonical.Pk.G1), n)
	}
	if n < 4*gpuMsmFloor {
		t.Fatalf("test SRS too small to engage the GPU path: n=%d", n)
	}

	return &kzgTestEnv{
		device:    device,
		canonical: canonical,
		lagrange:  lagrange,
		devCan:    loadBases(t, device, canonical.Pk.G1),
		devLag:    loadBases(t, device, lagrange.Pk.G1),
		n:         n,
	}
}

func assertDigestEqual(t *testing.T, what string, got, want kzg_bls12377.Digest) {
	t.Helper()
	gotRaw, wantRaw := got.RawBytes(), want.RawBytes()
	if !bytes.Equal(gotRaw[:], wantRaw[:]) {
		t.Fatalf("%s mismatch: gpu=%s upstream=%s", what, got.String(), want.String())
	}
}

// --- eval / dividePolyByXminusA clone units -------------------------------

func TestEvalClone(t *testing.T) {
	point := randomFr(t, 1)[0]

	// empty polynomial evaluates to zero (upstream Horner loop body never runs)
	if got := eval(nil, point); !got.IsZero() {
		t.Fatalf("eval(empty) = %s, want 0", got.String())
	}

	for _, size := range []int{1, 2, 17, 64, 100, 1023} {
		p := randomFr(t, size)
		got := eval(p, point)
		ref := polynomial.Polynomial(p)
		want := ref.Eval(&point)
		if !got.Equal(&want) {
			t.Fatalf("eval clone mismatch (size %d): got %s, want %s", size, got.String(), want.String())
		}
	}
}

func TestDividePolyByXminusAClone(t *testing.T) {
	// empty input returns an empty slice (upstream early return)
	if h := dividePolyByXminusA(nil, fr.Element{}, fr.Element{}); len(h) != 0 {
		t.Fatalf("dividePolyByXminusA(empty) returned %d coefficients", len(h))
	}

	for _, size := range []int{1, 2, 17, 100, 1024} {
		f := randomFr(t, size)
		a := randomFr(t, 1)[0]
		fa := eval(f, a)

		fCopy := make([]fr.Element, len(f))
		copy(fCopy, f)
		h := dividePolyByXminusA(fCopy, fa, a)

		if len(h) != size-1 {
			t.Fatalf("quotient degree (size %d): got %d coefficients, want %d", size, len(h), size-1)
		}
		// h(x)·(x−a) + f(a) == f(x) at random points
		for _, x := range randomFr(t, 4) {
			var lhs, xa fr.Element
			xa.Sub(&x, &a)
			hx := eval(h, x)
			lhs.Mul(&hx, &xa).Add(&lhs, &fa)
			fx := eval(f, x)
			if !lhs.Equal(&fx) {
				t.Fatalf("synthetic division identity broken (size %d)", size)
			}
		}
	}
}

// --- gpuCommit ------------------------------------------------------------

func assertCommitParity(t *testing.T, env *kzgTestEnv) {
	t.Helper()
	n := env.n
	for _, b := range []struct {
		name  string
		pk    kzg_bls12377.ProvingKey
		dev   icicle_core.DeviceSlice
		sizes []int
	}{
		// canonical window shape: quotient shards / openings (up to n+3)
		{"canonical", env.canonical.Pk, env.devCan, []int{1, 17, 63, 64, 65, n/2 + 1, n, n + 2, n + 3}},
		// Lagrange window shape: wire / BSB22 / Z commitments (up to n)
		{"lagrange", env.lagrange.Pk, env.devLag, []int{1, 17, 63, 64, 65, n/2 + 1, n}},
	} {
		for _, size := range b.sizes {
			t.Run(fmt.Sprintf("%s/size=%d", b.name, size), func(t *testing.T) {
				p := randomFr(t, size)
				got, err := gpuCommit(env.device, p, b.pk.G1, b.dev)
				if err != nil {
					t.Fatalf("gpuCommit: %v", err)
				}
				want, err := kzg_bls12377.Commit(p, b.pk)
				if err != nil {
					t.Fatalf("kzg.Commit: %v", err)
				}
				assertDigestEqual(t, "commitment", got, want)
			})
		}
	}

	// the nbTasks hint (prove.go:788 passes one) must not change the result
	t.Run("canonical/nbTasks", func(t *testing.T) {
		p := randomFr(t, n+3)
		got, err := gpuCommit(env.device, p, env.canonical.Pk.G1, env.devCan, 16)
		if err != nil {
			t.Fatalf("gpuCommit: %v", err)
		}
		want, err := kzg_bls12377.Commit(p, env.canonical.Pk, 16)
		if err != nil {
			t.Fatalf("kzg.Commit: %v", err)
		}
		assertDigestEqual(t, "commitment", got, want)
	})

	// oversized polynomial: upstream-identical error
	t.Run("canonical/oversized", func(t *testing.T) {
		p := randomFr(t, n+4)
		if _, err := gpuCommit(env.device, p, env.canonical.Pk.G1, env.devCan); !errors.Is(err, kzg_bls12377.ErrInvalidPolynomialSize) {
			t.Fatalf("want ErrInvalidPolynomialSize, got %v", err)
		}
	})
}

func TestGpuCommitParity(t *testing.T) {
	assertCommitParity(t, setupKzgTest(t))
}

// --- gpuOpen --------------------------------------------------------------

func assertOpenParity(t *testing.T, env *kzgTestEnv) {
	t.Helper()
	n := env.n
	for _, size := range []int{1, 17, 65, n, n + 2, n + 3} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			p := randomFr(t, size)
			point := randomFr(t, 1)[0]

			got, err := gpuOpen(env.device, p, point, env.canonical.Pk.G1, env.devCan)
			if err != nil {
				t.Fatalf("gpuOpen: %v", err)
			}
			want, err := kzg_bls12377.Open(p, point, env.canonical.Pk)
			if err != nil {
				t.Fatalf("kzg.Open: %v", err)
			}

			// both are deterministic: field-by-field byte equality
			if !got.ClaimedValue.Equal(&want.ClaimedValue) {
				t.Fatalf("ClaimedValue mismatch: gpu=%s upstream=%s", got.ClaimedValue.String(), want.ClaimedValue.String())
			}
			assertDigestEqual(t, "H", got.H, want.H)

			// the GPU proof must verify with unmodified gnark-crypto kzg.Verify
			digest, err := kzg_bls12377.Commit(p, env.canonical.Pk)
			if err != nil {
				t.Fatalf("kzg.Commit: %v", err)
			}
			if err := kzg_bls12377.Verify(&digest, &got, point, env.canonical.Vk); err != nil {
				t.Fatalf("kzg.Verify rejected the gpuOpen proof: %v", err)
			}
		})
	}

	// oversized polynomial: upstream-identical error
	t.Run("oversized", func(t *testing.T) {
		p := randomFr(t, n+4)
		if _, err := gpuOpen(env.device, p, randomFr(t, 1)[0], env.canonical.Pk.G1, env.devCan); !errors.Is(err, kzg_bls12377.ErrInvalidPolynomialSize) {
			t.Fatalf("want ErrInvalidPolynomialSize, got %v", err)
		}
	})
}

func TestGpuOpenParity(t *testing.T) {
	assertOpenParity(t, setupKzgTest(t))
}

// --- gpuBatchOpenSinglePoint ----------------------------------------------

func assertBatchOpenParity(t *testing.T, env *kzgTestEnv) {
	t.Helper()
	n := env.n
	for _, tc := range []struct {
		name           string
		sizes          []int
		withTranscript bool
	}{
		// prover-shaped batch: [linearised poly, blinded L/R/O, S1, S2] with
		// dataTranscript = ZShiftedOpening.ClaimedValue.Marshal() (prove.go:833)
		{"proverShape", []int{n + 3, n + 2, n + 2, n + 2, n, n}, true},
		{"mixedDegrees", []int{n + 3, n, n - 1, 65, 64, 63, 17, 1}, true},
		{"noTranscript", []int{n, n/2 + 1, 65}, false},
		{"singlePoly", []int{n}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			polys := make([][]fr.Element, len(tc.sizes))
			digests := make([]kzg_bls12377.Digest, len(tc.sizes))
			for i, size := range tc.sizes {
				polys[i] = randomFr(t, size)
				var err error
				digests[i], err = kzg_bls12377.Commit(polys[i], env.canonical.Pk)
				if err != nil {
					t.Fatalf("kzg.Commit digest %d: %v", i, err)
				}
			}
			point := randomFr(t, 1)[0]
			var dataTranscript [][]byte
			if tc.withTranscript {
				zShifted := randomFr(t, 1)[0]
				dataTranscript = append(dataTranscript, zShifted.Marshal())
			}

			got, err := gpuBatchOpenSinglePoint(env.device, polys, digests, point, sha256.New(), env.canonical.Pk.G1, env.devCan, dataTranscript...)
			if err != nil {
				t.Fatalf("gpuBatchOpenSinglePoint: %v", err)
			}
			want, err := kzg_bls12377.BatchOpenSinglePoint(polys, digests, point, sha256.New(), env.canonical.Pk, dataTranscript...)
			if err != nil {
				t.Fatalf("kzg.BatchOpenSinglePoint: %v", err)
			}

			// both are deterministic: field-by-field byte equality
			if len(got.ClaimedValues) != len(want.ClaimedValues) {
				t.Fatalf("ClaimedValues length: gpu=%d upstream=%d", len(got.ClaimedValues), len(want.ClaimedValues))
			}
			for i := range got.ClaimedValues {
				if !got.ClaimedValues[i].Equal(&want.ClaimedValues[i]) {
					t.Fatalf("ClaimedValues[%d] mismatch: gpu=%s upstream=%s", i, got.ClaimedValues[i].String(), want.ClaimedValues[i].String())
				}
			}
			assertDigestEqual(t, "H", got.H, want.H)

			// the GPU proof must verify with unmodified gnark-crypto
			// kzg.BatchVerifySinglePoint — its FoldProof re-derives gamma from
			// the transcript, so this pins the deriveGamma clone byte-exactly.
			if err := kzg_bls12377.BatchVerifySinglePoint(digests, &got, point, sha256.New(), env.canonical.Vk, dataTranscript...); err != nil {
				t.Fatalf("kzg.BatchVerifySinglePoint rejected the gpuBatchOpenSinglePoint proof: %v", err)
			}
		})
	}

	// upstream-identical errors
	t.Run("digestCountMismatch", func(t *testing.T) {
		polys := [][]fr.Element{randomFr(t, 65), randomFr(t, 65)}
		digests := make([]kzg_bls12377.Digest, 1)
		if _, err := gpuBatchOpenSinglePoint(env.device, polys, digests, randomFr(t, 1)[0], sha256.New(), env.canonical.Pk.G1, env.devCan); !errors.Is(err, kzg_bls12377.ErrInvalidNbDigests) {
			t.Fatalf("want ErrInvalidNbDigests, got %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		polys := [][]fr.Element{randomFr(t, n+4)}
		digests := make([]kzg_bls12377.Digest, 1)
		if _, err := gpuBatchOpenSinglePoint(env.device, polys, digests, randomFr(t, 1)[0], sha256.New(), env.canonical.Pk.G1, env.devCan); !errors.Is(err, kzg_bls12377.ErrInvalidPolynomialSize) {
			t.Fatalf("want ErrInvalidPolynomialSize, got %v", err)
		}
	})
}

func TestGpuBatchOpenSinglePointParity(t *testing.T) {
	assertBatchOpenParity(t, setupKzgTest(t))
}

// --- CPU leg parity (ICICLE_PLONK_FORCE_CPU_MSM=1) --------------------------

func TestGpuKzgForceCPU(t *testing.T) {
	t.Setenv("ICICLE_PLONK_FORCE_CPU_MSM", "1")
	env := setupKzgTest(t)
	t.Run("commit", func(t *testing.T) { assertCommitParity(t, env) })
	t.Run("open", func(t *testing.T) { assertOpenParity(t, env) })
	t.Run("batchOpen", func(t *testing.T) { assertBatchOpenParity(t, env) })
}
