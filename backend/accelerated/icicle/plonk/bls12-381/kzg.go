//go:build icicle

package bls12381

// KZG routines with the single big MSM of each routed through the gpuMsm
// chokepoint (DESIGN.md §2 rows 9-11, §12 P3.4). Everything else — Horner
// evaluation, synthetic division, the Fiat-Shamir gamma transcript, the
// gamma-folding — is a byte-faithful CPU clone of gnark-crypto.
//
// Provenance: github.com/consensys/gnark-crypto v0.20.1, ecc/bls12-381/kzg/kzg.go.
// Each block below cites its upstream line range. The only sanctioned
// deviations are: (a) the quotient/commitment MultiExp replaced by gpuMsm over
// the device-resident SRS window, (b) `pk ProvingKey` replaced by the
// (hostBases, deviceBases) pair gpuMsm needs, (c) gnark-crypto's internal
// parallel.Execute replaced by gnark's internal/utils.Parallelize (identical
// signature and chunking contract), (d) error values reused from the exported
// gnark-crypto kzg package so callers observe upstream-identical errors.

import (
	"hash"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/internal/utils"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ
//
// cloned byte-faithfully from gnark-crypto v0.20.1 ecc/bls12-381/kzg/kzg.go:57-64
// (unexported upstream).
func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	for i := n - 1; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}

// dividePolyByXminusA computes (f-f(a))/(x-a), in canonical basis, in regular form
// f memory is re-used for the result
//
// cloned byte-faithfully from gnark-crypto v0.20.1 ecc/bls12-381/kzg/kzg.go:593-614
// (unexported upstream).
func dividePolyByXminusA(f []fr.Element, fa, a fr.Element) []fr.Element {

	if len(f) == 0 {
		return []fr.Element{}
	}

	// first we compute f-f(a)
	f[0].Sub(&f[0], &fa)

	// now we use synthetic division to divide by x-a
	var t fr.Element
	for i := len(f) - 2; i >= 0; i-- {
		t.Mul(&f[i+1], &a)

		f[i].Add(&f[i], &t)
	}

	// the result is of degree deg(f)-1
	return f[1:]
}

// deriveGamma derives a challenge using Fiat Shamir to fold proofs.
//
// cloned byte-faithfully from gnark-crypto v0.20.1 ecc/bls12-381/kzg/kzg.go:558-591
// (unexported upstream). The transcript byte sequence is VERIFICATION-CRITICAL
// (DESIGN.md §10.3): the verifier's kzg.FoldProof recomputes gamma over exactly
// these bytes — point.Marshal, each digest's Marshal (uncompressed RawBytes),
// each claimed value's big-endian Marshal, then the dataTranscript blobs (the
// prover passes ZShiftedOpening.ClaimedValue.Marshal()).
func deriveGamma(point fr.Element, digests []kzg.Digest, claimedValues []fr.Element, hf hash.Hash, dataTranscript ...[]byte) (fr.Element, error) {

	// derive the challenge gamma, binded to the point and the commitments
	fs := fiatshamir.NewTranscript(hf, "gamma")
	if err := fs.Bind("gamma", point.Marshal()); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", claimedValues[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}

	for i := 0; i < len(dataTranscript); i++ {
		if err := fs.Bind("gamma", dataTranscript[i]); err != nil {
			return fr.Element{}, err
		}
	}

	gammaByte, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(gammaByte)

	return gamma, nil
}

// gpuCommit commits to a polynomial using a multi exponentiation against the
// device-resident SRS window [0:len(p)]. It is assumed that the polynomial is
// in canonical form, in Montgomery form.
//
// Clone of gnark-crypto v0.20.1 ecc/bls12-381/kzg/kzg.go:158-177 (Commit) with the
// MultiExp routed through gpuMsm. hostBases/deviceBases are a matching
// host/device SRS pair (pk.Kzg.G1 with devKzg, or pk.KzgLagrange.G1 with
// devLag); the window length is derived from len(p), never hard-coded
// (StatisticalZK changes sizes). nbTasks is accepted for call-site
// compatibility with kzg.Commit (prove.go:788 passes one); it is a CPU
// parallelism hint that cannot change the MSM result, so it is ignored —
// gpuMsm's CPU legs use the default MultiExp config.
func gpuCommit(device *icicle_runtime.Device, p []fr.Element, hostBases []curve.G1Affine, deviceBases icicle_core.DeviceSlice, nbTasks ...int) (kzg.Digest, error) {

	if len(p) > len(hostBases) {
		return kzg.Digest{}, kzg.ErrInvalidPolynomialSize
	}

	_ = nbTasks

	return gpuMsm(device, p, hostBases, deviceBases, 0)
}

// gpuOpen computes an opening proof of polynomial p at given point.
//
// Clone of gnark-crypto v0.20.1 ecc/bls12-381/kzg/kzg.go:179-205 (Open) with the
// quotient commitment routed through gpuCommit (the single big MSM). The
// Horner evaluation and the synthetic division stay CPU — loop-carried serial
// (DESIGN.md §2 row 9).
func gpuOpen(device *icicle_runtime.Device, p []fr.Element, point fr.Element, hostBases []curve.G1Affine, deviceBases icicle_core.DeviceSlice) (kzg.OpeningProof, error) {
	if len(p) > len(hostBases) {
		return kzg.OpeningProof{}, kzg.ErrInvalidPolynomialSize
	}

	// build the proof
	res := kzg.OpeningProof{
		ClaimedValue: eval(p, point),
	}

	// compute H
	// h reuses memory from _p
	_p := make([]fr.Element, len(p))
	copy(_p, p)
	h := dividePolyByXminusA(_p, res.ClaimedValue, point)

	// commit to H
	hCommit, err := gpuCommit(device, h, hostBases, deviceBases)
	if err != nil {
		return kzg.OpeningProof{}, err
	}
	res.H.Set(&hCommit)

	return res, nil
}

// gpuBatchOpenSinglePoint creates a batch opening proof at point of a list of
// polynomials. It's an interactive protocol, made non-interactive using Fiat
// Shamir.
//
// * point is the point at which the polynomials are opened.
// * digests is the list of committed polynomials to open, need to derive the challenge using Fiat Shamir.
// * polynomials is the list of polynomials to open, they are supposed to be of the same size.
// * dataTranscript extra data that might be needed to derive the challenge used for folding
//
// Clone of gnark-crypto v0.20.1 ecc/bls12-381/kzg/kzg.go:248-341
// (BatchOpenSinglePoint) with the folded-quotient commitment routed through
// gpuCommit (the single big MSM) and gnark-crypto's internal parallel.Execute
// replaced by gnark's internal/utils.Parallelize. The gamma transcript, the
// fold order over the polynomials, and the gamma-folding arithmetic are
// byte-identical CPU clones (DESIGN.md §2 row 11).
func gpuBatchOpenSinglePoint(device *icicle_runtime.Device, polynomials [][]fr.Element, digests []kzg.Digest, point fr.Element, hf hash.Hash, hostBases []curve.G1Affine, deviceBases icicle_core.DeviceSlice, dataTranscript ...[]byte) (kzg.BatchOpeningProof, error) {

	// check for invalid sizes
	nbDigests := len(digests)
	if nbDigests != len(polynomials) {
		return kzg.BatchOpeningProof{}, kzg.ErrInvalidNbDigests
	}

	// TODO ensure the polynomials are of the same size
	largestPoly := -1
	for _, p := range polynomials {
		if len(p) > len(hostBases) {
			return kzg.BatchOpeningProof{}, kzg.ErrInvalidPolynomialSize
		}
		if len(p) > largestPoly {
			largestPoly = len(p)
		}
	}

	var res kzg.BatchOpeningProof

	// compute the purported values
	res.ClaimedValues = make([]fr.Element, len(polynomials))
	var wg sync.WaitGroup
	wg.Add(len(polynomials))
	for i := 0; i < len(polynomials); i++ {
		go func(_i int) {
			res.ClaimedValues[_i] = eval(polynomials[_i], point)
			wg.Done()
		}(i)
	}

	// wait for polynomial evaluations to be completed (res.ClaimedValues)
	wg.Wait()

	// derive the challenge γ, binded to the point and the commitments
	gamma, err := deriveGamma(point, digests, res.ClaimedValues, hf, dataTranscript...)
	if err != nil {
		return kzg.BatchOpeningProof{}, err
	}

	// ∑ᵢγⁱf(a)
	var foldedEvaluations fr.Element
	chSumGammai := make(chan struct{}, 1)
	go func() {
		foldedEvaluations = res.ClaimedValues[nbDigests-1]
		for i := nbDigests - 2; i >= 0; i-- {
			foldedEvaluations.Mul(&foldedEvaluations, &gamma).
				Add(&foldedEvaluations, &res.ClaimedValues[i])
		}
		close(chSumGammai)
	}()

	// compute ∑ᵢγⁱfᵢ
	// note: if we are willing to parallelize that, we could clone the poly and scale them by
	// gamma n in parallel, before reducing into foldedPolynomials
	foldedPolynomials := make([]fr.Element, largestPoly)
	copy(foldedPolynomials, polynomials[0])
	gammas := make([]fr.Element, len(polynomials))
	gammas[0] = gamma
	for i := 1; i < len(polynomials); i++ {
		gammas[i].Mul(&gammas[i-1], &gamma)
	}

	for i := 1; i < len(polynomials); i++ {
		i := i
		utils.Parallelize(len(polynomials[i]), func(start, end int) {
			var pj fr.Element
			for j := start; j < end; j++ {
				pj.Mul(&polynomials[i][j], &gammas[i-1])
				foldedPolynomials[j].Add(&foldedPolynomials[j], &pj)
			}
		})
	}

	// compute H
	<-chSumGammai
	h := dividePolyByXminusA(foldedPolynomials, foldedEvaluations, point)
	foldedPolynomials = nil // same memory as h

	res.H, err = gpuCommit(device, h, hostBases, deviceBases)
	if err != nil {
		return kzg.BatchOpeningProof{}, err
	}

	return res, nil
}
