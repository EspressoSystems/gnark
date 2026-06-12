//go:build icicle

// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// CLONE of the native BW6-761 PLONK prover for the ICICLE backend (DESIGN.md
// §12 P3.5/P3.6).
//
// Provenance: backend/plonk/bw6-761/prove.go at gnark commit
// c74a2dc8b890c3d7d196bf20d857a1e482ac57f7 (branch philippe/gpu-experiment),
// plus the two unexported Fiat-Shamir helpers bindPublicData and
// deriveRandomness cloned from backend/plonk/bw6-761/verify.go:315-379 at the
// same commit (appended at the end of this file).
//
// Every difference from the upstream file is a sanctioned hunk recorded in
// CLONE_NOTES.md (the P3.8 adversarial-review contract). Outside those hunks
// this file is byte-identical to upstream — verify with:
//
//	diff -u backend/plonk/bw6-761/prove.go backend/accelerated/icicle/plonk/bw6-761/prove.go
//
// As of P3.6 the 10+c large MSM call sites (DESIGN.md §2 rows 1-11) are
// routed through the gpuMsm chokepoint (gpuMsm / gpuCommit / gpuOpen /
// gpuBatchOpenSinglePoint) against the device-resident dual SRS; every window
// length is derived from len(slice), never hard-coded. commitBlindingFactor,
// the correctionPoint ScalarMultiplication and all FFT/closure code stay on
// the CPU (DESIGN.md §3).
//
// Upstream-desync liability (DESIGN.md §10.5): changes to the upstream
// prove.go on master silently desync this clone; the commit hash above is the
// detection handle.

package bw6761

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/consensys/gnark-crypto/ecc"

	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/iop"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	"github.com/consensys/gnark/backend/accelerated/icicle/internal/gpuinit"
	plonk_bw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
	"github.com/consensys/gnark/backend/witness"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

const (
	id_L int = iota
	id_R
	id_O
	id_Z
	id_ZS
	id_Ql
	id_Qr
	id_Qm
	id_Qo
	id_Qk
	id_S1
	id_S2
	id_S3
	id_Qci // [ .. , Qc_i, Pi_i, ...]
)

// blinding factors
const (
	id_Bl int = iota
	id_Br
	id_Bo
	id_Bz
	nb_blinding_polynomials
)

// blinding orders (-1 to deactivate)
const (
	order_blinding_L = 1
	order_blinding_R = 1
	order_blinding_O = 1
	order_blinding_Z = 2
)

// [icicle] The proof type is the native [plonk_bw6761.Proof]: the clone
// constructs and returns the upstream type so that WriteTo/ReadFrom,
// MarshalSolidity and the unmodified plonk.Verify work unchanged.

// randFr is the randomness seam (DESIGN.md §10.1): the FIVE SetRandom sites
// of the upstream prover — and nothing else — draw their field elements
// through this function. The (tag, index) pair domain-separates every draw so
// a seeded override is independent of the goroutine schedule
// (initBlindingPolynomials runs on its own goroutine, bsb22Hint inside the
// solver). Tags, stable contract:
//
//	"bl"/"br"/"bo"/"bz"  blinding polynomial coefficients
//	                     (getRandomPolynomial; i = coefficient index)
//	"qsr0"/"qsr1"        the two StatisticalZK quotient-shard randomizers
//	                     (newInstance; i = 0)
//	"bsb22-<depth>"      the two BSB22 hint blinding draws for commitment
//	                     depth <depth> (bsb22Hint; i = 0 for the commitment
//	                     injection slot, i = 1 for the last-constraint slot)
//
// The default is fr.Element.SetRandom (crypto/rand) — production behavior
// identical to the native prover. Overridable only via export_test.go.
var randFr = defaultRandFr

func defaultRandFr(tag string, i int) (fr.Element, error) {
	var r fr.Element
	if _, err := r.SetRandom(); err != nil {
		return fr.Element{}, err
	}
	return r, nil
}

// onStageCheckpoint is the stage-checkpoint seam (DESIGN.md §10.2 reserve
// oracle): when non-nil it receives the field-element payload of each prover
// stage at the boundary where the value is final, in the checkpoint table
// order of gap_answers[4] §4 (stages whose payload is a commitment point are
// omitted — the Fiat-Shamir challenge checkpoints cover them transitively:
// a challenge mismatch IS a commitment byte mismatch). nil (the default) is a
// no-op. The payload slices alias live prover buffers that may be mutated
// after the call returns — consume (hash/copy) them synchronously.
var onStageCheckpoint func(stage string, data []fr.Element)

// checkpoint invokes the onStageCheckpoint seam; no-op when the seam is nil
// (production).
func checkpoint(stage string, data []fr.Element) {
	if onStageCheckpoint != nil {
		onStageCheckpoint(stage, data)
	}
}

// Prove generates a PLONK proof from a SparseR1CS with full witness (secret +
// public part).
//
// [icicle] The signature replaces the native (pk *ProvingKey, opts
// ...backend.ProverOption) pair with the wrapper [*ProvingKey] and the
// [*icicle.Config] carrying the prover options (opts.ProverOpts), matching the
// per-curve groth16 ICICLE entry point. The device setup below is the only
// GPU-related addition in P3.5; past it the prover body is upstream-identical
// and performs no GPU work.
func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts *icicle.Config) (*plonk_bw6761.Proof, error) {

	log := logger.Logger().With().
		Str("curve", spr.CurveID().String()).
		Int("nbConstraints", spr.GetNbConstraints()).
		Str("acceleration", "icicle").
		Str("backend", "plonk").Logger()

	// parse the options
	opt, err := backend.NewProverConfig(opts.ProverOpts...)
	if err != nil {
		return nil, fmt.Errorf("get prover options: %w", err)
	}

	start := time.Now()

	// device setup: warm up the ICICLE backend (process-wide, idempotent),
	// create the device handle and acquire the device-resident dual SRS. The
	// acquisition completes synchronously BEFORE spr.Solve runs — the BSB22
	// hint fires GPU MSMs inside the solver (DESIGN.md §5 ordering
	// invariant). The paired release drops this Prove's reference at exit;
	// the device SRS is freed only by the LAST in-flight Prove on this pk and
	// only when the key is not pinned (refcounted lifetime model,
	// provingkey.go) — the release-at-exit is sound because no GPU work
	// happens outside the errgroup tasks below (doc.go invariant 4).
	// Individual GPU operations are serialized by the per-device mutex held
	// inside each helper (acquireDeviceSRS, gpuMsm) — per-call granularity
	// per DESIGN.md §8, which is correct only because this package owns no
	// NTT-domain state (see doc.go).
	gpuinit.WarmUpOnce(opts)
	device := icicle_runtime.CreateDevice(opts.Backend.String(), opts.DeviceID)
	if err := pk.acquireDeviceSRS(&device, opts.PinToGPU); err != nil {
		return nil, fmt.Errorf("setup device pointers: %w", err)
	}
	defer pk.releaseDeviceSRS()

	// init instance
	g, ctx := errgroup.WithContext(context.Background())
	instance, err := newInstance(ctx, spr, pk, fullWitness, &opt, &device)
	if err != nil {
		return nil, fmt.Errorf("new instance: %w", err)
	}

	// solve constraints
	g.Go(instance.solveConstraints)

	// complete qk
	g.Go(instance.completeQk)

	// init blinding polynomials
	g.Go(instance.initBlindingPolynomials)

	// derive gamma, beta (copy constraint)
	g.Go(instance.deriveGammaAndBeta)

	// compute accumulating ratio for the copy constraint
	g.Go(instance.buildRatioCopyConstraint)

	// compute h
	g.Go(instance.computeQuotient)

	// open Z (blinded) at ωζ (proof.ZShiftedOpening)
	g.Go(instance.openZ)

	// linearized polynomial
	g.Go(instance.computeLinearizedPolynomial)

	// Batch opening
	g.Go(instance.batchOpening)

	if err := g.Wait(); err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")
	return instance.proof, nil
}

// represents a Prover instance
type instance struct {
	ctx context.Context

	pk    *ProvingKey
	proof *plonk_bw6761.Proof
	spr   *cs.SparseR1CS
	opt   *backend.ProverConfig

	// [icicle] GPU device handle the per-Prove device work runs on; consumed
	// by the MSM call sites routed through gpuMsm (P3.6).
	device icicle_runtime.Device

	fs             *fiatshamir.Transcript
	kzgFoldingHash hash.Hash // for KZG folding
	htfFunc        hash.Hash // hash to field function

	// polynomials
	x                         []*iop.Polynomial // x stores tracks the polynomial we need
	bp                        []*iop.Polynomial // blinding polynomials
	h                         *iop.Polynomial   // h is the quotient polynomial
	blindedZ                  []fr.Element      // blindedZ is the blinded version of Z
	quotientShardsRandomizers [2]fr.Element     // random elements for blinding the shards of the quotient

	precomputedDenominators    []fr.Element // stores the denominators of the Lagrange polynomials
	linearizedPolynomial       []fr.Element
	linearizedPolynomialDigest kzg.Digest

	fullWitness witness.Witness

	// bsb22 commitment stuff
	commitmentInfo constraint.PlonkCommitments
	commitmentVal  []fr.Element
	cCommitments   []*iop.Polynomial

	// challenges
	gamma, beta, alpha, zeta fr.Element

	// channel to wait for the steps
	chLRO,
	chQk,
	chbp,
	chZ,
	chH,
	chRestoreLRO,
	chZOpening,
	chLinearizedPolynomial,
	chGammaBeta chan struct{}

	domain0, domain1 *fft.Domain

	trace *plonk_bw6761.Trace
}

func newInstance(ctx context.Context, spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts *backend.ProverConfig, device *icicle_runtime.Device) (*instance, error) {
	if opts.HashToFieldFn == nil {
		opts.HashToFieldFn = hash_to_field.New([]byte("BSB22-Plonk"))
	}
	s := instance{
		ctx:                    ctx,
		pk:                     pk,
		device:                 *device,
		proof:                  &plonk_bw6761.Proof{},
		spr:                    spr,
		opt:                    opts,
		fullWitness:            fullWitness,
		bp:                     make([]*iop.Polynomial, nb_blinding_polynomials),
		fs:                     fiatshamir.NewTranscript(opts.ChallengeHash, "gamma", "beta", "alpha", "zeta"),
		kzgFoldingHash:         opts.KZGFoldingHash,
		htfFunc:                opts.HashToFieldFn,
		chLRO:                  make(chan struct{}, 1),
		chQk:                   make(chan struct{}, 1),
		chbp:                   make(chan struct{}, 1),
		chGammaBeta:            make(chan struct{}, 1),
		chZ:                    make(chan struct{}, 1),
		chH:                    make(chan struct{}, 1),
		chZOpening:             make(chan struct{}, 1),
		chLinearizedPolynomial: make(chan struct{}, 1),
		chRestoreLRO:           make(chan struct{}, 1),
	}
	s.initBSB22Commitments()
	s.x = make([]*iop.Polynomial, id_Qci+2*len(s.commitmentInfo))

	// init fft domains
	nbConstraints := spr.GetNbConstraints()
	sizeSystem := uint64(nbConstraints + len(spr.Public)) // len(spr.Public) is for the placeholder constraints
	s.domain0 = fft.NewDomain(sizeSystem)

	// sampling random numbers for blinding the quotient
	// [icicle] routed through the randFr seam (tags "qsr0"/"qsr1")
	if opts.StatisticalZK {
		var err error
		if s.quotientShardsRandomizers[0], err = randFr("qsr0", 0); err != nil {
			return nil, err
		}
		if s.quotientShardsRandomizers[1], err = randFr("qsr1", 0); err != nil {
			return nil, err
		}
	}

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	if sizeSystem < 6 {
		s.domain1 = fft.NewDomain(8*sizeSystem, fft.WithoutPrecompute())
	} else {
		s.domain1 = fft.NewDomain(4*sizeSystem, fft.WithoutPrecompute())
	}

	// build trace
	s.trace = plonk_bw6761.NewTrace(spr, s.domain0)

	return &s, nil
}

func (s *instance) initBlindingPolynomials() error {
	// [icicle] coefficients drawn through the randFr seam, one tag per
	// blinding polynomial
	var err error
	if s.bp[id_Bl], err = getRandomPolynomial(order_blinding_L, "bl"); err != nil {
		return err
	}
	if s.bp[id_Br], err = getRandomPolynomial(order_blinding_R, "br"); err != nil {
		return err
	}
	if s.bp[id_Bo], err = getRandomPolynomial(order_blinding_O, "bo"); err != nil {
		return err
	}
	if s.bp[id_Bz], err = getRandomPolynomial(order_blinding_Z, "bz"); err != nil {
		return err
	}
	checkpoint("bp-bl", s.bp[id_Bl].Coefficients())
	checkpoint("bp-br", s.bp[id_Br].Coefficients())
	checkpoint("bp-bo", s.bp[id_Bo].Coefficients())
	checkpoint("bp-bz", s.bp[id_Bz].Coefficients())
	close(s.chbp)
	return nil
}

func (s *instance) initBSB22Commitments() {
	s.commitmentInfo = s.spr.CommitmentInfo.(constraint.PlonkCommitments)
	s.commitmentVal = make([]fr.Element, len(s.commitmentInfo)) // TODO @Tabaie get rid of this
	s.cCommitments = make([]*iop.Polynomial, len(s.commitmentInfo))
	s.proof.Bsb22Commitments = make([]kzg.Digest, len(s.commitmentInfo))

	// override the hint for the commitment constraints
	bsb22ID := solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder)
	s.opt.SolverOpts = append(s.opt.SolverOpts, solver.OverrideHint(bsb22ID, s.bsb22Hint))
}

// Computing and verifying Bsb22 multi-commits explained in https://hackmd.io/x8KsadW3RRyX7YTCFJIkHg
func (s *instance) bsb22Hint(_ *big.Int, ins, outs []*big.Int) error {
	var err error
	commDepth := int(ins[0].Int64())
	ins = ins[1:]

	res := &s.commitmentVal[commDepth]

	commitmentInfo := s.spr.CommitmentInfo.(constraint.PlonkCommitments)[commDepth]
	committedValues := make([]fr.Element, s.domain0.Cardinality)
	offset := s.spr.GetNbPublicVariables()
	for i := range ins {
		committedValues[offset+commitmentInfo.Committed[i]].SetBigInt(ins[i])
	}
	// [icicle] the two blinding draws routed through the randFr seam
	// (tag "bsb22-<depth>", i = slot)
	if committedValues[offset+commitmentInfo.CommitmentIndex], err = randFr(fmt.Sprintf("bsb22-%d", commDepth), 0); err != nil { // Commitment injection constraint has qcp = 0. Safe to use for blinding.
		return err
	}
	if committedValues[offset+s.spr.GetNbConstraints()-1], err = randFr(fmt.Sprintf("bsb22-%d", commDepth), 1); err != nil { // Last constraint has qcp = 0. Safe to use for blinding
		return err
	}
	s.cCommitments[commDepth] = iop.NewPolynomial(&committedValues, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	// [icicle] DESIGN.md §2 row 4: BSB22 commitment routed through gpuCommit
	// against the Lagrange pair. This runs INSIDE spr.Solve — the device SRS
	// is resident before the solver starts (§5 ordering invariant) and gpuMsm
	// takes the per-device mutex per call.
	if s.proof.Bsb22Commitments[commDepth], err = gpuCommit(&s.device, s.cCommitments[commDepth].Coefficients(), s.pk.KzgLagrange.G1, s.pk.G1Device.KzgLagrange); err != nil {
		return err
	}

	s.htfFunc.Write(s.proof.Bsb22Commitments[commDepth].Marshal())
	hashBts := s.htfFunc.Sum(nil)
	s.htfFunc.Reset()
	nbBuf := fr.Bytes
	if s.htfFunc.Size() < fr.Bytes {
		nbBuf = s.htfFunc.Size()
	}
	res.SetBytes(hashBts[:nbBuf]) // TODO @Tabaie use CommitmentIndex for this; create a new variable CommitmentConstraintIndex for other uses
	res.BigInt(outs[0])

	return nil
}

// solveConstraints computes the evaluation of the polynomials L, R, O
// and sets x[id_L], x[id_R], x[id_O] in Lagrange form
func (s *instance) solveConstraints() error {
	_solution, err := s.spr.Solve(s.fullWitness, s.opt.SolverOpts...)
	if err != nil {
		return err
	}
	solution := _solution.(*cs.SparseR1CSSolution)
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		s.x[id_L] = iop.NewPolynomial(&evaluationLDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		wg.Done()
	}()
	go func() {
		s.x[id_R] = iop.NewPolynomial(&evaluationRDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		wg.Done()
	}()

	s.x[id_O] = iop.NewPolynomial(&evaluationODomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})

	wg.Wait()

	checkpoint("solution-l", evaluationLDomainSmall)
	checkpoint("solution-r", evaluationRDomainSmall)
	checkpoint("solution-o", evaluationODomainSmall)

	// commit to l, r, o and add blinding factors
	if err := s.commitToLRO(); err != nil {
		return err
	}
	close(s.chLRO)
	return nil
}

func (s *instance) completeQk() error {
	qk := s.trace.Qk.Clone()
	qkCoeffs := qk.Coefficients()

	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}

	copy(qkCoeffs, wWitness[:len(s.spr.Public)])

	// wait for solver to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	for i := range s.commitmentInfo {
		qkCoeffs[s.spr.GetNbPublicVariables()+s.commitmentInfo[i].CommitmentIndex] = s.commitmentVal[i]
	}

	s.x[id_Qk] = qk
	close(s.chQk)

	return nil
}

// computeLagrangeOneOnCoset computes 1/n (x**n-1)/(x-1) on coset*ωⁱ
func (s *instance) computeLagrangeOneOnCoset(cosetExpMinusOne fr.Element, index int) fr.Element {
	var res fr.Element
	res.Mul(&cosetExpMinusOne, &s.domain0.CardinalityInv).
		Mul(&res, &s.precomputedDenominators[index])
	return res
}

// commitToLRO commits to L, R, O polynomials using reduced-size MSMs.
//
// L, R, O live on a domain of size n = 2^k, but only offset = nbPublic + nbConstraints
// entries carry actual values. The rest are s0 = witness[0] (first public input).
// For R and O, the first nbPublic entries (placeholders) are also s0.
//
// Key identity: Σ_{i=0}^{n-1} KzgLagrange.G1[i] = [Σ L_i(τ)]₁ = [1]₁ = Kzg.G1[0]
//
// So we can rewrite the commitment as:
//
//	[P] = Σ P[i]·G1_lag[i]
//	    = Σ (P[i]-s0)·G1_lag[i] + s0·Σ G1_lag[i]
//	    = MSM((P[i]-s0), G1_lag[i])  + s0·Kzg.G1[0]
//
// The (P[i]-s0) terms are zero in the padding region, so the MSM only needs
// the non-padding entries. For a 2.2M-constraint circuit on a 4M domain,
// this nearly halves each MSM.
func (s *instance) commitToLRO() error {
	// wait for blinding polynomials to be initialized or context to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chbp:
	}

	n := int(s.domain0.Cardinality)
	nbPublic := len(s.spr.Public)
	offset := nbPublic + s.spr.GetNbConstraints()

	// s0 = witness[0] = first public input
	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}
	s0 := wWitness[0]

	// correctionPoint = s0 · [1]₁ = s0 · Kzg.G1[0]
	var s0BigInt big.Int
	s0.BigInt(&s0BigInt)
	var correctionPoint curve.G1Affine
	correctionPoint.ScalarMultiplication(&s.pk.Kzg.G1[0], &s0BigInt)

	g := new(errgroup.Group)

	// L: subtract s0, MSM on [0:offset], add correction + blinding, restore
	g.Go(func() (err error) {
		coeffs := s.x[id_L].Coefficients()
		for i := 0; i < offset; i++ {
			coeffs[i].Sub(&coeffs[i], &s0)
		}
		var commit curve.G1Affine
		// [icicle] DESIGN.md §2 row 1: MSM over the window [0:offset] of the
		// Lagrange SRS routed through the gpuMsm chokepoint.
		if commit, err = gpuMsm(&s.device, coeffs[:offset], s.pk.KzgLagrange.G1, s.pk.G1Device.KzgLagrange, 0); err != nil {
			return
		}
		for i := 0; i < offset; i++ {
			coeffs[i].Add(&coeffs[i], &s0)
		}
		commit.Add(&commit, &correctionPoint)
		cb := commitBlindingFactor(n, s.bp[id_Bl], s.pk.Kzg)
		s.proof.LRO[0].Add(&commit, &cb)
		return
	})

	// R: subtract s0, MSM on [nbPublic:offset], add correction + blinding, restore
	g.Go(func() (err error) {
		coeffs := s.x[id_R].Coefficients()
		for i := nbPublic; i < offset; i++ {
			coeffs[i].Sub(&coeffs[i], &s0)
		}
		var commit curve.G1Affine
		// [icicle] DESIGN.md §2 rows 2/3: MSM over the interior window
		// [nbPublic:offset] of the Lagrange SRS routed through gpuMsm.
		if commit, err = gpuMsm(&s.device, coeffs[nbPublic:offset], s.pk.KzgLagrange.G1, s.pk.G1Device.KzgLagrange, nbPublic); err != nil {
			return
		}
		for i := nbPublic; i < offset; i++ {
			coeffs[i].Add(&coeffs[i], &s0)
		}
		commit.Add(&commit, &correctionPoint)
		cb := commitBlindingFactor(n, s.bp[id_Br], s.pk.Kzg)
		s.proof.LRO[1].Add(&commit, &cb)
		return
	})

	// O: same as R
	g.Go(func() (err error) {
		coeffs := s.x[id_O].Coefficients()
		for i := nbPublic; i < offset; i++ {
			coeffs[i].Sub(&coeffs[i], &s0)
		}
		var commit curve.G1Affine
		// [icicle] DESIGN.md §2 rows 2/3: MSM over the interior window
		// [nbPublic:offset] of the Lagrange SRS routed through gpuMsm.
		if commit, err = gpuMsm(&s.device, coeffs[nbPublic:offset], s.pk.KzgLagrange.G1, s.pk.G1Device.KzgLagrange, nbPublic); err != nil {
			return
		}
		for i := nbPublic; i < offset; i++ {
			coeffs[i].Add(&coeffs[i], &s0)
		}
		commit.Add(&commit, &correctionPoint)
		cb := commitBlindingFactor(n, s.bp[id_Bo], s.pk.Kzg)
		s.proof.LRO[2].Add(&commit, &cb)
		return
	})

	return g.Wait()
}

// deriveGammaAndBeta (copy constraint)
func (s *instance) deriveGammaAndBeta() error {
	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}

	if err := bindPublicData(s.fs, "gamma", s.pk.Vk, wWitness[:len(s.spr.Public)]); err != nil {
		return err
	}

	// wait for LRO to be committed
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	gamma, err := deriveRandomness(s.fs, "gamma", &s.proof.LRO[0], &s.proof.LRO[1], &s.proof.LRO[2])
	if err != nil {
		return err
	}

	bbeta, err := s.fs.ComputeChallenge("beta")
	if err != nil {
		return err
	}
	s.gamma = gamma
	s.beta.SetBytes(bbeta)

	checkpoint("gamma", []fr.Element{s.gamma})
	checkpoint("beta", []fr.Element{s.beta})

	close(s.chGammaBeta)

	return nil
}

// commitToPolyAndBlinding computes the KZG commitment of a polynomial p
// in Lagrange form (large degree)
// and add the contribution of a blinding polynomial b (small degree)
// /!\ The polynomial p is supposed to be in Lagrange form.
func (s *instance) commitToPolyAndBlinding(p, b *iop.Polynomial) (commit curve.G1Affine, err error) {

	// [icicle] DESIGN.md §2 row 5: grand-product commitment routed through
	// gpuCommit against the Lagrange pair; the blinding commit below stays CPU.
	commit, err = gpuCommit(&s.device, p.Coefficients(), s.pk.KzgLagrange.G1, s.pk.G1Device.KzgLagrange)

	// we add in the blinding contribution
	n := int(s.domain0.Cardinality)
	cb := commitBlindingFactor(n, b, s.pk.Kzg)
	commit.Add(&commit, &cb)

	return
}

func (s *instance) deriveAlpha() (err error) {
	alphaDeps := make([]*curve.G1Affine, len(s.proof.Bsb22Commitments)+1)
	for i := range s.proof.Bsb22Commitments {
		alphaDeps[i] = &s.proof.Bsb22Commitments[i]
	}
	alphaDeps[len(alphaDeps)-1] = &s.proof.Z
	s.alpha, err = deriveRandomness(s.fs, "alpha", alphaDeps...)
	return err
}

func (s *instance) deriveZeta() (err error) {
	s.zeta, err = deriveRandomness(s.fs, "zeta", &s.proof.H[0], &s.proof.H[1], &s.proof.H[2])
	return
}

// computeQuotient computes H
func (s *instance) computeQuotient() (err error) {
	s.x[id_Ql] = s.trace.Ql
	s.x[id_Qr] = s.trace.Qr
	s.x[id_Qm] = s.trace.Qm
	s.x[id_Qo] = s.trace.Qo
	s.x[id_S1] = s.trace.S1
	s.x[id_S2] = s.trace.S2
	s.x[id_S3] = s.trace.S3

	for i := 0; i < len(s.commitmentInfo); i++ {
		s.x[id_Qci+2*i] = s.trace.Qcp[i]
	}

	n := s.domain0.Cardinality
	lone := make([]fr.Element, n)
	lone[0].SetOne()

	// wait for solver to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	for i := 0; i < len(s.commitmentInfo); i++ {
		s.x[id_Qci+2*i+1] = s.cCommitments[i]
	}

	// wait for Z to be committed or context done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chZ:
	}

	// derive alpha
	if err = s.deriveAlpha(); err != nil {
		return err
	}
	checkpoint("alpha", []fr.Element{s.alpha})

	// TODO complete waste of memory find another way to do that
	identity := make([]fr.Element, n)
	identity[1].Set(&s.beta)

	s.x[id_ZS] = s.x[id_Z].ShallowClone().Shift(1)

	numerator, err := s.computeNumerator()
	if err != nil {
		return err
	}
	checkpoint("numerator", numerator.Coefficients())

	s.h, err = divideByZH(numerator, [2]*fft.Domain{s.domain0, s.domain1})
	if err != nil {
		return err
	}
	checkpoint("h", s.h.Coefficients())

	// commit to h
	// [icicle] DESIGN.md §2 rows 6-8: the canonical (host, device) SRS pair is
	// passed so the three shard commitments route through gpuCommit.
	if err := commitToQuotient(&s.device, s.h1(), s.h2(), s.h3(), s.proof, s.pk.Kzg, s.pk.G1Device.Kzg); err != nil {
		return err
	}

	if err := s.deriveZeta(); err != nil {
		return err
	}
	checkpoint("zeta", []fr.Element{s.zeta})

	// wait for clean up tasks to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chRestoreLRO:
	}

	close(s.chH)

	return nil
}

func (s *instance) buildRatioCopyConstraint() (err error) {
	// wait for gamma and beta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chGammaBeta:
	}

	// TODO @gbotrel having iop.BuildRatioCopyConstraint return something
	// with capacity = len() + 4 would avoid extra alloc / copy during openZ
	s.x[id_Z], err = iop.BuildRatioCopyConstraint(
		[]*iop.Polynomial{
			s.x[id_L],
			s.x[id_R],
			s.x[id_O],
		},
		s.trace.S,
		s.beta,
		s.gamma,
		iop.Form{Basis: iop.Lagrange, Layout: iop.Regular},
		s.domain0,
	)
	if err != nil {
		return err
	}
	checkpoint("z-lagrange", s.x[id_Z].Coefficients())

	// commit to the blinded version of z
	s.proof.Z, err = s.commitToPolyAndBlinding(s.x[id_Z], s.bp[id_Bz])

	close(s.chZ)

	return
}

// open Z (blinded) at ωζ
func (s *instance) openZ() (err error) {
	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}
	var zetaShifted fr.Element
	zetaShifted.Mul(&s.zeta, &s.pk.Vk.Generator)
	s.blindedZ = getBlindedCoefficients(s.x[id_Z], s.bp[id_Bz])
	// open z at zeta
	// [icicle] DESIGN.md §2 row 9: the opening's quotient commitment routes
	// through gpuOpen against the canonical pair (Horner eval + synthetic
	// division stay CPU).
	s.proof.ZShiftedOpening, err = gpuOpen(&s.device, s.blindedZ, zetaShifted, s.pk.Kzg.G1, s.pk.G1Device.Kzg)
	if err != nil {
		return err
	}
	checkpoint("blinded-z", s.blindedZ)
	close(s.chZOpening)
	return nil
}

func (s *instance) h1() []fr.Element {
	var h1 []fr.Element
	if !s.opt.StatisticalZK {
		h1 = s.h.Coefficients()[:s.domain0.Cardinality+2]
	} else {
		h1 = make([]fr.Element, s.domain0.Cardinality+3)
		copy(h1, s.h.Coefficients()[:s.domain0.Cardinality+2])
		h1[s.domain0.Cardinality+2].Set(&s.quotientShardsRandomizers[0])
	}
	return h1
}

func (s *instance) h2() []fr.Element {
	var h2 []fr.Element
	if !s.opt.StatisticalZK {
		h2 = s.h.Coefficients()[s.domain0.Cardinality+2 : 2*(s.domain0.Cardinality+2)]
	} else {
		h2 = make([]fr.Element, s.domain0.Cardinality+3)
		copy(h2, s.h.Coefficients()[s.domain0.Cardinality+2:2*(s.domain0.Cardinality+2)])
		h2[0].Sub(&h2[0], &s.quotientShardsRandomizers[0])
		h2[s.domain0.Cardinality+2].Set(&s.quotientShardsRandomizers[1])
	}
	return h2
}

func (s *instance) h3() []fr.Element {
	var h3 []fr.Element
	if !s.opt.StatisticalZK {
		h3 = s.h.Coefficients()[2*(s.domain0.Cardinality+2) : 3*(s.domain0.Cardinality+2)]
	} else {
		h3 = make([]fr.Element, s.domain0.Cardinality+2)
		copy(h3, s.h.Coefficients()[2*(s.domain0.Cardinality+2):3*(s.domain0.Cardinality+2)])
		h3[0].Sub(&h3[0], &s.quotientShardsRandomizers[1])
	}
	return h3
}

func (s *instance) computeLinearizedPolynomial() error {

	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}

	qcpzeta := make([]fr.Element, len(s.commitmentInfo))
	var blzeta, brzeta, bozeta fr.Element
	var wg sync.WaitGroup
	wg.Add(3 + len(s.commitmentInfo))

	for i := 0; i < len(s.commitmentInfo); i++ {
		go func(i int) {
			qcpzeta[i] = s.trace.Qcp[i].Evaluate(s.zeta)
			wg.Done()
		}(i)
	}

	go func() {
		blzeta = evaluateBlinded(s.x[id_L], s.bp[id_Bl], s.zeta)
		wg.Done()
	}()

	go func() {
		brzeta = evaluateBlinded(s.x[id_R], s.bp[id_Br], s.zeta)
		wg.Done()
	}()

	go func() {
		bozeta = evaluateBlinded(s.x[id_O], s.bp[id_Bo], s.zeta)
		wg.Done()
	}()

	// wait for Z to be opened at zeta (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chZOpening:
	}
	bzuzeta := s.proof.ZShiftedOpening.ClaimedValue

	wg.Wait()

	s.linearizedPolynomial = s.innerComputeLinearizedPoly(
		blzeta,
		brzeta,
		bozeta,
		s.alpha,
		s.beta,
		s.gamma,
		s.zeta,
		bzuzeta,
		qcpzeta,
		s.blindedZ,
		coefficients(s.cCommitments),
		s.pk,
	)
	checkpoint("linearized-poly", s.linearizedPolynomial)

	var err error
	// [icicle] DESIGN.md §2 row 10: linearized-polynomial commitment routed
	// through gpuCommit against the canonical pair (the nbTasks hint is
	// accepted and ignored — it cannot change the MSM result).
	s.linearizedPolynomialDigest, err = gpuCommit(&s.device, s.linearizedPolynomial, s.pk.Kzg.G1, s.pk.G1Device.Kzg, runtime.NumCPU()*2)
	if err != nil {
		return err
	}
	close(s.chLinearizedPolynomial)
	return nil
}

func (s *instance) batchOpening() error {

	// wait for linearizedPolynomial to be computed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLinearizedPolynomial:
	}

	polysQcp := coefficients(s.trace.Qcp)
	polysToOpen := make([][]fr.Element, 6+len(polysQcp))
	copy(polysToOpen[6:], polysQcp)

	polysToOpen[0] = s.linearizedPolynomial
	polysToOpen[1] = getBlindedCoefficients(s.x[id_L], s.bp[id_Bl])
	polysToOpen[2] = getBlindedCoefficients(s.x[id_R], s.bp[id_Br])
	polysToOpen[3] = getBlindedCoefficients(s.x[id_O], s.bp[id_Bo])
	polysToOpen[4] = s.trace.S1.Coefficients()
	polysToOpen[5] = s.trace.S2.Coefficients()

	digestsToOpen := make([]curve.G1Affine, len(s.pk.Vk.Qcp)+6)
	copy(digestsToOpen[6:], s.pk.Vk.Qcp)

	digestsToOpen[0] = s.linearizedPolynomialDigest
	digestsToOpen[1] = s.proof.LRO[0]
	digestsToOpen[2] = s.proof.LRO[1]
	digestsToOpen[3] = s.proof.LRO[2]
	digestsToOpen[4] = s.pk.Vk.S[0]
	digestsToOpen[5] = s.pk.Vk.S[1]

	var err error
	// [icicle] DESIGN.md §2 row 11: the folded-quotient commitment routes
	// through gpuBatchOpenSinglePoint against the canonical pair; transcript,
	// fold order and dataTranscript bytes replicate upstream exactly.
	s.proof.BatchedProof, err = gpuBatchOpenSinglePoint(
		&s.device,
		polysToOpen,
		digestsToOpen,
		s.zeta,
		s.kzgFoldingHash,
		s.pk.Kzg.G1,
		s.pk.G1Device.Kzg,
		s.proof.ZShiftedOpening.ClaimedValue.Marshal(),
	)
	if err != nil {
		return err
	}
	checkpoint("batch-claimed-values", s.proof.BatchedProof.ClaimedValues)

	return nil
}

// evaluate the full set of constraints, all polynomials in x are back in
// canonical regular form at the end
func (s *instance) computeNumerator() (*iop.Polynomial, error) {
	// init vectors that are used multiple times throughout the computation
	n := s.domain0.Cardinality
	twiddles0 := make([]fr.Element, n)
	if n == 1 {
		// edge case
		twiddles0[0].SetOne()
	} else {
		twiddles, err := s.domain0.Twiddles()
		if err != nil {
			return nil, err
		}
		copy(twiddles0, twiddles[0])
		w := twiddles0[1]
		for i := len(twiddles[0]); i < len(twiddles0); i++ {
			twiddles0[i].Mul(&twiddles0[i-1], &w)
		}
	}

	// wait for chQk to be closed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return nil, errContextDone
	case <-s.chQk:
	}

	nbBsbGates := len(s.proof.Bsb22Commitments)

	gateConstraint := func(u ...fr.Element) fr.Element {

		var ic, tmp fr.Element

		ic.Mul(&u[id_Ql], &u[id_L])
		tmp.Mul(&u[id_Qr], &u[id_R])
		ic.Add(&ic, &tmp)
		tmp.Mul(&u[id_Qm], &u[id_L]).Mul(&tmp, &u[id_R])
		ic.Add(&ic, &tmp)
		tmp.Mul(&u[id_Qo], &u[id_O])
		ic.Add(&ic, &tmp).Add(&ic, &u[id_Qk])
		for i := 0; i < nbBsbGates; i++ {
			tmp.Mul(&u[id_Qci+2*i], &u[id_Qci+2*i+1])
			ic.Add(&ic, &tmp)
		}

		return ic
	}

	var cs, css fr.Element
	cs.Set(&s.domain1.FrMultiplicativeGen)
	css.Square(&cs)

	// stores the current coset shifter
	var coset fr.Element
	coset.SetOne()

	// cosetExponentiatedToNMinusOne stores <coset>^n-1
	var cosetExponentiatedToNMinusOne, one fr.Element
	one.SetOne()
	bn := big.NewInt(int64(n))

	orderingConstraint := func(index int, u ...fr.Element) fr.Element {

		gamma := s.gamma

		// ordering constraint
		var a, b, c, r, l, id fr.Element

		// evaluation of ID at coset*ωⁱ where i:=index
		id.Mul(&twiddles0[index], &coset).Mul(&id, &s.beta)

		a.Add(&gamma, &u[id_L]).Add(&a, &id)
		b.Mul(&id, &cs).Add(&b, &u[id_R]).Add(&b, &gamma)
		c.Mul(&id, &css).Add(&c, &u[id_O]).Add(&c, &gamma)
		r.Mul(&a, &b).Mul(&r, &c).Mul(&r, &u[id_Z])

		a.Add(&u[id_S1], &u[id_L]).Add(&a, &gamma)
		b.Add(&u[id_S2], &u[id_R]).Add(&b, &gamma)
		c.Add(&u[id_S3], &u[id_O]).Add(&c, &gamma)
		l.Mul(&a, &b).Mul(&l, &c).Mul(&l, &u[id_ZS])

		l.Sub(&l, &r)

		return l
	}

	localConstraint := func(index int, u ...fr.Element) fr.Element {
		// local constraint
		var res, lone fr.Element
		lone = s.computeLagrangeOneOnCoset(cosetExponentiatedToNMinusOne, index)
		res.SetOne()
		res.Sub(&u[id_Z], &res).Mul(&res, &lone)

		return res
	}

	rho := int(s.domain1.Cardinality / n)
	shifters := make([]fr.Element, rho)
	shifters[0].Set(&s.domain1.FrMultiplicativeGen)
	for i := 1; i < rho; i++ {
		shifters[i].Set(&s.domain1.Generator)
	}

	cosetTable, err := s.domain0.CosetTable()
	if err != nil {
		return nil, err
	}

	// init the result polynomial & buffer
	cres := make([]fr.Element, s.domain1.Cardinality)
	buf := make([]fr.Element, n)
	var wgBuf sync.WaitGroup

	allConstraints := func(index int, u ...fr.Element) fr.Element {

		// scale S1, S2, S3 by β
		u[id_S1].Mul(&u[id_S1], &s.beta)
		u[id_S2].Mul(&u[id_S2], &s.beta)
		u[id_S3].Mul(&u[id_S3], &s.beta)

		// blind L, R, O, Z, ZS
		var y fr.Element
		y = s.bp[id_Bl].Evaluate(twiddles0[index])
		u[id_L].Add(&u[id_L], &y)
		y = s.bp[id_Br].Evaluate(twiddles0[index])
		u[id_R].Add(&u[id_R], &y)
		y = s.bp[id_Bo].Evaluate(twiddles0[index])
		u[id_O].Add(&u[id_O], &y)
		y = s.bp[id_Bz].Evaluate(twiddles0[index])
		u[id_Z].Add(&u[id_Z], &y)

		// ZS is shifted by 1; need to get correct twiddle
		y = s.bp[id_Bz].Evaluate(twiddles0[(index+1)%int(n)])
		u[id_ZS].Add(&u[id_ZS], &y)

		a := gateConstraint(u...)
		b := orderingConstraint(index, u...)
		c := localConstraint(index, u...)
		c.Mul(&c, &s.alpha).Add(&c, &b).Mul(&c, &s.alpha).Add(&c, &a)
		return c
	}

	// for the first iteration, the scalingVector is the coset table
	scalingVector := cosetTable
	scalingVectorRev := make([]fr.Element, len(cosetTable))
	copy(scalingVectorRev, cosetTable)
	fft.BitReverse(scalingVectorRev) //nolint:staticcheck // method is backwards compatible

	// pre-computed to compute the bit reverse index
	// of the result polynomial
	m := uint64(s.domain1.Cardinality)
	mm := uint64(64 - bits.TrailingZeros64(m))

	s.precomputedDenominators = make([]fr.Element, s.domain0.Cardinality)
	bufBatchInvert := make([]fr.Element, s.domain0.Cardinality)

	for i := 0; i < rho; i++ {

		coset.Mul(&coset, &shifters[i])
		cosetExponentiatedToNMinusOne.Exp(coset, bn).
			Sub(&cosetExponentiatedToNMinusOne, &one)

		for j := 0; j < int(s.domain0.Cardinality); j++ {
			s.precomputedDenominators[j].
				Mul(&coset, &twiddles0[j]).
				Sub(&s.precomputedDenominators[j], &one)
		}
		batchInvert(s.precomputedDenominators, bufBatchInvert)

		// bl <- bl *( (s*ωⁱ)ⁿ-1 )s
		for _, q := range s.bp {
			cq := q.Coefficients()
			acc := cosetExponentiatedToNMinusOne
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &acc)
				acc.Mul(&acc, &shifters[i])
			}
		}
		if i == 1 {
			// we have to update the scalingVector; instead of scaling by
			// cosets we scale by the twiddles of the large domain.
			w := s.domain1.Generator
			scalingVector = make([]fr.Element, n)
			fft.BuildExpTable(w, scalingVector)

			// reuse memory
			copy(scalingVectorRev, scalingVector)
			fft.BitReverse(scalingVectorRev) //nolint:staticcheck // method is backwards compatible
		}

		// we do **a lot** of FFT here, but on the small domain.
		// note that for all the polynomials in the proving key
		// (Ql, Qr, Qm, Qo, S1, S2, S3, Qcp, Qc) and ID, LOne
		// we could pre-compute these rho*2 FFTs and store them
		// at the cost of a huge memory footprint.
		batchApply(s.x, func(p *iop.Polynomial) {
			nbTasks := calculateNbTasks(len(s.x)-1) * 2
			// shift polynomials to be in the correct coset
			p.ToCanonical(s.domain0, nbTasks)

			// scale by shifter[i]
			var w []fr.Element
			if p.Layout == iop.Regular {
				w = scalingVector
			} else {
				w = scalingVectorRev
			}

			cp := p.Coefficients()
			utils.Parallelize(len(cp), func(start, end int) {
				for j := start; j < end; j++ {
					cp[j].Mul(&cp[j], &w[j])
				}
			}, nbTasks)

			// fft in the correct coset
			p.ToLagrange(s.domain0, nbTasks).ToRegular()
		})

		wgBuf.Wait()

		if _, err := iop.Evaluate(
			allConstraints,
			buf,
			iop.Form{Basis: iop.Lagrange, Layout: iop.Regular},
			s.x...,
		); err != nil {
			return nil, err
		}
		wgBuf.Add(1)
		go func(i int) {
			for j := 0; j < int(n); j++ {
				// we build the polynomial in bit reverse order
				cres[bits.Reverse64(uint64(rho*j+i))>>mm] = buf[j]
			}
			wgBuf.Done()
		}(i)

		cosetExponentiatedToNMinusOne.
			Inverse(&cosetExponentiatedToNMinusOne)
		// bl <- bl *( (s*ωⁱ)ⁿ-1 )**-1
		for _, q := range s.bp {
			cq := q.Coefficients()
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &cosetExponentiatedToNMinusOne)
			}
		}
	}

	// scale everything back
	go func() {
		s.x[id_ZS] = nil
		s.x[id_Qk] = nil

		var cs fr.Element
		cs.Set(&shifters[0])
		for i := 1; i < len(shifters); i++ {
			cs.Mul(&cs, &shifters[i])
		}
		cs.Inverse(&cs)

		batchApply(s.x, func(p *iop.Polynomial) {
			if p == nil {
				return
			}
			p.ToCanonical(s.domain0, 8).ToRegular()
			scalePowers(p, cs)
		})

		for _, q := range s.bp {
			scalePowers(q, cs)
		}

		close(s.chRestoreLRO)
	}()

	// ensure all the goroutines are done
	wgBuf.Wait()

	res := iop.NewPolynomial(&cres, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse})

	return res, nil

}

// batchInvert modifies in place vec, with vec[i]<-vec[i]^{-1}, using
// the Montgomery batch inversion trick. We don't use gnark-crypto's batchInvert
// because we want to use a buffer preallocated, to avoid wasting memory.
// /!\ it doesn't check that all vec's inputs or non zero, it is ensured by the size
// of the field /!\
func batchInvert(vec, buf []fr.Element) {
	// local function only, vec and buf are of the same size
	copy(buf, vec)
	for i := 1; i < len(vec); i++ {
		vec[i].Mul(&vec[i], &vec[i-1])
	}
	acc := vec[len(vec)-1]
	acc.Inverse(&acc)
	for i := len(vec) - 1; i > 0; i-- {
		vec[i].Mul(&acc, &vec[i-1])
		acc.Mul(&acc, &buf[i])
	}
	vec[0].Set(&acc)
}

func calculateNbTasks(n int) int {
	nbAvailableCPU := runtime.NumCPU() - n
	if nbAvailableCPU < 0 {
		nbAvailableCPU = 1
	}
	nbTasks := 1 + (nbAvailableCPU / n)
	return nbTasks
}

// batchApply executes fn on all polynomials in x except x[id_ZS] in parallel.
func batchApply(x []*iop.Polynomial, fn func(*iop.Polynomial)) {
	var wg sync.WaitGroup
	for i := 0; i < len(x); i++ {
		if i == id_ZS {
			continue
		}
		wg.Add(1)
		go func(i int) {
			fn(x[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// p <- <p, (1, w, .., wⁿ) >
// p is supposed to be in canonical form
func scalePowers(p *iop.Polynomial, w fr.Element) {
	var acc fr.Element
	acc.SetOne()
	cp := p.Coefficients()
	for i := 0; i < p.Size(); i++ {
		cp[i].Mul(&cp[i], &acc)
		acc.Mul(&acc, &w)
	}
}

func evaluateBlinded(p, bp *iop.Polynomial, zeta fr.Element) fr.Element {
	// Get the size of the polynomial
	n := big.NewInt(int64(p.Size()))

	var pEvaluatedAtZeta fr.Element

	// Evaluate the polynomial and blinded polynomial at zeta
	chP := make(chan struct{}, 1)
	go func() {
		pEvaluatedAtZeta = p.Evaluate(zeta)
		close(chP)
	}()

	bpEvaluatedAtZeta := bp.Evaluate(zeta)

	// Multiply the evaluated blinded polynomial by tempElement
	var t fr.Element
	one := fr.One()
	t.Exp(zeta, n).Sub(&t, &one)
	bpEvaluatedAtZeta.Mul(&bpEvaluatedAtZeta, &t)

	// Add the evaluated polynomial and the evaluated blinded polynomial
	<-chP
	pEvaluatedAtZeta.Add(&pEvaluatedAtZeta, &bpEvaluatedAtZeta)

	// Return the result
	return pEvaluatedAtZeta
}

// /!\ modifies the size
func getBlindedCoefficients(p, bp *iop.Polynomial) []fr.Element {
	cp := p.Coefficients()
	cbp := bp.Coefficients()
	cp = append(cp, cbp...)
	for i := 0; i < len(cbp); i++ {
		cp[i].Sub(&cp[i], &cbp[i])
	}
	return cp
}

// commits to a polynomial of the form b*(Xⁿ-1) where b is of small degree
func commitBlindingFactor(n int, b *iop.Polynomial, key kzg.ProvingKey) curve.G1Affine {
	cp := b.Coefficients()
	np := b.Size()

	// lo
	var tmp curve.G1Affine
	tmp.MultiExp(key.G1[:np], cp, ecc.MultiExpConfig{})

	// hi
	var res curve.G1Affine
	res.MultiExp(key.G1[n:n+np], cp, ecc.MultiExpConfig{})
	res.Sub(&res, &tmp)
	return res
}

// return a random polynomial of degree n, if n==-1 cancel the blinding
// [icicle] coefficients drawn through the randFr seam, one draw per
// coefficient: randFr(tag, i) for i in [0, n]
func getRandomPolynomial(n int, tag string) (*iop.Polynomial, error) {
	var a []fr.Element
	if n == -1 {
		a = make([]fr.Element, 1)
		a[0].SetZero()
	} else {
		a = make([]fr.Element, n+1)
		for i := 0; i <= n; i++ {
			var err error
			if a[i], err = randFr(tag, i); err != nil {
				return nil, err
			}
		}
	}
	res := iop.NewPolynomial(&a, iop.Form{
		Basis: iop.Canonical, Layout: iop.Regular})
	return res, nil
}

func coefficients(p []*iop.Polynomial) [][]fr.Element {
	res := make([][]fr.Element, len(p))
	for i, pI := range p {
		res[i] = pI.Coefficients()
	}
	return res
}

// [icicle] DESIGN.md §2 rows 6-8: the three quotient-shard commitments route
// through gpuCommit against the CANONICAL pair (kzgPk.G1, devKzg). The shard
// sizes are len-derived (n+2, or n+3/n+3/n+2 under StatisticalZK — h1()/h2()/
// h3() decide); the canonical device base has exactly n+3 points, so the n+3
// windows fit by construction.
func commitToQuotient(device *icicle_runtime.Device, h1, h2, h3 []fr.Element, proof *plonk_bw6761.Proof, kzgPk kzg.ProvingKey, devKzg icicle_core.DeviceSlice) error {
	g := new(errgroup.Group)

	g.Go(func() (err error) {
		proof.H[0], err = gpuCommit(device, h1, kzgPk.G1, devKzg)
		return
	})

	g.Go(func() (err error) {
		proof.H[1], err = gpuCommit(device, h2, kzgPk.G1, devKzg)
		return
	})

	g.Go(func() (err error) {
		proof.H[2], err = gpuCommit(device, h3, kzgPk.G1, devKzg)
		return
	})

	return g.Wait()
}

// divideByZH
// The input must be in LagrangeCoset.
// The result is in Canonical Regular. (in place using a)
func divideByZH(a *iop.Polynomial, domains [2]*fft.Domain) (*iop.Polynomial, error) {
	smallDomain, bigDomain := domains[0], domains[1]
	if smallDomain == nil || bigDomain == nil {
		return nil, errors.New("invalid domain")
	}
	if smallDomain.Cardinality == 0 || bigDomain.Cardinality == 0 {
		return nil, errors.New("invalid domain cardinality")
	}
	if bigDomain.Cardinality%smallDomain.Cardinality != 0 {
		return nil, errors.New("invalid domain ratio")
	}

	// check that the basis is LagrangeCoset
	if a.Basis != iop.LagrangeCoset || a.Layout != iop.BitReverse {
		return nil, errors.New("invalid form")
	}

	// prepare the evaluations of x^n-1 on the big domain's coset
	xnMinusOneInverseLagrangeCoset := evaluateXnMinusOneDomainBigCoset(domains)
	rho := int(bigDomain.Cardinality / smallDomain.Cardinality)

	r := a.Coefficients()
	n := uint64(len(r))
	nn := uint64(64 - bits.TrailingZeros64(n))

	utils.Parallelize(len(r), func(start, end int) {
		for i := start; i < end; i++ {
			iRev := bits.Reverse64(uint64(i)) >> nn
			r[i].Mul(&r[i], &xnMinusOneInverseLagrangeCoset[int(iRev)%rho])
		}
	})

	// since a is in bit reverse order, ToRegular shouldn't do anything
	a.ToCanonical(bigDomain).ToRegular()

	return a, nil

}

// evaluateXnMinusOneDomainBigCoset evaluates Xᵐ-1 on DomainBig coset
func evaluateXnMinusOneDomainBigCoset(domains [2]*fft.Domain) []fr.Element {

	rho := domains[1].Cardinality / domains[0].Cardinality

	res := make([]fr.Element, rho)

	expo := big.NewInt(int64(domains[0].Cardinality))
	res[0].Exp(domains[1].FrMultiplicativeGen, expo)

	var t fr.Element
	t.Exp(domains[1].Generator, expo)

	one := fr.One()

	for i := 1; i < int(rho); i++ {
		res[i].Mul(&res[i-1], &t)
		res[i-1].Sub(&res[i-1], &one)
	}
	res[len(res)-1].Sub(&res[len(res)-1], &one)

	res = fr.BatchInvert(res)

	return res
}

// innerComputeLinearizedPoly computes the linearized polynomial in canonical basis.
// The purpose is to commit and open all in one ql, qr, qm, qo, qk.
// * lZeta, rZeta, oZeta are the evaluation of l, r, o at zeta
// * z is the permutation polynomial, zu is Z(μX), the shifted version of Z
// * pk is the proving key: the linearized polynomial is a linear combination of ql, qr, qm, qo, qk.
//
// The Linearized polynomial is:
//
// α²*L₁(ζ)*Z(X)
// + α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(β*s3(X))*Z(μζ) - Z(X)*(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ))
// + l(ζ)*Ql(X) + l(ζ)r(ζ)*Qm(X) + r(ζ)*Qr(X) + o(ζ)*Qo(X) + Qk(X) + ∑ᵢQcp_(ζ)Pi_(X)
// - Z_{H}(ζ)*((H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
//
// /!\ blindedZCanonical is modified
func (s *instance) innerComputeLinearizedPoly(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, qcpZeta, blindedZCanonical []fr.Element, pi2Canonical [][]fr.Element, pk *ProvingKey) []fr.Element {

	// l(ζ)r(ζ)
	var rl fr.Element
	rl.Mul(&rZeta, &lZeta)

	// s1 =  α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)
	// s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	// the linearised polynomial is
	// α²*L₁(ζ)*Z(X) +
	// s1*s3(X)+s2*Z(X) + l(ζ)*Ql(X) +
	// l(ζ)r(ζ)*Qm(X) + r(ζ)*Qr(X) + o(ζ)*Qo(X) + Qk(X) + ∑ᵢQcp_(ζ)Pi_(X) -
	// Z_{H}(ζ)*((H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
	var s1, s2 fr.Element
	chS1 := make(chan struct{}, 1)
	go func() {
		s1 = s.trace.S1.Evaluate(zeta)                       // s1(ζ)
		s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma) // (l(ζ)+β*s1(ζ)+γ)
		close(chS1)
	}()

	tmp := s.trace.S2.Evaluate(zeta)                         // s2(ζ)
	tmp.Mul(&tmp, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma) // (r(ζ)+β*s2(ζ)+γ)
	<-chS1
	s1.Mul(&s1, &tmp).Mul(&s1, &zu).Mul(&s1, &beta).Mul(&s1, &alpha) // (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*Z(μζ)*α

	var uzeta, uuzeta fr.Element
	uzeta.Mul(&zeta, &pk.Vk.CosetShift)
	uuzeta.Mul(&uzeta, &pk.Vk.CosetShift)

	s2.Mul(&beta, &zeta).Add(&s2, &lZeta).Add(&s2, &gamma)      // (l(ζ)+β*ζ+γ)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)  // (r(ζ)+β*u*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma) // (o(ζ)+β*u²*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	s2.Neg(&s2).Mul(&s2, &alpha)

	// Z_h(ζ), ζⁿ⁺², L₁(ζ)*α²*Z
	var zhZeta, zetaNPlusTwo, alphaSquareLagrangeZero, one, den, frNbElmt fr.Element
	one.SetOne()
	nbElmt := int64(s.domain0.Cardinality)
	alphaSquareLagrangeZero.Set(&zeta).Exp(alphaSquareLagrangeZero, big.NewInt(nbElmt)) // ζⁿ
	zetaNPlusTwo.Mul(&alphaSquareLagrangeZero, &zeta).Mul(&zetaNPlusTwo, &zeta)         // ζⁿ⁺²
	alphaSquareLagrangeZero.Sub(&alphaSquareLagrangeZero, &one)                         // ζⁿ - 1
	zhZeta.Set(&alphaSquareLagrangeZero)                                                // Z_h(ζ) = ζⁿ - 1
	frNbElmt.SetUint64(uint64(nbElmt))
	den.Sub(&zeta, &one).Inverse(&den)                           // 1/(ζ-1)
	alphaSquareLagrangeZero.Mul(&alphaSquareLagrangeZero, &den). // L₁ = (ζⁿ - 1)/(ζ-1)
									Mul(&alphaSquareLagrangeZero, &alpha).
									Mul(&alphaSquareLagrangeZero, &alpha).
									Mul(&alphaSquareLagrangeZero, &s.domain0.CardinalityInv) // α²*L₁(ζ)

	s3canonical := s.trace.S3.Coefficients()

	s.trace.Qk.ToCanonical(s.domain0).ToRegular()

	// len(h1)=len(h2)=len(blindedZCanonical)=len(h3)+1 when Statistical ZK is activated
	// len(h1)=len(h2)=len(h3)=len(blindedZCanonical)-1 when Statistical ZK is deactivated
	h1 := s.h1()
	h2 := s.h2()
	h3 := s.h3()

	// at this stage we have
	// s1 =  α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)
	// s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	utils.Parallelize(len(blindedZCanonical), func(start, end int) {

		cql := s.trace.Ql.Coefficients()
		cqr := s.trace.Qr.Coefficients()
		cqm := s.trace.Qm.Coefficients()
		cqo := s.trace.Qo.Coefficients()
		cqk := s.trace.Qk.Coefficients()

		var t, t0, t1 fr.Element

		for i := start; i < end; i++ {
			t.Mul(&blindedZCanonical[i], &s2) // -Z(X)*α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
			if i < len(s3canonical) {
				t0.Mul(&s3canonical[i], &s1) // α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)*β*s3(X)
				t.Add(&t, &t0)
			}
			if i < len(cqm) {
				t1.Mul(&cqm[i], &rl)     // l(ζ)r(ζ)*Qm(X)
				t.Add(&t, &t1)           // linPol += l(ζ)r(ζ)*Qm(X)
				t0.Mul(&cql[i], &lZeta)  // l(ζ)Q_l(X)
				t.Add(&t, &t0)           // linPol += l(ζ)*Ql(X)
				t0.Mul(&cqr[i], &rZeta)  //r(ζ)*Qr(X)
				t.Add(&t, &t0)           // linPol += r(ζ)*Qr(X)
				t0.Mul(&cqo[i], &oZeta)  // o(ζ)*Qo(X)
				t.Add(&t, &t0)           // linPol += o(ζ)*Qo(X)
				t.Add(&t, &cqk[i])       // linPol += Qk(X)
				for j := range qcpZeta { // linPol += ∑ᵢQcp_(ζ)Pi_(X)
					t0.Mul(&pi2Canonical[j][i], &qcpZeta[j])
					t.Add(&t, &t0)
				}
			}

			t0.Mul(&blindedZCanonical[i], &alphaSquareLagrangeZero) // α²L₁(ζ)Z(X)
			blindedZCanonical[i].Add(&t, &t0)                       // linPol += α²L₁(ζ)Z(X)

			// if statistical zeroknowledge is deactivated, len(h1)=len(h2)=len(h3)=len(blindedZ)-1.
			// Else len(h1)=len(h2)=len(blindedZCanonical)=len(h3)+1
			if i < len(h3) {
				t.Mul(&h3[i], &zetaNPlusTwo).
					Add(&t, &h2[i]).
					Mul(&t, &zetaNPlusTwo).
					Add(&t, &h1[i]).
					Mul(&t, &zhZeta)
				blindedZCanonical[i].Sub(&blindedZCanonical[i], &t) // linPol -= Z_h(ζ)*(H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
			} else {
				if s.opt.StatisticalZK {
					t.Mul(&h2[i], &zetaNPlusTwo).
						Add(&t, &h1[i]).
						Mul(&t, &zhZeta)
					blindedZCanonical[i].Sub(&blindedZCanonical[i], &t) // linPol -= Z_h(ζ)*(H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
				}
			}
		}
	})

	return blindedZCanonical
}

var errContextDone = errors.New("context done")

// bindPublicData binds the public data (permutation, coefficients, public
// inputs) to the given Fiat-Shamir challenge.
//
// [icicle] cloned byte-faithfully from backend/plonk/bw6-761/verify.go:315-359
// at commit c74a2dc8b890c3d7d196bf20d857a1e482ac57f7 (unexported upstream;
// shared between the native prover and verifier). The only deviation is the
// vk parameter type, qualified as *plonk_bw6761.VerifyingKey. The byte
// sequence is TRANSCRIPT-CRITICAL (DESIGN.md §10.3): Marshal() is the
// uncompressed point encoding — any drift silently breaks Fiat-Shamir with no
// diagnostic.
func bindPublicData(fs *fiatshamir.Transcript, challenge string, vk *plonk_bw6761.VerifyingKey, publicInputs []fr.Element) error {

	// permutation
	if err := fs.Bind(challenge, vk.S[0].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[1].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[2].Marshal()); err != nil {
		return err
	}

	// coefficients
	if err := fs.Bind(challenge, vk.Ql.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qr.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qm.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qo.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qk.Marshal()); err != nil {
		return err
	}
	for i := range vk.Qcp {
		if err := fs.Bind(challenge, vk.Qcp[i].Marshal()); err != nil {
			return err
		}
	}

	// public inputs
	for i := 0; i < len(publicInputs); i++ {
		if err := fs.Bind(challenge, publicInputs[i].Marshal()); err != nil {
			return err
		}
	}

	return nil

}

// deriveRandomness derives a Fiat-Shamir challenge from the given points.
//
// [icicle] cloned byte-faithfully from backend/plonk/bw6-761/verify.go:361-379
// at commit c74a2dc8b890c3d7d196bf20d857a1e482ac57f7 (unexported upstream;
// shared between the native prover and verifier). RawBytes() is the
// uncompressed point encoding — TRANSCRIPT-CRITICAL, see bindPublicData.
func deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...*curve.G1Affine) (fr.Element, error) {

	var buf [curve.SizeOfG1AffineUncompressed]byte
	var r fr.Element

	for _, p := range points {
		buf = p.RawBytes()
		if err := fs.Bind(challenge, buf[:]); err != nil {
			return r, err
		}
	}

	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return r, err
	}
	r.SetBytes(b)
	return r, nil
}
