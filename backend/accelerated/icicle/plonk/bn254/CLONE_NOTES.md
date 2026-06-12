# CLONE_NOTES — sanctioned-hunk list for the BN254 ICICLE PLONK prover clone

This file is the P3.8 adversarial-review contract (DESIGN.md §10.5) and the
Phase 4 per-curve port recipe. It enumerates **every** place
`backend/accelerated/icicle/plonk/bn254/prove.go` differs from its upstream
source. Any diff hunk not listed here is clone drift and must be rejected.

- **Upstream source:** `backend/plonk/bn254/prove.go` (1489 lines) plus the
  two unexported Fiat-Shamir helpers `bindPublicData` / `deriveRandomness`
  from `backend/plonk/bn254/verify.go:315-359` / `:361-379`.
- **Upstream commit:** `c74a2dc8b890c3d7d196bf20d857a1e482ac57f7`
  (branch `philippe/gpu-experiment`). Upstream files are NEVER modified.
- **Verification command (the diff gate is mechanical, not vibes):**

  ```
  diff -u backend/plonk/bn254/prove.go backend/accelerated/icicle/plonk/bn254/prove.go
  ```

- **Hunk count at P3.5: exactly 22.** Every hunk belongs to one of the
  sanctioned edit classes (a)–(e) below. P3.6 will add the MSM call-site
  swap class (DESIGN.md §2 rows 1–11) and must update this file and the count.

## Sanctioned edit classes

| Class | Description |
|---|---|
| (a) | build tag, provenance header, package name, imports |
| (b) | instance/Prove plumbing for the wrapper `*ProvingKey`, the native `plonk_bn254.{Proof,Trace,VerifyingKey,NewTrace}` types, and the device handle |
| (c) | randomness seam: `randFr(tag, i)` threaded through ALL FIVE upstream SetRandom sites |
| (d) | stage-checkpoint seam: nil-guarded `checkpoint(stage, data)` calls at the DESIGN.md §10.2 stage boundaries |
| (e) | the two `verify.go` Fiat-Shamir helper clones appended at the end of the file |

Explicitly **not** present at P3.5: every `kzg.Commit` / `MultiExp` /
`kzg.Open` / `kzg.BatchOpenSinglePoint` call site is still the native CPU
call, byte-identical to upstream. All aliasing/mutation invariants
(witness −s0/+s0 bracket in commitToLRO, s.x trace aliasing, the id_ZS
ShallowClone skip in batchApply, the Qk clone in completeQk, blindedZ
overwritten in place by the linearized polynomial) are untouched upstream
code (DESIGN.md §10.4).

## Hunk-by-hunk inventory (diff order; upstream line numbers)

| # | Upstream @@ | Class | Content |
|---|---|---|---|
| 1 | `@@ -1,9 +1,32 @@` | (a) | `//go:build icicle`; "Code generated" marker replaced by the provenance header (upstream path + commit hash, CLONE_NOTES pointer, P3.5 no-GPU-MSM note, desync liability); `package plonk` → `package bn254` |
| 2 | `@@ -31,6 +54,9 @@` | (a) | imports added: `icicle` (Config), `gpuinit`, `plonk_bn254` |
| 3 | `@@ -39,6 +65,8 @@` | (a) | import added: `icicle_runtime` |
| 4 | `@@ -75,44 +103,101 @@` | (b)(c)(d) | `type Proof` DELETED (the clone constructs the native `plonk_bn254.Proof` so serialization/Verify work unchanged); seam declarations added: `var randFr = defaultRandFr` + `defaultRandFr` (crypto/rand default, tag contract documented), `var onStageCheckpoint` + nil-guarded `checkpoint` helper; `Prove` signature → `Prove(spr, pk *ProvingKey, fullWitness, opts *icicle.Config) (*plonk_bn254.Proof, error)`; log gains `Str("acceleration", "icicle")`; `backend.NewProverConfig(opts.ProverOpts...)`; device-setup block added (gpuinit.WarmUpOnce → pk.PinToGPU = opts.PinToGPU → CreateDevice → setupDevicePointers BEFORE the solver per DESIGN §5 → `defer pk.FreeGPUResources()` when !PinToGPU); `newInstance` call gains `&device` |
| 5 | `@@ -157,10 +242,14 @@` | (b) | instance fields: `proof *plonk_bn254.Proof`; new `device icicle_runtime.Device` (consumed by the P3.6 MSM swaps) |
| 6 | `@@ -199,17 +288,18 @@` | (b) | `trace *plonk_bn254.Trace`; `newInstance` gains the `device *icicle_runtime.Device` param; struct literal sets `device: *device`, `proof: &plonk_bn254.Proof{}` |
| 7 | `@@ -236,9 +326,15 @@` | (c) | seam site 2+3: `quotientShardsRandomizers[0/1]` ← `randFr("qsr0"/"qsr1", 0)` with error propagation (upstream ignored the SetRandom error) |
| 8 | `@@ -251,16 +347,31 @@` | (b)(c)(d) | `plonk_bn254.NewTrace`; `initBlindingPolynomials` rewritten: `getRandomPolynomial(order, tag)` with tags `"bl"/"br"/"bo"/"bz"` + error propagation (seam site 1, four polynomials); checkpoints `bp-bl/br/bo/bz` |
| 9 | `@@ -290,10 +401,12 @@` | (c) | seam sites 4+5: the two bsb22Hint blinding draws ← `randFr(fmt.Sprintf("bsb22-%d", commDepth), 0/1)` (same target slots, same comments) |
| 10 | `@@ -340,6 +453,10 @@` | (d) | checkpoints `solution-l/r/o` after `wg.Wait()`, before commitToLRO |
| 11 | `@@ -518,6 +635,9 @@` | (d) | checkpoints `gamma`, `beta` before `close(s.chGammaBeta)` |
| 12 | `@@ -594,6 +714,7 @@` | (d) | checkpoint `alpha` after deriveAlpha |
| 13 | `@@ -605,11 +726,13 @@` | (d) | checkpoints `numerator` (after computeNumerator, before divideByZH consumes it in place) and `h` (after divideByZH) |
| 14 | `@@ -619,6 +742,7 @@` | (d) | checkpoint `zeta` after deriveZeta |
| 15 | `@@ -657,6 +781,7 @@` | (d) | checkpoint `z-lagrange` after BuildRatioCopyConstraint |
| 16 | `@@ -682,6 +807,7 @@` | (d) | checkpoint `blinded-z` after kzg.Open, before `close(s.chZOpening)` |
| 17 | `@@ -783,6 +909,7 @@` | (d) | checkpoint `linearized-poly` after innerComputeLinearizedPoly, before kzg.Commit |
| 18 | `@@ -832,8 +959,12 @@` | (d) | batchOpening tail: `return err` split into err-check + checkpoint `batch-claimed-values` + `return nil` |
| 19 | `@@ -1236,7 +1367,9 @@` | (c) | `getRandomPolynomial(n int, tag string) (*iop.Polynomial, error)` — signature gains the tag and an error |
| 20 | `@@ -1244,12 +1377,15 @@` | (c) | seam site 1 body: `a[i], err = randFr(tag, i)` (one draw per coefficient, i = coefficient index); `return res, nil` |
| 21 | `@@ -1260,7 +1396,7 @@` | (b) | `commitToQuotient(..., proof *plonk_bn254.Proof, ...)` |
| 22 | `@@ -1487,3 +1623,85 @@` | (e) | `bindPublicData` (verify.go:315-359) + `deriveRandomness` (verify.go:361-379) appended with provenance comments. Byte-identical to upstream except the `vk *plonk_bn254.VerifyingKey` parameter qualification (mechanically verified, see below) |

### Helper-clone fidelity check

```
diff <(sed -n '315,359p' backend/plonk/bn254/verify.go) \
     <(awk '/^func bindPublicData/,/^}$/' backend/accelerated/icicle/plonk/bn254/prove.go \
        | sed 's/plonk_bn254\.VerifyingKey/VerifyingKey/')
diff <(sed -n '361,379p' backend/plonk/bn254/verify.go) \
     <(awk '/^func deriveRandomness/,/^}$/' backend/accelerated/icicle/plonk/bn254/prove.go)
```

Both diffs are empty at the upstream commit above.

## Randomness seam contract (class (c), DESIGN.md §10.1)

Upstream has **exactly five** SetRandom sites (`grep -n SetRandom
backend/plonk/bn254/prove.go`); all five — and nothing else — route through
the package-level `randFr(tag string, i int) (fr.Element, error)`:

| Seam site | Upstream | Tag | i |
|---|---|---|---|
| blinding poly coefficients | prove.go:1247 via initBlindingPolynomials | `"bl"` `"br"` `"bo"` `"bz"` | coefficient index 0..order |
| StatisticalZK shard randomizer 0 | prove.go:240 | `"qsr0"` | 0 |
| StatisticalZK shard randomizer 1 | prove.go:241 | `"qsr1"` | 0 |
| bsb22 commitment-injection blind | prove.go:293 | `"bsb22-<commDepth>"` | 0 |
| bsb22 last-constraint blind | prove.go:296 | `"bsb22-<commDepth>"` | 1 |

The (tag, index) signature is mandatory: a tag-only hook would degenerate
seeded blinding polynomials to equal coefficients, and the prover's
goroutine schedule must not influence the draw a site receives. Default =
`fr.Element.SetRandom` (crypto/rand): production behavior identical to
upstream. Override only via `export_test.go` (`SetRandFr`).

Note vs DESIGN.md: §10.1 names the bsb22 tags `"bsb22-<depth>-<slot>"`; with
the two-argument seam the slot travels in `i` instead — same domain
separation, recorded here as the binding contract.

## Stage checkpoints (class (d), DESIGN.md §10.2 reserve oracle)

Stages in pipeline order (gap_answers[4] §4 table), payload = `[]fr.Element`:
`bp-bl` `bp-br` `bp-bo` `bp-bz`, `solution-l/r/o`, `gamma`, `beta`,
`z-lagrange`, `alpha`, `numerator`, `h`, `zeta`, `blinded-z`,
`linearized-poly`, `batch-claimed-values`. Checkpoints whose upstream payload
is a commitment point (proof.LRO, Bsb22Commitments, proof.Z, proof.H, opening
H's) are intentionally omitted: the challenge checkpoints (`gamma`, `alpha`,
`zeta`) hash those commitments, so a commitment byte mismatch surfaces as a
challenge mismatch. The seam receives live prover buffers and must consume
them synchronously. nil seam (default) is a no-op behind a single nil check.

## P3.6 swap map — the 10+c MSM call sites in THIS file (by clone line number)

All currently native CPU calls, to be routed through `gpuMsm`/`gpuCommit`/
`gpuOpen`/`gpuBatchOpenSinglePoint` (DESIGN.md §2; windows derived from
`len(slice)`, never hard-coded):

| §2 row | Call site (clone prove.go) | Current call |
|---|---|---|
| 1 | `commitToLRO`, line 555 | `commit.MultiExp(s.pk.KzgLagrange.G1[:offset], coeffs[:offset], ...)` |
| 2 | `commitToLRO`, line 574 | `commit.MultiExp(s.pk.KzgLagrange.G1[nbPublic:offset], ...)` |
| 3 | `commitToLRO`, line 593 | `commit.MultiExp(s.pk.KzgLagrange.G1[nbPublic:offset], ...)` |
| 4 (×c) | `bsb22Hint`, line 413 | `kzg.Commit(s.cCommitments[commDepth].Coefficients(), s.pk.KzgLagrange)` |
| 5 | `commitToPolyAndBlinding`, line 652 | `kzg.Commit(p.Coefficients(), s.pk.KzgLagrange)` |
| 6–8 | `commitToQuotient`, lines 1403/1408/1413 | three `kzg.Commit(h_i, kzgPk)` |
| 9 | `openZ`, line 806 | `kzg.Open(s.blindedZ, zetaShifted, s.pk.Kzg)` → `gpuOpen` |
| 10 | `computeLinearizedPolynomial`, line 915 | `kzg.Commit(s.linearizedPolynomial, s.pk.Kzg, runtime.NumCPU()*2)` |
| 11 | `batchOpening`, line 954 | `kzg.BatchOpenSinglePoint(...)` → `gpuBatchOpenSinglePoint` |

Stays CPU forever (DESIGN.md §3): `commitBlindingFactor` (lines 1360/1364,
two size-≤3 MultiExps), `correctionPoint.ScalarMultiplication`
(commitToLRO, line 544), all FFT/closure code.

## Other P3.5 decisions recorded for review

1. **File name:** DESIGN.md §4 places the prover clone in `icicle.go`; the
   clone lives in `prove.go` instead because `icicle.go` already carries the
   MSM machinery (P3.2). Same package, pure file-layout deviation.
2. **Per-call device mutex, no whole-Prove lock:** Prove does NOT hold the
   per-device mutex across the prove. DESIGN.md §8 mandates per-call
   granularity for v1 (the whole-Prove mutex is the *Increment 2* redesign),
   and both `setupDevicePointers` and `gpuMsm` acquire the mutex internally —
   a whole-Prove hold would deadlock the P3.6 MSM swaps. The §5 ordering
   invariant (device SRS resident before `spr.Solve`) is enforced by calling
   `setupDevicePointers` synchronously before the errgroup starts.
3. **Seams are package-level vars** (not instance fields as sketched in
   DESIGN.md §4): simpler export_test.go surface; overriding them while
   another Prove runs in-process is racy and forbidden for tests (the GPU
   suite is sequential, doc.go).
4. **`onStageCheckpoint` payload is `[]fr.Element`** (DESIGN.md §10.2 sketches
   `[]byte`): fr.Element limb comparison is exact, so Montgomery-form bugs
   still surface; point-valued stages are covered via the challenge
   checkpoints (see above).
5. `getRandomPolynomial`/`initBlindingPolynomials`/`newInstance` now
   propagate randFr errors that upstream's bare `SetRandom()` calls ignored
   (qsr sites) — strictly more conservative; identical behavior when the
   default crypto/rand seam never errors.

## Phase 4 port recipe

Per curve (bls12-377, bls12-381, bw6-761): `cp` the upstream
`backend/plonk/<curve>/prove.go` (byte-identical layout across curves modulo
imports, verified in `.phase1-map.json` gap_answers[5]) and re-apply exactly
the 22 hunks above with identifier substitution (`bn254` → curve name in
import paths and the `plonk_bn254`/`icicle_runtime` aliases). The randFr tag
strings, checkpoint stage names, and hunk classes are curve-invariant.
