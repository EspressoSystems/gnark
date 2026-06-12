# DESIGN.md — ICICLE GPU offload for the gnark Plonk prover (v1: MSM-only)

Branch `philippe/gpu-experiment` · Phase 2 output · Status: awaiting post-design checkpoint sign-off
Synthesized from 3 biased proposals + 3-lens judge panel. **Winning approach: MSM-only offload** (correctness and simplicity judges; the performance judge's preferred increments are preserved verbatim in Appendix A as the gated follow-up). All file:line evidence below is verified in `.phase1-map.json` (Phase 1, 13 agents).

---

## 1. Goal & scope

GPU-accelerate the gnark Plonk prover with icicle-gnark v3.2.2, mirroring the working Groth16 integration (`backend/accelerated/icicle/groth16/`, Phase 0 green on the RTX 3070 for all 4 curves) into a new `backend/accelerated/icicle/plonk/`.

**In scope (v1):**
- Offload exactly the **10+c large G1 MSMs** per proof to the GPU against a device-resident dual SRS (`pk.Kzg.G1`, n+3 canonical points; `pk.KzgLagrange.G1`, n Lagrange points).
- Curves: bn254 first (Phase 3), then bls12-377, bls12-381, bw6-761 (Phase 4). koalabear out of scope (no small-field support in icicle-gnark v3.2.2).
- The prover is a **clone** of `backend/plonk/<curve>/prove.go` into build-tagged packages (groth16 precedent) — there is no interception seam in gnark-crypto kzg. The clone returns the native `*plonk_<curve>.Proof`, so the **unmodified** `plonk.Verify` is the hard correctness gate.
- Quality bar: working experiment. Hand-written per-curve files; codegen templates deferred. CPU-only builds completely unaffected (icicle/!icicle stub pattern). pk serialization byte-compatible.

**Explicitly out of scope (v1), recorded for Increment 2 in Appendix A:**
- Any device NTT. This package **never calls `InitDomain`** — zero NTT-domain state exists. This is the load-bearing simplification: it structurally eliminates the NTT ordering/coset silent-corruption class, the KNM/KMN intermediate-order hazard, 2–3 GiB of VRAM pressure, and the C-level NTT-domain-singleton coexistence hazard with groth16-icicle.
- Device constraint closure (~7% ceiling; not expressible in v3.2.2: no scalar broadcast, no D2D copy, no gather, no batch inversion; VecOps are elementwise Add/Sub/Mul only).

**Decision framing (per the post-design checkpoint):** this is a *staged* decision, not a final answer. v1 is bounded by the MSM Amdahl ceiling (1.62× at 2^22, §14). Phase 6 publishes the MSM/FFT/PCIe decomposition so the Increment-2 go/no-go (divideByZH, then device-resident numerator NTTs, +11–13% at 2^20–2^22 per gap_answers[1] §5) can be argued from data.

---

## 2. What is offloaded — exact op table

All GPU MSMs flow through **one synchronous chokepoint** `gpuMsm(scalars []fr.Element, baseWindow icicle_core.DeviceSlice) (curve.G1Affine, error)`:

```
inside icicle_runtime.RunOnDevice(&device, ...) and under the per-device mutex:
  cfg := icicle_msm.GetDefaultMSMConfig()        // FRESH config per call — MsmCheck mutates
  cfg.AreScalarsMontgomeryForm = true            // raw Montgomery upload, no conversion kernel
  cfg.AreBasesMontgomeryForm   = false           // bases pre-converted at load (loadG1)
  (icicle_core.HostSlice[fr.Element])(scalars).CopyToDevice(&scalarsDev, true)
  res := msmChunkedG1(scalarsDev, baseWindow, cfg)   // copied verbatim from groth16 (adaptive chunk/window tuner)
  scalarsDev.Free()
  return projectiveToGnarkAffine(res)            // ToBytesLittleEndian → fp.LittleEndian.Element
```

Built-in switches (provably inert when env unset — they gate added code, never change the default path): `ICICLE_PLONK_DEBUG_MSM=1` (shadow-compare vs `curve.G1Affine.MultiExp` on identical inputs, error on mismatch), `ICICLE_PLONK_FORCE_CPU_MSM=1` (helper computes via MultiExp — the determinism oracle's CPU leg). A size floor (`len(scalars) < 64` → CPU MultiExp) handles zero-length/tiny windows uniformly and makes degenerate geometries (e.g. `offset == nbPublic`) safe by construction — `DeviceSlice.Range` panics on `end <= start`, so the floor check happens before any Range call.

**Every window length is derived from `len(slice)` — never hard-coded n+2/n+3** (StatisticalZK changes shard sizes).

| # | MSM | Clone call site (upstream prove.go) | Size | Base window (device view, zero-copy) | Notes |
|---|-----|--------------------------------------|------|--------------------------------------|-------|
| 1 | L wire commitment | commitToLRO g1, :432-448 (MultiExp :438) | `offset = nbPublic+nbConstraints ≤ n` | `devLag.RangeTo(offset, false)` | host s0-subtract (:434-436) and restore (:441-443) bracket the synchronous GPU call; correctionPoint `ScalarMultiplication` + `commitBlindingFactor` stay CPU. Preserves the reduced-MSM identity (#1716) exactly |
| 2 | R wire commitment | :451-467 (:457) | `offset − nbPublic` | `devLag.Range(nbPublic, offset, false)` | interior window; Range semantics verified core/slice.go:59-118 |
| 3 | O wire commitment | :470-486 (:476) | `offset − nbPublic` | same as R | |
| 4 | BSB22 commitment ×c | bsb22Hint :280-315 (kzg.Commit :300) | n | `devLag.RangeTo(len(coeffs), false)` | runs **inside `spr.Solve`** via `solver.OverrideHint`; see ordering invariant §5. Both SetRandom sites (:293,:296) route through the randomness seam. `htfFunc.Write(commitment.Marshal())` → completeQk untouched |
| 5 | Grand-product Z | commitToPolyAndBlinding :530-540 (:532), called :662 | n | `devLag.RangeTo(len(coeffs), false)` | blinding (size ≤3 MSMs) stays CPU |
| 6-8 | Quotient shards H1/H2/H3 | commitToQuotient :1263-1282 (:1267/:1272/:1277) | `len(hi)` = n+2 each; n+3/n+3/n+2 with StatisticalZK | `devKzg.RangeTo(len(hi), false)` | shard assembly h1()/h2()/h3() (:689-724) incl. StatisticalZK randomizer stitching stays on host; canonical device base has exactly n+3 points (setup.go:126), so the n+3 windows fit by construction |
| 9 | Z-shift opening quotient | openZ :670-687 → `gpuOpen` (clone of gnark-crypto kzg.go:181-205) | n+2 (= len(blindedZ)−1) | `devKzg.RangeTo(len(h), false)` | Horner eval + `dividePolyByXminusA` (kzg.go:57-64/:595-614 clones) stay CPU — loop-carried serial |
| 10 | Linearized polynomial | computeLinearizedPolynomial :788 | n+3 | `devKzg.RangeTo(len(p), false)` | `innerComputeLinearizedPoly` (:1352-1487) incl. Qk ToCanonical (:1420) stays CPU; blindedZ aliasing read-only at MSM time |
| 11 | Batch-opening folded quotient | batchOpening :796-839 → `gpuBatchOpenSinglePoint` (clone of kzg.go:255-341) | n+2 | `devKzg.RangeTo(len(h), false)` | byte-exact `deriveGamma` clone (kzg.go:559-591); γ-folding on CPU via `internal/utils.Parallelize`; fold order over [linPoly, blinded L,R,O, S1,S2, Qcp...] preserved |

---

## 3. What stays on CPU and why

Measured CPU profile (i7-11800H 16T, refCircuit; gap_answers[1] §3): Prove wall **0.465 s / 1.81 s / 8.6 s / 36.4 s** at 2^16/2^18/2^20/2^22; **MSM 54.7% / 47.6% / 43.3% / 38.1%** of samples; **FFT machinery 29.7% → 47.6%** (rising with n), of which the computeNumerator per-coset pipeline is 13–19% and divideByZH's 4n iNTT most of the rest; pointwise constraint closure ~7%.

| Kept on CPU | Why |
|---|---|
| 8 tiny blinding MSMs (`commitBlindingFactor` :1223-1236, size 2–3 over `Kzg.G1[:np]` / `Kzg.G1[n:n+np]`) + correctionPoint (:427) | launch-overhead-dominated; hard fact from the inventory |
| **All ~112 FFTs**: computeNumerator :841-1123 (batchApply pipeline, scalingVectors, bitrev scatter, restore pass), divideByZH :1287-1324 (4n coset-iNTT), Qk ToCanonical :1420 | The 30–48% FFT share is the deliberately rejected increment: full computeNumerator offload is **not expressible** in v3.2.2 primitives; the expressible subset (device-resident numerator NTT pipeline) adds only ~11–13% at 2^20–2^22 for the highest correctness risk in the design space (KNM/KMN hazards, arbitrary-coset slow path, trace-aliased D2H writebacks, 2–3 GiB VRAM killing bw6-761@2^22). Recorded as Increment 2, Appendix A |
| batchInvert :1125-1143, Horner evals, synthetic division, γ-folding, grand product, trace build, solver | serial / O(n) scalar work, not GPU-shaped |
| Entire Fiat-Shamir transcript, blinding, witness handling | byte-identical cloned CPU code — the correctness foundation (§10) |

Consequence: the divergence surface between the GPU prover and upstream is **exactly the 10+c MSM outputs plus three cloned gnark-crypto kzg helpers**.

---

## 4. Package structure & public API

Mirrors `backend/accelerated/icicle/groth16/` exactly; hand-written per-curve (codegen deferred).

```
backend/accelerated/icicle/
  opts.go                          UNCHANGED — Config/Option/PinToGPU reused
  internal/gpuinit/                NEW, //go:build icicle
    gpuinit.go                     process-wide warm-up: one sync.Once → LoadBackend/
                                   LoadBackendFromEnvOrDefault, GetDeviceCount, per-device
                                   CreateDevice + RunOnDevice{CreateStream, WarmUpDevice}
                                   (body lifted from groth16_icicle.go:33-72)
  groth16/groth16_icicle.go        one-line redirect to gpuinit.WarmUpOnce — this file is
                                   HAND-WRITTEN (verified: no "Code generated" header; the
                                   generator emits only per-curve doc/icicle/provingkey files),
                                   so the codegen-deferred bar is honored. Own commit, gated
                                   by re-running the groth16 GPU marshal test (§12, P3.0)
  plonk/
    plonk_all.go                   untagged — Verify/NewVerifyingKey/NewProof/NewCS thin wrappers
    plonk_icicle.go                //go:build icicle — dispatch Prove/Setup/NewProvingKey
    plonk_noicicle.go              //go:build !icicle — identical signatures, panic("icicle backend
                                   requested but program compiled without 'icicle' build tag")
    marshal_test.go                //go:build icicle — end-to-end gate, 4 curves
    bench_test.go                  //go:build icicle — Phase 6
    bn254/
      doc.go                       untagged (package non-empty without tag; carries the
                                   coexistence + concurrency contract, §8)
      provingkey.go                //go:build icicle — ProvingKey wrapper, deviceInfo,
                                   setupDevicePointers, FreeGPUResources
      icicle.go                    //go:build icicle — cloned prove.go (provenance header with
                                   upstream commit hash) + bindPublicData/deriveRandomness
                                   (verify.go:315-359/:361-379) + MSM machinery copied verbatim
                                   from groth16/bn254/icicle.go (G2/NTT/Den code deleted)
      kzg.go                       //go:build icicle — clones of gnark-crypto unexported: eval
                                   (kzg.go:57-64), dividePolyByXminusA (:595-614), deriveGamma
                                   (:559-591) + gpuCommit/gpuOpen/gpuBatchOpenSinglePoint
      msm_test.go, kzg_test.go     //go:build icicle — parity gates (§11)
      export_test.go               test seams (randFr hook, stage checkpoints)
    bls12-377/  bls12-381/  bw6-761/   identifier-substituted copies of bn254 (Phase 4);
                                   upstream prove.go is byte-identical across curves modulo imports
```

**Types (bn254 sketch):**

```go
type deviceInfo struct {
    G1Device struct {
        Kzg         icicle_core.DeviceSlice // pk.Kzg.G1, n+3 pts, standard form
        KzgLagrange icicle_core.DeviceSlice // pk.KzgLagrange.G1, n pts, standard form
    }
    // NO CosetGenerator, NO NTT state — MSM-only (coupling documented in §8)
}

type ProvingKey struct {
    plonk_bn254.ProvingKey  // embedded BY VALUE: WriteTo/ReadFrom/WriteRawTo/UnsafeReadFrom/
                            // VerifyingKey promoted → serialization byte-identical to native
    *deviceInfo             // nil until first use; never serialized
    setupMu  sync.Mutex
    PinToGPU bool
}

func NewProvingKey() *ProvingKey
func Setup(spr *cs.SparseR1CS, srs, srsLagrange *kzg.SRS) (*ProvingKey, *plonk_bn254.VerifyingKey, error)
     // native plonk_bn254.Setup, then pk.ProvingKey = *nativePk (shallow: 2 slice headers + Vk ptr)
func Prove(spr *cs.SparseR1CS, pk *ProvingKey, w witness.Witness, cfg *icicle.Config) (*plonk_bn254.Proof, error)
func (pk *ProvingKey) FreeGPUResources()
```

The cloned `instance` gains: `pk *ProvingKey` (field promotion keeps `s.pk.Kzg/.KzgLagrange/.Vk` working), `device icicle_runtime.Device`, `randFr func(tag string, i int) (fr.Element, error)` (nil ⇒ `fr.Element.SetRandom`), `onStageCheckpoint func(name string, payload []byte)` (nil in production).

**Dispatch (plonk_icicle.go):**

```go
func Prove(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, w witness.Witness,
           opts ...icicle.Option) (plonk.Proof, error)
    // icicle.NewConfig(opts) → gpuinit.WarmUpOnce(cfg) → type-switch on *cs_<curve>.SparseR1CS,
    // pk.(*icicle_<curve>.ProvingKey); returns the native *plonk_<curve>.Proof → plonk.Verify dispatches
func Setup(ccs constraint.ConstraintSystem, srs, srsLagrange kzg.SRS) (plonk.ProvingKey, plonk.VerifyingKey, error)
    // mirrors backend/plonk/plonk.go:94-109 switch incl. *srs.(*kzg_<curve>.SRS) assertions
func NewProvingKey(curveID ecc.ID) plonk.ProvingKey
// NO DummySetup — plonk has none upstream
```

`backend.ProverOption`s flow via `icicle.Config.ProverOpts` (existing opts.go, untouched) into `backend.NewProverConfig` inside the per-curve Prove, so StatisticalZK/ChallengeHash/KZGFoldingHash work. Untagged `go build ./...` stays green via the stubs; `go build -tags=icicle ./...` compiles without loading any .so. No file under `backend/plonk/` is touched.

---

## 5. ProvingKey / device lifecycle

- `setupDevicePointers(device)` — under `setupMu` + the per-device mutex: `loadG1(pk.Kzg.G1)` and `loadG1(pk.KzgLagrange.G1)` (raw memcpy + in-place device `AffineFromMontgomery`, groth16 icicle.go:319-331). Idempotent (no-op when `deviceInfo != nil`). **n and offset are taken from the freshly built domains / spr, never from slim pk fields.**
- **Ordering invariant (explicit, not by-construction accident):** `setupDevicePointers` completes synchronously, and the per-device mutex is held appropriately, **before `spr.Solve` runs** — the BSB22 hint fires GPU MSMs inside the solver. This holds in both pinned and unpinned modes.
- `PinToGPU=true` (via `WithPinKeysToGPU`): the dual SRS persists across Prove calls (one-time ~80 ms upload at 2^22 bn254); `FreeGPUResources()` frees both slices, nils `deviceInfo`, is idempotent. `PinToGPU=false`: upload at Prove start, deferred free at Prove end — **per-Prove lifetime, never per-MSM** (4+c MSMs share the Lagrange base).
- Per-proof buffers: each MSM's scalar upload is freed immediately after the call inside `RunOnDevice`. MSM results: 1 projective point D2H per chunk.
- `loadG1` converts **on device only** — no code path ever writes to the host `pk.Kzg.G1`/`pk.KzgLagrange.G1` slices (the wrapper shares backing arrays with the native pk; asserted by the marshal test, §11.3).
- Per-proof PCIe ≈ 10n·32B ≈ 320 MiB @2^20 / 1.28 GiB @2^22 → ~50 ms / ~205 ms at the measured 6.3 GB/s — 1–2% of the CPU MSM time replaced. No pinned host memory (pageable copies; measured bandwidth already reflects that).

---

## 6. NTT / coset config table — every Plonk transform

**v1 executes zero device NTTs and never calls `InitDomain`.** The table records, for every transform in the prover, the v1 disposition and the *verified* ICICLE config for Increment 2 (gap_answers[0]; semantics: ICICLE coset convention == gnark OnCoset, same CosetGen both directions, inverse applied internally; KNR==DIF, KRN==DIT; KNM/KMN are a matched mixed-order pair; coset application in bit-reversed order == gnark `scalingVectorRev`).

| Transform (clone site) | gnark shape | v1 | Verified ICICLE config (Increment 2 only) |
|---|---|---|---|
| computeNumerator round-i ToCanonical (batchApply, :1035-1057) | FFTInverse DIF + 1/n, size n, ×(12+2c) polys | **CPU** | `Ntt(KInverse)`, `Ordering=KNM`, `BatchSize=12+2c` — paired with the KMN below; identical {logn, batch} on both halves; nothing may read the M-order intermediate (algorithm-dependent); optionally pin `CUDA_NTT_ALGORITHM` via ConfigExtension |
| computeNumerator round-i ToLagrangeCoset | scalingVectorRev + FFT DIT on coset | **CPU** | `Ntt(KForward)`, `Ordering=KMN`, `CosetGen = shifters[i]`: round 0 = `domain1.FrMultiplicativeGen` (u = 5/22/15/15…; arbitrary-coset slow path — host serial O(n) table per call), rounds ≥1 = `w_4n` (fast subgroup path) — **NOT `fft.Generator(2n)` as in groth16** |
| Restore pass (:1090-1114) | ToCanonical + ToRegular + scalePowers, cumulative coset | **CPU** | `Ntt(KInverse)`, `Ordering=KNN`, `CosetGen = u·w_4n^{ρ−1}` — natural output fuses iNTT + bit-reverse + coset⁻ʲ·(1/n); KNM forbidden (no device bit-reverse exists) |
| **divideByZH** ToCanonical on domain1 (:1320) | FFTInverse DIT OnCoset, size 4n, WithoutPrecompute domain | **CPU** | `Ntt(KInverse)`, **`Ordering=KRN`**, `CosetGen = u` (FrMultiplicativeGen, standard-form limbs) — bit-rev in, **NATURAL out** for the contiguous h1/h2/h3 slices. **The groth16 KNR recipe is provably wrong here** (groth16's G1.Z basis is bit-reversed at setup; Plonk's canonical SRS is natural-order → KNR = silent proof corruption). Fold 1/(Xⁿ−1) into the host scatter (Appendix A.2) |
| Qk ToCanonical (:1420) | FFTInverse + BitReverse, size n | **CPU** | `Ntt(KInverse)`, `Ordering=KNN`, `CosetGen = 1` |
| `InitDomain` | — | **never called** | root = `fft.Generator(domain1.Cardinality)` = 4n (8n when n<6); limbs via `.Bits()` + `ConvertUint64ArrToUint32Arr` (never `ntt.GetRootOfUnity` — broken wrapper); tracker must record the **true root order** (groth16 records protocol-n: icicle.go:96 vs :134 inconsistency — do not copy) |

Any future NTT parity test must use the **commitment-level natural-order assertion** (kzg-commit both coefficient slices, not just vector-compare) plus an explicit **KNR-output-is-not-natural negative test** (techniques endorsed by all three judges).

---

## 7. Montgomery / R-factor discipline per buffer

Exactly two disciplines exist in v1, both with line-cited working groth16 precedent. There are no device VecOps and no `FromMontgomery` calls anywhere in the pipeline — the R^k product-degree bookkeeping hazard is structurally absent.

| Buffer | Host form | Device form | Mechanism |
|---|---|---|---|
| SRS bases (both) | Montgomery | **standard** | `loadG1` (groth16 icicle.go:319-331): raw `CopyToDevice` then in-place `AffineFromMontgomery` — once at load; every MSM sets `AreBasesMontgomeryForm=false` |
| MSM scalars (all 10+c uploads) | Montgomery | **Montgomery** | raw `(HostSlice[fr.Element])` memcpy; `AreScalarsMontgomeryForm=true` (groth16 Krs precedent, icicle.go:1229-1232). **Never** call FromMontgomery on these — double conversion |
| MSM result | — | projective, standard bytes | 1-elem `HostSlice[Projective]` D2H; `projectiveToGnarkAffine` (ToBytesLittleEndian → `fp.LittleEndian.Element`, validates + re-Montgomeryizes; chunk partials accumulated as G1Jac on host) |

Recorded ICICLE behavior (verified, relevant to Increment 2): an MSM over **device-resident** scalars with `AreScalarsMontgomeryForm=true` converts into a *freshly allocated* device buffer (cuda_msm.cuh:497-515) — input never mutated, but budget one extra transient scalar buffer per such call.

---

## 8. Global state & groth16 coexistence

**Decisive simplification: no `InitDomain`, no NTT-domain state.** The entire `nttDomainMaxByDevice` singleton problem (per-(curve,device) C-level domain singleton; groth16's ReleaseDomain-during-NTT race at icicle.go:803 vs 821) is moot for v1: plonk-icicle and groth16-icicle in one process share `libicicle_field_<curve>` but plonk performs zero operations on the C NTT domain — neither can corrupt the other's domain.

Per-curve plonk package state (duplicated, groth16-pattern, zero generated-file edits):
- `deviceMuLock sync.Mutex` + `deviceMu map[int32]*sync.Mutex` — per-device mutex held around **each individual GPU operation** (SRS upload, every gpuMsm). **Per-call granularity is correct here *only because* this package owns no NTT-domain state** — documented loudly in doc.go and here: if Increment 2 ever lands, the locking design must be revisited wholesale (whole-Prove mutex acquired before `setupDevicePointers` *and* before `spr.Solve`, + true-root-order domain tracker), not patched incrementally. Per-call locking serializes the prover's own concurrent goroutines (commitToLRO ×3, commitToQuotient ×3, the bsb22 hint in the solver) and makes the non-atomic `GetAvailableMemory`-driven tuner reads safe; under interleaving the tuner only degrades gracefully (smaller chunks/windows — it sizes against currently-free VRAM with a 0.7 factor), never OOMs; §9's headroom absorbs misestimates, and §11.6's race test exercises this.
- `msmChunkCapOnce`/`msmMaxWindowOnce` env caches duplicated (harmless cached ints).

**Warm-up — decision settled (not dual-tracked):** hoisted into `backend/accelerated/icicle/internal/gpuinit` with a one-line redirect in the **hand-written** `groth16_icicle.go`, landed in its own commit gated by re-running the existing groth16 GPU marshal test (P3.0). This eliminates the double-`LoadBackend` (idempotency undocumented), the leaked stream per device, and the second transient half-of-free-VRAM grab that duplicated Onces would cause. Pre-approved fallback if the redirect is rejected at review: duplicated Once in plonk_icicle.go with the warts documented in doc.go.

**Coexistence contract (doc.go):**
1. plonk-icicle never touches the NTT domain — no same-curve domain hazard with groth16, full stop.
2. Concurrent groth16 ∥ plonk proving on one device is **unsupported** (independent per-device mutexes; both adaptive MSM tuners read free VRAM non-atomically). Sequential mixed use is supported and smoke-tested (groth16 → plonk → groth16, one process, §11.6).
3. Plonk-only concurrent Proves on one device are safe (per-device mutex), subject to VRAM for pinned SRS sets.
4. Hoisting a shared per-(curve,device) true-root-order domain tracker is the recorded upstreaming follow-up (requires the groth16 template fix — exactly the codegen work the quality bar defers).

---

## 9. Memory budget vs 8 GB

Peak = CUDA context (~350 MiB empirical) + pinned dual SRS (2n+3)·A + **max** single-MSM transient (scalars m·s + indices 16·m·nofBms + buckets 4·P·2^c·nofBms, m = min(size, 2^18 chunk cap), c=16; per `computeRequiredMSMMemory`, groth16 icicle.go:731-781, corroborated against cuda_msm.cuh:423-578). Transients never sum — the per-device mutex serializes GPU ops. Element sizes (gap_answers[3] §0): bn254 A=64/P=96/s=32/nofBms=16; bls12-377/-381 A=96/P=144/s=32/16; bw6-761 A=192/P=288/s=48/24. Usable ≈ 7.3 GiB.

| n | bn254 | bls12-377/381 | bw6-761 |
|---|---|---|---|
| 2^20 | 128 + ≤480 + 350 ≈ **0.95 GiB** | 192 + ≤672 + 350 ≈ **1.2 GiB** | 384 + ≤1872 + 350 ≈ **2.6 GiB** |
| 2^21 | ≈ **1.07 GiB** | ≈ **1.4 GiB** | ≈ **2.9 GiB** |
| 2^22 | 512 + 576 + 350 ≈ **1.45 GiB** | 768 + 768 + 350 ≈ **1.85 GiB** | 1536 + 2016 + 350 ≈ **3.85 GiB** |

bw6-761@2^22 c=16 feasibility (the only <2× slack row): free after residents ≈ 7.3 − 1.5 − 0.35 = 5.45 GiB; tuner threshold 0.7·5.45 = 3.8 GiB ≥ 1.82 GiB buckets+indices → **c=16 survives, no window degradation** (verified at Phase 4, P4.3). Worst case leaves ≥3.4 GiB headroom; every curve benchmarks to 2^22 (the SRS-availability cap; 2^23 would need a new SRS and is out of scope). The 0.7 factor and 2^18 chunk cap are kept verbatim — they are what let pinned bases and transients coexist automatically in groth16. WarmUpDevice's transient half-of-free grab happens before any pinning and frees immediately. Contrast: the full numerator offload was 6.9–7.7 GiB at bw6@2^22 — borderline-infeasible (gap_answers[3] §7), one of the reasons it is deferred.

---

## 10. Correctness plan

**Core property:** every FFT, the closure, blinding, transcript, and aliasing-sensitive code is byte-identical cloned CPU code. Correctness collapses to (a) MSM parity and (b) clone fidelity.

**10.1 Randomness seam** (gap_answers[4]): exactly 5 SetRandom sites — getRandomPolynomial (:1247 via initBlindingPolynomials, **one draw per coefficient**), quotientShardsRandomizers (:240-241, StatisticalZK only), two in bsb22Hint (:293/:296). The clone threads them through `instance.randFr(tag string, i int)` — **the (tag, index) signature is mandatory** (a tag-only hook would degenerate seeded blinding polynomials to equal coefficients). Tags: `"bl"/"br"/"bo"/"bz"` (+ coefficient index), `"qsr0"/"qsr1"`, `"bsb22-<depth>-<slot>"`. Test hook = `sha256(seed‖tag‖i)` → `SetBytes` — domain-separated and goroutine-schedule-independent (initBlindingPolynomials runs on its own goroutine; bsb22Hint inside the solver). `getRandomPolynomial` becomes an instance method. nil ⇒ `fr.Element.SetRandom` (production identical to native). Exposed only via export_test.go; the native prover and `backend.ProverConfig` are **not** patched.

**10.2 Stage-wise oracle, collapsed to per-MSM shadow compare:**
- Primary: `ICICLE_PLONK_DEBUG_MSM=1` — gpuMsm also runs `curve.G1Affine.MultiExp` on identical (window, scalars) inputs and errors on mismatch. Deterministic, seed-free, localizes failure to one of the 11 call-site classes.
- Secondary: seeded determinism — prove twice (GPU vs `ICICLE_PLONK_FORCE_CPU_MSM=1`), byte-compare serialized proofs. Identical bytes prove every FS challenge and all CPU stages match end-to-end.
- Reserve: `onStageCheckpoint` hook against the 15-checkpoint table (gap_answers[4] §4), payloads encoded as `RawBytes()`/raw fr bytes **so Montgomery-form bugs surface as byte diffs**; nil in production.
- **Stated oracle limitation:** proof-byte comparison is clone-vs-clone only — the native prover has no randomness seam and stays unpatched, so the only native cross-checks are (i) unmodified `plonk.Verify` acceptance and (ii) the kzg-helper byte-parity tests vs gnark-crypto (which are seed-free and fully deterministic). Do not mistake the determinism test for native-equivalence.

**10.3 Fiat-Shamir preservation:** cloned byte-exactly — `NewTranscript(opts.ChallengeHash, "gamma","beta","alpha","zeta")` (:217); `bindPublicData`/`deriveRandomness` duplicated from verify.go:315-359/:361-379 (uncompressed `RawBytes()`/`Marshal()` — compressed bytes silently break FS); bare-β ComputeChallenge; hash-to-field default `New([]byte("BSB22-Plonk"))` (:206-208 == verify.go:152-154); `deriveGamma` reimplemented from kzg.go:559-591 binding point.Marshal, each digest uncompressed, each claimedValue.Marshal, then `dataTranscript = ZShiftedOpening.ClaimedValue.Marshal()` (:833). All pinned by the byte-parity unit tests (§11.2) **before** prover wiring.

**10.4 Aliasing/mutation invariants — preserved by construction:** in-place witness s0-subtract/restore around the synchronous gpuMsm (upload after subtract, restore after return — exactly like the MultiExp it replaces); s.x trace aliasing and the id_ZS ShallowClone skip in batchApply untouched; Qk clone untouched; blindedZ overwritten by linearized poly (scalars copied to device at call time — no retained device references to host slices); 9-goroutine/9-channel choreography unchanged; pk bytes never mutated (TestProver byte-compare gate).

**10.5 Clone-fidelity gate:** provenance header recording the exact upstream commit hash of `backend/plonk/<curve>/prove.go`; a **committed sanctioned-hunk list** (imports; instance fields; the 11 MSM call-site swaps; pk type; randFr seam; checkpoint hook; device setup) that the adversarial `diff -u` review checks every hunk against — the diff gate is mechanical, not vibes. Known maintenance liability, recorded: upstream changes to prove.go on master silently desync the clone; the provenance header is the detection handle.

---

## 11. Test plan

All GPU tests behind `//go:build icicle`, run via `nix develop --command go test -tags=icicle -p 1 ./backend/accelerated/icicle/...` — **`-p 1` (sequential packages) is part of the documented invocation**; the single shared 3070 makes parallel curve suites flake otherwise. No CI (consistent with groth16; doc.go disclaims it).

1. **MSM parity units** (`msm_test.go`, per curve): gpuMsm vs `curve.G1Affine.MultiExp` on random Montgomery scalars over real SRS-shaped bases; sizes {2^10, 2^14, 2^16, 2^18, n+2, n+3, 17 (odd), 63/64 (floor boundary)}; windows {full, `[0:offset]`, `[nbPublic:offset]` with nbPublic∈{1,5}, degenerate `offset==nbPublic` (floor path)}; pinned vs unpinned. Green **before any prover code exists** — this is the v1 analog of the GPU_EXPERIMENT.md pre-flight rule.
2. **kzg-clone byte-parity units** (`kzg_test.go`): gpuOpen / gpuBatchOpenSinglePoint with `ICICLE_PLONK_FORCE_CPU_MSM=1` vs gnark-crypto `kzg.Open`/`kzg.BatchOpenSinglePoint` on random polynomials (mixed degrees, dataTranscript bytes) → byte-equal OpeningProof/BatchOpeningProof. Proves deriveGamma/eval/divide/fold clones byte-exact in isolation. **Lands and passes before prover wiring (P3.4 < P3.6).**
3. **End-to-end + serialization (the hard gate)** (`marshal_test.go`, 4 curves, groth16 marshal_test.go:29-105 pattern): both directions native-Setup→serialize→icicle-ReadFrom→GPU-Prove and icicle-Setup→serialize→native; **every GPU proof verified by unmodified `plonk.Verify`**; pk fidelity via `bytes.Equal` on WriteTo streams — native-vs-icicle **and** before-vs-after Prove (TestProver invariant; also guards against any write to the shared host SRS backing arrays).
4. **Determinism**: SetTestRandomness(seed); GPU vs FORCE_CPU_MSM byte-equal proofs; plus an unseeded verify-only run (catches anything a seeded stub could mask). Debug ladder: DEBUG_MSM shadow compare → onStageCheckpoint vs the 15-checkpoint table.
5. **Circuit matrix per curve — non-negotiable gates, not nice-to-haves** (c=0 in all default tests): plain circuit; >1 public input (nbPublic window + correctionPoint identity); **BSB22 commitment circuit (c≥1)** — solver-hint GPU MSM + bsb22 randomness tags + ordering invariant; **WithStatisticalZeroKnowledge** — n+3/n+3/n+2 shards + qsr seam + len-derived windows; tiny circuit (small n, chunker small path, MSM floor).
6. **Regression & hygiene**: untagged `go test -short ./...` untouched (success criterion 2); `go build -tags=icicle ./...` compile gate; `go test -tags=icicle -race -count=1` incl. two concurrent Proves on one pk (setupMu + per-device mutex + tuner interleaving); mixed-use smoke: groth16 → plonk → groth16, one process (validates the shared gpuinit Once and non-interference); the gpuinit commit itself gated by the groth16 GPU marshal test.
7. **Benchmark (Phase 6)** (`bench_test.go`, BenchmarkLargeProver pattern, FS-cached SRS): CPU vs GPU per curve at 2^16/2^18/2^20/2^21/2^22, pinned/unpinned axes, **with per-MSM and transfer timings** (groth16 isProfileMode pattern) — validates the ≤200 ms/2^22-MSM assumption, makes any deviceMu stall or silent CPU-backend dispatch (37× outlier) visible rather than inferred, and publishes the MSM/FFT/PCIe decomposition + small-n crossovers for the Increment-2 decision.

---

## 12. Implementation steps

**Phase 3 (bn254):**

- **P3.0** — gpuinit hoist, own commit: `internal/gpuinit` + one-line redirect in hand-written `groth16_icicle.go`; gate: groth16 GPU marshal test green. (Fallback pre-approved: duplicated Once + doc.go warts.)
- **P3.1** — Skeleton: `plonk/{plonk_all,plonk_icicle,plonk_noicicle}.go` + `bn254/{doc,provingkey}.go`; both `go build ./...` and `go build -tags=icicle ./...` green.
- **P3.2** — MSM machinery: copy from groth16/bn254/icicle.go (projectiveToGnarkAffine/g1ProjectiveToG1Jac :266-285, loadG1 :319-331, msmChunkedG1 :362-414, configureMSM/computeMinMSMChunks/computeRequiredMSMMemory/chunkCountFromCap + env helpers :469-781, mutex helpers :79-86; delete G2/NTT/Den). Build the single `gpuMsm` chokepoint (fresh config per call, Montgomery flags, size floor, DEBUG/FORCE env switches). `msm_test.go` parity matrix green on the GPU — **device path validated before any prover code**.
- **P3.3** — ProvingKey wrapper: deviceInfo, setupDevicePointers (both loadG1 under setupMu+deviceMu), FreeGPUResources, Setup/NewProvingKey.
- **P3.4** — kzg.go clones (eval, dividePolyByXminusA, deriveGamma; gnark-crypto `parallel.Execute` → `internal/utils.Parallelize`) + gpuCommit/gpuOpen/gpuBatchOpenSinglePoint; `kzg_test.go` byte-parity vs gnark-crypto green — **before prover wiring**.
- **P3.5** — Clone the prover: prove.go → icicle.go (provenance header, upstream commit hash) + bindPublicData/deriveRandomness; thread `randFr(tag, i)` through all 5 sites + onStageCheckpoint; Prove entry (NewProverConfig from cfg.ProverOpts, CreateDevice, setupDevicePointers-before-Solve, deferred Free when !PinToGPU, returns `*plonk_bn254.Proof`). **Gate: marshal_test green in ALL-CPU mode (FORCE_CPU_MSM)** — clone fidelity, FS bytes, and pk serialization isolated from GPU bugs.
- **P3.6** — Swap the 10+c MSM call sites per §2 (len-derived windows). Leave commitBlindingFactor, correctionPoint, and all FFT/closure code untouched.
- **P3.7** — bn254 gates: marshal both directions + GPU prove + unmodified plonk.Verify + pk byte-compares; determinism test; circuit matrix (public>1, c≥1, StatisticalZK, tiny); race pass.
- **P3.8** — Adversarial diff review against the committed sanctioned-hunk list; Montgomery-flag and window audit at every call site; commit; update GPU_EXPERIMENT.md progress log.

**Phase 4 (3 curves, parallel worktrees, GPU runs serialized):**

- **P4.1** — bls12-377: identifier substitution of the bn254 package (imports, package names, icicle wrappers; no per-curve conditionals — Plonk has no G2 path); MSM constants from the working groth16/bls12-377 file; full per-curve test suite; commit.
- **P4.2** — bls12-381: same recipe; commit.
- **P4.3** — bw6-761: same recipe with an explicit constants checklist against the working groth16 bw6-761 file (s=48B, 12 scalar limbs, nofBms=24); verify the tuner keeps c=16 at 2^21–2^22 per §9; commit.
- **P4.4** — Wrap-up: 4-curve marshal loop green; cross-curve diff (four icicle.go files identical modulo identifiers); mixed groth16+plonk smoke; progress log. Phases 5–6 proceed per GPU_EXPERIMENT.md (multi-lens verify; benchmark + report).

---

## 13. Risks

| Risk | Sev | Mitigation |
|---|---|---|
| Clone drift / transcription error in the 1489-line prove.go clone silently breaks FS or an aliasing invariant | high | Provenance header w/ commit hash; committed sanctioned-hunk list + adversarial diff gate; all-CPU-mode marshal gate before GPU wiring; determinism byte-compare; unmodified plonk.Verify as the hard gate; upstream-desync liability documented |
| deriveGamma / bindPublicData / deriveRandomness byte drift (compressed vs uncompressed, binding order) — silent FS failure, no diagnostic | high | kzg byte-parity tests vs gnark-crypto land before wiring; clones use Marshal/RawBytes exactly as upstream; covered transitively by determinism test |
| Montgomery mistakes (double conversion; bases not converted while cfg says standard) | high | Exactly two disciplines, both groth16-precedented; DEBUG_MSM shadow compare catches at first MSM; parity matrix per curve |
| GPU call outside RunOnDevice silently dispatches to the icicle CPU backend (measured 37×, no error) | med | Single gpuMsm chokepoint — auditable at one site; everything inside RunOnDevice; Phase 6 per-MSM timings expose outliers |
| BSB22 solver-hint MSM untested by default circuits (c=0 everywhere) | med | c≥1 circuit is a non-negotiable per-curve gate; setupDevicePointers-before-Solve is a stated invariant |
| Mixed groth16+plonk process interference | med→low | gpuinit shared Once removes the double-LoadBackend/stream-leak class; no NTT state removes the domain class; sequential smoke test; concurrent same-device use documented unsupported |
| Concurrent Proves race the non-atomic VRAM tuner | med | Per-device mutex serializes all plonk GPU ops; tuner degrades gracefully by design; ≥3.4 GiB worst-case headroom; race test |
| Edge geometries (zero-length/tiny windows panic in Range; StatisticalZK n+3 vs base bounds) | low | MSM size floor before any Range; len-derived windows; canonical base exactly n+3 by setup.go:126; explicit edge tests |
| pk serialization regression / Prove mutating pk / writes to shared host SRS arrays | low | deviceInfo never serialized; loadG1 converts on device only; byte-compare gates both directions + before/after Prove |
| bw6-761 constant assumptions | low | Constants copied from working groth16 bw6 file + explicit checklist; memory model validated by Phase 0 |
| Speedup disappoints vs assumption (≤200 ms/2^22 GPU MSM; deviceMu doesn't stall errgroup) | med (perf only) | Stated as assumptions, measured honestly in Phase 6 per-MSM; floor = CPU behavior is never worse than baseline (FORCE_CPU fallback exists) |

---

## 14. Expected speedup (honest, Amdahl-grounded)

From the measured profile (§3): **Amdahl ceilings for MSM→0: 2.21× / 1.91× / 1.76× / 1.62×** at 2^16/2^18/2^20/2^22.

Realized estimate, assumptions stated: (1) ≤200 ms per 2^22-size GPU MSM incl. launch + chunking — extrapolated from the working groth16 integration on this exact GPU/kernels/chunker, *not yet measured for Plonk's sizes* (Phase 6 measures); (2) deviceMu serialization does not stall the prover — the errgroup overlaps GPU MSMs with CPU FFT work, and freed CPU threads accelerate the remaining FFT share, so sample-share Amdahl slightly *underestimates* wall gain; (3) c=0 (each BSB22 commitment adds a size-n GPU MSM — helps the GPU share). PCIe (≈205 ms @2^22) is 1–2% of the ~13.9 s CPU MSM time replaced — transfers cannot eat this win.

| n | CPU wall | projected GPU wall | speedup |
|---|---|---|---|
| 2^16 | 0.465 s | ~0.22–0.25 s | **~1.9–2.1×** |
| 2^20 | 8.6 s | ~5.1 s | **~1.65–1.7×** |
| 2^22 | 36.4 s | ~24.5–25 s | **~1.45–1.5×** |

Stated plainly: MSM-only is the one scope whose relative win **grows as n shrinks** (highest MSM share, tiny transfers) and **shrinks as n grows** — at 2^22 the FFT machinery (47.6% of samples) stays entirely on CPU and bounds the headline number. That ceiling is accepted at the post-design checkpoint; the next increment (+11–13% at 2^20–2^22 for the device-resident numerator pipeline, per gap_answers[1] §5) is specified in Appendix A and decided from Phase 6 data, not folded into v1.

---

## 15. Resolved concerns

Every judge concern, with its resolution in this design.

**Correctness judge:**
1. *Clone fidelity dominant risk* → §10.5: provenance commit-hash header, committed sanctioned-hunk list, adversarial diff gate; kzg byte-parity tests land before wiring (P3.4 < P3.6).
2. *Randomness seam must be (tag, index)* → adopted; §10.1 (`randFr(tag string, i int)`; per-coefficient draws preserved).
3. *BSB22 ordering as explicit invariant + c≥1 test* → §5 ordering invariant; §11.5 non-negotiable gate; hint body inside RunOnDevice via the gpuMsm chokepoint.
4. *Per-call mutex coupling to no-NTT-state; never half-adopt an NTT stage* → §8 documents the coupling loudly; Appendix A.0 states Increment 2 requires the full locking + domain-tracker redesign as a package, never an incremental patch.
5. *Duplicated-Once LoadBackend idempotency* → moot: gpuinit hoist adopted (P3.0, own commit, groth16-gated); mixed-use smoke retained.
6. *Validate the 200 ms MSM assumption and no-stall claim* → stated as assumptions in §14; Phase 6 per-MSM/transfer timings are a deliverable (§11.7).
7. *Edge geometries (zero-length Range panic, tiny n, n+3 windows)* → gpuMsm size floor before any Range; len-derived windows; n+3 fits the exactly-(n+3)-point base; explicit tests §11.1/§11.5.
8. *Shallow-copy pk shares backing arrays* → §5 loadG1-device-only rule + §11.3 byte-compares both directions and before/after Prove.
9. *Set ceiling expectations + name Increment 2* → §1, §14, Appendix A.
10. *DEBUG/FORCE switches inert in production* → §2: env-gated additions to the single chokepoint; default path unchanged when unset.

**Performance judge** (its winner's concerns, mapped onto the chosen scope):
1. *Stage-gating contract* → v1 **is** Stage A, a complete committable deliverable per curve; Appendix A defines Increment 2 as separately gated work with its own preflight.
2. *Re-baseline headline numbers; deduct arbitrary-coset costs* → v1 numbers contain no NTT claims; Appendix A.2/A.4 records the arbitrary-coset slow-path cost (~0.2–0.3 s serial host table at 4n=2^24) as a deduction any Increment-2 estimate must make; quote 1.8–2.1× (not 2.2×) if Increment 2 proceeds.
3. *Per-round D2H writeback seam (trace-aliased slices, Basis/Layout flips)* → deferred with the stage; Appendix A.5 records the seam and required tests so it is never re-derived.
4. *KNM/KMN pair discipline* → Appendix A.5: identical {logn, batch} both halves, no reads of the M-order intermediate, per-curve mismatch demo test, ConfigExtension pin decided up front.
5. *InitDomain re-creates the coexistence hazard* → structurally absent in v1 (§8); Appendix A.0 carries the contract incl. the failing direction (plonk-4n then groth16-2n Release+Init) and the smoke-test ordering requirement.
6. *groth16_icicle.go redirect in own gated commit* → P3.0, exactly so.
7. *Mutex-before-Solve and setup-after-mutex* → §5 invariant (v1: setupDevicePointers completes before Solve; per-call mutex correct absent NTT state); Appendix A.0 mandates the whole-Prove form for Increment 2.
8. *Every auto-disable path is a tested configuration* → v1 has no stage masks; the only alternate path (FORCE_CPU_MSM) is exercised by the determinism gate every run.
9. *Keep the armored host-scalar msmChunkedG1 byte-auditable* → v1 has no device-scalar variant; Appendix A.3 requires isolating one if ever added.
10. *Benchmark must publish breakdown + small-n crossovers, stated plainly* → §11.7, §14.

**Simplicity judge:**
1. *Ceiling explicitly accepted; staged decision* → §1, §14.
2. *Concrete clone-drift mitigation + maintenance liability* → §10.5.
3. *Oracle limitation stated (clone-vs-clone only)* → §10.2.
4. *kzg differential tests before wiring* → P3.4 ordering, §11.2.
5. *Tuner under interleaving degrades gracefully; cross-package concurrency unsupported* → §8, §9, race test §11.6.
6. *c≥1 and StatisticalZK as non-negotiable gates* → §11.5.
7. *Warm-up settled, not dual-tracked* → §8 (hoist adopted; fallback pre-approved but not default).
8. *pk byte-compare hard gates* → §11.3.
9. *`-p 1` serialization in the documented invocation* → §11 header.
10. *bw6-761 constants checklist + c=16 survival* → P4.3, §9.

---

## Appendix A — Increment 2 (recorded, NOT in v1): NTT offload recipes

Everything here is verified (gap_answers[0] kernel-level evidence; judge-endorsed grafts) and recorded so it never has to be re-derived. **Entry conditions:** Phase 6 data justifies it; the global-state plan (A.0) is adopted **as a whole**; per-curve preflight NTT matrix green before any prover wiring; n ≥ 2^18 gating (below it, PCIe + launch floors make NTT offload a net loss).

**A.0 Global-state package (all-or-nothing):** whole-Prove per-device mutex acquired **before** `setupDevicePointers` and **before** `spr.Solve`; per-curve `nttDomainMaxByDevice` tracker recording the **true root order** passed to InitDomain (4n; 8n when n<6) — never groth16's protocol-n convention (icicle.go:96 vs :134); InitDomain root = `fft.Generator(domain1.Cardinality)` via `.Bits()` + `ConvertUint64ArrToUint32Arr` (never `ntt.GetRootOfUnity`); doc.go coexistence contract gains the failing direction: same-curve groth16 after plonk can Release+Init a smaller domain → plonk's recorded 4n is stale → loud NTT-size failure; mixed smoke test must cover that order. `FreeGPUResources` never releases the NTT domain (groth16 contract).

**A.1 divideByZH (first increment):** `Ntt(KInverse, Ordering=KRN, CosetGen=u=FrMultiplicativeGen)` on the 4n cres → **natural-order** canonical output. **Never KNR** (groth16's recipe; silent corruption here) and never KNM. Preflight: commitment-level natural-order assertion + explicit KNR negative test, sizes spanning the radix-2/mixed-radix boundary (2^10/2^14/2^17), Montgomery-passthrough variant. CPU baseline is extra slow here (WithoutPrecompute domain rebuilds 4n twiddles + cosetTableInv per proof, fft.go:125-189) — this is the best risk-adjusted NTT prize.

**A.2 zhInv-fold-into-scatter (verified identity):** `cres[bitrev_4n(ρ·j+i)] = buf[j] · zhInvLagrangeCoset[i]` — exact because natural index k=ρ·j+i gives k%ρ==i, constant per round (prove.go:1069-1076 / 1312-1317). Eliminates both the device VecOp and any 4n ZHInv resident vector. Optimization knob if the arbitrary-coset slow path hurts: precomputed standard-form u^{−j} unshift vector + subgroup-path iNTT + one VecOp (one-standard-operand Montgomery rule applies).

**A.3 StatisticalZK correction points (verified algebra)** for committing H shards from device-resident contiguous ranges: `H1 += r0·Kzg.G1[n+2]`; `H2 += r1·Kzg.G1[n+2] − r0·Kzg.G1[0]`; `H3 −= r1·Kzg.G1[0]` (from prove.go:689-724). Judge-preferred v-next default: keep committing from **host** shard slices via native h1()/h2()/h3() with len-derived sizes (h returns to host for linearization anyway; device-Range scalars save ~60 ms at 2^22 and require a device-scalar msmChunkedG1 variant — if added, isolate it from the verbatim-copied host-scalar helper). Note A device-resident-scalar MSM with `AreScalarsMontgomeryForm=true` converts into a fresh device buffer (cuda_msm.cuh:497-515) — budget the transient.

**A.4 Numerator pipeline (+11–13% at 2^20–2^22, gap_answers[1] §5):** contiguous (12+2c)·n device batch; per round i: `Ntt(KInverse, KNM, BatchSize=12+2c)` then `Ntt(KForward, KMN, CosetGen=shifters[i])` — shifters[0]=u (arbitrary-coset slow path, one serial host O(n) table per call — deduct from estimates), shifters[i≥1]=w_4n (fast path, needs the 4n domain); restore = `Ntt(KInverse, KNN, CosetGen=u·w_4n^{ρ−1})`. Closure stays on host (D2H per round). VRAM: xDev freed before cres allocated; bw6-761@2^22 likely degrades to MSM+ZH only — every degraded mode is a distinct tested configuration hitting the same verifier gate.

**A.5 Required discipline if A.4 lands:** KNM/KMN pair — identical {logn, BatchSize}, nothing reads the M-order intermediate, per-curve mismatch-demo preflight, decide the `CUDA_NTT_ALGORITHM` ConfigExtension pin up front. D2H writebacks into trace-aliased iop.Polynomials need: an enumerated map of which s.x slots live on device (id_ZS excluded — shares storage with Z; Qk-clone slot handling), manual Basis/Layout updates, a restored-trace byte-compare checkpoint, and a ZS-rotation read-path test. Locking reverts to whole-Prove granularity (A.0).