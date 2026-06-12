# GPU support for Plonk (ICICLE) — experiment plan

Branch: `philippe/gpu-experiment` · Started: 2026-06-11 · Status: **Phase 6 in progress — benchmark matrix running (Phases 0–5 done)**

## Goal

GPU-accelerate the Plonk prover using [ICICLE](https://github.com/ingonyama-zk/icicle-gnark), mirroring the
existing Groth16 integration at `backend/accelerated/icicle/groth16/` into a new
`backend/accelerated/icicle/plonk/`.

**Scope:** bn254, bls12-377, bls12-381, bw6-761 — the same curve set as the Groth16 ICICLE
integration. The koalabear Plonk backend is out of scope (icicle-gnark v3.2.2 has no
small-field support).

**Quality bar:** working experiment. All 4 curves working and benchmarked on this branch;
codegen templates, docs and upstream polish deferred.

## Success criteria

1. `go test -tags=icicle` passes on the dev GPU for all 4 curves: a proof generated on the
   GPU **verifies with the unmodified CPU verifier** (the hard correctness gate).
2. CPU-only builds and the existing test suite are completely unaffected.
3. Benchmark report: CPU vs GPU prove times across circuit sizes that fit in 8 GB VRAM,
   with a breakdown of where time goes (MSM vs NTT vs host↔device transfer).
4. Everything committed incrementally on this branch.

## Dev machine

RTX 3070 (8 GB VRAM, sm_86), driver CUDA 12.2, no host `nvcc`. Environment is provided by
a `flake.nix` dev shell (Go toolchain + ICICLE CUDA backend; host `libcuda` from the
driver). The GPU is a single shared resource: GPU test runs serialize even when
implementation work is parallel.

## Phases

| # | Phase | Shape | Exit criterion |
|---|-------|-------|----------------|
| 0 | Environment gate | inline | Existing **Groth16** ICICLE test passes on GPU inside `nix develop` |
| 1 | Understand | workflow: 6 parallel readers + completeness critic | Structured map of the 6 subsystems below |
| 2 | Design | workflow: 3 biased designers → judge panel → synthesis | `DESIGN.md` committed |
| — | **Checkpoint** | user reviews `DESIGN.md` | sign-off before any prover code |
| 3 | bn254 reference impl | tight build→GPU-test→fix loop | bn254 GPU proof verifies on CPU; adversarial diff review; commit |
| 4 | Port to 3 other curves | workflow: parallel agents in worktrees; GPU tests serialized | per-curve tests green; commit per curve |
| 5 | Verify | workflow: multi-lens | roundtrips, serialization, no-tag CPU regression, race detector, 3-lens adversarial review |
| 6 | Benchmark + report | inline + agents | CPU vs GPU table per curve, 2^16 → VRAM limit |

Phase 1 reader assignments: (a) Groth16-ICICLE integration anatomy (build tags,
registration, device-memory lifecycle, offloaded ops); (b) Plonk prover hot path — every
MSM (3 wire commitments, permutation z, 3 quotient parts, 2 KZG openings) and every
FFT/coset-FFT with sizes, plus the goroutine pipelining around them; (c) `kzg.Commit`
call sites and how to intercept gnark-side; (d) icicle-gnark v3 API surface (MSM, NTT
incl. coset/ordering, memory management); (e) Plonk ProvingKey structure — device-side
caching candidates; (f) test/bench infrastructure.

Phase 2 designer biases: minimal MSM-only offload · aggressive device-resident MSM+NTT ·
strict consistency with the Groth16 pattern. Judges score correctness risk, expected
speedup on a 3070 (PCIe transfer can eat the win), and effort.

## Known risks

- **Nix packaging of the prebuilt ICICLE CUDA backend** (patchelf, host `libcuda`
  wiring) — Phase 0 gates on this precisely because it's the most likely grind.
- **Coset-NTT semantics**: icicle NTT config vs gnark-crypto `fft.Domain`
  (coset generator, element ordering). Pre-flight unit test comparing the two on random
  vectors *before* wiring into the prover — mismatches here corrupt proofs silently.
- **PCIe overhead**: GPU offload may be a net loss below some circuit size on a 3070.
  The benchmark phase measures this honestly; offload thresholds are an expected outcome.
- **8 GB VRAM** caps benchmark sizes around 2^20–2^22 given Plonk's polynomial count.

## Autonomy model

Phases run as sequential multi-agent workflows with the orchestrator reading each phase's
result before shaping the next. Durable state: commits on this branch, this file
(status line + progress log below), and `DESIGN.md`. The only planned interruption is the
post-design checkpoint.

## Progress log

- 2026-06-11: Plan approved (autonomy: pause after design doc; quality: working
  experiment; env: nix flake). This file committed. Phase 0 started.
- 2026-06-11: **Phase 0 done.** `flake.nix` builds icicle-gnark v3.2.2 (4 curves,
  CUDA 12.6 toolkit, sm_86) and provides the dev shell. Gate test green:
  `nix develop --command go test -tags=icicle ./backend/accelerated/icicle/groth16/`
  proves+verifies Groth16 on the RTX 3070 for all 4 curves. Two environment traps
  fixed along the way, documented in flake.nix comments: host-glibc shadowing via
  LD_LIBRARY_PATH (only driver libs are exposed now) and missing `$ORIGIN` rpath on
  the per-curve CUDA backend libs (their dlopen failed silently → "operation not
  supported on device CUDA"). Phase 1 (subsystem-mapping workflow) running.
- 2026-06-11: **Phase 1 done.** 13 agents (6 readers + critic + 6 gap-fillers) produced
  `.phase1-map.json` (committed; full subsystem map with file:line evidence). Headline
  findings: (1) measured CPU profile 2^16–2^22 — MSM 38–55% of prover time, FFT machinery
  30–48%, pointwise constraint work only ~7%; (2) full computeNumerator offload is NOT
  expressible in icicle-gnark v3.2.2 (no scalar broadcast / d2d copy / gather / batch
  inversion) — MSM-first scope is quantitatively justified; (3) no interception seam in
  gnark-crypto kzg → the GPU prover clones `backend/plonk/<curve>/prove.go` (groth16
  precedent), unexported-symbol inventory mapped; (4) all five Plonk transform shapes
  mapped to ICICLE NTT configs — note the groth16 KNR recipe does NOT apply (Plonk's
  quotient needs natural order) and the coset generator is FrMultiplicativeGen, not
  fft.Generator(2n); (5) VRAM budget worked: dual SRS at n=2^22 = 0.5–1.5 GiB per curve,
  fits the 8 GB card; (6) prover has exactly 5 SetRandom sites and no injection point —
  the clone adds a deterministic-randomness hook for stage-wise CPU-vs-GPU testing.
  Phase 2 (3 biased designers → 3-lens judge panel → DESIGN.md synthesis) running.
- 2026-06-11: **Phase 2 done — CHECKPOINT.** Judge panel (correctness/performance/
  simplicity lenses): 2 of 3 picked **MSM-only for v1**; the performance judge's
  preferred NTT increments are preserved verbatim in DESIGN.md Appendix A as a
  data-gated follow-up (decided from Phase 6 numbers, not folded into v1).
  DESIGN.md committed: 10+c G1 MSMs offloaded against a device-resident dual SRS
  through a single gpuMsm chokepoint; zero InitDomain calls (structurally eliminates
  the NTT silent-corruption class and the groth16 domain-singleton coexistence
  hazard); prove.go cloned per curve with a deterministic-randomness seam and an
  all-CPU clone-fidelity gate before any GPU wiring. Honest projection: ~1.9–2.1×
  at 2^16 shrinking to ~1.45–1.5× at 2^22 (FFT stays on CPU; Amdahl ceiling 1.62×).
  Awaiting user sign-off before Phase 3 (bn254 implementation).
- 2026-06-11: Design accepted by user. **Phase 3 (bn254) done** — commits 70c70571
  (P3.0 gpuinit hoist), 53b87306 (P3.1 skeleton), fd76cf98 (P3.2 gpuMsm + 22-case
  GPU parity matrix), 50aff4fe (P3.3 ProvingKey wrapper + device dual SRS),
  c74a2dc8 (P3.4 kzg clones, byte-parity), e3ccdbb2 (P3.5 prove.go clone, 22
  sanctioned hunks, deterministic-randomness seam, clone-fidelity gate),
  59f7cc7b/1a00c198 (P3.6/P3.7 the 10+c MSM swap + gates: seeded GPU-vs-forced-CPU
  proofs BYTE-IDENTICAL across the circuit matrix incl. BSB22-in-solver,
  StatisticalZK, tiny-circuit floor; race clean). P3.8 adversarial review (45
  agents, 3 lenses, 2-skeptic verification): 12 confirmed findings → fixed in
  51959d67 — notably a real CRITICAL (deferred FreeGPUResources freeing the device
  SRS under concurrent Proves on a shared pk) now solved with a refcounted
  device-SRS lifetime model + race-tested concurrent-Prove gates; plus device-
  identity check, ReadFrom device-state invalidation, VRAM-OOM as errors,
  chunked-MSM parity coverage. 2eaf9553 fixed the dev-shell libstdc++ leak.
- 2026-06-11: **Phase 4 done** — ports: bls12-377 (5a0a3a49), bls12-381 (9fb97188),
  bw6-761 (e054047a). Each: 9-step ordered identifier substitution, zero
  non-identifier differences needed (all MSM machinery derives sizes from
  unsafe.Sizeof/fr.Bits/fr.Limbs — confirmed even for bw6-761's 48B scalars/192B
  points), clone-fidelity gate exactly 25 hunks per curve, cross-package
  diff-of-diffs empty, full per-curve gate suites green incl. determinism oracles
  and -race. 4-curve marshal loop + mixed groth16→plonk→groth16 smoke green.
- 2026-06-11: **Phase 6 harness built** (`backend/accelerated/icicle/plonk/bench_test.go`,
  `//go:build icicle`): `BenchmarkPlonkProveCPU` (real upstream backend/plonk
  prover) vs `BenchmarkPlonkProveGPU` (pinned steady-state: untimed warm-up prove
  loads the backend and uploads+pins the dual SRS before ResetTimer;
  FreeGPUResources after each timed leg keeps VRAM bounded) over the scaled
  referenceCircuit with the X=1,Y=1 witness trick; lazy per-(curve,size) setup
  cache (PLONK has no DummySetup) so any `-bench` regex pays only for selected
  sizes; both legs verify one untimed proof; everything skipped under `-short`.
  Matrix: bn254/bls12-377/bls12-381 at 2^16/18/20/22, bw6-761 at 2^16/18/20/21
  (2^21 included — 385G disk free makes the SRS-cache objection void; 2^22
  excluded for one-time SRS-gen/Setup wall time). Smoke gate green (bn254 2^16,
  -benchtime=2x): CPU 0.594 s/op, GPU 0.545 s/op — sane, single setup, backend
  loaded from nix store. NB the smoke GPU number is well below the §14 ~2×
  projection at 2^16; to be measured properly by the full matrix under exclusive
  GPU access (commands + ~1.5-3 h runtime and ~4.2 GiB SRS-cache disk estimates
  in the bench_test.go header, incl. an ICICLE_STEP_PROFILE per-MSM pass).
- 2026-06-11: **Phase 5 done.** (a) Full untagged `go test -short ./...` regression:
  exit 0, zero failures — upstream gnark untouched. (b) Adversarial review of the
  refcounted lifetime model (22 agents, 2 lenses + 2-skeptic verification):
  3 confirmed findings fixed in d88aa264 — TOCTOU in ReadFrom/UnsafeReadFrom
  (setupMu now held across the entire deserialization; -race stress test added),
  unjoined gpuinit warm-up transient (warm-up goroutines now joined, streams
  synchronized+destroyed, VRAM precheck re-samples before erroring), and the
  per-curve per-device mutex hoisted into shared internal/devicemutex so
  cross-curve plonk Proves on one GPU serialize correctly (doc contract updated
  in all 4 packages). All gates re-green incl. -race on all four curve packages.
  Phase 6 benchmark matrix launched (8 timing runs + 4 step-profile passes).
