# Phase A — GPU Prize Quantification for the Lineth (Linea) PoC Prover

**Date:** 2026-06-12 · **Scope:** read-only synthesis · **Sources:** pinned prover `linea-monorepo/prover@v0.0.0-20260529143340-467d7a4a0fb0` source, local PoC asset manifests (built 2026-06-05), user-measured request timings (r7iz.32xlarge run), our gnark GPU branch measurements (`/home/work/repositories/gnark/GPU_EXPERIMENT.md`, `bench-results/`, `DESIGN.md` §3/§14), public Linea/gnark record.

**Label key:** **[M]** measured · **[D]** documented (source/config/manifest) · **[I]** inferred (arithmetic on measured data, assumptions stated) · **[G]** guess (plausible, unverified).

---

## 0. Executive summary

- All gnark-Plonk proving per batch concentrates in **4 circuits**: the execution-limitless outer wrap (BLS12-377), and the aggregation request's PI-interconnection (BLS12-377, 2^24), aggregation-N (BW6-761, 2^20), emulation (BN254, 2^25). Everything else is koalabear Wizard/Vortex (zero MSM, structurally immune to our offload) or dev-mode dummies. **[M/D]**
- On the PoC's 128-vCPU box, the **pure Plonk prove kernels are projected at only ~95 s of the 1177 s aggregation request** (~8%), and **CPU MSM within them only ~20 s** **[I]**. The request is dominated by PI compile-at-prove-time, witness generation, and multi-GB setup loads — none of which MSM offload touches.
- **H100 beats 128-core CPU MSM ~2–3× at every real size; L40S is roughly parity-to-loss** **[I]**. MSM-only offload therefore buys **~1.5–8% window latency** depending on the unknown execution-wrap share — the decisive unknown.
- The single gating measurement is **one batch re-run with `LIMITLESS_PERF_LOG=true`** (instrumentation already built into the pinned prover; zero code changes — recipe in §6). Decision thresholds in §5.
- **Wildcard that changes everything:** if DA flips from `dev` to `full` (documented "~20-min" 2^27 BLS12-377 proof per blob, 2 blobs/window), gnark Plonk becomes >50% of the window and a GPU deployment is clearly justified. **[D/I]**

---

## 1. Per-batch proof inventory

Batch = one 2-block conflation **[D]** (`coordinator-config-v2.toml: blocks-limit=2`); 1 blob/batch; 1 aggregation per ~2 batches (`proofs-limit=3`). Measured window (blocks 1–4) = 2 execution + 2 compression + 1 aggregation request **[M]**.

| # | Proof | System | Curve/field | Domain (size) | Count per batch | Provenance / confidence |
|---|---|---|---|---|---|---|
| 1 | GL segment proofs | Wizard/Vortex (RS + ring-SIS + Poseidon2) | koalabear (31-bit) | 2^25-row fixed recursion shape | ~N per batch (N = discovered modules, 18 clusters defined; exact count block-dependent, unmeasured) | **[D]** source `distribute.go`, `limitless.go`; count **[G]** |
| 2 | LPP segment proofs | Wizard/Vortex | koalabear | same | ~N per batch | **[D]**; count **[G]** |
| 3 | Conglomeration merges | Wizard/Vortex (final merge BLS-friendly Vortex, no SIS) | koalabear → BLS12-377-friendly | — | numGL+numLPP−1 | **[D]** `prove.go:722-851` |
| 4 | **Execution-limitless outer wrap** | **gnark Plonk (KZG)** | **BLS12-377** | capacity 2^24 **[D]** `builder_limitless.go:40` — **conflicts** with srs-gen comment "~2^27 constraints" **[D]** `docker/srs-gen/main.go`; actual size **unknown** | **1** | High confidence it exists & is unique; size = **open conflict**, resolved by §6 |
| 5 | Compression / DA | dummy gnark Plonk (dev mode) | BLS12-377 | trivial | 1 | **[M]** 6.6 s measured + `prover_mode="dev"` **[D]**; full mode = real 2^27 BLS12-377 ("~20 min") **[D]** |
| 6 | **PI-interconnection** | **gnark Plonk** | **BLS12-377** | **11,276,421 constraints → 2^24** | 0.5 (1 per aggregation) | **[M]** manifest 2026-06-05. ⚠ post-2026-06-09 config (PI dims 400/400/200) makes it **larger**, count unknown, capacity 2^27 **[D]** |
| 7 | **Aggregation-N** | **gnark Plonk** | **BW6-761** | **564,847 → 2^20** (N=1) | 0.5 | **[M]** manifest. ⚠ current config builds aggregation-**10** — larger, unknown **[D]** |
| 8 | **Emulation** | **gnark Plonk** | **BN254** | **25,008,661 → 2^25** | 0.5 | **[M]** manifest; least likely to have grown **[I]** |
| 9 | Invalidity | gnark Plonk | BLS12-377 ≤2^24 | — | 0 (normal operation) | **[D]** |

All gnark proves flow through one chokepoint: `circuits/prove.go:80` (`plonk.Prove`), and the pinned gnark commit `c62f696e` is an ancestor of our `philippe/gpu-experiment` branch → a `go.mod replace` is a clean Phase-B drop-in. **[M]**

---

## 2. GPU applicability per gnark-Plonk layer

### 2.1 Model inputs (our measurements, RTX 3070 8 GB / i7-11800H 16T)

CPU Plonk prove walls **[M]** (`GPU_EXPERIMENT.md` Results): bn254 32.50 s @2^22; bls12-377 39.25 s @2^22; bw6-761 32.78 s @2^20, 64.87 s @2^21. Growth per 4× size: ×3.97–4.28 measured → use **×4.2/4× [I]**.
MSM share of CPU prove **[M]** (DESIGN.md §3, sampled): 54.7/47.6/43.3/38.1% @2^16/18/20/22 → extrapolated **~33% @2^24, ~31% @2^25, ~28% @2^27 [I]** (−~4.8 pts per 4×).
Per-MSM GPU device time on 3070 (with 16–17× chunking) **[M]** (`bench-results/*-msmprofile.txt`): bn254 ~0.39 s @2^22 (≈ **93 ns/point**); bls12-377 ~0.65 s (≈ **155 ns/pt**); bw6-761 ~2.1 s @2^21 (≈ **1000 ns/pt**). Plonk = 10 size-n MSMs + c BSB22 commitments (all four real circuits use BSB22 → **c≥1**, model **11 MSMs**) **[M/D]**.

### 2.2 Scaling rules (stated assumptions)

- Laptop 16T → r7iz 128 vCPU: **whole prove wall ÷5** (range 4–7), **MSM ÷8** (near-linear parallelism, per prompt guidance + gnark's parallel MSM) **[I]**.
- GPU per-MSM cost: linear in n **[M-validated within curve]**; across cards, bandwidth-scaled (MSM is memory-bandwidth-bound): 3070 448 GB/s → **L40S ÷1.93**, **H100 ÷7.48** **[I, ±50%]**. The chunked-cost basis is conservative (per-chunk launch + host projective→affine doesn't bandwidth-scale); removing the 2^18 chunk cap is documented to remove ~75% of chunk overhead → an extra **~1.5× headroom [I]** on top of all GPU numbers below.

### 2.3 Per-layer projection on the PoC instance class (r7iz.32xlarge)

| Layer | Size | Laptop-16T prove (extrap.) | **r7iz CPU prove (÷5)** | r7iz CPU MSM (÷8 of laptop MSM) | GPU MSM device-busy: L40S / **H100** | Dual-SRS VRAM |
|---|---|---|---|---|---|---|
| PI-interconnection | bls12-377 2^24 | 39.25×4.2 ≈ 165 s **[I]** | **~33 s** (24–41) | 165×0.33÷8 ≈ **6.8 s** | 14.8 s / **3.8 s** (→ ~2.5 s chunk-fixed) | 2×2^24×96 B = **3.2 GB** |
| Emulation | bn254 2^25 | 32.5×4.2×2.05 ≈ 280 s **[I]** | **~56 s** (40–70) | 280×0.31÷8 ≈ **10.9 s** | 17.7 s / **4.6 s** (→ ~3 s) | 2×2^25×64 B = **4.3 GB** |
| Aggregation-1 | bw6-761 2^20 | 32.78 s **[M]** | **~6.6 s** | 32.78×0.47÷8 ≈ **1.9 s** | 6.0 s / **1.6 s** (→ ~1 s) | 2×2^20×192 B = **0.40 GB** |
| Exec outer (if 2^24) | bls12-377 | ~165 s | **~33 s** | **~6.8 s** | 14.8 s / **3.8 s** | 3.2 GB |
| Exec outer (if 2^27) | bls12-377 | ~1435 s | **~287 s** | **~54 s** | 119 s / **31 s** (→ ~20 s) | **25.8 GB** |
| DA-full (if enabled) | bls12-377 2^27 | ~1435 s | ~287 s kernel (config says ~20 min total **[D]**) | ~54 s | 119 s / **31 s** | 25.8 GB |

**VRAM verdict [I]:** H100 80 GB holds *every* real circuit's dual SRS simultaneously (agg-trio ≈ 7.9 GB; + 2^27 BLS12-377 ≈ 34 GB total) — chunking and SRS streaming disappear entirely. L40S 48 GB also fits all (tight at ~34 GB). RTX 4090 24 GB fits the aggregation trio + a 2^24 outer (~11 GB) but **not** any 2^27 circuit (25.8 GB SRS alone) → streamed/chunked SRS mandatory there. Our 3070 8 GB needs streaming at every real size.

**The sobering arithmetic [I]:** total CPU MSM across the three aggregation-request proves on 128 vCPU ≈ 6.8+10.9+1.9 ≈ **20 s** (range 15–28 s) of the measured 1177 s request. Pure prove kernels ≈ **95 s** (range 70–120 s) ≈ 8%. The other ~1080 s is PI `frontend.Compile` at prove time (11.3M constraints, largely serial), witness/assignment (25M emulated-BW6 constraints), multi-GB `LoadSetup` disk reads, and the inline sanity `plonk.Verify` — consistent with the team's own r7iz rationale ("serial recursion… fan-out can't") **[D]** and with DA-full's 287 s kernel vs "~20 min" total **[D/I]**. *Caveat: this 5×/8× scaling model is the weakest link; the §6 instrumentation measures it directly.*

---

## 3. Window-latency scenarios

Measured window (blocks 1–4) **[M]**: 2 × execution (1726+1770 s) + aggregation 1177 s + compression 2×6.6 s = **4686 s ≈ 78.1 min**. (3-exec windows scale proportionally.) The only unknown is the wrap share **w** = outer-Plonk fraction (`outer_proof` perf phase) of each ~29-min execution request. Note the measured run also contained ~6–12 min/exec of on-the-fly segment *compilation* **[D]** that the current `serialization=true` config removes — a free, non-GPU win already banked.

For calibration **[I]**: my model predicts w ≈ 2–4% if the outer is really 2^24, w ≈ 16–25% if it is ~2^27 (the srs-gen comment). w=50% would require the wrap phase to be witness-dominated far beyond the model.

| Scenario | Wrap/exec | Total gnark-Plonk time in window | **Floor** (all gnark-Plonk → 0) | **H100 MSM-only window** (saving = w×1740×0.31×0.65 per exec + ~12 s agg) **[I]** | H100 + Increment-2 NTT offload **[G]** |
|---|---|---|---|---|---|
| w = 10% | 174 s | 2×174+1177 = 1525 s (32.5%) | 3161 s = **52.7 min** | 4686−82 ≈ 4604 s = 76.7 min (**−1.7%**) | ~−4–5% |
| w = 30% | 522 s | 2221 s (47.4%) | 2465 s = **41.1 min** | 4686−222 ≈ 4464 s = 74.4 min (**−4.7%**) | ~−10–13% |
| w = 50% | 870 s | 2917 s (62.3%) | 1769 s = **29.5 min** | 4686−364 ≈ 4322 s = 72.0 min (**−7.8%**) | ~−17–20% |

Arithmetic shown for w=30%: per-exec saving = 0.30×1740 s × 0.31 (MSM share) × 0.65 (H100 removes ~65% of CPU-MSM net, ratio ≈ 2.9×) ≈ 105 s; window = 4686 − 2×105 − 12 ≈ 4464 s.

**Reading:** even the *floor* at w=30% only takes the window from 78 → 41 min, because the koalabear Wizard segments dominate execution. MSM-only GPU realizes 5–12% of the gap to that floor. The full prize requires either Increment 2 (NTT offload), a much larger measured w, or the DA-full flip (+~40 min/window of pure 2^27 gnark Plonk, all GPU-addressable).

---

## 4. Hardware recommendation (latency metric)

Additive configs, r7iz.32xlarge retained as the base in all cases:

| Config | GPU MSM vs 128-core CPU MSM at real sizes | Projected window effect (MSM-only) | Verdict |
|---|---|---|---|
| **r7iz + H100 80 GB** | **Wins ~2–3× everywhere** **[I]**: PI 2^24 3.8→2.5 s vs 6.8 s CPU; emu 2^25 4.6→3 s vs 10.9 s; 2^27 bls 31→20 s vs 54 s; bw6 2^20 1.6 s vs 1.9 s (marginal). All SRS resident (≤34 GB), zero chunking, and offload frees all 128 cores for the overlapped FFT pipeline (extra credit not counted above). | −1.7% to −7.8% per §3; −4–20% with Increment 2 | **The only GPU worth adding.** Buy/rent one only after the §6 measurement justifies it. |
| **r7iz + L40S 48 GB** | **Parity to loss [I]**: PI 14.8 s vs 6.8 s CPU; emu 17.7 s vs 10.9 s; bw6 6.0 s vs 1.9 s. Even with the ~1.5× chunk-fix it roughly ties the CPU. (Matches the public caution: gnark's 20–40× Groth16-on-L40S claims were vs an 8-vCPU baseline **[D]**.) | ≈ 0% | **Not worth it** on a 128-core box. |
| **r7iz alone (no GPU)** | — | baseline | Correct choice if measured w ≲ 10% and DA stays dev. |

Honesty notes: H100 numbers assume bandwidth-linear MSM scaling (±50%); the chunked-cost basis is pessimistic in the opposite direction; net error band ~±2×. Even at the pessimistic edge, H100 ≥ parity; at the optimistic edge ~4×.

*Cost footnote (explicitly secondary): r7iz.32xlarge ≈ $10–11/hr [D]; single-H100 cloud ≈ $2.5–10/hr (non-AWS clouds / p5 fractional), L40S (g6e) ≈ $1.9–3/hr. Adding an H100 raises window cost ~25% for ≤8% latency — fine under the stated "latency only" objective, but it frames how small the prize is.*

---

## 5. Decision recommendation

**Gate everything on one measurement** (§6): the `outer_proof` phase share of an execution request, plus per-layer timestamps inside the aggregation request, from a single batch re-run on the already-running fresh box (`i-0be0edec4c67114df`) **[M-able this week]**.

- **GO on Phase B+C (H100) if** measured `outer_proof` ≥ **~20% of the execution request (≥ ~350 s)** — implying a ~2^26–2^27-scale outer wrap — **or** the aggregation prove kernels measure ≥ ~4× my model (≥ ~400 s of the 1177 s), **or** there is any roadmap intent to flip DA to `full` (then GO unconditionally: +2×~20 min/window of 2^27 BLS12-377 Plonk is the dominant term and H100-addressable). Under GO, sequence: **(1) execution outer (BLS12-377)** — it multiplies by exec count; **(2) emulation (BN254 2^25)**; **(3) PI (BLS12-377 2^24)**; and ship the cheap tuning first (chunk-cap raise, host-side Montgomery, per-MSM streams — `GPU_EXPERIMENT.md` tuning list) plus Increment-2 NTT offload as the real lever (MSM-only Amdahl-caps at the ~31% MSM share).
- **NO-GO (default posture) if** measured w ≲ 10% and DA stays dev: MSM-only H100 buys ≤ ~2% window latency. Park the gnark GPU branch (it is merge-clean and proof-byte-identical; zero carrying cost) and revisit at the next config change.
- **Never worth accelerating:** aggregation-N at bw6-761 2^20 — our best speedup curve (1.5–1.86×) but ~6.6 s CPU / ~2 s MSM absolute, one proof per *two* batches → ~1–2 s/window; compression dummies (6.6 s); the Wizard L0 via this path (zero MSM; a koalabear ICICLE NTT/Poseidon2 project is a different, much larger effort — and Linea itself is solving L0 on CPU with small-fields, 50× claimed **[D]**, which would make the surviving outer Plonk stack *more* GPU-relevant later).
- **Cheaper-than-GPU latency levers spotted in passing [I]:** cache the PI `frontend.Compile` (recomputed every aggregation at prove time); the already-made `serialization=true` switch (removes 6–12 min/exec of in-memory compilation vs the measured run); pipelining the aggregation request against the next window's executions.

---

## 6. Instrumentation recipe (zero prover-code changes)

The pinned prover already contains per-phase JSONL instrumentation (`backend/execution/limitless/perf_log.go`), gated by an env var, writing `./limitless_perf_<UTC-ts>.jsonl` in the container CWD with events `phase_start|phase_end|job_start|job_end`, phases `bootstrapper, GL, LPP, conglomeration, setup, outer_proof`, field `elapsed_s` **[M]**. The aggregation request's per-layer boundaries are existing `logrus.Infof` lines at the default `log_level = 4` **[M]**.

**1. Enable the perf log + keep docker logs** — in `e2e/poc.sh`, inside the generated `docker-compose.override.yml` prover service, add:

```yaml
    environment:
      LIMITLESS_PERF_LOG: "true"     # add alongside GOMAXPROCS/GOMEMLIMIT
    logging:
      driver: json-file
      options: { max-size: "512m", max-file: "4" }
```

**2. Harvest step** — append to `poc.sh` after the `wait_for_proof aggregation` line (and run manually before any box teardown):

```bash
mkdir -p "$ROOT/tmp/perf"
docker logs -t lineth-prover &> "$ROOT/tmp/perf/prover-docker.log"
for f in $(docker exec lineth-prover sh -c \
    'find / -maxdepth 4 -name "limitless_perf_*.jsonl" 2>/dev/null'); do
  docker cp "lineth-prover:$f" "$ROOT/tmp/perf/"
done
# pull off-box immediately (the EC2 box is disposable):
# scp -r ubuntu@<box>:.../lineth/tmp/perf ./tmp/perf-$(date +%F)
```

**3. Execution-request breakdown** (answers the w question directly):

```bash
jq -r 'select(.event=="phase_end")
       | [.ts, .phase, (.elapsed_s|floor)] | @tsv' tmp/perf/limitless_perf_*.jsonl
# wrap share w = outer_proof elapsed_s / sum of all phase elapsed_s
jq -r 'select(.event=="job_end")
       | [.phase, .module, (.elapsed_s|floor)] | @tsv' tmp/perf/limitless_perf_*.jsonl \
  | sort -k3 -rn | head -20   # heaviest GL/LPP/conglo jobs
```

**4. Aggregation-request per-layer split** — `docker logs -t` prefixes RFC3339 timestamps to every line; deltas between these boundary lines are the layer times:

```bash
grep -E 'generating proof \(mode|Creating the witness|Generating the proof|Sanity-checking the proof|reading the BW6 setup|running the BW6 prover|reading the BN254 setup|running the prover for the BN254' \
  tmp/perf/prover-docker.log \
| while read -r ts rest; do printf '%s %s\n' "$(date -d "${ts%%[+Z]*}" +%s)" "$rest"; done \
| awk 'NR>1 {printf "+%4ds  ", $1-p} {p=$1; $1=""; print}'
```

Layer attribution: PI = first `Creating the witness`→`Generating the proof`→`Sanity-checking` triple (PI's `frontend.Compile` is the gap before it); BW6 = `running the BW6 prover` → `reading the BN254 setup`; emulation = `running the prover for the BN254 circuit` → request end. gnark's own `prover done … took=` debug lines, if present in the image's output, give the pure kernel time per curve directly — grep for `prover done` as a bonus.

**5. Request-level cross-check** (matches the previously measured 1726/1770/1177/6.6 s numbers): `grep -E 'took [0-9]+ seconds and returned exit code' tmp/perf/prover-docker.log` — same lines the old `aws-bench` parsed.

One batch through this pipeline yields: w (execution wrap share), the PI-compile/witness/prove/BW6/emulation split of the 1177 s, and the post-Jun-9 circuit sizes (re-read `3.0.0/*/manifest.json` after `aws-restore-assets`) — every open input to §3/§5.