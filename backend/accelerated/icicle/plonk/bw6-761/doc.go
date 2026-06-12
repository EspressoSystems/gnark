// Package bw6761 implements ICICLE acceleration for the BW6-761 PLONK backend.
//
// v1 offloads exactly the large G1 MSMs of the prover to the GPU against a
// device-resident dual SRS (canonical + Lagrange). All FFTs, the constraint
// closure, blinding, and the Fiat-Shamir transcript remain byte-identical
// cloned CPU code. This package never calls InitDomain — it owns zero ICICLE
// NTT-domain state.
//
// # Coexistence and concurrency contract
//
//  1. This package never touches the ICICLE NTT domain, so there is no
//     same-curve domain hazard with the groth16 ICICLE backend, full stop.
//  2. Concurrent groth16 and plonk proving on one device is UNSUPPORTED: the
//     two packages hold independent per-device mutexes and both adaptive MSM
//     tuners read free VRAM non-atomically. Sequential mixed use in one
//     process (groth16 -> plonk -> groth16) is supported.
//  3. Plonk-only concurrent Proves on one device are safe — including on one
//     shared *ProvingKey: the device-resident SRS is reference-counted (one
//     reference per in-flight Prove; freed by the last release unless the key
//     is pinned, see provingkey.go) and individual GPU operations are
//     serialized by the per-device mutex — subject to available VRAM for
//     pinned SRS sets.
//  4. INVARIANT — no GPU work outside the errgroup tasks of Prove: every GPU
//     operation of a Prove call runs inside (or synchronously before) the
//     errgroup tasks that Prove waits on. computeNumerator's detached restore
//     goroutine is CPU-only. The release of the device SRS at Prove exit
//     (which may free it) depends on this invariant; any future NTT offload
//     that touches the device from a detached goroutine must join it before
//     Prove returns.
//
// The per-device mutex is held around each individual GPU operation (SRS
// upload, every MSM). This per-call granularity is correct ONLY BECAUSE this
// package owns no NTT-domain state. If device NTTs are ever added
// (Increment 2), the locking design must be revisited wholesale (whole-Prove
// mutex acquired before setupDevicePointers and before spr.Solve, plus a
// true-root-order domain tracker) — never patched incrementally.
//
// There is no CI coverage for this package: tests require a CUDA-capable GPU
// and are gated behind the 'icicle' build tag. Run them sequentially
// (go test -tags=icicle -p 1) — concurrent test packages sharing one GPU
// flake.
package bw6761
