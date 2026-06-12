# GPU Plonk experiment task runner (see GPU_EXPERIMENT.md).
#
# Works from the host (wraps every command in `nix develop --command`) or from
# inside `nix develop` (runs directly — detected via ICICLE_BACKEND_INSTALL_DIR,
# which the dev shell exports).
#
# GPU notes: `-p 1` serializes test binaries on the single GPU; `-count=1`
# disables result caching so the GPU actually runs.

nix := if env_var_or_default("ICICLE_BACKEND_INSTALL_DIR", "") == "" { "nix develop --command" } else { "" }
gotest := nix + " go test -tags=icicle -count=1 -p 1"
plonk := "./backend/accelerated/icicle/plonk/"

# list available recipes
default:
    @just --list

# full GPU suite: Groth16 + Plonk, all 4 curves (~2 min)
test:
    {{gotest}} -timeout 30m ./backend/accelerated/icicle/...

# all Plonk GPU packages (dispatch + 4 curves)
test-plonk:
    {{gotest}} -timeout 30m {{plonk}}...

# one curve's Plonk GPU package (bn254 | bls12-377 | bls12-381 | bw6-761)
test-curve curve='bn254':
    {{gotest}} -timeout 15m {{plonk}}{{curve}}/

# end-to-end gate: GPU prove -> unmodified CPU verifier, all 4 curves
test-e2e:
    {{gotest}} -timeout 30m -run 'TestMarshal' -v {{plonk}}

# strongest oracle: seeded GPU vs forced-CPU proofs must be byte-identical
test-oracle curve='bn254':
    {{gotest}} -timeout 15m -run 'TestProveGPUvsForcedCPU|TestProveDeterministic' -v {{plonk}}{{curve}}/

# race detector over the Plonk GPU packages (slow: ~10 min for bw6-761 alone)
test-race:
    {{nix}} go test -tags=icicle -race -count=1 -p 1 -timeout 40m {{plonk}}...

# upstream CPU regression: Plonk backends, no GPU, no build tag
test-cpu:
    {{nix}} go test -short -count=1 ./backend/plonk/...

# full untagged regression over the whole repo (what CI runs; ~10+ min)
test-cpu-all:
    {{nix}} go test -short -count=1 ./...

# compile + vet both with and without the icicle tag
check:
    {{nix}} go build ./...
    {{nix}} go build -tags=icicle ./...
    {{nix}} go vet -tags=icicle ./backend/accelerated/icicle/...

# CPU-vs-GPU prove benchmark at one curve/size (sizes: 16|18|20|22; bw6-761 max 21)
bench curve='bn254' size='16':
    {{nix}} go test -tags=icicle -run NONE -p 1 -timeout 0 \
        -bench 'PlonkProve(CPU|GPU)/{{replace(curve, "-", "_")}}/2\^{{size}}$' \
        -benchtime=3x {{plonk}}

# full benchmark matrix (~1.5-3 h; commands + estimates in bench_test.go header)
bench-matrix:
    @echo "Runs ~1.5-3h under exclusive GPU access. See the header of"
    @echo "backend/accelerated/icicle/plonk/bench_test.go for the per-curve"
    @echo "commands, or run them via: just bench <curve> <size>"
    @echo "Measured results from 2026-06-11 are in bench-results/."
