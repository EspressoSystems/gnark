{
  # Dev environment for the GPU Plonk experiment (see GPU_EXPERIMENT.md).
  # Provides Go and the ICICLE GPU libraries (built from the icicle-gnark fork)
  # so that `go test -tags=icicle` works inside `nix develop`.
  #
  # The CUDA backend is compiled with toolkit 12.6 for sm_86; it runs on the
  # host's 12.2 driver via CUDA minor-version compatibility. libcuda.so.1
  # comes from the host driver, hence the LD_LIBRARY_PATH entry below.
  description = "gnark dev shell with ICICLE GPU backend";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        config = {
          allowUnfree = true;
          cudaSupport = true;
        };
      };
      cudaPackages = pkgs.cudaPackages_12_6;

      icicle-gnark = cudaPackages.backendStdenv.mkDerivation {
        pname = "icicle-gnark";
        version = "3.2.2";

        src = pkgs.fetchFromGitHub {
          owner = "ingonyama-zk";
          repo = "icicle-gnark";
          rev = "v3.2.2";
          hash = "sha256-kbXwg1cF72flzpl1+20D+smYKgl7Aslbf1KSCi6ur34=";
        };

        sourceRoot = "source/icicle";

        nativeBuildInputs = [
          pkgs.cmake
          pkgs.patchelf
          cudaPackages.cuda_nvcc
        ];

        buildInputs = [
          cudaPackages.cuda_cudart
        ];

        # One cmake configure per curve, mirroring wrappers/golang/build.sh.
        # CUDA_ARCH=86 (RTX 3070): the build sandbox has no GPU, so the
        # nvidia-smi autodetection in cmake/Common.cmake would fail.
        dontUseCmakeConfigure = true;
        enableParallelBuilding = true;

        buildPhase = ''
          runHook preBuild
          for curve in bn254 bls12_377 bls12_381 bw6_761; do
            echo "=== building ICICLE for $curve ==="
            cmake -S . -B "build-$curve" \
              -DCURVE="$curve" \
              -DMSM=ON -DNTT=ON -DG2=ON \
              -DCUDA_ARCH=86 \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX="$out"
            cmake --build "build-$curve" -j"$NIX_BUILD_CORES" --target install
          done
          runHook postBuild
        '';

        # install happens per-curve in buildPhase (cmake --target install)
        installPhase = "true";

        # The per-curve CUDA backend libs depend on sibling libs in the same
        # directory (e.g. libicicle_backend_cuda_curve_X.so needs
        # libicicle_backend_cuda_field_X.so) but are dlopen'd by
        # libicicle_device without that directory on any search path. Without
        # $ORIGIN the dlopen fails silently and GPU ops never register
        # ("operation not supported on device CUDA").
        postFixup = ''
          find "$out/lib/backend" -name '*.so' -exec patchelf --add-rpath '$ORIGIN' {} \;
        '';
      };
    in
    {
      packages.${system} = {
        inherit icicle-gnark;
        default = icicle-gnark;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.go
          icicle-gnark
        ];

        # Matches backend/accelerated/icicle/doc.go, with /usr/local/lib
        # replaced by the nix store path.
        CGO_LDFLAGS = "-L${icicle-gnark}/lib -licicle_device -lstdc++ -lm -Wl,-rpath=${icicle-gnark}/lib";
        ICICLE_BACKEND_INSTALL_DIR = "${icicle-gnark}/lib/backend";

        shellHook = ''
          # Expose only the host NVIDIA driver libs (libcuda & friends) — putting
          # all of /usr/lib/x86_64-linux-gnu on LD_LIBRARY_PATH would shadow the
          # nix glibc and break every nix-built binary.
          driver_dir="$HOME/.cache/gnark-icicle-driver"
          mkdir -p "$driver_dir"
          for lib in libcuda.so.1 libnvidia-ptxjitcompiler.so.1 libnvidia-ml.so.1; do
            [ -e "/usr/lib/x86_64-linux-gnu/$lib" ] && ln -sf "/usr/lib/x86_64-linux-gnu/$lib" "$driver_dir/"
          done
          export LD_LIBRARY_PATH="${icicle-gnark}/lib:$driver_dir''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        '';
      };
    };
}
