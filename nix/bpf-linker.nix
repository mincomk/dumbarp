# Custom bpf-linker built against LLVM 22 to match the LLVM version bundled
# with fenix's current stable rustc. The version of bpf-linker shipped in
# nixpkgs at the time of writing (0.9.15) does not support the `llvm-22`
# feature flag, so building eBPF with rustc 1.95+ via that package produces
# "ERROR llvm: Invalid record" at link time.
{
  lib,
  rustPlatform,
  fetchFromGitHub,
  symlinkJoin,
  llvmPackages_22,
  zlib,
  libxml2,
}:

let
  # bpf-linker 0.10.x's build.rs assumes a monolithic LLVM install: it locates
  # `llvm-config` on PATH (or under LLVM_PREFIX) and then expects libLLVM to
  # live at `<that-prefix>/lib`. nixpkgs splits these across `dev` (headers,
  # `bin/llvm-config`) and `lib` (`libLLVM-22.so`) outputs, so we fuse them
  # into one tree the build script can understand.
  llvm = symlinkJoin {
    name = "llvm-${llvmPackages_22.llvm.version}-joined";
    paths = [
      llvmPackages_22.llvm.dev
      llvmPackages_22.llvm.lib
    ];
  };
in

rustPlatform.buildRustPackage rec {
  pname = "bpf-linker";
  version = "0.10.3";

  src = fetchFromGitHub {
    owner = "aya-rs";
    repo = "bpf-linker";
    tag = "v${version}";
    hash = "sha256-QqJtiKQgU1rgiQOTw5kn0LhxiGrGz65y9wzMMpqEBz8=";
  };

  cargoHash = "sha256-zA3R34QS3wAALEIo7k37BjDgyfzqg0n12Z0rZ/GTIIk=";

  buildNoDefaultFeatures = true;
  buildFeatures = [ "llvm-${lib.versions.major llvmPackages_22.llvm.version}" ];

  nativeBuildInputs = [ llvm ];

  buildInputs = [
    zlib
    libxml2
  ];

  # Point bpf-linker's build.rs at the merged LLVM prefix so it can find both
  # llvm-config and libLLVM.
  env.LLVM_PREFIX = "${llvm}";

  doCheck = false;

  meta = {
    description = "BPF static linker built against LLVM ${lib.versions.major llvmPackages_22.llvm.version}";
    homepage = "https://github.com/aya-rs/bpf-linker";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "bpf-linker";
    platforms = lib.platforms.linux;
  };
}
