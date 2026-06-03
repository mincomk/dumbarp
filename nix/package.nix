{
  lib,
  pkgs,
  callPackage,
  crane,
  fenix,
  pkg-config,
}:

let
  # aya-build invokes a nested `cargo build -Z build-std=core --target bpfel-unknown-none`
  # to compile the eBPF crate. We could use a nightly toolchain, but bpf-linker in
  # nixpkgs is built against a specific stable LLVM (21 at time of writing) — using a
  # newer nightly produces LLVM IR that bpf-linker cannot read ("Invalid record").
  # So we pin to stable + rust-src and rely on RUSTC_BOOTSTRAP=1 to let stable cargo
  # accept the unstable `-Z build-std` flag.
  rustToolchain = fenix.combine [
    fenix.stable.toolchain
    fenix.stable.rust-src
  ];

  craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

  bpf-linker = callPackage ./bpf-linker.nix { };

  src = craneLib.cleanCargoSource ../.;

  # The nested `cargo build -Z build-std=core` invoked by aya-build resolves
  # rust-src's own sysroot dependencies (proc_macro → rustc-literal-escaper, …).
  # Vendor rust-src's Cargo.lock alongside the workspace's so those crates are
  # available offline inside the Nix sandbox.
  cargoVendorDir = craneLib.vendorMultipleCargoDeps {
    inherit (craneLib.findCargoFiles src) cargoConfigs;
    cargoLockList = [
      ../Cargo.lock
      "${rustToolchain}/lib/rustlib/src/rust/library/Cargo.lock"
    ];
  };

  commonArgs = {
    inherit src cargoVendorDir;
    pname = "dumbarpd";
    version = "0.1.0";
    strictDeps = true;

    nativeBuildInputs = [
      pkg-config
      bpf-linker
    ];

    cargoExtraArgs = "-p dumbarpd --locked";

    # Required so aya-build's nested cargo invocation can use `-Z build-std=core`
    # against stable rustc. (aya-build also reads this flag to decide whether to
    # add `-Z build-std` in the first place.)
    RUSTC_BOOTSTRAP = "1";

    doCheck = false;
  };

  # Skip the eBPF build while caching deps — crane stubs sources, so the eBPF
  # bin would be stubbed too and fail to compile for bpfel-unknown-none.
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      AYA_BUILD_SKIP = "1";
    }
  );
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    meta = {
      description = "XDP-based ARP responder daemon with a REST control API";
      homepage = "https://github.com/mincomk/dumbarp";
      license = with lib.licenses; [
        mit
        asl20
      ];
      mainProgram = "dumbarpd";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    };
  }
)
