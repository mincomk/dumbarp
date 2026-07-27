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

  # `ebpf` gates the bits only the aya-using crates need: bpf-linker on PATH,
  # RUSTC_BOOTSTRAP for the nested `-Z build-std`, and AYA_BUILD_SKIP while
  # caching deps (crane stubs sources, so the eBPF bin would be stubbed too and
  # fail to compile for bpfel-unknown-none).
  mkDumbarpPackage =
    {
      pname,
      description,
      ebpf ? false,
    }:
    let
      commonArgs = {
        inherit src cargoVendorDir pname;
        version = "0.1.0";
        strictDeps = true;

        nativeBuildInputs = [ pkg-config ] ++ lib.optional ebpf bpf-linker;

        cargoExtraArgs = "-p ${pname} --locked";

        doCheck = false;
      }
      // lib.optionalAttrs ebpf {
        RUSTC_BOOTSTRAP = "1";
      };

      cargoArtifacts = craneLib.buildDepsOnly (
        commonArgs // lib.optionalAttrs ebpf { AYA_BUILD_SKIP = "1"; }
      );
    in
    craneLib.buildPackage (
      commonArgs
      // {
        inherit cargoArtifacts;

        meta = {
          inherit description;
          homepage = "https://github.com/mincomk/dumbarp";
          license = with lib.licenses; [
            mit
            asl20
          ];
          mainProgram = pname;
          platforms = [
            "x86_64-linux"
            "aarch64-linux"
          ];
        };
      }
    );
in
{
  dumbarpd = mkDumbarpPackage {
    pname = "dumbarpd";
    description = "XDP-based ARP responder daemon with a REST control API";
    ebpf = true;
  };

  dumbarp-gateway = mkDumbarpPackage {
    pname = "dumbarp-gateway";
    description = "Gateway-side reconciler that installs source-based routes for IPs leased by dumbarp daemons";
  };

  dumbarp-routerd = mkDumbarpPackage {
    pname = "dumbarp-routerd";
    description = "Router-node reconciler: source-based routes plus the DSCP-mode eBPF datapath";
    ebpf = true;
  };
}
