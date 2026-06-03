{
  description = "dumbarp — XDP-based ARP responder daemon (dumbarpd)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    crane.url = "github:ipetkov/crane";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
      fenix,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem = flake-utils.lib.eachSystem supportedSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          fenixPkgs = fenix.packages.${system};

          dumbarpd = pkgs.callPackage ./nix/package.nix {
            inherit crane;
            fenix = fenixPkgs;
          };
        in
        {
          packages = {
            inherit dumbarpd;
            default = dumbarpd;
          };

          devShells.default =
            let
              devToolchain = fenixPkgs.combine [
                fenixPkgs.stable.toolchain
                fenixPkgs.stable.rust-src
              ];
            in
            pkgs.mkShell {
              inputsFrom = [ dumbarpd ];
              packages = [
                devToolchain
                pkgs.bpf-linker
                pkgs.cargo-deb
                pkgs.pkg-config
                fenixPkgs.rust-analyzer
              ];

              RUST_SRC_PATH = "${fenixPkgs.stable.rust-src}/lib/rustlib/src/rust/library";
              RUSTC_BOOTSTRAP = "1";
            };

          checks = {
            inherit dumbarpd;
          };

          formatter = pkgs.nixfmt-rfc-style;
        }
      );
    in
    perSystem
    // {
      nixosModules.dumbarpd = import ./nix/module.nix;
      nixosModules.default = self.nixosModules.dumbarpd;

      overlays.default = _final: prev: {
        dumbarpd = self.packages.${prev.stdenv.hostPlatform.system}.dumbarpd;
      };
    };
}
