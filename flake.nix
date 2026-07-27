{
  description = "dumbarp — XDP ARP responder (dumbarpd), route reconcilers (dumbarp-gateway, dumbarp-routerd)";

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

      packageNames = [
        "dumbarpd"
        "dumbarp-gateway"
        "dumbarp-routerd"
      ];

      perSystem = flake-utils.lib.eachSystem supportedSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          fenixPkgs = fenix.packages.${system};

          # callPackage adds `override`/`overrideDerivation` to the returned set;
          # keep only the real derivations so `packages` and `checks` stay clean.
          built = pkgs.callPackage ./nix/package.nix {
            inherit crane;
            fenix = fenixPkgs;
          };
          dumbarpPackages = lib.genAttrs packageNames (name: built.${name});
        in
        {
          packages = dumbarpPackages // {
            default = dumbarpPackages.dumbarpd;
          };

          devShells.default =
            let
              devToolchain = fenixPkgs.combine [
                fenixPkgs.stable.toolchain
                fenixPkgs.stable.rust-src
              ];
            in
            pkgs.mkShell {
              inputsFrom = lib.attrValues dumbarpPackages;
              packages = [
                devToolchain
                pkgs.bpf-linker
                pkgs.bpftool
                pkgs.cargo-deb
                pkgs.pkg-config
                fenixPkgs.rust-analyzer
              ];

              RUST_SRC_PATH = "${fenixPkgs.stable.rust-src}/lib/rustlib/src/rust/library";
              RUSTC_BOOTSTRAP = "1";
            };

          checks = dumbarpPackages;

          formatter = pkgs.nixfmt-rfc-style;
        }
      );

      lib = nixpkgs.lib;
    in
    perSystem
    // {
      nixosModules = {
        dumbarpd = import ./nix/module.nix;
        dumbarp-gateway = import ./nix/gateway-module.nix;
        dumbarp-routerd = import ./nix/routerd-module.nix;

        default = {
          imports = [
            self.nixosModules.dumbarpd
            self.nixosModules.dumbarp-gateway
            self.nixosModules.dumbarp-routerd
          ];
        };
      };

      overlays.default =
        _final: prev:
        lib.genAttrs packageNames (name: self.packages.${prev.stdenv.hostPlatform.system}.${name});
    };
}
