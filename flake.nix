{
  description = "PayPal Auth VM - Reproducible GCP Image";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/9cb344e96d5b6918e94e1bca2d9f3ea1e9615545";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        pkgsStatic = pkgs.pkgsStatic;

        paypal-auth-vm = pkgsStatic.rustPlatform.buildRustPackage {
          pname = "paypal-auth-vm";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # Ensure static linking
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgsStatic.openssl ];

          # Link-time optimizations and stripping are handled by Cargo.toml profile.release
          # but we can ensure musl here.
          doCheck = false;
        };

        bootEnv = import ./initramfs.nix {
          pkgs = pkgs;
          binaryPath = "${paypal-auth-vm}/bin/paypal-auth-vm";
        };

      in {
        packages = {
          default = paypal-auth-vm;
          inherit paypal-auth-vm;
          initramfs-gcp = bootEnv.initramfs;
          kernel-gcp = bootEnv.kernel;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustup
            gcc
            pkg-config
            qemu_kvm
            xorriso
            pkgsStatic.stdenv.cc
          ];

          shellHook = ''
            export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
            echo "🚀 PayPal Auth VM Development Shell (Flake)"
          '';
        };
      }
    );
}
