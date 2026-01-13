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

        # Tool to ensure binary reproducibility
        add-determinism = pkgs.rustPlatform.buildRustPackage rec {
          pname = "add-determinism";
          version = "0.4.0";
          src = pkgs.fetchCrate {
            inherit pname version;
            sha256 = "sha256-PKzFRAAdgTuGKDOrm+epzXfwNYVSON0eCEeYMg16MNw=";
          };
          cargoHash = "sha256-NfbOInNRmaFnHrbZNGTj0eXivfCNjys+IfJo/DZUrP4=";
        };

        paypal-auth-vm = pkgsStatic.rustPlatform.buildRustPackage {
          pname = "paypal-auth-vm";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # Ensure static linking
          nativeBuildInputs = [ pkgs.pkg-config add-determinism ];
          buildInputs = [ pkgsStatic.openssl ];

          # Link-time optimizations and stripping are handled by Cargo.toml profile.release
          # Post-install normalization for reproducibility
          postInstall = ''
            add-determinism $out/bin/paypal-auth-vm
          '';

          doCheck = false;
        };

        bootEnv = import ./initramfs.nix {
          pkgs = pkgs;
          binaryPath = "${paypal-auth-vm}/bin/paypal-auth-vm";
        };

        # The specific workflow requested by the user: decompress, apply add-det, recompress
        initramfs-normalized = pkgs.stdenv.mkDerivation {
          name = "initramfs-normalized";
          nativeBuildInputs = [ pkgs.gzip add-determinism ];
          src = bootEnv.initramfs;
          dontUnpack = true;
          buildPhase = ''
            mkdir -p $out
            echo "🔧 Normalizing initramfs with add-determinism..."
            
            # Decompress
            gzip -d -c $src/initrd > initrd.cpio
            
            # Apply add-determinism to the raw CPIO
            add-determinism initrd.cpio
            
            # Recompress with fixed timestamp and max compression
            gzip -n -9 < initrd.cpio > $out/initrd
            
            # Force the timestamp to match legacy SOURCE_DATE_EPOCH (2022-01-01)
            touch -d "@1640995200" $out/initrd
            
            # Also create a .gz symlink for compatibility
            ln -s initrd $out/initrd.gz
          '';
          installPhase = "true";
        };

      in {
        packages = {
          default = initramfs-normalized;
          inherit paypal-auth-vm initramfs-normalized add-determinism;
          initramfs-raw = bootEnv.initramfs;
          initramfs-gcp = initramfs-normalized;
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
