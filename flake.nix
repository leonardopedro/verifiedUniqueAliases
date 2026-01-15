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
          
          # Add add-det symlink for compatibility with legacy scripts
          postInstall = ''
            ln -s add-determinism $out/bin/add-det
          '';
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
          # Post-install normalization for reproducibility (matches build-native.sh:84-86)
          postInstall = ''
            add-determinism $out/bin/paypal-auth-vm
            touch -d "@1640995200" $out/bin/paypal-auth-vm
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
            echo "🔧 Normalizing initramfs with add-determinism (based on build-native.sh)..."
            
            # Step 1: Decompress
            gzip -d -c $src/initrd > initrd.uncompressed
            
            # Step 2: Apply add-determinism to uncompressed initramfs (matches build-native.sh:138)
            add-determinism initrd.uncompressed
            
            # Step 3: Recompress with deterministic gzip (matches build-native.sh:142)
            gzip -n -9 < initrd.uncompressed > initrd.tmp
            
            # Step 4: Apply add-determinism to COMPRESSED initramfs (matches build-native.sh:146)
            add-determinism initrd.tmp
            
            # Final move and timestamp normalization
            mv initrd.tmp $out/initrd
            touch -d "@1640995200" $out/initrd
            
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
