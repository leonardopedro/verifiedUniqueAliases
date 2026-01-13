{ pkgs, ... }: 
let
  # Pin to the exact same commit as local/flake for 100% reproducibility
  pinnedPkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/9cb344e96d5b6918e94e1bca2d9f3ea1e9615545.tar.gz") { 
    config.allowUnfree = true;
  };
in {
  channel = "stable-25.05"; 

  # These packages are available in the IDX environment
  packages = [
    pinnedPkgs.rustup
    pinnedPkgs.gcc
    pinnedPkgs.git
    pinnedPkgs.git-lfs
    pinnedPkgs.nix        # Ensure nix-build/nix-flakes is available
    pinnedPkgs.qemu_kvm   # To test images locally
    pinnedPkgs.diffoscope # For reproducibility analysis
    pinnedPkgs.pkg-config
    pinnedPkgs.llvmPackages.libclang
  ];

  env = {
    # Helps 'bindgen' and other tools find libclang
    LIBCLANG_PATH = "${pinnedPkgs.llvmPackages.libclang.lib}/lib";
  };

  idx = {
    extensions = [ "rust-lang.rust-analyzer" ];
    previews = { enable = true; previews = {}; };
    workspace = {
      # Runs when a workspace is first created
      onCreate = {
        install-add-determinism = "git lfs install && rustup default stable && cargo install add-determinism || echo 'skipped'";
        setup-podman = "./fix-podman-idx.sh";
      };
      # Runs when a workspace is started
      onStart = {
        # Optional: ensure everything is buildable
        # build = "./rebuild.sh";
      };
    };
  };
}

