# To learn more about how to use Nix to configure your environment
# see: https://firebase.google.com/docs/studio/customize-workspace
{ pkgs, ... }: {
  # Which nixpkgs channel to use.
  # Channel: stable-24.05 (nixos-24.05.7376.b134951a4c9f as of 2024-12-31)
  # This provides reproducible builds with security updates
  channel = "stable-24.05"; # or "unstable"

  # Use https://search.nixos.org/packages to find packages
  packages = [
    # pkgs.go
    #pkgs.python311
    #pkgs.python311Packages.pip
    # pkgs.nodejs_20
    # pkgs.nodePackages.nodemon
    
    # Build tools
    pkgs.curl
    pkgs.gcc
    pkgs.gnumake
    pkgs.rustup
    
    # Dracut and kernel
    # pkgs.dracut # Removed as we use native Nix build
    pkgs.xorriso  # Required for grub-mkrescue
    pkgs.linux
    pkgs.kmod
    
    # Musl for static binaries
    pkgs.musl
    pkgs.musl.dev
    pkgs.pkgsMusl.stdenv.cc
    
    # Container support (optional, can be removed if not using Docker/Podman)
    pkgs.podman
    pkgs.sudo
    
    # Archive tools
    pkgs.cpio
    pkgs.gzip
    pkgs.xz
    
    # QEMU and image creation tools
    pkgs.qemu_kvm      # Provides qemu-img for image conversion
    pkgs.grub2         # Bootloader installation
    pkgs.parted        # Disk partitioning
    pkgs.dosfstools    # FAT filesystem support
    pkgs.e2fsprogs     # ext4 filesystem tools (mkfs.ext4)
    pkgs.util-linux    # Loop device support (losetup, mount, etc.)
  ];

  # Sets environment variables in the workspace
  env = { # Tell Cargo to use 'musl-gcc' for the musl target instead of guessing
    CC_x86_64_unknown_linux_musl = "musl-gcc";
    CXX_x86_64_unknown_linux_musl = "musl-g++";
    
    # Linker configuration
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "musl-gcc";
    
    # Optional: Archive tool
    AR_x86_64_unknown_linux_musl = "ar";
    };

  services.docker.enable = true;

  idx = {
    # Search for the extensions you want on https://open-vsx.org/ and use "publisher.id"
    extensions = [
      # "vscodevim.vim"
    ];

    # Enable previews
    previews = {
      enable = true;
      previews = {
        # web = {
        #   # Example: run "npm run dev" with PORT set to IDX's defined port for previews,
        #   # and show it in IDX's web preview panel
        #   command = ["npm" "run" "dev"];
        #   manager = "web";
        #   env = {
        #     # Environment variables to set for your server
        #     PORT = "$PORT";
        #   };
        # };
      };
    };

    # Workspace lifecycle hooks
    workspace = {
      # Runs when a workspace is first created
      onCreate = {
        # Install add-determinism for reproducible builds
        # This tool normalizes binaries and archives to remove non-deterministic metadata
        install-add-determinism = "cargo install add-determinism || echo 'add-determinism installation skipped'";
      };
      # Runs when the workspace is (re)started
      onStart = {
        # Example: start a background task to watch and re-build backend code
        # watch-backend = "npm run watch-backend";
      };
    };
  };
}
