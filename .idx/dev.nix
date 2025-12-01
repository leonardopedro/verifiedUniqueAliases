# To learn more about how to use Nix to configure your environment
# see: https://firebase.google.com/docs/studio/customize-workspace
{ pkgs, ... }: {
  # Which nixpkgs channel to use - pinned for reproducibility
  # Using stable-25.05 ensures consistent package versions
  channel = "stable-25.05";

  # Use https://search.nixos.org/packages to find packages
  packages = [
    # Build tools
    pkgs.curl
    pkgs.clang
    pkgs.gnumake
    pkgs.rustup
    
    # Kernel and boot tools
    pkgs.xorriso  # Required for grub-mkrescue
    pkgs.linux
    pkgs.kmod
    
    # Musl toolchain for static linking (Clang)
    pkgs.pkgsMusl.clang
    pkgs.musl
    
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
  env = {
    # Point cc-rs to the musl clang compiler
    CC_x86_64_unknown_linux_musl = "clang";
    CXX_x86_64_unknown_linux_musl = "clang++";
    
    # Configure linker
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "clang";
    
    # Clang specific flags for static musl build
    CFLAGS_x86_64_unknown_linux_musl = "-static";
  };

  idx = {
    # Search for the extensions you want on https://open-vsx.org/ and use "publisher.id"
    extensions = [
      # "vscodevim.vim"
    ];

    # Enable previews
    previews = {
      enable = true;
      previews = {};
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
