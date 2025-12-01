{ pkgs, ... }: {
  channel = "stable-24.05"; 

  packages = [
    pkgs.rustup
    pkgs.xorriso
    pkgs.git-lfs
    pkgs.linux
    
    # Build tools
    pkgs.curl
    pkgs.gnumake
    pkgs.rustup
    
    # Kernel and boot tools
    pkgs.xorriso  # Required for grub-mkrescue
    pkgs.linux
    pkgs.kmod
    
    # Musl toolchain for static linking
    # Use pkgsCross to get the x86_64-unknown-linux-musl-gcc binary
    pkgs.pkgsCross.musl64.stdenv.cc
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
    # Point cc-rs to the musl compiler
    CC_x86_64_unknown_linux_musl = "x86_64-unknown-linux-musl-gcc";
    # Also set generic CC for musl target just in case
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "x86_64-unknown-linux-musl-gcc";
  };

  services.docker.enable = true;

  idx = {
    extensions = [ "rust-lang.rust-analyzer" ];
    previews = { enable = true; previews = {}; };
    workspace = {
      onCreate = {
        install-add-determinism = "cargo install add-determinism || echo 'skipped'";
      };
    };
  };
}