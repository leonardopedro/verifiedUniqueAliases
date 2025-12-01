{ pkgs, ... }: {
  channel = "stable-24.05"; 

  packages = [
    pkgs.rustup
    pkgs.pkgsStatic.xorriso
    pkgs.pkgsStatic.git-lfs
    pkgs.linux
    pkgs.pkgsStatic.busybox
    
    
    # Build tools
    pkgs.pkgsStatic.curl
    pkgs.pkgsStatic.gnumake
    
    # Kernel and boot tools
    # pkgs.xorriso is already added above
    # pkgs.linux is already added above
    pkgs.pkgsStatic.kmod
    
    # Musl toolchain for static linking
    # Use pkgsStatic to get the static gcc binary
    pkgs.pkgsStatic.stdenv.cc
    # pkgs.musl # pkgsStatic implies musl on linux usually, or we can add it if needed explicitly, but stdenv.cc should cover the compiler.
    
    # Archive tools
    pkgs.pkgsStatic.cpio
    pkgs.pkgsStatic.gzip
    pkgs.pkgsStatic.xz
    
    # QEMU and image creation tools
    pkgs.qemu_kvm      # Keep dynamic for host performance/compatibility
    pkgs.grub2         # Keep dynamic, grub build is complex
    pkgs.pkgsStatic.parted        # Disk partitioning
    pkgs.pkgsStatic.dosfstools    # FAT filesystem support
    pkgs.pkgsStatic.e2fsprogs     # ext4 filesystem tools (mkfs.ext4)
    pkgs.pkgsStatic.util-linux    # Loop device support (losetup, mount, etc.)
  ];

  # Sets environment variables in the workspace
  env = {
    # Point cc-rs to the musl compiler
    # pkgsStatic.stdenv.cc provides the compiler wrapper. 
    # For x86_64-linux, pkgsStatic uses musl.
    # The binary name might be just 'gcc' or 'x86_64-unknown-linux-musl-gcc' depending on how it's wrapped.
    # We'll assume standard cross names or just 'gcc' if it's the primary compiler in that env, 
    # but since we are adding it to a normal env, it might be prefixed.
    # Actually, pkgsStatic.stdenv.cc usually provides the cross-compiler.
    CC_x86_64_unknown_linux_musl = "x86_64-unknown-linux-musl-gcc";
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