#git lfs install && rustup default stable
{ pkgs, ... }: {
  channel = "stable-25.05"; 

  packages = [
    pkgs.rustup
    pkgs.gcc
    #pkgs.pkgsStatic.musl
    pkgs.xorriso
    pkgs.git-lfs
    pkgs.linux
    pkgs.pkgsStatic.busybox
    
    
    # Build tools
    pkgs.curl
    pkgs.gnumake
    
    # Kernel and boot tools
    # pkgs.xorriso is already added above
    # pkgs.linux is already added above
    pkgs.pkgsStatic.kmod
    
    # Musl toolchain for static linking
    # Use pkgsStatic to get the static gcc binary
    pkgs.pkgsStatic.stdenv.cc
    # pkgs.musl # pkgsStatic implies musl on linux usually, or we can add it if needed explicitly, but stdenv.cc should cover the compiler.
    
    # Archive tools
    pkgs.cpio
    pkgs.gzip
    pkgs.xz
    pkgs.glibc.bin
    
    # QEMU and image creation tools
    pkgs.qemu_kvm      # Keep dynamic for host performance/compatibility
    pkgs.grub2         # Keep dynamic, grub build is complex
    pkgs.parted        # Disk partitioning
    pkgs.dosfstools    # FAT filesystem support
    pkgs.e2fsprogs     # ext4 filesystem tools (mkfs.ext4)
    pkgs.util-linux    # Loop device support (losetup, mount, etc.)
    pkgs.binutilsNoLibc
    pkgs.cmake
    pkgs.clang
    pkgs.musl
    pkgs.pkg-config
    pkgs.llvmPackages.libclang 
    pkgs.grub2_efi
    pkgs.mtools
    pkgs.dosfstools
  ];

  env = {
    # Helps 'bindgen' (used by aws-lc-sys) find libclang
    LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

    # Point cc-rs to the musl compiler
    # pkgsStatic.stdenv.cc provides the compiler wrapper. 
    # For x86_64-linux, pkgsStatic uses musl.
    # The binary name might be just 'gcc' or 'x86_64-unknown-linux-musl-gcc' depending on how it's wrapped.
    # We'll assume standard cross names or just 'gcc' if it's the primary compiler in that env, 
    # but since we are adding it to a normal env, it might be prefixed.
    # Actually, pkgsStatic.stdenv.cc usually provides the cross-compiler.
    # Helps 'bindgen' (used by aws-lc-sys) find libclang
#    CC_x86_64_unknown_linux_musl = "musl-gcc";
    CXX_x86_64_unknown_linux_musl = "x86_64-unknown-linux-musl-g++";
    
    # Linker configuration
 #   CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "musl-gcc";
    
    # Optional: Archive tool
    AR_x86_64_unknown_linux_musl = "ar";
    CC_x86_64_unknown_linux_musl = "x86_64-unknown-linux-musl-gcc";
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "x86_64-unknown-linux-musl-gcc";
  };

  idx = {
    extensions = [ "rust-lang.rust-analyzer" ];
    previews = { enable = true; previews = {}; };
    workspace = {
      onCreate = {
        install-add-determinism = "git lfs install && rustup default stable && cargo install add-determinism || echo 'skipped'";
      };
    };
  };
}

