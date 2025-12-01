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
    pkgs.cmake        # aws-lc-sys often requires cmake
    pkgs.pkg-config   # Helps find libraries
    
    # --- CLANG FOR MUSL ---
    # This provides the Clang compiler configured for Musl libc
    pkgs.pkgsMusl.clang
    # This provides llvm-ar and other binutils
    pkgs.pkgsMusl.llvmPackages.bintools 
    
    # Standard tools
    pkgs.kmod
    pkgs.qemu_kvm
    pkgs.grub2
    pkgs.parted
    pkgs.dosfstools
    pkgs.e2fsprogs
    pkgs.util-linux
  ];

  env = { 
    # --- RUST & C INTEROP CONFIGURATION ---
    
    # 1. Tell Cargo to use Clang for the Musl target
    CC_x86_64_unknown_linux_musl = "clang";
    CXX_x86_64_unknown_linux_musl = "clang++";
    
    # 2. Tell Cargo to use LLVM-AR (essential for Clang builds)
    AR_x86_64_unknown_linux_musl = "llvm-ar";
    
    # 3. Tell Cargo to use Clang as the Linker
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "clang";
    
    # 4. Ensure flags are set for static linking
    CFLAGS_x86_64_unknown_linux_musl = "-static -flto=thin";
    CXXFLAGS_x86_64_unknown_linux_musl = "-static -flto=thin";
    
    # 5. Help Bindgen find Clang (used by aws-lc-sys)
    LIBCLANG_PATH = "${pkgs.pkgsMusl.libclang.lib}/lib";
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