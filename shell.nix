# Development shell for the PayPal Auth VM project
# Usage: nix-shell

{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "paypal-auth-vm-dev";

  # Development tools and dependencies
  buildInputs = with pkgs; [
    # Build tools
    curl
    gcc
    gnumake
    rustup
    nix # Ensure nix-build is available
    
    # Kernel and boot tools
    xorriso  # Required for grub-mkrescue
    linuxPackages.kernel
    kmod
    
    # Musl toolchain for static linking (GCC)
    pkgsCross.musl64.stdenv.cc
    musl
    
    # Container support (optional)
    podman
    sudo
    
    # Archive tools
    cpio
    gzip
    xz
    
    # QEMU and image creation tools
    qemu_kvm      # Provides qemu-img for image conversion
    grub2         # Bootloader installation
    parted        # Disk partitioning
    dosfstools    # FAT filesystem support
    e2fsprogs     # ext4 filesystem tools (mkfs.ext4)
    util-linux    # Loop device support (losetup, mount, etc.)
    mtools        # MS-DOS tools for mcopy/mformat (rootless)
    OVMF          # UEFI firmware for QEMU testing
    binutils      # For objcopy (UKI creation)
    systemd       # For linuxx64.efi.stub
    dracut        # For initramfs generation
    linuxPackages_latest.kernel # Latest kernel (6.9+)
    rpm           # For extracting OCI kernel packages
    p7zip         # Fallback for RPM extraction
    zstd          # Modern compression support
  ];

  # Environment variables
  shellHook = ''
    # Configure musl compiler for Rust (GCC)
    export CC_x86_64_unknown_linux_musl="x86_64-unknown-linux-musl-gcc"
    export CXX_x86_64_unknown_linux_musl="x86_64-unknown-linux-musl-g++"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="x86_64-unknown-linux-musl-gcc"
    export CFLAGS_x86_64_unknown_linux_musl="-static"

    # Export kernel module path for Dracut
    export KERNEL_DIR="${pkgs.linuxPackages_latest.kernel}/lib/modules"
    export KERNEL_VERSION=$(ls $KERNEL_DIR)
    
    echo "🚀 PayPal Auth VM Development Environment (GCC + Musl)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Available tools:"
    echo "  - Rust toolchain (via rustup)"
    echo "  - QEMU for testing images"
    echo "  - GRUB for bootloader creation"
    echo "  - Nix for reproducible builds"
    echo ""
    echo "To build the QCOW2 image:"
    echo "  ./build-native.sh"
    echo ""
    
    # Install add-determinism if not already installed
    if ! command -v add-det &> /dev/null; then
      echo "📦 Installing add-determinism for reproducible builds..."
      cargo install add-determinism 2>/dev/null || echo "⚠️  add-determinism installation skipped"
    fi
  '';
}
