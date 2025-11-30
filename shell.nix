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
    
    # Kernel and boot tools
    xorriso  # Required for grub-mkrescue
    linuxPackages.kernel
    kmod
    
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
  ];

  # Environment variables
  shellHook = ''
    echo "🚀 PayPal Auth VM Development Environment"
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
