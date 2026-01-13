#!/bin/bash
set -e

# Source Nix profile if needed
[ -e /etc/profile.d/nix.sh ] && . /etc/profile.d/nix.sh

echo "🔨 Building artifacts via Nix Flake..."
# Build both initramfs and kernel
nix build .#initramfs-gcp .#kernel-gcp --no-link

# Get the paths
INITRD_PATH=$(nix build .#initramfs-gcp --no-link --print-out-paths)/initrd
KERNEL_DIR=$(nix build .#kernel-gcp --no-link --print-out-paths)
KERNEL_PATH=$(find $KERNEL_DIR -name vmlinuz -o -name bzImage | head -n 1)

if [ -z "$KERNEL_PATH" ]; then
    echo "❌ Could not find kernel binary in $KERNEL_DIR"
    exit 1
fi

echo "🚀 Launching QEMU..."
echo "Kernel: $KERNEL_PATH"
echo "Initrd: $INITRD_PATH"

# Run QEMU
# -m 1G: Give enough RAM
# -kernel / -initrd: Boot our custom artifacts
# -append: Kernel command line for console and silent boot
# -nographic: Use the terminal for serial output
# -netdev user: Simple networking
qemu-system-x86_64 \
    -m 1G \
    -kernel "$KERNEL_PATH" \
    -initrd "$INITRD_PATH" \
    -append "console=ttyS0 quiet panic=1" \
    -nographic \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -serial mon:stdio \
    -no-reboot
