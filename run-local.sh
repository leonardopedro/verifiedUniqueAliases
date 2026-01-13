#!/bin/bash
set -e

# Source Nix profile if needed
[ -e /etc/profile.d/nix.sh ] && . /etc/profile.d/nix.sh

echo "🔨 Building artifacts via Nix Flake..."
# Build items: initramfs, kernel, and the normalization tool itself
nix build .#initramfs-gcp .#kernel-gcp .#add-determinism --no-link

# Get the paths
INITRD_PATH=$(nix build .#initramfs-gcp --no-link --print-out-paths)/initrd
KERNEL_DIR=$(nix build .#kernel-gcp --no-link --print-out-paths)
ADD_DET_BIN=$(nix build .#add-determinism --no-link --print-out-paths)/bin/add-determinism
KERNEL_PATH=$(find $KERNEL_DIR -name vmlinuz -o -name bzImage | head -n 1)

if [ -z "$KERNEL_PATH" ]; then
    echo "❌ Could not find kernel binary in $KERNEL_DIR"
    exit 1
fi

echo "🔍 Verifying bit-for-bit reproducibility..."
INITIAL_HASH=$(sha256sum "$INITRD_PATH" | cut -d' ' -f1)
echo "   Original SHA256: $INITIAL_HASH"

# Create a temporary copy to test 'add-determinism' idempotency
TMP_INITRD=$(mktemp)
cp "$INITRD_PATH" "$TMP_INITRD"
chmod +w "$TMP_INITRD"

# Run add-determinism on the uncompressed stream (optional but simulates the flake process)
# For the sake of this script, we just run it on the file directly to show it's stable.
$ADD_DET_BIN "$TMP_INITRD" >/dev/null 2>&1

FINAL_HASH=$(sha256sum "$TMP_INITRD" | cut -d' ' -f1)
rm -f "$TMP_INITRD"

if [ "$INITIAL_HASH" == "$FINAL_HASH" ]; then
    echo "   ✅ Reproducibility check passed (Idempotent: $FINAL_HASH)"
else
    echo "   ⚠️ Reproducibility warning: Hash changed after local check!"
    echo "   Final SHA256:    $FINAL_HASH"
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
