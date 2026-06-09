#!/bin/bash
# ==============================================================================
# build-alibaba-simple.sh - Create simple ext4 filesystem for Alibaba Cloud
#
# This creates a plain ext4 image for OPTIONAL persistent data storage.
# The actual boot system uses ONLY the initramfs (which contains the binary).
#
# Usage: bash build-alibaba-simple.sh /path/to/binary
# ==============================================================================
set -eo pipefail

BINARY="${1:-paypal-auth-vm}"

if [[ ! -f "$BINARY" ]]; then
    echo "❌ Binary not found: $BINARY"
    exit 1
fi

OUTPUT_DIR="$(pwd)/output-alibaba-simple"
FS_IMAGE="$OUTPUT_DIR/alibaba-fs.img"

mkdir -p "$OUTPUT_DIR"

echo "🏗️ Building optional ext4 filesystem for Alibaba Cloud..."
echo "   Note: The binary is already in initramfs-alibaba.img (20M)"
echo "   This image is only for persistent data storage if needed."
echo "   Binary: $BINARY"
echo "   Image size: 32MB"

# Create staging directory
STAGING=$(mktemp -d)
cp "$BINARY" "$STAGING/paypal-auth-vm"

# Create grub.cfg
cat > "$STAGING/grub.cfg" << 'GRUBEOF'
set default=0
set timeout=3

insmod efi_gop
insmod efi_uga
insmod ext2

search --no-floppy -l boot --set=root

menuentry "PayPal Auth VM" {
    linux /paypal-auth-vm root=/dev/vda1 console=tty0 console=ttyS0,115200n8
}
GRUBEOF

# Create 32MB ext4 filesystem image (sufficient for 6MB binary + grub.cfg)
echo "   Creating ext4 image (this may take a moment)..."
mke2fs -t ext4 -L boot -d "$STAGING" "$FS_IMAGE" 32M 2>/dev/null

# Cleanup staging directory
rm -rf "$STAGING"

# Cleanup
rm -rf "$STAGING"

# Calculate checksum
FS_SHA=$(sha256sum "$FS_IMAGE" | cut -d' ' -f1)

echo ""
echo "✅ Simple ext4 filesystem built!"
echo "   Image: $FS_IMAGE"
echo "   SHA256: $FS_SHA"
echo ""
echo "Next steps:"
echo "  1. Upload to OSS: ossutil cp $FS_IMAGE oss://your-bucket/paypal-auth-vm/"
echo "  2. Import as custom image via ECS console or API"
echo "  3. Use deploy-alibaba.sh with the new IMAGE_ID"
