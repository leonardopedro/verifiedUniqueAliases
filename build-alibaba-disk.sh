#!/bin/bash
# ==============================================================================
# build-alibaba-disk.sh - Build disk image for Alibaba Cloud ECS
#
# Creates a tarball suitable for OSS upload and custom image import.
# Alibaba Cloud requires disk images in qcow2 or raw format, uploaded to OSS.
#
# Usage: bash build-alibaba-disk.sh /path/to/binary
# ==============================================================================
set -eo pipefail

BUILD_FEATURE="${BUILD_FEATURE:-alibabacloud}"
BINARY="${1:-}"

if [[ -z "$BINARY" ]]; then
    # Default to the latest build output
    BINARY="target/x86_64-unknown-linux-gnu/release/paypal-auth-vm"
fi

if [[ ! -f "$BINARY" ]]; then
    echo "❌ Binary not found: $BINARY"
    echo "   Build first: cargo build --release --features $BUILD_FEATURE"
    exit 1
fi

OUTPUT_DIR="$(pwd)/output-alibaba"
DISK_IMAGE="$OUTPUT_DIR/disk.img"
DISK_TAR="$OUTPUT_DIR/disk-alibaba.tar.gz"

mkdir -p "$OUTPUT_DIR"

echo "🏗️ Building Alibaba Cloud disk image..."
echo "   Binary: $BINARY"
echo "   Size: 1GB (sparse)"

# Create a 1GB sparse disk image with GPT + bootable partition
dd if=/dev/zero of="$DISK_IMAGE" bs=1M count=0 seek=1024 2>/dev/null

echo "📋 Creating GPT partition table..."
sgdisk -n 1:2048:-8192 -t 1:ef00 -c 1:"boot" "$DISK_IMAGE" >/dev/null 2>&1

# Find partition offset (sector 2048 = 1MB)
PART_OFFSET=$((2048 * 512))

# Create ext4 filesystem on the partition
LOOP_DEV=$(losetup --find --show --offset "$PART_OFFSET" "$DISK_IMAGE")
mkfs.ext4 -L boot "$LOOP_DEV" 2>/dev/null

echo "📦 Populating boot partition..."
MOUNT_POINT=$(mktemp -d)
mount "$LOOP_DEV" "$MOUNT_POINT"

# Create directory structure
mkdir -p "$MOUNT_POINT"/
cp "$BINARY" "$MOUNT_POINT/paypal-auth-vm"

# Generate GRUB config for Alibaba Cloud
cat > "$MOUNT_POINT/grub.cfg" << 'GRUBEOF'
set default=0
set timeout=3

insmod efi_gop
insmod efi_uga
insmod ext2
insmod part_gpt

search --no-floppy -l boot --set=root

menuentry "PayPal Auth VM" {
    linux /paypal-auth-vm root=/dev/vda1 console=tty0 console=ttyS0,115200n8
}
GRUBEOF

sync
umount "$MOUNT_POINT"
losetup -d "$LOOP_DEV"
rmdir "$MOUNT_POINT"

# Calculate checksum
DISK_SHA=$(sha256sum "$DISK_IMAGE" | cut -d' ' -f1)

# Package as tarball for easy upload
tar czf "$DISK_TAR" -C "$OUTPUT_DIR" disk.img

echo ""
echo "✅ Alibaba Cloud disk image built!"
echo "   Disk image: $DISK_IMAGE"
echo "   Tarball: $DISK_TAR"
echo "   SHA256: $DISK_SHA"
echo ""
echo "Next steps:"
echo "  1. Upload to OSS: ossutil cp $DISK_IMAGE oss://your-bucket/paypal-auth-vm/"
echo "  2. Import as custom image via Alibaba Cloud ECS console or API"
echo "  3. Use deploy-alibaba.sh with the new IMAGE_ID"
