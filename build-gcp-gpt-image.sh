#!/bin/bash
# ==============================================================================
# build-gcp-gpt-image.sh - Reproducible GPT Disk Image for GCP Confidential VM
# Strategy: build ESP → extract contents → normalize → rebuild ESP → pack disk
# ==============================================================================
set -e

export SOURCE_DATE_EPOCH=1712260800
export TZ=UTC
export LC_ALL=C.UTF-8

IMAGE_NAME="paypal-auth-vm-gcp.qcow2"
RAW_IMAGE="disk.raw"
TAR_IMAGE="disk.tar.gz"
ESP_IMAGE="esp.img"
ESP_MOUNT="$(pwd)/esp_mount"

echo "💿 Assembling GCP-Optimized Reproducible Image Stack..."

# Artifacts from output/
KERNEL="./output/vmlinuz"
INITRD="./output/initramfs-paypal-auth.img"
SHIM="./output/shimx64.efi"
GRUB="./output/grubx64.efi"

if [ ! -f "$KERNEL" ] || [ ! -f "$INITRD" ] || [ ! -f "$SHIM" ] || [ ! -f "$GRUB" ]; then
    echo "❌ Missing artifacts in output/! Run docker build first."
    exit 1
fi

# Normalize all input artifact timestamps
touch -d "@$SOURCE_DATE_EPOCH" "$KERNEL" "$INITRD" "$SHIM" "$GRUB"

# ==============================================================================
# PHASE 1: Build the ESP partition image
# ==============================================================================
echo "🔨 Formatting EFI System Partition (FAT32)..."
truncate -s 512M $ESP_IMAGE
# --invariant: replaces all random/time-based values with constants
mkfs.vfat -F 32 -i 12345678 --invariant -n "EFI" $ESP_IMAGE

echo "📦 Populating ESP via mtools..."
echo "mtools_skip_check=1" > .mtoolsrc
MTOOLSRC="$(pwd)/.mtoolsrc"
export MTOOLSRC
export MTOOLS_NO_CONF=1

mmd -i $ESP_IMAGE ::/EFI
mmd -i $ESP_IMAGE ::/EFI/BOOT
# Use -m to preserve timestamp from source files (which are set to SOURCE_DATE_EPOCH)
mcopy -v -m -i $ESP_IMAGE "$SHIM"   ::/EFI/BOOT/BOOTX64.EFI
mcopy -v -m -i $ESP_IMAGE "$GRUB"   ::/EFI/BOOT/grubx64.efi
mcopy -v -m -i $ESP_IMAGE "$KERNEL" ::/EFI/BOOT/vmlinuz
mcopy -v -m -i $ESP_IMAGE "$INITRD" ::/EFI/BOOT/initrd.img

# Create GRUB config
cat <<EOF > grub.cfg
set default=0
set timeout=0
menuentry "GCP Confidential PayPal Auth (Secure & Measured)" {
    linux /EFI/BOOT/vmlinuz root=tmpfs rootok=1 console=ttyS0 selinux=0 panic=1 net.ifnames=0 biosdevname=0 rd.debug
    initrd /EFI/BOOT/initrd.img
}
EOF
touch -d "@$SOURCE_DATE_EPOCH" grub.cfg
mcopy -v -m -i $ESP_IMAGE grub.cfg ::/EFI/BOOT/grub.cfg

# ==============================================================================
# PHASE 2: Extract contents → normalize at file level → rebuild ESP
# This is the key step: extract all files, sort them, reinject deterministically
# ==============================================================================
echo "🔄 Normalizing ESP: extract → sort → rebuild..."

# Create a fresh, normalized ESP image
ESP_NORM="esp_norm.img"
truncate -s 512M $ESP_NORM
mkfs.vfat -F 32 -i 12345678 --invariant -n "EFI" $ESP_NORM

# Extract all files from esp.img to a temp dir (sorted order)
mkdir -p "$ESP_MOUNT"
# Use mtools to list and copy each file in deterministic alphabetical order
for RPATH in \
    "EFI/BOOT/BOOTX64.EFI" \
    "EFI/BOOT/grubx64.efi" \
    "EFI/BOOT/grub.cfg" \
    "EFI/BOOT/initrd.img" \
    "EFI/BOOT/vmlinuz"; do
    mkdir -p "$ESP_MOUNT/$(dirname $RPATH)"
    mcopy -n -i $ESP_IMAGE "::/$RPATH" "$ESP_MOUNT/$RPATH"
    # Normalize file timestamp
    touch -d "@$SOURCE_DATE_EPOCH" "$ESP_MOUNT/$RPATH"
done

# Re-inject into the fresh normalized ESP in deterministic order
mmd -i $ESP_NORM ::/EFI
mmd -i $ESP_NORM ::/EFI/BOOT
for RPATH in \
    "EFI/BOOT/BOOTX64.EFI" \
    "EFI/BOOT/grubx64.efi" \
    "EFI/BOOT/grub.cfg" \
    "EFI/BOOT/initrd.img" \
    "EFI/BOOT/vmlinuz"; do
    mcopy -v -m -i $ESP_NORM "$ESP_MOUNT/$RPATH" "::/$RPATH"
done

# Replace original ESP with normalized one
mv $ESP_NORM $ESP_IMAGE
rm -rf "$ESP_MOUNT"

# ==============================================================================
# PHASE 3: Assemble the raw disk with fixed GPT metadata
# Use sgdisk with explicit fixed UUIDs for a deterministic GPT header and Protective MBR
# ==============================================================================
echo "🏗️  Constructing GPT disk with fixed UUIDs using sgdisk..."
# Create 1GB image to be safe
dd if=/dev/zero of=$RAW_IMAGE bs=1M count=1024 status=none

# ~512MiB ESP starting at sector 2048 (1MiB offset)
# with size 1048576 sectors (512MiB), type ef00 (EFI System), and fixed GUIDs.
sgdisk --clear -g \
       --disk-guid=00000000-0000-0000-0000-000000000001 \
       --new=1:2048:1050623 \
       --typecode=1:ef00 \
       --partition-guid=1:00000000-0000-0000-0000-000000000002 \
       --change-name=1:"EFI System Partition" \
       $RAW_IMAGE >/dev/null

# Inject normalized ESP into partition slot (proven: bs=1M seek=1)
dd if=$ESP_IMAGE of=$RAW_IMAGE bs=1M seek=1 conv=notrunc status=none

# ==============================================================================
# PHASE 4: Normalize the final raw disk image
# ==============================================================================
echo "🔍 Final normalization of RAW disk..."
touch -d "@$SOURCE_DATE_EPOCH" "$RAW_IMAGE"

if command -v add-det >/dev/null; then
    add-det "$RAW_IMAGE"
fi

# ==============================================================================
# PHASE 5: Package outputs
# ==============================================================================
echo "🔄 Converting to QCOW2..."
rm -f $IMAGE_NAME
qemu-img convert -f raw -O qcow2 $RAW_IMAGE $IMAGE_NAME
if command -v add-det >/dev/null; then
    add-det "$IMAGE_NAME"
fi

echo "📦 Packaging to disk.tar.gz (deterministic)..."
rm -f "$TAR_IMAGE"
tar --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --sort=name \
    -czf "$TAR_IMAGE" "$RAW_IMAGE"

if command -v add-det >/dev/null; then
    add-det "$TAR_IMAGE"
fi

# Cleanup
rm -f .mtoolsrc grub.cfg $ESP_IMAGE

echo ""
echo "✅ Synthesis Complete."
sha256sum "$RAW_IMAGE" "$TAR_IMAGE" "$IMAGE_NAME"
