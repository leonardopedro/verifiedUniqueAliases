#!/bin/bash
# ==============================================================================
# build-native-efi-image.sh (v16 Native EFI Disk)
# ==============================================================================
# Creates a GPT-partitioned disk image with a FAT32 ESP.
# This avoids the UEFI firmware assertion crash with ISOs on OCI SEV-SNP.
# ==============================================================================

set -e

PROJECT_ROOT=$(pwd)
OUTPUT_DIR="$PROJECT_ROOT/dstack-output"
mkdir -p "$OUTPUT_DIR"

# 1. Prepare Content
KERNEL="/tmp/dstack-base-0.5.8/bzImage"
INITRD="$OUTPUT_DIR/initramfs-ol8.cpio.gz"

if [ ! -f "$INITRD" ]; then
    echo "❌ Error: Run build-dstack-guest-image.sh (v15) first to generate OL8 initrd."
    exit 1
fi

echo "💿 Assembling Native EFI Disk Image (v16)..."

# 2. Use Podman to build the disk image (no root needed on host)
cat << 'DISK_EOF' > /tmp/make-efi-disk.sh
#!/bin/bash
set -e
IMAGE_SIZE=256
truncate -s ${IMAGE_SIZE}M /tmp/disk.raw

# Create GPT partition table
parted -s /tmp/disk.raw mklabel gpt
parted -s /tmp/disk.raw mkpart primary fat32 1MiB 100%
parted -s /tmp/disk.raw set 1 esp on

# Format and Copy (using mtools to avoid loop mounts)
# mformat -i /tmp/disk.raw@@1M -F ::
# mcopy -i /tmp/disk.raw@@1M /tmp/vmlinuz ::vmlinuz
# mcopy -i /tmp/disk.raw@@1M /tmp/initrd.img ::initrd.img

# Actually, the most reliable way in a container is to use mkfs.vfat on a partition offset
# But we'll use 'guestfish' if we install it, or just 'mtools'
dnf install -y mtools parted qemu-img-ev 2>/dev/null

# Format the partition (start at 1MiB = 2048 sectors)
# We'll use a hack: create a separate FAT image and dd it into the disk
truncate -s 250M /tmp/esp.img
mkfs.vfat /tmp/esp.img
mmd -i /tmp/esp.img ::/EFI
mmd -i /tmp/esp.img ::/EFI/BOOT
mcopy -i /tmp/esp.img /tmp/vmlinuz ::/EFI/BOOT/vmlinuz
mcopy -i /tmp/esp.img /tmp/initrd.img ::/EFI/BOOT/initrd.img

# Create GRUB config
cat <<EOF > /tmp/grub.cfg
set default=0
set timeout=0
menuentry "Oracle Linux 8 Native Confidential" {
    linux /EFI/BOOT/vmlinuz console=ttyS0 quiet selinux=0 panic=1
    initrd /EFI/BOOT/initrd.img
}
EOF
mcopy -i /tmp/esp.img /tmp/grub.cfg ::/EFI/BOOT/grub.cfg

# Construct a simple EFI payload (GRUB)
# This is complex, so we'll use the 'EFI Stub' trick if vmlinuz supports it.
# For now, let's just make vmlinuz the default boot loader (BOOTX64.EFI)
# BUT we need to pass arguments. So we NEED a loader.
dnf install -y grub2-efi-x64-modules grub2-tools 2>/dev/null
grub2-mkstandalone -O x86_64-efi -o /tmp/BOOTX64.EFI "boot/grub/grub.cfg=/tmp/grub.cfg"
mcopy -i /tmp/esp.img /tmp/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI

# DD the ESP into the GPT disk
dd if=/tmp/esp.img of=/tmp/disk.raw bs=1M seek=1 conv=notrunc

# Convert to QCOW2
qemu-img convert -f raw -O qcow2 /tmp/disk.raw /tmp/output.qcow2
DISK_EOF

podman run --rm \
    -v "/tmp/make-efi-disk.sh:/tmp/make.sh:Z" \
    -v "$KERNEL:/tmp/vmlinuz:Z" \
    -v "$INITRD:/tmp/initrd.img:Z" \
    -v "$OUTPUT_DIR:/tmp/output_dir:Z" \
    oraclelinux:8 \
    bash /tmp/make.sh && cp "$OUTPUT_DIR/output.qcow2" "$OUTPUT_DIR/paypal-auth-ol8-native.qcow2"

echo "✅ SUCCESS! v16 Native EFI image complete."
