#!/bin/bash
# This script runs INSIDE the Oracle Linux QEMU VM to build the initramfs

set -e

echo "🔧 Setting up build environment inside VM..."

# Install dependencies
echo "📦 Installing packages..."
# Package manager detection
if command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v microdnf &>/dev/null; then
    PKG_MGR="microdnf"
else
    echo "❌ No package manager found"
    exit 1
fi

echo "📦 Installing packages using $PKG_MGR..."
$PKG_MGR install -y \
    dracut \
    kernel-core \
    kernel-modules \
    kmod \
    curl \
    gcc \
    gcc-c++ \
    make \
    util-linux \
    linux-firmware \
    python3 \
    python3-pip \
    libarchive \
    git \
    cpio \
    gzip

# Install Rust
echo "🦀 Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91.1 --profile minimal
source $HOME/.cargo/env

# Install add-determinism
echo "🔨 Installing add-determinism..."
cargo install -j 1 add-determinism

# Add cargo to PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Change to synced directory
cd /vagrant

# Install QEMU tools and GRUB for image creation
echo "📦 Installing image creation tools..."
# Oracle Linux 10 uses dnf, and some package names might differ or require extra repos
$PKG_MGR install -y qemu-img grub2-pc grub2-tools-extra parted dosfstools

# Run the build
echo "🏗️  Building initramfs..."
./build-initramfs-dracut.sh

# Verify the initramfs was built successfully
INITRAMFS_FILE="initramfs-paypal-auth.img"
if [ ! -f "$INITRAMFS_FILE" ]; then
    echo "❌ Initramfs build failed! File not found: $INITRAMFS_FILE"
    echo "   Please check build output above for errors."
    exit 1
fi

echo "✅ Initramfs built successfully: $INITRAMFS_FILE"

# Create Bootable QCOW2 Image
echo "💿 Creating bootable QCOW2 image..."
OUTPUT_IMG="paypal-auth-vm.qcow2"
RAW_IMG="disk.raw"

# 1. Create raw disk file (2GB)
truncate -s 2G "$RAW_IMG"

# 2. Partition disk (BIOS/GPT hybrid for compatibility)
parted -s "$RAW_IMG" mklabel gpt
parted -s "$RAW_IMG" mkpart primary ext4 1MiB 100%
parted -s "$RAW_IMG" set 1 bios_grub on

# 3. Setup Loop Device
LOOP_DEV=$(losetup -fP --show "$RAW_IMG")
echo "   Loop device: $LOOP_DEV"

# 4. Format Partition
mkfs.ext4 "${LOOP_DEV}p1"

# 5. Mount and Install
MOUNT_DIR=$(mktemp -d)
mount "${LOOP_DEV}p1" "$MOUNT_DIR" || { echo "❌ Mount failed"; exit 1; }

# Verify mount succeeded
if ! mountpoint -q "$MOUNT_DIR"; then
    echo "❌ Mount point not valid"
    exit 1
fi

# Install Kernel and Initramfs
mkdir -p "$MOUNT_DIR/boot"

# Find and copy kernel
KERNEL_FILE=$(ls /boot/vmlinuz-* | head -1)
if [ -z "$KERNEL_FILE" ]; then
    echo "❌ No kernel found in /boot"
    exit 1
fi
echo "   Using kernel: $KERNEL_FILE"
cp "$KERNEL_FILE" "$MOUNT_DIR/boot/vmlinuz"

cp "$INITRAMFS_FILE" "$MOUNT_DIR/boot/initramfs.img"

# Install GRUB
grub2-install --target=i386-pc --boot-directory="$MOUNT_DIR/boot" --modules="part_gpt ext2" "$LOOP_DEV"

# Configure GRUB
cat > "$MOUNT_DIR/boot/grub2/grub.cfg" <<EOF
set default=0
set timeout=1

menuentry 'PayPal Auth VM' {
    linux /boot/vmlinuz root=/dev/sda1 ro console=ttyS0 earlycon earlyprintk=ttyS0
    initrd /boot/initramfs.img
}
EOF

# Cleanup
umount "$MOUNT_DIR"
losetup -d "$LOOP_DEV"
rm -rf "$MOUNT_DIR"

# 6. Convert to QCOW2
qemu-img convert -f raw -O qcow2 "$RAW_IMG" "$OUTPUT_IMG"
rm -f "$RAW_IMG"

echo "✅ Build complete!"
echo "📁 Output location: $OUTPUT_IMG"
echo ""
echo "To copy the file to host, you can use:"
echo "  cp $OUTPUT_IMG /mnt/source/"
