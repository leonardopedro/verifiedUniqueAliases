#!/bin/bash
# ==============================================================================
# build-v26-nix-gpt.sh (Confidential TCB / Measured Boot)
# ==============================================================================
# Builds a 100% Static Nix Initramfs with embedded application, packaged 
# into an OCI-compliant GPT EFI Disk to satisfy AMD SEV-SNP measured boot
# constraints (hardware attestation).
# ==============================================================================

set -e

echo "🏗️  Building 100% Static Measured Image (Nix + GPT)..."

BUILD_DIR=$(pwd)
BUILD_TARGET="x86_64-unknown-linux-musl"
BINARY_PATH="$BUILD_DIR/target/$BUILD_TARGET/release/paypal-auth-vm"

# 1. Build the Rust Static Binary
echo "🦀 Compiling static payload..."
cargo build --release --target "$BUILD_TARGET" --quiet

# 2. Build the Initramfs via Nix (injecting the binary)
echo "❄️  Building declarative initramfs (TCB)..."
nix-build initramfs.nix -A initramfs --arg binaryPath $BINARY_PATH -o result-initramfs
nix-build initramfs.nix -A kernel -o result-kernel

INITRAMFS_FILE="result-initramfs/initrd"
KERNEL_FILE="result-kernel/bzImage"

# 3. Create OCI-Compliant GPT EFI Disk (Solves Firmware ASSERTs)
echo "💿 Assembling standard EFI GPT disk..."
rm -rf v26-esp v26-esp.img disk-v26.raw dstack-output/paypal-auth-v26.qcow2
mkdir -p v26-esp/EFI/BOOT

# Hardened Kernel Command Line exactly matching Phala/Dstack recommendations
# for Confidential Computing
cat <<EOF > v26-esp/EFI/BOOT/grub.cfg
set default=0
set timeout=0
menuentry 'Confidential PayPal Auth (Measured Boot)' {
    linux /EFI/BOOT/vmlinuz console=ttyS0 quiet selinux=0 panic=1 net.ifnames=0 biosdevname=0 random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock
    initrd /EFI/BOOT/initramfs.img
}
EOF

cp "$KERNEL_FILE" v26-esp/EFI/BOOT/vmlinuz
cp "$INITRAMFS_FILE" v26-esp/EFI/BOOT/initramfs.img

# Generate an EFI GRUB payload
grub-mkstandalone -O x86_64-efi -o v26-esp/EFI/BOOT/BOOTX64.EFI "boot/grub/grub.cfg=v26-esp/EFI/BOOT/grub.cfg"

# Package into GPT disk
truncate -s 200M v26-esp.img
mkfs.vfat v26-esp.img
mcopy -i v26-esp.img -s v26-esp/* ::/

truncate -s 250M disk-v26.raw
parted -s disk-v26.raw mklabel gpt
parted -s disk-v26.raw mkpart primary fat32 1MiB 100%
parted -s disk-v26.raw set 1 esp on
dd if=v26-esp.img of=disk-v26.raw bs=1M seek=1 conv=notrunc

mkdir -p dstack-output
qemu-img convert -f raw -O qcow2 disk-v26.raw dstack-output/paypal-auth-v26.qcow2

echo "✅ Image 'paypal-auth-v26.qcow2' generated successfully."
