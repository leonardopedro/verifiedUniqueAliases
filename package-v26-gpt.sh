#!/bin/bash
set -e

echo "💿 Assembling standard EFI GPT disk with Nix kernel & initrd..."
rm -rf v26-esp v26-esp.img disk-v26.raw dstack-output/paypal-auth-v26.qcow2
mkdir -p v26-esp/EFI/BOOT

INITRAMFS_FILE="result-initramfs/initrd"
KERNEL_FILE="result-kernel/bzImage"

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

# Generate an EFI GRUB payload natively using the host OS tools
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
