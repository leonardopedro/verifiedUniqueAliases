#!/bin/bash
# ==============================================================================
# build-dracut-carbon-copy.sh (v25)
# ==============================================================================
# Uses an Oracle Linux 8 container to build a production-grade initramfs.
# ==============================================================================

set -e

PROJECT_ROOT=$(pwd)
OUTPUT_DIR="$PROJECT_ROOT/dstack-output"
mkdir -p "$OUTPUT_DIR"

APP_BINARY="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/paypal-auth-vm"

echo "🚜 Building Production Initramfs via Oracle Linux 8 Dracut..."

# Create assembly script
cat << 'DRACUT_EOF' > /tmp/run-dracut.sh
#!/bin/bash
set -e
# Install core building tools
dnf install -y dracut dracut-network kernel network-scripts iproute 2>/dev/null

# Prepare App
cp /tmp/app-binary /usr/bin/paypal-auth-vm
chmod +x /usr/bin/paypal-auth-vm

# Create a custom dracut module for our app
mkdir -p /usr/lib/dracut/modules.d/99paypal
cat << 'MOD_EOF' > /usr/lib/dracut/modules.d/99paypal/module-setup.sh
#!/bin/bash
check() { return 0; }
depends() { echo "base network"; }
install() {
    inst /usr/bin/paypal-auth-vm /usr/bin/paypal-auth-vm
}
MOD_EOF
chmod +x /usr/lib/dracut/modules.d/99paypal/module-setup.sh

# Build the initramfs (optimized for OCI)
# We use the kernel version installed by DNF
KVER=$(ls /lib/modules | head -1)
echo "Building for Kernel: $KVER"

dracut --force --no-hostonly --no-hostonly-cmdline \
    --add "base network" \
    --add-drivers "virtio virtio_net virtio_blk virtio_pci" \
    --include /usr/bin/paypal-auth-vm /usr/bin/paypal-auth-vm \
    /tmp/production-initrd.img $KVER

# Copy kernel out too
cp /boot/vmlinuz-$KVER /tmp/production-vmlinuz
DRACUT_EOF

# Run in Podman
podman run --rm --privileged \
    -v "/tmp/run-dracut.sh:/tmp/run.sh:Z" \
    -v "$APP_BINARY:/tmp/app-binary:Z" \
    -v "$OUTPUT_DIR:/tmp/output:Z" \
    oraclelinux:8 \
    bash -c "bash /tmp/run.sh && cp /tmp/production-initrd.img /tmp/output/ && cp /tmp/production-vmlinuz /tmp/output/"

echo "💿 Assembling Carbon Copy GPT Disk..."
# Now we use the EXTRACTED Oracle Linux 8 Kernel (guaranteed compatible)
KERNEL="$OUTPUT_DIR/production-vmlinuz"
INITRD="$OUTPUT_DIR/production-initrd.img"

# Use the v24 script logic to wrap into GPT
mkdir -p v25-esp/EFI/BOOT
cat <<EOF > v25-esp/EFI/BOOT/grub.cfg
set default=0
set timeout=0
menuentry "Oracle Linux 8 Dracut Boot" {
    linux /EFI/BOOT/vmlinuz console=ttyS0 quiet selinux=0 panic=1 random.trust_cpu=y no-kvmclock rd.shell=0
    initrd /EFI/BOOT/initrd.img
}
EOF
cp "$KERNEL" v25-esp/EFI/BOOT/vmlinuz
cp "$INITRD" v25-esp/EFI/BOOT/initrd.img

grub-mkstandalone -O x86_64-efi -o v25-esp/EFI/BOOT/BOOTX64.EFI "boot/grub/grub.cfg=v25-esp/EFI/BOOT/grub.cfg"

truncate -s 200M v25-esp.img && mkfs.vfat v25-esp.img && mcopy -i v25-esp.img -s v25-esp/* ::/
truncate -s 256M disk-v25.raw && parted -s disk-v25.raw mklabel gpt && parted -s disk-v25.raw mkpart primary fat32 1MiB 100% && parted -s disk-v25.raw set 1 esp on
dd if=v25-esp.img of=disk-v25.raw bs=1M seek=1 conv=notrunc
qemu-img convert -f raw -O qcow2 disk-v25.raw dstack-output/paypal-auth-v25.qcow2

echo "✅ SUCCESS! v25 Dracut image complete."
