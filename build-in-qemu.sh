#!/bin/bash
set -e

# Configuration
# We use the Oracle Linux 10 Vagrant box image
# URL: https://yum.oracle.com/boxes/oraclelinux/ol10/OL10U0_x86_64-vagrant-libvirt-b684.box
IMAGE_NAME="OL10U0_x86_64-vagrant-libvirt-b684.box" 
IMAGE_SHA256="c0808977959d91703f4eb1448ecd96911a61c39540d0b004712b0f90162b1441"
SNAPSHOT_NAME="vm-snapshot.qcow2"
EXTRACTED_IMG="box.img"

# 1. Check for Image
if [ ! -f "$EXTRACTED_IMG" ]; then
    echo "❌ Patched base image ($EXTRACTED_IMG) not found!"
    echo "   Please ensure box.img is present and patched with edd=off."
    exit 1
fi
echo "✅ Patched base image found: $EXTRACTED_IMG"

# 2. Create Snapshot (Overlay)
echo "📸 Creating snapshot..."
rm -f "$SNAPSHOT_NAME"
qemu-img create -f qcow2 -b "$EXTRACTED_IMG" -F qcow2 "$SNAPSHOT_NAME" 20G

# 3. Boot QEMU
echo "🚀 Booting QEMU VM..."
echo ""
echo "INSTRUCTIONS:"
echo "1. Login with: vagrant / vagrant"
echo "2. Switch to root: sudo su -"
echo "3. Mount the shared directory: mkdir -p /mnt/source && mount -t 9p -o trans=virtio,version=9p2000.L source /mnt/source"
echo "4. Run the build script: cd /mnt/source && chmod +x build-inside-vm.sh && ./build-inside-vm.sh"
echo "5. Shutdown with: poweroff"
echo ""

# Check for KVM support
ACCEL=""
if [ -e /dev/kvm ]; then
    ACCEL="-enable-kvm -cpu host"
    echo "   (KVM acceleration enabled)"
else
    ACCEL="-cpu qemu64"
    echo "   (KVM not found, using software emulation - this will be slow)"
fi

qemu-system-x86_64 \
    -m 8G \
    -smp 4 \
    -machine pc \
    $ACCEL \
    -kernel vmlinuz-native \
    -initrd initramfs-paypal-auth.img \
    -append "root=UUID=457bca7f-1820-41ec-be10-65113c9211fc rw console=tty0 console=ttyS0 edd=off rd.lvm.vg=vg_main rd.lvm.lv=vg_main/lv_root systemd.log_level=debug systemd.log_target=console" \
    -drive file="$SNAPSHOT_NAME",format=qcow2,if=none,id=hd0 \
    -device virtio-blk-pci,drive=hd0 \
    -virtfs local,path=$(pwd),mount_tag=source,security_model=mapped-xattr,id=source \
    -nographic \
    -serial mon:stdio
    
echo "✅ VM exited."
