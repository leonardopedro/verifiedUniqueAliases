#!/bin/bash
set -e

# Configuration
# We use the Vagrant box image because it has a pre-configured 'vagrant' user
# URL: https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Vagrant-libvirt-43-1.6.x86_64.vagrant.libvirt.box
IMAGE_NAME="box.img" 
IMAGE_SHA256="e35f9d2662e8e44e444c55e26ddd7ab0518576a06c7d71900c6a3f4fbf80064d"
SNAPSHOT_NAME="vm-snapshot.qcow2"

# 1. Check for Image
if [ ! -f "$IMAGE_NAME" ]; then
    echo "❌ Vagrant box image ($IMAGE_NAME) not found!"
    echo "   Please run: curl -L -o fedora-vagrant.box https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Vagrant-libvirt-43-1.6.x86_64.vagrant.libvirt.box && tar -xvf fedora-vagrant.box"
    exit 1
else
    echo "✅ Base image found: $IMAGE_NAME"
    
    # Verify SHA256
    echo "🔐 Verifying SHA256 checksum..."
    echo "$IMAGE_SHA256  $IMAGE_NAME" | sha256sum -c -
    if [ $? -ne 0 ]; then
        echo "❌ SHA256 verification failed!"
        echo "   The image might be corrupted. Please delete '$IMAGE_NAME' and re-download."
        exit 1
    fi
    echo "✅ SHA256 verified"
fi

# 2. Create Snapshot (Overlay)
echo "📸 Creating snapshot..."
rm -f "$SNAPSHOT_NAME"
qemu-img create -f qcow2 -b "$IMAGE_NAME" -F qcow2 "$SNAPSHOT_NAME" 20G

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
    -m 4G \
    -smp 4 \
    $ACCEL \
    -drive file="$SNAPSHOT_NAME",format=qcow2 \
    -virtfs local,path=$(pwd),mount_tag=source,security_model=mapped-xattr,id=source \
    -nographic 
    
echo "✅ VM exited."
