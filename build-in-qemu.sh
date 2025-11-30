#!/bin/bash
set -e

# Configuration
IMAGE_URL="https://yum.oracle.com/templates/OracleLinux/OL10/u0/x86_64/OL10U0_x86_64-kvm-b266.qcow2"
IMAGE_NAME="OL10U0_x86_64-kvm-b266.qcow2"
IMAGE_SHA256="f88b0f73a5a48cbcb23a72cae33c93847c10fd183de6527ddf1ae807a84ca19e"
SNAPSHOT_NAME="vm-snapshot.qcow2"

# 1. Download Base Image
if [ ! -f "$IMAGE_NAME" ]; then
    echo "⬇️  Downloading Oracle Linux 10 Cloud Image..."
    curl -L -o "$IMAGE_NAME" "$IMAGE_URL"
    
    # Verify SHA256
    echo "🔐 Verifying SHA256 checksum..."
    echo "$IMAGE_SHA256  $IMAGE_NAME" | sha256sum -c -
    if [ $? -ne 0 ]; then
        echo "❌ SHA256 verification failed!"
        rm -f "$IMAGE_NAME"
        exit 1
    fi
    echo "✅ SHA256 verified"
else
    echo "✅ Base image found: $IMAGE_NAME"
    # Verify existing image
    echo "🔐 Verifying SHA256 checksum..."
    echo "$IMAGE_SHA256  $IMAGE_NAME" | sha256sum -c -
    if [ $? -ne 0 ]; then
        echo "⚠️  SHA256 mismatch! Re-downloading..."
        rm -f "$IMAGE_NAME"
        curl -L -o "$IMAGE_NAME" "$IMAGE_URL"
        echo "$IMAGE_SHA256  $IMAGE_NAME" | sha256sum -c -
        if [ $? -ne 0 ]; then
            echo "❌ SHA256 verification failed!"
            rm -f "$IMAGE_NAME"
            exit 1
        fi
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
echo "1. Login with: root / (no password initially, set one if prompted)"
echo "2. Mount the shared directory: mkdir -p /mnt/source && mount -t virtiofs source /mnt/source"
echo "3. Run the build script: cd /mnt/source && ./build-inside-vm.sh"
echo "4. After build completes, shutdown with: poweroff"
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
    -drive file=/dev/vg_qemu/my_vm_disk,format=raw,if=virtio,cache=none \
    -nographic \
    #-virtfs local,path=$(pwd),mount_tag=source,security_model=mapped-xattr,id=source \
    
echo "✅ VM exited."
