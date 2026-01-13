#!/bin/bash
set -e

# Boot from physical USB (/dev/sda)
DISK="/dev/sda"

echo "🚀 Booting from USB ($DISK)..."
echo "WARNING: Ensure you have write permissions (usually sudo)."

sudo qemu-system-x86_64 \
    -m 6G \
    -smp 4 \
    -machine pc \
    -enable-kvm -cpu host \
    -drive file="$DISK",format=raw,if=virtio \
    -nographic \
    -serial mon:stdio \
    -virtfs local,path=$(pwd),mount_tag=vagrant,security_model=mapped-xattr,id=vagrant
