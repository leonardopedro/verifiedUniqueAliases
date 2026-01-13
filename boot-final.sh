#!/bin/bash
set -e

IMAGE="box-final.qcow2"

echo "🚀 Booting $IMAGE with QEMU..."
echo "Log: serial console should show GRUB and boot messages."
echo "Login: vagrant/vagrant or root/vagrant"

qemu-system-x86_64 \
    -m 4G \
    -smp 2 \
    -machine pc \
    -enable-kvm -cpu host \
    -drive file="$IMAGE",format=qcow2,if=virtio \
    -nographic \
    -serial mon:stdio
