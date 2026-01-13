#!/usr/bin/env bash
set -euo pipefail

echo "🔍 Inspecting GRUB configuration in box.img"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script requires sudo privileges"
    echo "Please run: sudo $0"
    exit 1
fi

# Load NBD module
modprobe nbd max_part=8

# Connect box.img to NBD device
qemu-nbd -c /dev/nbd0 box.img
sleep 2

# Mount
mkdir -p /mnt/ol10-check
mount /dev/nbd0p2 /mnt/ol10-check

# Show GRUB config
echo "📄 GRUB Configuration (/mnt/ol10-check/grub2/grub.cfg):"
echo "=========================================================="
grep -A 2 "menuentry" /mnt/ol10-check/grub2/grub.cfg | head -40

echo ""
echo "📄 Showing all 'linux' lines:"
echo "=============================="
grep "^\s*linux" /mnt/ol10-check/grub2/grub.cfg | head -20

# Cleanup  
umount /mnt/ol10-check
qemu-nbd -d /dev/nbd0

echo ""
echo "✅ Inspection complete"
