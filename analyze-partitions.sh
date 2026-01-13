#!/usr/bin/env bash
set -eu

echo "🔍 Analyzing box.img partition layout"
echo "======================================"
echo ""

if [  "$EUID" -ne 0 ]; then 
    echo "⚠️  This script requires sudo"
    echo "Please run: sudo $0"
    exit 1
fi

modprobe nbd max_part=8
qemu-nbd -c /dev/nbd0 box.img
sleep 2

echo "📋 Partition table:"
fdisk -l /dev/nbd0 | grep "^/dev"

echo ""
echo "🔍 Checking each partition..."

for part in /dev/nbd0p1 /dev/nbd0p2 /dev/nbd0p3; do
    if [ -b "$part" ]; then
        echo ""
        echo "=== $part ==="
        blkid "$part" || echo "No filesystem"
        
        mkdir -p /mnt/check
        if mount "$part" /mnt/check 2>/dev/null; then
            echo "✅ Mounted successfully"
            echo "Contents:"
            ls -la /mnt/check | head -20
            
            # Check for boot files
            if [ -d "/mnt/check/boot" ]; then
                echo "📂 Found /boot directory"
                ls -R /mnt/check/boot | head -50
            fi
            
            # Check for loader entries
            if [ -d "/mnt/check/loader" ]; then
                echo "📂 Found /loader directory"
                ls -R  /mnt/check/loader
            fi
            
            umount /mnt/check
        else
            echo "❌ Could not mount (might be LVM or swap)"
        fi
    fi
done

qemu-nbd -d /dev/nbd0
echo ""
echo "✅ Analysis complete"
