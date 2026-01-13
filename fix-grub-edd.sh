#!/usr/bin/env bash
set -euo pipefail

IMG_PATH="${1:-box.img}"
echo "🔧 Fixing boot configuration in $IMG_PATH to add edd=off"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script requires sudo privileges"
    echo "Please run: sudo $0 <image_path>"
    exit 1
fi

# Load NBD module
modprobe nbd max_part=8

# Connect image
echo "🔗 Connecting to /dev/nbd0..."
qemu-nbd -c /dev/nbd0 "$IMG_PATH"
sleep 2
partprobe /dev/nbd0 || true
sleep 1

# Create mount point
MOUNT_POINT="/mnt/ol10-fix"
mkdir -p "$MOUNT_POINT"

# Function to fix a partition
fix_partition() {
    local part=$1
    echo "🔍 Checking $part..."
    if ! mount "$part" "$MOUNT_POINT" 2>/dev/null; then
        return
    fi
    echo "✅ Mounted $part"

    # 1. Try BLS entries
    local bls_found=false
    for bls_dir in "$MOUNT_POINT/loader/entries" "$MOUNT_POINT/boot/loader/entries"; do
        if [ -d "$bls_dir" ]; then
            echo "  📂 Found BLS directory: $bls_dir"
            for entry in "$bls_dir"/*.conf; do
                if [ -f "$entry" ]; then
                    if grep -q "edd=off" "$entry"; then
                        echo "    ✅ $(basename "$entry") already has edd=off"
                    else
                        sed -i 's/^options \(.*\)/options \1 edd=off/' "$entry"
                        echo "    ✏️  Added edd=off to $(basename "$entry")"
                    fi
                    bls_found=true
                fi
            done
        fi
    done

    # 2. Try grub.cfg
    local grub_found=false
    for grub_cfg in "$MOUNT_POINT/grub2/grub.cfg" "$MOUNT_POINT/boot/grub2/grub.cfg" "$MOUNT_POINT/boot/grub/grub.cfg"; do
        if [ -f "$grub_cfg" ]; then
            echo "  📂 Found GRUB config: $grub_cfg"
            if grep -q "edd=off" "$grub_cfg"; then
                echo "    ✅ $grub_cfg already has edd=off"
            else
                # Very simple sed for any linux line
                sed -i 's/^\s*linux.*/& edd=off/' "$grub_cfg"
                echo "    ✏️  Added edd=off to $grub_cfg"
            fi
            grub_found=true
        fi
    done

    umount "$MOUNT_POINT"
}

# Try all partitions
for p in /dev/nbd0p1 /dev/nbd0p2 /dev/nbd0p3; do
    if [ -b "$p" ]; then
        fix_partition "$p"
    fi
done

# Disconnect
echo "🔌 Disconnecting /dev/nbd0..."
qemu-nbd -d /dev/nbd0
echo "✅ Done!"
