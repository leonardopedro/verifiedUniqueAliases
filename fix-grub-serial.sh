#!/usr/bin/env bash
set -euo pipefail

IMG_PATH="${1:-box.raw}"
echo "🔧 Adding serial console to GRUB in $IMG_PATH"

if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Requires sudo"
    exit 1
fi

# Connect image
modprobe nbd max_part=8
qemu-nbd -f raw -c /dev/nbd0 "$IMG_PATH"
sleep 2
partprobe /dev/nbd0 || true
sleep 1

MOUNT_POINT="/mnt/ol10-grub"
mkdir -p "$MOUNT_POINT"

cleanup() {
    umount "$MOUNT_POINT" 2>/dev/null || true
    qemu-nbd -d /dev/nbd0 2>/dev/null || true
}
trap cleanup EXIT

# Try boot partition (usually p2 for boot)
for part in /dev/nbd0p2 /dev/nbd0p1; do
    if mount "$part" "$MOUNT_POINT" 2>/dev/null; then
        echo "✅ Mounted $part"
        
        # Check for grub.cfg
        for grub_cfg in "$MOUNT_POINT/grub2/grub.cfg" "$MOUNT_POINT/boot/grub2/grub.cfg"; do
            if [ -f "$grub_cfg" ]; then
                echo "📝 Found: $grub_cfg"
                
                # Add serial console config at the top
                if ! grep -q "serial --unit=0" "$grub_cfg"; then
                    sed -i '1i serial --unit=0 --speed=115200\nterminal_input serial console\nterminal_output serial console' "$grub_cfg"
                    echo "✏️ Added serial console config"
                else
                    echo "✅ Serial already configured"
                fi
                
                # Show first 10 lines
                echo "--- First 10 lines of grub.cfg ---"
                head -10 "$grub_cfg"
            fi
        done
        
        umount "$MOUNT_POINT"
        break
    fi
done

echo "✅ Done!"
