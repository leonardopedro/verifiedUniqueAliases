#!/usr/bin/env bash
set -euo pipefail

IMG_PATH="box.raw"
NEW_INITRD="initramfs-paypal-auth.img"

cleanup() {
    if [ -n "${MOUNT_ROOT:-}" ]; then
        umount "$MOUNT_ROOT" 2>/dev/null || true
    fi
    # Lazy cleanup of device maps if possible
}
trap cleanup EXIT

echo "🔗 Connecting image..."
kpartx -av "$IMG_PATH"
sleep 1
# Mount boot partition (p2) directly as we know layout
mkdir -p /mnt/ol10-boot
mount /dev/mapper/loop0p2 /mnt/ol10-boot
MOUNT_ROOT="/mnt/ol10-boot"

echo "📂 Mounted boot at $MOUNT_ROOT"
BLS_DIR="$MOUNT_ROOT/loader/entries"

for conf in "$BLS_DIR"/*.conf; do
    if [ -f "$conf" ]; then
        echo "📄 Updating: $(basename "$conf")"
        # Backup
        cp "$conf" "${conf}.bak"
        
        # Replace initrd line
        sed -i "s|^initrd .*|initrd /$NEW_INITRD|" "$conf"
        
        echo "✅ Updated initrd to $NEW_INITRD"
        grep "^initrd" "$conf"
    fi
done

echo "✅ Done"
