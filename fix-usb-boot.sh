#!/usr/bin/env bash
set -euo pipefail

DEV="/dev/sda2"
MOUNT_POINT="/mnt/ol10-boot-fix"

echo "🔧 Patching GRUB on $DEV"
sudo mkdir -p "$MOUNT_POINT"
sudo mount "$DEV" "$MOUNT_POINT"

# 1. Add serial settings to grub.cfg
GRUB_CFG="$MOUNT_POINT/grub2/grub.cfg"
if [ -f "$GRUB_CFG" ]; then
    echo "📄 Patching $GRUB_CFG"
    # Prepend serial settings
    sudo sed -i '1i serial --unit=0 --speed=115200\nterminal_input serial console\nterminal_output serial console' "$GRUB_CFG"
fi

# 2. Ensure BLS entry uses correct initrd
BLS_DIR="$MOUNT_POINT/loader/entries"
for conf in "$BLS_DIR"/*.conf; do
    echo "📄 Verifying BLS entry: $conf"
    # Ensure it uses initramfs-paypal-auth.img
    if sudo grep -q "initrd" "$conf"; then
        sudo sed -i 's|^initrd .*|initrd /initramfs-paypal-auth.img|' "$conf"
        # Ensure it has console=ttyS0 and edd=off
        if ! sudo grep -q "console=ttyS0" "$conf"; then
            sudo sed -i '/^options/ s/$/ console=ttyS0/' "$conf"
        fi
        if ! sudo grep -q "edd=off" "$conf"; then
            sudo sed -i '/^options/ s/$/ edd=off/' "$conf"
        fi
        # Remove quiet/rhgb
        sudo sed -i 's/ quiet//g' "$conf"
        sudo sed -i 's/ rhgb//g' "$conf"
    fi
done

sudo umount "$MOUNT_POINT"
echo "✅ Done"
