#!/usr/bin/env bash
set -euo pipefail

DEV="/dev/sda2"
MOUNT_POINT="/mnt/ol10-boot-fix"

echo "🔧 Mount and verify GRUB config on $DEV"
sudo mkdir -p "$MOUNT_POINT"
sudo mount "$DEV" "$MOUNT_POINT"

echo "📂 Files in /grub2:"
sudo ls -F "$MOUNT_POINT/grub2"

echo "📝 Current grub.cfg start:"
sudo head -n 20 "$MOUNT_POINT/grub2/grub.cfg"

# Ensure there is a search line or set root
# Usually it looks like:
# set root='hd0,gpt2'
# if we are in BIOS it might need to be (hd0,gpt2)

# Also check for grubenv
if [ -f "$MOUNT_POINT/grub2/grubenv" ]; then
    echo "📋 grubenv content:"
    sudo cat "$MOUNT_POINT/grub2/grubenv"
fi

sudo umount "$MOUNT_POINT"
echo "✅ Done"
