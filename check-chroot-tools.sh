#!/usr/bin/env bash
set -euo pipefail

IMG_PATH="box.raw"
MOUNT_ROOT="/mnt/ol10-chroot"

cleanup() {
    umount -l "$MOUNT_ROOT/boot" 2>/dev/null || true
    umount -l "$MOUNT_ROOT/dev" 2>/dev/null || true
    umount -l "$MOUNT_ROOT/proc" 2>/dev/null || true
    umount -l "$MOUNT_ROOT/sys" 2>/dev/null || true
    umount -l "$MOUNT_ROOT" 2>/dev/null || true
    vgchange -an vg_main 2>/dev/null || true
    kpartx -dv "$IMG_PATH" 2>/dev/null || true
    losetup -D 2>/dev/null || true
}
trap cleanup EXIT

echo "🔗 Connecting image..."
kpartx -av "$IMG_PATH"
sleep 1
vgchange -ay vg_main
sleep 1

echo "📂 Mounting..."
mkdir -p "$MOUNT_ROOT"
mount -o nouuid /dev/mapper/vg_main-lv_root "$MOUNT_ROOT"

echo "🔍 Checking for tools..."
if chroot "$MOUNT_ROOT" which microdnf >/dev/null 2>&1; then
    echo "✅ microdnf found"
else
    echo "❌ microdnf NOT found"
fi

if chroot "$MOUNT_ROOT" which dnf >/dev/null 2>&1; then
    echo "✅ dnf found"
else
    echo "❌ dnf NOT found"
fi

chroot "$MOUNT_ROOT" rpm -qa | grep -E "dnf|rpm|yum" | head -5 || true
