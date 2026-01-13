#!/usr/bin/env bash
set -euo pipefail

IMG_PATH="box.raw"
MOUNT_ROOT="/mnt/ol10-chroot"

cleanup() {
    echo "🧹 Cleaning up..."
    umount -l "$MOUNT_ROOT/boot" || true
    umount -l "$MOUNT_ROOT/dev/shm" || true
    umount -l "$MOUNT_ROOT/dev/pts" || true
    umount -l "$MOUNT_ROOT/dev" || true
    umount -l "$MOUNT_ROOT/proc" || true
    umount -l "$MOUNT_ROOT/sys" || true
    umount -l "$MOUNT_ROOT/run" || true
    umount -l "$MOUNT_ROOT" || true
    vgchange -an vg_main || true
    kpartx -dv "$IMG_PATH" || true
    losetup -D || true
}

trap cleanup EXIT

echo "🔗 Connecting image..."
kpartx -av "$IMG_PATH"
sleep 2

echo "📦 Activating LVM..."
vgchange -ay vg_main
sleep 1

echo "📂 Mounting filesystems..."
mkdir -p "$MOUNT_ROOT"
mount -o nouuid /dev/mapper/vg_main-lv_root "$MOUNT_ROOT"
mount -o nouuid /dev/mapper/loop0p2 "$MOUNT_ROOT/boot"

echo "💉 Bind mounting virtual filesystems..."
for dir in /dev /dev/pts /dev/shm /proc /sys /run; do
    mkdir -p "$MOUNT_ROOT$dir"
    mount --bind "$dir" "$MOUNT_ROOT$dir"
done

# Fix DNS
cp /etc/resolv.conf "$MOUNT_ROOT/etc/resolv.conf"

echo "🚀 Entering chroot to run build..."
# Run dracut inside chroot
KVER="6.12.0-102.36.5.2.el10uek.x86_64"
echo "🛠️ Running dracut for kernel $KVER..."
chroot "$MOUNT_ROOT" /usr/bin/bash -c "
    dracut -v --no-hostonly --force /tmp/initramfs-paypal-auth.img $KVER
"

echo "📝 Copying result to host..."
cp "$MOUNT_ROOT/tmp/initramfs-paypal-auth.img" "./initramfs-paypal-auth.img"

echo "✅ Build completed inside chroot!"
# The script will cleanup on exit due to trap
