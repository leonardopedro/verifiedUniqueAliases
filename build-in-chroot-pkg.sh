#!/usr/bin/env bash
set -euo pipefail

IMG_PATH="box.raw"

cleanup() {
    # We don't unmount the root as it's automounted, but we should clean our binds
    if [ -n "${MOUNT_ROOT:-}" ]; then
        umount -l "$MOUNT_ROOT/boot" 2>/dev/null || true
        umount -l "$MOUNT_ROOT/dev" 2>/dev/null || true
        umount -l "$MOUNT_ROOT/proc" 2>/dev/null || true
        umount -l "$MOUNT_ROOT/sys" 2>/dev/null || true
    fi
    # Don't deactivate VG if automounted, let user session handle it or lazy cleanup
    # But usually better to try closing if we opened it
    # kpartx -dv "$IMG_PATH" 2>/dev/null || true
}
trap cleanup EXIT

echo "🔗 Connecting image..."
kpartx -av "$IMG_PATH"
sleep 2
vgchange -ay vg_main
sleep 2

# Find mount point
MOUNT_ROOT=$(findmnt -n -o TARGET /dev/mapper/vg_main-lv_root || true)

if [ -z "$MOUNT_ROOT" ]; then
    echo "⚠️  Not automounted, trying manual mount..."
    MOUNT_ROOT="/mnt/ol10-chroot"
    mkdir -p "$MOUNT_ROOT"
    mount /dev/mapper/vg_main-lv_root "$MOUNT_ROOT"
fi

echo "📂 Root at: $MOUNT_ROOT"

# Mount boot (automount usually doesn't mount boot partition of LVM styled image)
# boot is usually p2
if ! mountpoint -q "$MOUNT_ROOT/boot"; then
    echo "  Mounting /boot..."
    mount /dev/mapper/loop0p2 "$MOUNT_ROOT/boot"
fi

echo "check for dnf/microdnf"
PKG_MGR=""
if chroot "$MOUNT_ROOT" which microdnf >/dev/null 2>&1; then
    PKG_MGR="microdnf"
elif chroot "$MOUNT_ROOT" which dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
else
    echo "❌ No package manager found!"
    exit 1
fi
echo "✅ Using $PKG_MGR"

echo "💉 Bind mounting virtual filesystems..."
for dir in /dev /proc /sys; do
    mkdir -p "$MOUNT_ROOT$dir"
    mount --bind "$dir" "$MOUNT_ROOT$dir"
done

# Fix DNS
cp /etc/resolv.conf "$MOUNT_ROOT/etc/resolv.conf"

echo "🚀 Running build in chroot..."
# Create the build script inside
cat > "$MOUNT_ROOT/tmp/build.sh" <<EOF
#!/bin/bash
set -e
echo "📦 Installing dependencies..."
if [ "$PKG_MGR" = "microdnf" ]; then
    microdnf install -y dracut-config-generic dracut-network qemu-guest-agent virtio-win || true
else
    dnf install -y dracut-config-generic dracut-network qemu-guest-agent || true
fi

echo "🛠️ Rebuilding initramfs..."
# Find kernel version from /lib/modules
KVER=\$(ls /lib/modules/ | sort -V | tail -1)
if [ -z "\$KVER" ]; then
    echo "❌ Could not find kernel modules!"
    exit 1
fi
echo "Kernel: \$KVER"
dracut -v --no-hostonly --force /boot/initramfs-paypal-auth.img \$KVER

EOF
chmod +x "$MOUNT_ROOT/tmp/build.sh"

chroot "$MOUNT_ROOT" /tmp/build.sh

echo "📝 Copying result..."
cp "$MOUNT_ROOT/boot/initramfs-paypal-auth.img" ./initramfs-paypal-auth-final.img

echo "✅ Done!"
