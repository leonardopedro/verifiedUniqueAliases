#!/bin/bash
# ==============================================================================
# build-supported-ol8-image.sh (v15 Oracle Linux 8 Native - PODMAN ASSEMBLY)
# ==============================================================================
# Uses podman to assemble the rootfs securely without permission issues.
# ==============================================================================

set -e

PROJECT_ROOT=$(pwd)
OUTPUT_DIR="$PROJECT_ROOT/dstack-output"
mkdir -p "$OUTPUT_DIR"

APP_BINARY="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/paypal-auth-vm"

echo "🚜 Building Oracle Linux 8 RootFS via Podman..."

# Create assembly script for inside the container
cat << 'ASSEMBLY_EOF' > /tmp/assemble-ol8.sh
#!/bin/bash
set -e
# Install missing tools
microdnf install findutils cpio gzip -y 2>/dev/null
mkdir -p /rootfs/{bin,sbin,etc,proc,sys,dev,tmp,run,usr/bin,usr/lib64,lib64}
cp -a /usr/bin/* /rootfs/usr/bin/ 2>/dev/null || true
cp -a /usr/lib64/* /rootfs/usr/lib64/ 2>/dev/null || true
cp -a /lib64/* /rootfs/lib64/ 2>/dev/null || true

# Inject App
cp /tmp/app-binary /rootfs/usr/bin/paypal-auth-vm
chmod +x /rootfs/usr/bin/paypal-auth-vm

# Create /init
cat << 'INIT_EOF' > /rootfs/init
#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || true
mkdir -p /run /tmp
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
ip link set lo up
# Minimal DHCP
if [ -f /usr/sbin/dhclient ]; then /usr/sbin/dhclient eth0; else ip addr add 10.0.2.15/24 dev eth0; ip link set eth0 up; ip route add default via 10.0.2.2; fi
echo "🚀 Launching supported OL8 workload..."
exec /usr/bin/paypal-auth-vm
INIT_EOF
chmod +x /rootfs/init

# Pack
cd /rootfs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > /tmp/initramfs-ol8.cpio.gz
ASSEMBLY_EOF

# Run assembly in Podman
podman run --rm \
    -v "/tmp/assemble-ol8.sh:/tmp/assemble.sh:Z" \
    -v "$APP_BINARY:/tmp/app-binary:Z" \
    -v "$OUTPUT_DIR:/tmp/output:Z" \
    oraclelinux:8-slim \
    bash -c "bash /tmp/assemble.sh && cp /tmp/initramfs-ol8.cpio.gz /tmp/output/"

echo "💿 Building EFI Disk Image..."
ISO_ROOT="$PROJECT_ROOT/iso-root"
rm -rf "$ISO_ROOT" && mkdir -p "$ISO_ROOT/boot/grub"
cp /tmp/dstack-base-0.5.8/bzImage "$ISO_ROOT/boot/vmlinuz"
cp "$OUTPUT_DIR/initramfs-ol8.cpio.gz" "$ISO_ROOT/boot/initrd.img"

cat <<EOF > "$ISO_ROOT/boot/grub/grub.cfg"
set default=0
set timeout=1
menuentry "Oracle Linux 8 Confidential v15" {
    linux /boot/vmlinuz console=ttyS0 quiet selinux=0 panic=1
    initrd /boot/initrd.img
}
EOF

grub-mkrescue -o "$OUTPUT_DIR/paypal-auth-ol8.iso" "$ISO_ROOT" 2>/dev/null
qemu-img convert -f raw -O qcow2 "$OUTPUT_DIR/paypal-auth-ol8.iso" "$OUTPUT_DIR/paypal-auth-ol8.qcow2"

echo "✅ SUCCESS! v15 OL8 image complete."
