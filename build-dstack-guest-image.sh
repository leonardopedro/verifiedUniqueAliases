#!/bin/bash
# build-dstack-guest-image.sh
# 🏗️  Builds a dstack-compatible Guest VM image bundle using:
#     1. The static Rust binary from this project
#     2. The Phala Network Guest OS (meta-dstack) components

set -e

# Configuration
PROJECT_ROOT=$(pwd)
META_DSTACK_DIR="$PROJECT_ROOT/meta-dstack"
DSTACK_SDK_DIR="/tmp/dstack-tee" # Used by dstack-sdk dependency in Cargo.toml
BUILD_TARGET="x86_64-unknown-linux-gnu"
OUTPUT_DIR="$PROJECT_ROOT/dstack-output"
IMAGE_NAME="paypal-auth-dstack"
VERSION="0.1.0"

# Reproducible timestamps
export SOURCE_DATE_EPOCH=1640995200 
export TZ=UTC
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"

echo "🚀 Starting dstack Guest Image Build..."

# 1. Ensure meta-dstack is present
if [ ! -d "$META_DSTACK_DIR" ]; then
    echo "📥 Cloning meta-dstack..."
    git clone https://github.com/Dstack-TEE/meta-dstack.git "$META_DSTACK_DIR"
fi

# Ensure dstack-sdk source is present
if [ ! -d "$DSTACK_SDK_DIR" ]; then
    echo "📥 Cloning dstack (for dstack-sdk)..."
    git clone https://github.com/Dstack-TEE/dstack.git "$DSTACK_SDK_DIR"
fi

# 2. Build the static Rust binary
echo "🦀 Building static Rust binary ($BUILD_TARGET)..."
# Ensure we have the musl target
rustup target add $BUILD_TARGET 2>/dev/null || true

# Set optimization flags for small, hardened binary
export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"
cargo build --release --target $BUILD_TARGET

BINARY_PATH="$PROJECT_ROOT/target/$BUILD_TARGET/release/paypal-auth-vm"
if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Binary not found at $BINARY_PATH"
    exit 1
fi

# Normalize binary timestamp
if command -v add-det &>/dev/null; then
    add-det "$BINARY_PATH"
fi
touch -d "@${SOURCE_DATE_EPOCH}" "$BINARY_PATH"

# 3. Prepare Image Components (Kernel & BIOS)
# We use dstack's utility to download a pre-built stable base if bitbake isn't running
echo "📥 Fetching Base OS components (kernel/ovmf) from Dstack..."
mkdir -p "$OUTPUT_DIR/base"
cd "$META_DSTACK_DIR"
# Use version 0.5.8 as specified in the project's other scripts
./build.sh dl 0.5.8 
BASE_IMG_DIR="$META_DSTACK_DIR/images/dstack-0.5.8"

if [ ! -d "$BASE_IMG_DIR" ]; then
    echo "⚠️  Base image not found at $BASE_IMG_DIR, checking for dev version..."
    ./build.sh dl -dev 0.5.8
    BASE_IMG_DIR="$META_DSTACK_DIR/images/dstack-dev-0.5.8"
fi

if [ ! -d "$BASE_IMG_DIR" ]; then
    echo "❌ Could not find or download dstack base image components."
    exit 1
fi

# 4. Create custom initramfs with our binary
echo "🔨 Creating custom initramfs..."
INITRD_ROOT="$PROJECT_ROOT/initrd-root"
rm -rf "$INITRD_ROOT"
mkdir -p "$INITRD_ROOT"

# Minimal layout for a standalone guest
# We want our binary to be /init (no need for systemd/busybox in a minimal image)
cp "$BINARY_PATH" "$INITRD_ROOT/init"
chmod +x "$INITRD_ROOT/init"

# Create the cpio archive reproducibly
cd "$INITRD_ROOT"
find . -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
find . -print0 | LC_ALL=C sort -z | cpio --renumber-inodes --null -ov --format=newc --owner=root:root | gzip -n -9 > "$OUTPUT_DIR/initramfs-paypal.cpio.gz"
cd "$PROJECT_ROOT"

# Normalize initramfs for reproducibility
if command -v add-det &>/dev/null; then
    echo "   Decompressing initramfs for add-det..."
    gzip -d -c "$OUTPUT_DIR/initramfs-paypal.cpio.gz" > "$OUTPUT_DIR/initramfs-paypal.cpio"
    add-det "$OUTPUT_DIR/initramfs-paypal.cpio"
    
    echo "   Recompressing with deterministic gzip..."
    gzip -n -9 < "$OUTPUT_DIR/initramfs-paypal.cpio" > "$OUTPUT_DIR/initramfs-paypal.cpio.gz.tmp"
    add-det "$OUTPUT_DIR/initramfs-paypal.cpio.gz.tmp"
    
    mv "$OUTPUT_DIR/initramfs-paypal.cpio.gz.tmp" "$OUTPUT_DIR/initramfs-paypal.cpio.gz"
    rm -f "$OUTPUT_DIR/initramfs-paypal.cpio"
fi

# 5. Assemble the Bundle
echo "📦 Assembling dstack image bundle..."
BUNDLE_DIR="$OUTPUT_DIR/$IMAGE_NAME-$VERSION"
mkdir -p "$BUNDLE_DIR"

# Copy components from base image
cp "$BASE_IMG_DIR/bzImage" "$BUNDLE_DIR/"
cp "$BASE_IMG_DIR/ovmf.fd" "$BUNDLE_DIR/"

# Replace initramfs with our custom one
cp "$OUTPUT_DIR/initramfs-paypal.cpio.gz" "$BUNDLE_DIR/initramfs.cpio.gz"

# Generate dstack-compatible metadata.json
# Phala dstack-vmm uses this to know how to boot the VM
cat <<EOF > "$BUNDLE_DIR/metadata.json"
{
    "bios": "ovmf.fd",
    "kernel": "bzImage",
    "cmdline": "console=ttyS0 init=/init panic=1 quiet random.trust_cpu=y no-kvmclock pci=noearly pci=nommconf",
    "initrd": "initramfs.cpio.gz",
    "version": "$VERSION",
    "shared_ro": true,
    "is_dev": true,
    "git_revision": "$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
}
EOF

# Calculate checksums
cd "$BUNDLE_DIR"
sha256sum ovmf.fd bzImage initramfs.cpio.gz metadata.json > sha256sum.txt
SHA256=$(sha256sum sha256sum.txt | awk '{print $1}')
echo "$SHA256" > digest.txt
cd "$PROJECT_ROOT"

# 6. Create final compressed bundle reproducibly
echo "📚 Creating final bundle: $IMAGE_NAME-$VERSION.tar.gz"
(cd "$OUTPUT_DIR" && tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    -czvf "$IMAGE_NAME-$VERSION.tar.gz" "$(basename "$BUNDLE_DIR")")

# 7. (Optional) Convert to QCOW2 for OCI
echo "⚙️  Generating bootable QCOW2 for OCI..."
# We use a minimal bootloader setup to convert the bundle components into a single disk image
# This mimics the build-native.sh but with dstack components
ISO_ROOT="$PROJECT_ROOT/iso-root"
mkdir -p "$ISO_ROOT/boot/grub"
cp "$BUNDLE_DIR/bzImage" "$ISO_ROOT/boot/vmlinuz"
cp "$BUNDLE_DIR/initramfs.cpio.gz" "$ISO_ROOT/boot/initrd"

cat <<EOF > "$ISO_ROOT/boot/grub/grub.cfg"
set default=0
set timeout=1
menuentry 'Dstack PayPal Guest' {
    linux /boot/vmlinuz console=ttyS0 quiet init=/init
    initrd /boot/initrd
}
EOF

grub-mkrescue -o "$OUTPUT_DIR/$IMAGE_NAME.iso" "$ISO_ROOT"
qemu-img convert -f raw -O qcow2 "$OUTPUT_DIR/$IMAGE_NAME.iso" "$OUTPUT_DIR/$IMAGE_NAME.qcow2"
rm -f "$OUTPUT_DIR/$IMAGE_NAME.iso"
rm -rf "$ISO_ROOT"

# Normalize QCOW2 for reproducibility
echo "🔧 Normalizing QCOW2 image..."
if command -v add-det &>/dev/null; then
    add-det "$OUTPUT_DIR/$IMAGE_NAME.qcow2"
fi

echo "✅ SUCCESS!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Bundle:  $OUTPUT_DIR/$IMAGE_NAME-$VERSION.tar.gz"
echo "💿 QCOW2:   $OUTPUT_DIR/$IMAGE_NAME.qcow2"
echo "🔢 Digest:  $SHA256"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "To run with dstack-vmm:"
echo "  dstack-vmm --image-path $OUTPUT_DIR/$IMAGE_NAME-$VERSION --app-id 0"
echo ""
echo "To test locally with QEMU:"
echo "  qemu-system-x86_64 -m 2G -kernel $BUNDLE_DIR/bzImage -initrd $BUNDLE_DIR/initramfs.cpio.gz -append \"console=ttyS0 init=/init\" -nographic"
