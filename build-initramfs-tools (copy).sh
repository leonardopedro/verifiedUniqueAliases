#!/bin/bash
set -e

# Ensure cargo binaries are in PATH
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"

echo "🏗️  Building reproducible initramfs with initramfs-tools..."

# Set reproducible build environment
export SOURCE_DATE_EPOCH=1712260800
export TZ=UTC
export LC_ALL=C.UTF-8

BUILD_TARGET="x86_64-unknown-linux-gnu"

# Determine Rust binary location (Support local, docker, and cloud build VM)
if [ -f "/app/target/$BUILD_TARGET/release/paypal-auth-vm" ]; then
    BIN_PATH="/app/target/$BUILD_TARGET/release/paypal-auth-vm"
elif [ -f "./target/$BUILD_TARGET/release/paypal-auth-vm" ]; then
    BIN_PATH="./target/$BUILD_TARGET/release/paypal-auth-vm"
elif [ -f "/tmp/paypal-auth-vm-bin" ]; then
    BIN_PATH="/tmp/paypal-auth-vm-bin"
elif [ -f "./paypal-auth-vm-bin" ]; then
    BIN_PATH="./paypal-auth-vm-bin"
elif [ -f "$HOME/paypal-auth-vm-bin" ]; then
    BIN_PATH="$HOME/paypal-auth-vm-bin"
else
    echo "❌ ERROR: No pre-built Rust binary found at any expected location!"
    echo "Check: /app/target/..., ./target/..., or ~/paypal-auth-vm-bin"
    exit 1
fi

echo "✅ Using pre-built binary: $BIN_PATH"
# Ensure executable
chmod +x "$BIN_PATH"

# Copy binary to /tmp for hook detection
if [ "$BIN_PATH" != "/tmp/paypal-auth-vm-bin" ]; then
    cp "$BIN_PATH" /tmp/paypal-auth-vm-bin
    chmod +x /tmp/paypal-auth-vm-bin
    echo "📋 Copied binary to /tmp/paypal-auth-vm-bin"
fi

# Build base initramfs with mkinitramfs (kernel modules, busybox, etc.)
echo "🔨 Running mkinitramfs for base image..."
# Get kernel version (take the latest/highest version if multiple are present)
KERNEL_VERSION=$(ls -1 /lib/modules | sort -rV | head -n 1)
echo "🔍 Using kernel version: $KERNEL_VERSION"

mkdir -p output
OUTPUT_FILE="$(pwd)/output/initramfs-paypal-auth.img"

if [ ! -d "/lib/modules/$KERNEL_VERSION" ]; then
    echo "❌ Kernel modules for $KERNEL_VERSION not found! Available:"
    ls -F /lib/modules
    exit 1
fi

# Workaround for iscsi permission issue
sudo touch /etc/iscsi/initiatorname.iscsi 2>/dev/null || true
sudo chmod 644 /etc/iscsi/initiatorname.iscsi 2>/dev/null || true

# Build base initramfs (hooks will run but may not complete due to multi-stage DESTDIR issue)
sudo rm -f /boot/initrd.img-$KERNEL_VERSION
sudo mkinitramfs -o /boot/initrd.img-$KERNEL_VERSION $KERNEL_VERSION

# Manually add binaries and libraries to the initramfs
echo "📦 Adding binaries and libraries to initramfs..."
cd /tmp
rm -rf initramfs_manual
mkdir initramfs_manual
cd initramfs_manual

# Extract base initramfs
cpio -idm < /boot/initrd.img-$KERNEL_VERSION >/dev/null 2>&1

# Add /init binary with dependencies
echo "  Adding /init binary..."
cp /tmp/paypal-auth-vm-bin ./init
chmod 755 ./init

# Copy libraries for /init
ldd /tmp/paypal-auth-vm-bin 2>&1 | grep "=>" | awk '{print $3}' | while read lib; do
    if [ -n "$lib" ] && [ -f "$lib" ]; then
        mkdir -p "./$(dirname $lib)"
        cp -n "$lib" "./$lib" 2>/dev/null || true
    fi
done
ldd /tmp/paypal-auth-vm-bin 2>&1 | grep "/ld-" | awk '{print $1}' | while read linker; do
    if [ -f "$linker" ]; then
        mkdir -p "./$(dirname $linker)"
        cp -n "$linker" "./$linker" 2>/dev/null || true
    fi
done

# Add TPM2 tools with dependencies
echo "  Adding TPM2 tools..."
mkdir -p usr/bin
for tool in tpm2_createpolicy tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_quote tpm2_createak tpm2_pcrextend; do
    if [ -f /usr/bin/$tool ]; then
        cp /usr/bin/$tool usr/bin/
        ldd /usr/bin/$tool 2>&1 | grep "=>" | awk '{print $3}' | while read lib; do
            [ -n "$lib" ] && [ -f "$lib" ] && mkdir -p "./$(dirname $lib)" && cp -n "$lib" "./$lib" 2>/dev/null || true
        done
    fi
done

# Add other required tools
echo "  Adding network and utility tools..."
[ -f /sbin/ip ] && cp /sbin/ip usr/bin/ || [ -f /usr/sbin/ip ] && cp /usr/sbin/ip usr/bin/

# Add modprobe with dependencies
if [ -f /sbin/modprobe ]; then
    cp /sbin/modprobe sbin/modprobe
    ldd /sbin/modprobe 2>&1 | grep "=>" | awk '{print $3}' | while read lib; do
        [ -n "$lib" ] && [ -f "$lib" ] && mkdir -p "./$(dirname $lib)" && cp -n "$lib" "./$lib" 2>/dev/null || true
    done
fi

[ -f /usr/bin/curl ] && cp /usr/bin/curl usr/bin/ || true
[ -f /usr/bin/sha256sum ] && cp /usr/bin/sha256sum usr/bin/ || true

# Repack as gzip-compressed cpio
echo "  Repacking initramfs..."
find . | cpio --quiet -o -H newc | gzip -n > "$OUTPUT_FILE"

# Clean up
cd ~
rm -rf /tmp/initramfs_manual

# Restore ownership
sudo chown $(whoami):$(whoami) "$OUTPUT_FILE"

# Verify the result
echo "🔍 Verifying initramfs contents..."
cd /tmp
rm -rf initramfs_verify
mkdir initramfs_verify
cd initramfs_verify
gunzip -c "$OUTPUT_FILE" | cpio -idm >/dev/null 2>&1

if [ -f init ]; then
    echo "  ✓ /init binary present"
else
    echo "  ✗ ERROR: /init binary missing!"
    exit 1
fi

LIB_COUNT=$(find lib lib64 usr/lib -name '*.so*' 2>/dev/null | wc -l)
echo "  ✓ $LIB_COUNT shared libraries included"

if [ -f usr/bin/tpm2_createpolicy ]; then
    echo "  ✓ TPM2 tools included"
else
    echo "  ✗ WARNING: TPM2 tools missing"
fi

cd ~
rm -rf /tmp/initramfs_verify

HASH=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)
echo "$HASH" > "${OUTPUT_FILE}.sha256"

# Create build manifest
RUST_VER=$(rustc --version 2>/dev/null || echo "pre-built container")
cat > output/build-manifest.json << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "kernel_version": "$KERNEL_VERSION",
  "rust_version": "$RUST_VER",
  "target": "$BUILD_TARGET",
  "initramfs_sha256": "$HASH"
}
EOF

echo "✅ Build complete. SHA256: $HASH"
