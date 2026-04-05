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
else
    echo "❌ ERROR: No pre-built Rust binary found at any expected location!"
    echo "Check: /app/target/..., ./target/..., or ~/paypal-auth-vm-bin"
    exit 1
fi

echo "✅ Using pre-built binary: $BIN_PATH"
# Ensure executable
chmod +x "$BIN_PATH"

# Configure initramfs-tools in a local directory (no sudo required for config)
echo "📋 Configuring local initramfs-tools environment..."
CFG_DIR="$(pwd)/initramfs_cfg"
mkdir -p "$CFG_DIR/hooks"
mkdir -p "$CFG_DIR/scripts/init-premount"
mkdir -p "$CFG_DIR/conf.d"

# Use system config as base
cp /etc/initramfs-tools/initramfs.conf "$CFG_DIR/" || echo "MODULES=most" > "$CFG_DIR/initramfs.conf"

# Set host-only mode if possible, but explicitly force network drivers
sed -i 's/^MODULES=.*/MODULES=dep/' "$CFG_DIR/initramfs.conf"
echo "gve" >> "$CFG_DIR/modules"
echo "virtio_net" >> "$CFG_DIR/modules"
echo "tpm_tis" >> "$CFG_DIR/modules"
echo "sev-guest" >> "$CFG_DIR/modules"

# Determine Rust binary location
if [ -f "/app/target/$BUILD_TARGET/release/paypal-auth-vm" ]; then
    BIN_PATH="/app/target/$BUILD_TARGET/release/paypal-auth-vm"
elif [ -f "./target/$BUILD_TARGET/release/paypal-auth-vm" ]; then
    BIN_PATH="./target/$BUILD_TARGET/release/paypal-auth-vm"
elif [ -f "/tmp/paypal-auth-vm-bin" ]; then
    BIN_PATH="/tmp/paypal-auth-vm-bin"
else
    echo "❌ ERROR: No pre-built binary found! Compilation skipped in cloud-only mode."
    exit 1
fi

echo "✅ Using binary: $BIN_PATH"
# Correct hooks/paypal-auth binary path
sed -i "s|copy_exec /app/target/.*|copy_exec ${BIN_PATH} /usr/bin/paypal-auth-vm|" hooks/paypal-auth

cp hooks/paypal-auth "$CFG_DIR/hooks/"
cp hooks/zz-reproducible.sh "$CFG_DIR/hooks/"
cp scripts/init-premount/paypal-auth "$CFG_DIR/scripts/init-premount/"

chmod +x "$CFG_DIR/hooks/"* "$CFG_DIR/scripts/init-premount/"*

# Build initramfs
echo "🔨 Running mkinitramfs using local config..."
# Get kernel version (take the latest/highest version if multiple are present)
KERNEL_VERSION=$(ls -1 /lib/modules | sort -rV | head -n 1)
echo "🔍 Using kernel version: $KERNEL_VERSION"

mkdir -p output
OUTPUT_FILE="output/initramfs-paypal-auth.img"

if [ ! -d "/lib/modules/$KERNEL_VERSION" ]; then
    echo "❌ Kernel modules for $KERNEL_VERSION not found! Available:"
    ls -F /lib/modules
    exit 1
fi

# We use -d to specify our local configuration directory
if ! mkinitramfs -d "$CFG_DIR" -o "$OUTPUT_FILE" "$KERNEL_VERSION"; then
    echo "⚠️  mkinitramfs failed with MODULES=dep. Falling back to MODULES=most..."
    sed -i 's/^MODULES=dep/MODULES=most/' "$CFG_DIR/initramfs.conf"
    mkinitramfs -d "$CFG_DIR" -o "$OUTPUT_FILE" "$KERNEL_VERSION"
fi

# Normalize the resulting image by extracting and repacking
# The image produced by mkinitramfs is now final because our hook placed the binary at /init
echo "✅ mkinitramfs successfully generated $OUTPUT_FILE with native PID 1 Rust init."


# 4. Final step: The file is already complete at $OUTPUT_FILE
sudo chown $(whoami):$(whoami) "$OUTPUT_FILE"

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
