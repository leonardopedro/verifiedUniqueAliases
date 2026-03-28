#!/bin/bash
# Phala Network TEE (dstack) Debian Package Builder
# Builds a reproducible Debian package containing the official Phala TEE toolchain.

set -e

# Configuration
PACKAGE_NAME="phala-dstack"
VERSION="0.5.8"
INSTALL_PREFIX="/opt/phala-dstack"
BUILD_ROOT="/tmp/phala-dstack-deb-build"
SOURCE_DIR="/tmp/dstack-tee"

# Reproducibility
export SOURCE_DATE_EPOCH=1640995200 
export TZ=UTC

echo "🏗️  Building Phala Network TEE Debian package..."
echo "📦 Package: $PACKAGE_NAME"
echo "🔢 Version: $VERSION"

# 1. Ensure binaries are built
echo "🦀 Checking binaries in $SOURCE_DIR/target/release..."
BINARIES=("dstack-vmm" "dstack-guest-agent" "dstack-kms" "dstack-mr")

for bin in "${BINARIES[@]}"; do
    if [ ! -f "$SOURCE_DIR/target/release/$bin" ]; then
        echo "❌ Binary $bin not found. Building now..."
        cd "$SOURCE_DIR" && cargo build --release --bin "$bin"
    else
        echo "✅ Found $bin"
    fi
done

# 2. Prepare build directory
echo "📂 Preparing build directory..."
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT$INSTALL_PREFIX/bin"
mkdir -p "$BUILD_ROOT/usr/bin"

# 3. Copy binaries and normalize timestamps
for bin in "${BINARIES[@]}"; do
    echo "   Copying $bin..."
    cp "$SOURCE_DIR/target/release/$bin" "$BUILD_ROOT$INSTALL_PREFIX/bin/"
    touch -d "@${SOURCE_DATE_EPOCH}" "$BUILD_ROOT$INSTALL_PREFIX/bin/$bin"
    
    # Create symlinks in /usr/bin
    ln -sf "$INSTALL_PREFIX/bin/$bin" "$BUILD_ROOT/usr/bin/$bin"
done

# 4. Wrap into .deb with fpm
echo "🏗️  Wrapping into .deb with fpm..."
fpm -s dir -t deb \
    -n "$PACKAGE_NAME" \
    -v "$VERSION" \
    --prefix / \
    -C "$BUILD_ROOT" \
    --description "Official Phala Network TEE Toolchain (dstack suite)" \
    --maintainer "Phala Network & Antigravity Assistant" \
    --vendor "Phala Network" \
    --url "https://github.com/Dstack-TEE/dstack" \
    .

# Clean up
echo "🧹 Cleaning up..."
rm -rf "$BUILD_ROOT"

DEB_FILE=$(ls ${PACKAGE_NAME}_${VERSION}_*.deb)
echo "✅ SUCCESS! Package is ready: $DEB_FILE"
echo "Install with: sudo dpkg -i $DEB_FILE"
