#!/bin/bash
set -e

# Configuration
PACKAGE_NAME="oci-cli"
VERSION="3.76.2" # Latest version as detected
INSTALL_PREFIX="/opt/oci-cli"
BUILD_DIR="/tmp/oci-cli-build"

echo "🧪 Building OCI CLI Debian package..."
echo "📦 Package: $PACKAGE_NAME"
echo "🔢 Version: $VERSION"
echo "📂 Prefix: $INSTALL_PREFIX"

# 1. Clean build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR$INSTALL_PREFIX"

# 2. Create a fresh virtual environment
echo "🐍 Creating virtual environment..."
python3 -m venv "$BUILD_DIR$INSTALL_PREFIX"

# 3. Upgrade pip and install oci-cli
echo "📥 Installing oci-cli..."
"$BUILD_DIR$INSTALL_PREFIX/bin/pip" install --upgrade pip
"$BUILD_DIR$INSTALL_PREFIX/bin/pip" install "oci-cli==$VERSION"

# 4. Modify Shebangs
echo "🔧 Normalizing shebangs..."
# Finds all files in bin, replaces the build-time path with the final install-time path
find "$BUILD_DIR$INSTALL_PREFIX/bin" -type f -exec sed -i "s|$BUILD_DIR$INSTALL_PREFIX|$INSTALL_PREFIX|g" {} +

# 5. Create /usr/bin symlink
echo "🔗 Creating /usr/bin/oci symlink..."
mkdir -p "$BUILD_DIR/usr/bin"
ln -sf "$INSTALL_PREFIX/bin/oci" "$BUILD_DIR/usr/bin/oci"

# 6. Build the package with fpm
echo "🏗️  Wrapping into .deb..."
fpm -s dir -t deb \
    -n "$PACKAGE_NAME" \
    -v "$VERSION" \
    --prefix / \
    -C "$BUILD_DIR" \
    --description "Oracle Cloud Infrastructure CLI (Bundled Venv)" \
    --maintainer "Leonardo Pedro <leonardopedro4@gmail.com>" \
    .

# Clean up
echo "🧹 Cleaning up build directory..."
rm -rf "$BUILD_DIR"

echo "✅ SUCCESS! Package is ready in the current folder: $(ls oci-cli_${VERSION}_amd64.deb)"
