#!/bin/bash
# Build initramfs using Docker with Oracle Linux
# This runs Dracut inside a proper FHS-compliant environment

set -e

# Fix for IDX/Podman: ensure TMPDIR points to an existing directory
# Podman defaults to /var/tmp which is missing in some IDX environments
export TMPDIR="/tmp"
mkdir -p "$TMPDIR"

echo "🐳 Building initramfs using Docker (Oracle Linux)..."
echo ""

# Check for Docker/Podman
if command -v docker &>/dev/null; then
    CONTAINER_CMD="docker"
elif command -v podman &>/dev/null; then
    CONTAINER_CMD="podman"
else
    echo "❌ Docker or Podman is required but not found!"
    echo "   Please install Docker or Podman."
    exit 1
fi

echo "Using: $CONTAINER_CMD"

# Build the Docker image
echo "🏗️  Building Docker image..."
$CONTAINER_CMD build --target builder -t paypal-auth-builder .

# Create output directory
mkdir -p docker-output

# Extract artifacts from the builder stage
echo "📦 Extracting build artifacts..."
$CONTAINER_CMD create --name paypal-extract paypal-auth-builder 2>/dev/null || true
$CONTAINER_CMD cp paypal-extract:/output/. ./docker-output/ 2>/dev/null || {
    # Alternative: if /output doesn't exist, try /app
    echo "   Trying alternative extraction path..."
    $CONTAINER_CMD cp paypal-extract:/app/initramfs-paypal-auth.img ./docker-output/ 2>/dev/null || true
    $CONTAINER_CMD cp paypal-extract:/app/vmlinuz ./docker-output/ 2>/dev/null || true
    $CONTAINER_CMD cp paypal-extract:/app/build-manifest.json ./docker-output/ 2>/dev/null || true
}
$CONTAINER_CMD rm paypal-extract 2>/dev/null || true

# Check what we got
echo ""
echo "📁 Extracted artifacts:"
ls -la docker-output/

# Copy to main directory for build-native.sh
if [ -f "docker-output/initramfs-paypal-auth.img" ]; then
    cp docker-output/initramfs-paypal-auth.img ./initramfs-paypal-auth.img
    echo "✅ Initramfs ready: initramfs-paypal-auth.img"
fi

if [ -f "docker-output/vmlinuz" ]; then
    cp docker-output/vmlinuz ./vmlinuz
    echo "✅ Kernel ready: vmlinuz"
fi

if [ -f "docker-output/paypal-auth-vm.efi" ]; then
    cp docker-output/paypal-auth-vm.efi ./paypal-auth-vm.efi
    echo "✅ UKI ready: paypal-auth-vm.efi"
fi

echo ""
echo "✅ Docker build complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next step: Create the bootable QCOW2 image:"
echo "  ./build-native.sh --skip-initramfs"
echo ""
