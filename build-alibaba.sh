#!/bin/bash
# ==============================================================================
# build-alibaba.sh - Full build pipeline for Alibaba Cloud Confidential VM
#
# This script:
#   1. Builds the Rust binary with --features alibabacloud
#   2. Packages it into a format ready for disk image creation
#
# Usage: bash build-alibaba.sh
# ==============================================================================
set -eo pipefail

echo "============================================================"
echo "🏗️  Building PayPal Auth VM for Alibaba Cloud (Intel TDX)"
echo "============================================================"

echo "⏳ [1/2] Compiling Rust binary with alibabacloud feature..."

cargo build --release --features alibabacloud --target x86_64-unknown-linux-gnu

BINARY="target/x86_64-unknown-linux-gnu/release/paypal-auth-vm"

if [[ ! -f "$BINARY" ]]; then
    echo "❌ Build failed - binary not found"
    exit 1
fi

BINARY_SHA=$(sha256sum "$BINARY" | cut -d' ' -f1)

echo "✅ Binary built: $BINARY"
echo "   Size: $(du -h "$BINARY" | cut -f1)"
echo "   SHA256: $BINARY_SHA"
echo ""
echo "⏳ [2/2] Creating disk image for Alibaba Cloud..."

bash "$(dirname "$0")/build-alibaba-disk.sh" "$BINARY"

echo ""
echo "============================================================"
echo "🎉 Alibaba Cloud build complete!"
echo "============================================================"
echo "   Binary  : $BINARY"
echo "   Disk    : output-alibaba/disk-alibaba.tar.gz"
echo "   Deploy  : bash deploy-alibaba.sh"
echo "============================================================"
