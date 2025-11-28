#!/bin/bash
set -e

echo "🔬 Testing Rust Binary Reproducibility with cargo-reproduce"
echo "============================================================="
echo ""

# Ensure cargo bin is in PATH for add-det
export PATH="$HOME/.cargo/bin:$PATH"

# Set reproducible build environment (same as module-setup.sh and build-initramfs-dracut.sh)
export SOURCE_DATE_EPOCH=1640995200  # 2022-01-01 00:00:00 UTC
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Build target
BUILD_TARGET="x86_64-unknown-linux-gnu"

# Build flags (same as module-setup.sh)
export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_OPT_LEVEL=2

# Add target if not already added
rustup target add $BUILD_TARGET 2>/dev/null || true

# Check if add-det is available
if command -v add-det &> /dev/null; then
    echo "✅ add-det found at: $(which add-det)"
    USE_ADD_DET=true
else
    echo "❌ add-det not found!"
    echo "   Installing add-determinism..."
    cargo install add-determinism
    USE_ADD_DET=true
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 First Build"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Clean and build first time
cargo clean
cargo build --release --target $BUILD_TARGET

# Apply add-det
if [ "$USE_ADD_DET" = true ]; then
    echo "🔧 Applying add-det normalization..."
    add-det target/$BUILD_TARGET/release/paypal-auth-vm
fi

# Normalize timestamp
touch -d "@${SOURCE_DATE_EPOCH}" target/$BUILD_TARGET/release/paypal-auth-vm

# Save first binary and compute hash
cp target/$BUILD_TARGET/release/paypal-auth-vm /tmp/paypal-auth-vm-build1
HASH1=$(sha256sum /tmp/paypal-auth-vm-build1 | cut -d' ' -f1)
SIZE1=$(stat -c%s /tmp/paypal-auth-vm-build1)

echo "✅ First build complete"
echo "   SHA256: $HASH1"
echo "   Size:   $SIZE1 bytes"

# Wait a moment to ensure different build environment
sleep 2

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Second Build"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Clean and build second time
cargo clean
cargo build --release --target $BUILD_TARGET

# Apply add-det
if [ "$USE_ADD_DET" = true ]; then
    echo "🔧 Applying add-det normalization..."
    add-det target/$BUILD_TARGET/release/paypal-auth-vm
fi

# Normalize timestamp
touch -d "@${SOURCE_DATE_EPOCH}" target/$BUILD_TARGET/release/paypal-auth-vm

# Save second binary and compute hash
cp target/$BUILD_TARGET/release/paypal-auth-vm /tmp/paypal-auth-vm-build2
HASH2=$(sha256sum /tmp/paypal-auth-vm-build2 | cut -d' ' -f1)
SIZE2=$(stat -c%s /tmp/paypal-auth-vm-build2)

echo "✅ Second build complete"
echo "   SHA256: $HASH2"
echo "   Size:   $SIZE2 bytes"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 Comparison Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$HASH1" = "$HASH2" ]; then
    echo "✅ SUCCESS: Binaries are IDENTICAL! 🎉"
    echo ""
    echo "   Build 1 SHA256: $HASH1"
    echo "   Build 2 SHA256: $HASH2"
    echo ""
    echo "   The Rust binary build is reproducible!"
    echo ""
    echo "🧹 Cleaning up temporary files..."
    rm -f /tmp/paypal-auth-vm-build1 /tmp/paypal-auth-vm-build2
else
    echo "❌ FAILURE: Binaries are DIFFERENT!"
    echo ""
    echo "   Build 1 SHA256: $HASH1"
    echo "   Build 2 SHA256: $HASH2"
    echo ""
    echo "   Size comparison:"
    echo "   Build 1: $SIZE1 bytes"
    echo "   Build 2: $SIZE2 bytes"
    echo ""
    
    # Run diffoscope if available
    if command -v diffoscope &> /dev/null; then
        echo "🔬 Running diffoscope to analyze differences..."
        echo ""
        diffoscope /tmp/paypal-auth-vm-build1 /tmp/paypal-auth-vm-build2 || true
    else
        echo "💡 Install diffoscope for detailed analysis:"
        echo "   pip install diffoscope"
        echo ""
        echo "   You can also manually compare the binaries:"
        echo "   - Build 1: /tmp/paypal-auth-vm-build1"
        echo "   - Build 2: /tmp/paypal-auth-vm-build2"
    fi
    
    exit 1
fi

echo "✅ Reproducibility test complete!"
