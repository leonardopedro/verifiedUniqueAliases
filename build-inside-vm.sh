#!/bin/bash
# This script runs INSIDE the Oracle Linux QEMU VM to build the initramfs

set -e

echo "🔧 Setting up build environment inside VM..."

# Install dependencies
echo "📦 Installing packages..."
microdnf install -y \
    dracut \
    kernel-core \
    kernel-modules \
    kmod \
    curl \
    gcc \
    gcc-c++ \
    make \
    util-linux \
    linux-firmware \
    python3 \
    python3-pip \
    libarchive \
    git \
    cpio \
    gzip

# Install Rust
echo "🦀 Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91.1 --profile minimal
source $HOME/.cargo/env

# Install add-determinism
echo "🔨 Installing add-determinism..."
cargo install -j 1 add-determinism

# Add cargo to PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Change to mounted source directory
cd /mnt/source

# Run the build
echo "🏗️  Building initramfs..."
./build-initramfs-dracut.sh

echo "✅ Build complete!"
echo "📁 Output location: img/initramfs-paypal-auth.img"
echo ""
echo "To copy the file to host, you can use:"
echo "  cp img/initramfs-paypal-auth.img /mnt/source/"
