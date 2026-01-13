#!/bin/bash
# Consolidated build script for reproducible GCP initramfs
set -e

echo "🏗️  Building reproducible initramfs for GCP..."

# 1. Build the Rust binary (static) using Nix
# We use nix-shell to ensure all dependencies are present, or just run cargo if in the right env.
# However, to be PURELY reproducible, we should do it via a Nix derivation.
# For now, let's use the local 'nix-build' on initramfs.nix which can take binaryPath.

echo "🦀 Building Rust binary..."
# Ensure we have the target
rustup target add x86_64-unknown-linux-musl

# Build with deterministic flags
export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"
cargo build --release --target x86_64-unknown-linux-musl

BINARY_PATH="$(pwd)/target/x86_64-unknown-linux-musl/release/paypal-auth-vm"

echo "❄️  Building initramfs and fetching kernel via Nix..."
nix-build initramfs.nix --argstr binaryPath "$BINARY_PATH" -o result

# Result will contain:
# result/initramfs.cpio.gz
# result/kernel (vmlinuz)

echo "📦 Extracting artifacts..."
cp result/initramfs.cpio.gz ./initramfs-gcp.img
cp result/kernel ./vmlinuz-gcp

echo "✅ Build complete!"
echo "📍 Initramfs: ./initramfs-gcp.img"
echo "📍 Kernel: ./vmlinuz-gcp"

# Reproducibility check (optional)
# sha256sum ./initramfs-gcp.img
