#!/bin/bash
# Reproducible build script using Nix Flakes.
set -e

echo "🔨 Building PayPal Auth VM initramfs..."

# Build the initramfs using the flake
nix build .#initramfs-gcp -o result

echo "✅ Build complete!"
echo "Artifacts available in ./result:"
ls -l result/
