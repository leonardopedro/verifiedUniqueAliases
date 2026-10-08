#!/bin/bash
# ==============================================================================
# build-oci-docker.sh - Build Oracle Cloud bootable image using Docker
#
# Builds the binary (--features oci), initramfs, and QCOW2 disk image inside a
# Docker container for 100% reproducibility, then extracts artifacts to the host.
#
# Usage: bash build-oci-docker.sh
# ==============================================================================
set -eo pipefail

# Prefer docker, fall back to rootless podman
ENGINE="$(command -v docker || command -v podman || true)"
if [ -z "$ENGINE" ]; then
    echo "ERROR: neither docker nor podman found in PATH" >&2
    exit 1
fi

echo "============================================================"
echo "🐳 Building Oracle Cloud VM (AMD SEV-SNP) using $ENGINE"
echo "============================================================"

# Build the container image (binary + initramfs + qcow2)
"$ENGINE" build -f Dockerfile.oci -t paypal-auth-vm:oci .

# Extract artifacts from the container
echo ""
echo "📦 Extracting artifacts..."
"$ENGINE" rm -f tmp_oci 2>/dev/null || true
"$ENGINE" create --name tmp_oci paypal-auth-vm:oci
"$ENGINE" cp tmp_oci:/paypal-auth-vm-oci.qcow2 ./paypal-auth-vm-oci.qcow2
"$ENGINE" cp tmp_oci:/initramfs-paypal-auth.img ./initramfs-oci.img
"$ENGINE" cp tmp_oci:/grub.cfg ./grub-oci.cfg
"$ENGINE" cp tmp_oci:/packages.txt ./packages-oci.txt
"$ENGINE" cp tmp_oci:/paypal-auth-vm-bin ./paypal-auth-vm || true
"$ENGINE" rm tmp_oci

# Compute hashes
echo ""
echo "📋 Computing SHA256 hashes..."
QCOW_SHA=$(sha256sum paypal-auth-vm-oci.qcow2 | cut -d' ' -f1)
INITRD_SHA=$(sha256sum initramfs-oci.img | cut -d' ' -f1)

echo ""
echo "============================================================"
echo "✅ Oracle Cloud Build Complete!"
echo "============================================================"
echo "   paypal-auth-vm-oci.qcow2: $QCOW_SHA (import this)"
echo "   initramfs-oci.img:        $INITRD_SHA"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Import the QCOW2 as an Oracle Cloud custom image:"
echo "     bash import-oci-image.sh"
echo "  2. Deploy: bash deploy-oci.sh"
echo ""

# Output for GitHub Actions if present
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "disk-sha256=$QCOW_SHA" >> "$GITHUB_OUTPUT"
    echo "initrd-sha256=$INITRD_SHA" >> "$GITHUB_OUTPUT"
fi
