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
# The binary lives at /build/paypal-auth-vm-bin in the image-builder stage;
# the old single-path copy silently kept a STALE host-side ./paypal-auth-vm
# (|| true), which made the provenance preflight hash the wrong file.
"$ENGINE" cp tmp_oci:/build/paypal-auth-vm-bin ./paypal-auth-vm \
    || "$ENGINE" cp tmp_oci:/paypal-auth-vm-bin ./paypal-auth-vm \
    || { echo "❌ could not extract the enclave binary from the image" >&2; exit 1; }
"$ENGINE" rm tmp_oci

# Compute hashes
echo ""
echo "📋 Computing SHA256 hashes..."
QCOW_SHA=$(sha256sum paypal-auth-vm-oci.qcow2 | cut -d' ' -f1)
INITRD_SHA=$(sha256sum initramfs-oci.img | cut -d' ' -f1)

# ---------------------------------------------------------------------------
# GitHub provenance preflight (audit follow-up — the "❌ Binary" trap).
# verify.html checks api.github.com/.../attestations/sha256:<hash> for the
# EXACT hashes a report carries, and CI only attests artifacts built FROM A
# PUSHED COMMIT. A build from a dirty/uncommitted tree can never be attested,
# so every report from it fails provenance. Warn loudly before the operator
# imports + deploys a doomed image.
# ---------------------------------------------------------------------------
if command -v curl &>/dev/null; then
    REPO="leonardopedro/verifiedUniqueAliases"
    check_attested() {
        local label="$1" hash="$2" status
        if [[ -z "$hash" ]]; then echo "   ⚠️  $label: hash unavailable"; return; fi
        status=$(curl -s -o /dev/null -w '%{http_code}' \
            -H 'Accept: application/vnd.github+json' \
            "https://api.github.com/repos/${REPO}/attestations/sha256:${hash}" 2>/dev/null || echo 000)
        case "$status" in
            200) echo "   ✅ $label: attested by GitHub Actions (${hash:0:12}…)" ;;
            404) echo "   ❌ $label: NOT attested (${hash:0:12}…) — reports from this image will show a provenance failure." ;;
            *)   echo "   ⚠️  $label: could not query GitHub (HTTP $status) — verify later" ;;
        esac
    }
    echo ""
    echo "🔎 GitHub provenance preflight (did CI attest THIS build's hashes?)"
    if [[ -f paypal-auth-vm ]]; then
        check_attested "Enclave Binary" "$(sha256sum paypal-auth-vm | cut -d' ' -f1)"
    fi
    check_attested "Initramfs" "$INITRD_SHA"
    check_attested "QCOW2 Disk"  "$QCOW_SHA"
    echo "   (a ❌ means: commit + push first so CI attests, then rebuild from"
    echo "    the clean checkout — the build is bitwise-reproducible)"
fi

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
