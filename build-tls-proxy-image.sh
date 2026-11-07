#!/bin/bash
# =============================================================================
# build-tls-proxy-image.sh — build the DUAL-SERVICE confidential VM disk.
#
# Same pipeline as the PayPal-only image (Dockerfile.alibaba: rust-builder →
# image-builder → assembler), with `--build-arg TLS_PROXY=1`, which additionally
# compiles tls-proxy/ and packs its binary into the initramfs next to /init.
# Without the arg the assembler produces the byte-identical PayPal-only disk, so
# the existing workflow is unaffected by this script's existence.
#
# Produces: output-tls-proxy/disk-tls-proxy.raw  (GPT + single ESP, UEFI)
#           output-tls-proxy/SHA256SUMS
#
# Usage: bash build-tls-proxy-image.sh
# =============================================================================
set -eo pipefail

ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
    if command -v docker >/dev/null 2>&1; then ENGINE=docker
    elif command -v podman >/dev/null 2>&1; then ENGINE=podman
    else echo "❌ Neither docker nor podman found"; exit 1
    fi
fi

TAG="${TLS_PROXY_IMAGE_TAG:-paypal-auth-vm:dual-service}"
OUT_DIR="$(pwd)/output-tls-proxy"

echo "=============================================================="
echo "🧩 Building dual-service confidential VM disk (PayPal + TLS proxy)"
echo "   engine : $ENGINE"
echo "   image  : $TAG"
echo "=============================================================="

# Engine-correct build flags. The two engines need DIFFERENT sets and getting
# this wrong fails in seconds, not minutes:
#   * --security-opt/--cap-add exist for podman build only. `docker buildx
#     build` (what `docker build` is on any current runner) has no such flags
#     and dies with "unknown flag: --cap-add" immediately — that was the first
#     CI failure of this workflow.
#   * --load is docker-only and REQUIRED whenever buildx runs a
#     docker-container builder (setup-buildx-action sets one as default):
#     without it the build succeeds into the cache and the `create` below then
#     fails with "no such image".
BUILD_FLAGS=(--build-arg TLS_PROXY=1 -f Dockerfile.alibaba -t "$TAG")
if [[ "$ENGINE" == "docker" ]]; then
    BUILD_FLAGS+=(--load)
else
    BUILD_FLAGS+=(--security-opt seccomp=unconfined --cap-add=SYS_ADMIN)
fi

# Same retry-and-annotate shape as build-attest.yml: raw job logs need
# repo-admin access, so the tail of a failed attempt goes into a check-run
# annotation where it is publicly readable.
for attempt in 1 2; do
    if $ENGINE build "${BUILD_FLAGS[@]}" . 2>&1 | tee /tmp/dual-build.log; then
        break
    fi
    echo "::error title=$ENGINE build failed (attempt $attempt)::$(tail -c 1800 /tmp/dual-build.log | tr '\n' '|')"
    [[ "$attempt" == 1 ]] && { echo "build attempt 1 failed — retrying once"; sleep 20; } || exit 1
done

mkdir -p "$OUT_DIR"
$ENGINE rm -f tmp-tls-proxy 2>/dev/null || true
$ENGINE create --name tmp-tls-proxy "$TAG" >/dev/null
$ENGINE cp tmp-tls-proxy:/disk-alibaba.raw "$OUT_DIR/disk-tls-proxy.raw"
# The proxy binary and the initramfs are attested artifacts in their own right
# (the initramfs digest is a measured-boot input), so publish them beside the
# disk rather than only inside it.
$ENGINE cp tmp-tls-proxy:/tls-proxy-bin "$OUT_DIR/tls-proxy-bin" 2>/dev/null || true
$ENGINE cp tmp-tls-proxy:/initramfs-paypal-auth.img "$OUT_DIR/initramfs-dual.img" 2>/dev/null || true
$ENGINE rm tmp-tls-proxy >/dev/null

(
    cd "$OUT_DIR"
    sha256sum disk-tls-proxy.raw >SHA256SUMS
    [[ -f tls-proxy-bin ]] && sha256sum tls-proxy-bin >>SHA256SUMS
    [[ -f initramfs-dual.img ]] && sha256sum initramfs-dual.img >>SHA256SUMS
)

echo "=============================================================="
echo "✅ Built $OUT_DIR/disk-tls-proxy.raw"
echo "   Size : $(( $(stat -c%s "$OUT_DIR/disk-tls-proxy.raw") / 1048576 )) MiB"
cat "$OUT_DIR/SHA256SUMS"
echo "=============================================================="
echo "Next: import the disk (import-alibaba-image.sh), launch it with"
echo "deploy-alibaba.sh, and ship a config whose \"services\" block enables"
echo "\"tls_proxy\" — see config.proxy.example.json and docs/tls-proxy.md."
echo "The dual image has its OWN RTMR2/self-measure pins: rotate them before"
echo "any audit trusts this build."
echo "=============================================================="
