#!/bin/bash
# =============================================================================
# build-alibaba-simple.sh — RETIRED (v185), hard-fail stub.
#
# This script built output-alibaba-simple/alibaba-fs.img: a plain ext4
# "optional persistent data" image with a grub.cfg that boots nothing the
# deployment flow uses. The enclave boots exclusively from the measured
# GPT/ESP disk (GPT + ESP: shim/grub/vmlinuz/initrd), and its own comment
# even admitted "the actual boot system uses ONLY the initramfs" — the
# artifact could never end up in a deployable image, but its name invited
# the same wrong-builder mistake as build-alibaba-disk.sh (v184).
#
# The real builder:
#
#     bash build-alibaba-docker.sh
#
# which produces output-alibaba/disk-alibaba.raw — the artifact
# import-alibaba-image.sh uploads and check-manifest-parity.mjs verifies.
# =============================================================================
echo "❌ build-alibaba-simple.sh is retired — it built an unused non-bootable ext4 image." >&2
echo "   Use the real reproducible builder instead:" >&2
echo "       bash build-alibaba-docker.sh" >&2
echo "   (produces output-alibaba/disk-alibaba.raw — the image import-alibaba-image.sh uploads)" >&2
exit 1
