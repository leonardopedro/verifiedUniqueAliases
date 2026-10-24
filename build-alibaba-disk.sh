#!/bin/bash
# =============================================================================
# build-alibaba-disk.sh — RETIRED (v184), hard-fail stub.
#
# This script used to build output-alibaba/disk.img: a plain ext4 partition
# holding just the binary + a grub.cfg. That artifact is NOT the measured
# boot image this project deploys — no GPT/ESP, no shim/grub UKI chain, no
# kernel/initramfs, nothing in the measured manifest. Importing it (or its
# tarball) produces an instance that cannot boot the enclave, and because
# the output name pattern looked plausible it was once run by mistake
# during a deploy cycle (v184).
#
# The real builder — multi-stage Docker synthesis producing the deployable
# output-alibaba/disk-alibaba.raw (GPT + ESP: shim/grub/vmlinuz/initrd,
# digest-checked against the live manifest by check-manifest-parity.mjs):
#
#     bash build-alibaba-docker.sh
#
# =============================================================================
echo "❌ build-alibaba-disk.sh is retired — it built a legacy non-bootable artifact." >&2
echo "   Use the real measured-boot builder instead:" >&2
echo "       bash build-alibaba-docker.sh" >&2
echo "   (produces output-alibaba/disk-alibaba.raw — the image import-alibaba-image.sh uploads)" >&2
exit 1
