#!/bin/bash
# =============================================================================
# build-alibaba.sh — RETIRED (v184), fail-fast stub.
#
# This wrapper used to: (1) cargo build WITHOUT the `alibabacloud` feature
# flag the deployment image needs, then (2) chain into the retired
# build-alibaba-disk.sh, which produced output-alibaba/disk-alibaba.tar.gz —
# a plain ext4 image with no GPT/ESP/UKI measured-boot chain that cannot
# boot the enclave.
#
# The real build is the multi-stage Docker synthesis (snapshot-pinned Debian
# Trixie, correct feature flag, measured ESP disk):
#
#     bash build-alibaba-docker.sh
#
# which produces output-alibaba/disk-alibaba.raw — the artifact
# import-alibaba-image.sh uploads and check-manifest-parity.mjs verifies.
# =============================================================================
echo "❌ build-alibaba.sh is retired — it built the wrong artifact (no measured boot chain)." >&2
echo "   Use the real reproducible builder instead:" >&2
echo "       bash build-alibaba-docker.sh" >&2
echo "   (produces output-alibaba/disk-alibaba.raw — the image import-alibaba-image.sh uploads)" >&2
exit 1
