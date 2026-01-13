#!/usr/bin/env bash
set -euo pipefail

# Summary: This script takes a pragmatic approach to get the Oracle Linux 10 QEMU build working
# by accepting that direct BIOS boot is unreliable and using a known-good alternative approach.
#
# We'll use the existing Docker-based build as a reference but run everything directly on the host.

echo "🔧 Building Oracle Linux 10 QCOW2 image (native host build)"
echo "============================================================"
echo ""

# Run the build script directly on the host
./build-inside-vm.sh

echo ""
echo "✅ Build complete!"
