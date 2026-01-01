#!/bin/bash
set -e

# Repo URL for Oracle Linux 9 UEK R7 (x86_64)
REPO_URL="https://yum.oracle.com/repo/OracleLinux/OL9/UEKR7/x86_64"
OUTPUT_DIR="kernel-oracle"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "🔍 Fetching Oracle UEK kernel list..."
# Fetch index, grep for kernel pkgs, extract filenames, sort by version, take last (latest)
LATEST_RPM=$(curl -s "$REPO_URL/index.html" | \
    grep -o 'href="getPackage/kernel-uek-[0-9].*\.rpm"' | \
    sed 's/href="getPackage\///;s/"//' | \
    sort -V | \
    tail -n 1)

if [ -z "$LATEST_RPM" ]; then
    echo "❌ Could not find kernel-uek RPM"
    exit 1
fi

RPM_URL="$REPO_URL/getPackage/$LATEST_RPM"
echo "⬇️  Downloading $LATEST_RPM..."
echo "   URL: $RPM_URL"

curl -L -o "kernel.rpm" "$RPM_URL"

echo "📦 Extracting kernel RPM..."
# Try 7z if available (handles modern RPM compression better than old rpm2cpio)
if command -v 7z &>/dev/null; then
    # 7z recursively extracts the RPM content (cpio) then the cpio content
    7z x -y kernel.rpm
    # The output is usually a cpio archive named 'kernel.cpio' or similar, or just raw files
    # Check what we got
    if [ -f "kernel.cpio" ]; then
        7z x -y kernel.cpio
    elif [ -f "payload.cpio" ]; then # Some older RPM variants
        7z x -y payload.cpio
    elif ls *.cpio 1> /dev/null 2>&1; then
        CPIO_FILE=$(ls *.cpio | head -n1)
        7z x -y "$CPIO_FILE"
    else
        # Sometimes 7z extracts directly to dirs
        echo "   7z extraction complete (direct)."
    fi
else
    # Fallback to rpm2cpio
    rpm2cpio kernel.rpm | cpio -idm --quiet
fi

# Locate version and files
MODULES_DIR=$(find lib/modules -maxdepth 1 -type d -name "5.*" | head -n1)
KERNEL_VERSION=$(basename "$MODULES_DIR")
VMLINUZ=$(find lib/modules/"$KERNEL_VERSION" -name "vmlinuz" -o -name "bzImage" | head -n1)

if [ -z "$VMLINUZ" ]; then
    # Sometimes it's in /boot in the RPM
    VMLINUZ=$(find boot -name "vmlinuz*" | head -n1)
fi

echo "✅ Extracted Oracle UEK Kernel: $KERNEL_VERSION"
echo "   Modules: $MODULES_DIR"
echo "   Kernel:  $VMLINUZ"

# Create helper for dracut build
echo "$KERNEL_VERSION" > version.txt
ln -sf "$VMLINUZ" vmlinuz
ln -sf "$MODULES_DIR" modules
