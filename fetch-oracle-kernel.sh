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
    grep -o 'href="getPackage/kernel-uek-core-[0-9].*\.rpm"' | \
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
# Try 7z if available (handles modern RPM wrapping)
if command -v 7z &>/dev/null; then
    # 7z recursively extracts the RPM content
    7z x -y kernel.rpm
    
    # Handle the payload which might be zstd compressed cpio
    # Look for .cpio.zstd first
    if ls *.cpio.zstd 1> /dev/null 2>&1; then
        ZSTD_FILE=$(ls *.cpio.zstd | head -n1)
        echo "   Decompressing $ZSTD_FILE..."
        if command -v zstd &>/dev/null; then
            zstd -d --rm "$ZSTD_FILE"
        else
            7z x -y "$ZSTD_FILE"
        fi
    fi
    
    # Now look for .cpio (either directly extracted or decompressed above)
    if ls *.cpio 1> /dev/null 2>&1; then
        CPIO_FILE=$(ls *.cpio | head -n1)
        echo "   Extracting CPIO archive: $CPIO_FILE"
        # Use 7z or cpio to extract the archive
        # 7z is robust, but cpio -idm is classic
        cpio -idm --quiet < "$CPIO_FILE"
    else
        echo "⚠️ No .cpio file found after extraction? Checking for directories..."
    fi
else
    # Fallback to rpm2cpio (likely to fail on zstd RPMs)
    rpm2cpio kernel.rpm | cpio -idm --quiet
fi

# Locate version and files using recursive find to handle UsrMerge (usr/lib/modules)
echo "🔍 Searching for kernel files..."
MODULES_DIR=$(find . -type d -name "modules" | grep -v "kernel/" | head -n1)
if [ -z "$MODULES_DIR" ]; then
    echo "❌ Could not find 'modules' directory."
    echo "Directory listing:"
    ls -F
    exit 1
fi

# Drill down to actual version directory (usually inside modules/)
# e.g., usr/lib/modules/5.15.0-300.el9...
ACTUAL_MODULE_DIR=$(find "$MODULES_DIR" -maxdepth 1 -type d -name "5.*" | head -n1)

if [ -z "$ACTUAL_MODULE_DIR" ]; then
    echo "❌ Could not find kernel version directory inside $MODULES_DIR"
    exit 1
fi

KERNEL_VERSION=$(basename "$ACTUAL_MODULE_DIR")
echo "   Found version: $KERNEL_VERSION"

# Find vmlinuz anywhere
VMLINUZ=$(find . -name "vmlinuz*" | grep "$KERNEL_VERSION" | head -n1)

if [ -z "$VMLINUZ" ]; then
    # Try generic find
    VMLINUZ=$(find . -name "vmlinuz*" | head -n1)
fi

if [ -z "$VMLINUZ" ]; then
    echo "❌ Could not find vmlinuz binary."
    exit 1
fi

MODULES_ABS_DIR="$(pwd)/$ACTUAL_MODULE_DIR"
VMLINUZ_ABS="$(pwd)/$VMLINUZ"

echo "✅ Extracted Oracle UEK Kernel: $KERNEL_VERSION"
echo "   Modules: $MODULES_ABS_DIR"
echo "   Kernel:  $VMLINUZ_ABS"

# Create helper for dracut build
echo "$KERNEL_VERSION" > version.txt
ln -sf "$VMLINUZ_ABS" vmlinuz
ln -sf "$MODULES_ABS_DIR" modules
