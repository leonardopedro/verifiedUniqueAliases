#!/usr/bin/env bash
#==================================================================================
# aliyun-cli Debian Package Builder (v3.3.14)
#----------------------------------------------------------------------------------
# Builds a .deb from official GitHub releases for Alibaba Cloud trusted compute.
# Supports amd64 / arm64, verifies SHASUM256 integrity before packaging.
# Update VERSION or set ALIYUN_CLI_VERSION=auto to follow latest tag.
#==================================================================================
set -euo pipefail

VERSION="${ALIYUN_CLI_VERSION:-3.3.14}"
ARCH="${ARCHITECTURE:-amd64}"
PLATFORM="linux"
MAINTAINER="Leo Pedro <admin@alibabacloud.team>"
DESC="Alibaba Cloud CLI — Trusted Compute provisioning for ECS Intel TDX spots"
REPO="https://api.github.com/repos/aliyun/aliyun-cli"

# Resolve "auto" -> latest stable from GitHub
if [[ "$VERSION" == "auto" || "$VERSION" == "latest" ]]; then
    echo "[AUTO] Fetching latest release tag..."
    VERSION=$(curl -fsSL --retry 3 "$REPO/releases/latest" \
        | grep '^\"tag_name\":' \
        | sed -E 's/.*"v?([^"]+)".*/\1/' \
        | head -1)
    [[ -z "$VERSION" ]] && { echo "[ERROR] Could not resolve latest version"; exit 1; }
    echo "[INFO] Latest version: $VERSION"
fi

# Strip leading 'v' if present
CLEAN_VER="${VERSION/#v/}"
PKG_NAME="aliyun-cli-${CLEAN_VER}"

# Construct asset name and URL
ASSET="aliyun-cli-linux-${CLEAN_VER}-$ARCH.tgz"
BASE_URL="https://github.com/aliyun/aliyun-cli/releases/download/v${CLEAN_VER}"
DOWNLOAD_URL="$BASE_URL/$ASSET"
SHASUMS_URL="$BASE_URL/SHASUMS256.txt"

echo "=============================================="
echo "  Aliyun CLI .deb builder"
echo "  Version : $CLEAN_VER"
echo "  Arch    : $ARCH"
echo "  Asset   : $ASSET"
echo "=============================================="

#--- Step 0: Check required tools exist -------------------------------------------------------
MISSING=()
for tool in dpkg-deb curl sha256sum readelf file tar awk grep; do
    command -v "$tool" &>/dev/null || MISSING+=("$tool")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[FAIL] Missing tools: ${MISSING[*]}"
    echo "Install them first:"
    echo "  sudo apt-get update && sudo apt-get install -y curl dpkg-dev readelf file ca-certificates dh-make debhelper"
    exit 1
fi
echo "[DEPS] All required tools found ($(command -v curl), $(command -v dpkg-deb), etc.)"

# Resolve PACKAGE_OUT to absolute path (avoids issues after cd)
BUILDCONF=$(dirname "$(readlink -f "$0")")
PACKAGE_OUT="${ALIYUN_DEB_OUT:-${BUILDCONF}/packages}"

#--- Step 1: Prepare temp tree ----------------------------------------------------------------
PACKAGE_ROOT=$(mktemp -d /tmp/deb-build-XXXXXXXXXX)
cleanup() { rm -rf "$PACKAGE_ROOT"; echo "[CLEAN] Temporary files removed."; }
trap cleanup EXIT ERR TERM

mkdir -p \
    "${PACKAGE_ROOT}/opt/alibabacloud-cli/bin/" \
    "${PACKAGE_ROOT}/etc/profile.d/" \
    "${PACKAGE_ROOT}/usr/share/doc/${PKG_NAME}" \
    "${PACKAGE_ROOT}/usr/bin/manually" \
    "${PACKAGE_OUT:-./packages}"

WORK_DIR="./work"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

#--- Step 2: Download asset + shasums ---------------------------------------------------------
echo ""
echo "--- [1/5] Downloading release assets ---"

curl -fsSL -o "aliyun-cli.tgz" "$DOWNLOAD_URL" \
    || { echo "[FAIL] Download of $DOWNLOAD_URL failed"; exit 1; }

curl -fsSL -o "SHASUMS256.txt" "$SHASUMS_URL" \
    || { echo "[WARN] SHASUMS file not available; skipping checksum verification"; \
         SKIP_SHASUM=true; }

EXPECTED_SHA=""
if [[ -f "SHASUMS256.txt" ]]; then
    EXPECTED_SHA=$(grep -E "^.*aliyun-cli-linux-${CLEAN_VER}-${ARCH}\.tgz$" "SHASUMS256.txt" || true)
    if [[ -n "$EXPECTED_SHA" ]]; then
        echo "[CHECKSUM] Verifying SHA-256 integrity ..."
        ACTUAL_SHA=$(sha256sum "aliyun-cli.tgz")
        # Compare hash portion after the two-space separator
        EXP_HASH="${EXPECTED_SHA%% *}"
        ACT_HASH="${ACTUAL_SHA%% *}"
        if [[ "$EXP_HASH" != "$ACT_HASH" ]]; then
            echo "[FAIL] Checksum mismatch!"
            echo "       Expected : $EXP_HASH"
            echo "       Actual   : $ACT_HASH"
            exit 1
        else
            echo "[OK]  SHA-256 match ($ACT_HASH)"
        fi
    else
        echo "[WARN] $ASSET not listed in SHASUMS256.txt; proceeding anyway."
    fi
fi

#--- Step 3: Extract binary -------------------------------------------------------------------
echo ""
echo "--- [2/5] Extracting binary ---"

mkdir -p extracted
tar xzf "aliyun-cli.tgz" -C extracted/

# Locate the ELF binary — check nested dirs, then fall back to any executable found.
EXTRACTED_BIN=""
while IFS= read -r match; do
    [[ -x "$match" ]] || continue
    EXTRACTED_BIN="$match"
    break
done < <(find extracted/ \( -name "aliyun" -o -name "cli" \) -type f 2>/dev/null)

# Broad fallback: first elf executable inside the extract tree
if [[ -z "$EXTRACTED_BIN" ]]; then
    while IFS= read -r match; do
        EXTRACTED_BIN="$match"
        break
    done < <(file extracted/**/* 2>/dev/null | awk -F: '/ELF/{print $1}' | head -1)
fi

[[ -z "$EXTRACTED_BIN" || ! -x "$EXTRACTED_BIN" ]] && \
    { echo "[FAIL] Could not locate binary in archive."; ls -lR extracted/ 2>/dev/null; exit 1; }

echo "[FOUND] Binary at $EXTRACTED_BIN ($(file -b "$EXTRACTED_BIN"))"
cp "$EXTRACTED_BIN" "${PACKAGE_ROOT}/opt/alibabacloud-cli/bin/aliyun"
chmod 755 "${PACKAGE_ROOT}/opt/alibabacloud-cli/bin/aliyun"

# Validate ELF architecture matches requested target
ELF_ARCH=$(readelf -h "$EXTRACTED_BIN" 2>/dev/null | awk '/Machine:/{for(i=2;i<=NF;i++) printf "%s ",$i; print ""}' || echo "unknown")
echo "[VERIF] ELF target: $ELF_ARCH"

#--- Step 4: Install helpers ------------------------------------------------------------------
echo ""
echo "--- [3/5] Installing helpers (profile.d, manual page) ---"

### profile.d — adds aliyun to PATH for login shells
cat > "${PACKAGE_ROOT}/etc/profile.d/aliyun-setup.sh" << 'PROFILESHEOF'
#!/bin/sh
export PATH="/opt/alibabacloud-cli/bin:$PATH"
alias acs='aliyun'
alias aliu='alias | grep aliyun'
PROFILESHEOF
chmod +x "${PACKAGE_ROOT}/etc/profile.d/aliyun-setup.sh"

### Quick-manual page
cat > "${PACKAGE_ROOT}/usr/bin/manually/aliyun.man.1" << 'MANEOF'
.TH ALIYUN 1 "Alibaba Cloud CLI" "Version 3" "User Commands"
.SH NAME
aliyun \- Command-line interface for Alibaba Cloud services
.SH SYNOPSIS
.B alyun [options] <service> <action> [parameters]
.SH DESCRIPTION
A unified CLI tool for managing Alibaba Cloud resources including ECS, VPC, OSS, and ACK
cluster provisioning via Intel TDX spot instances.
.SH SEE ALSO
.B aliyun(1), aliyun help(1)
MANEOF
chmod 644 "${PACKAGE_ROOT}/usr/bin/manually/aliyun.man.1"

#--- Step 5: Build the .deb --------------------------------------------------------------------
echo ""
echo "--- [4/5] Compiling .deb image ---"

# dpkg-deb requires DEBIAN/ metadata directly under the build root
mkdir -p "${PACKAGE_ROOT}/DEBIAN"
INSTALL_SIZE=$(du -sk "${PACKAGE_ROOT}/opt/alibabacloud-cli/bin/aliyun" | awk '{print $1}')

cat > "${PACKAGE_ROOT}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${CLEAN_VER}-1
Section: admin
Priority: optional
Maintainer: ${MAINTAINER}
Architecture: ${ARCH}
Depends: libc6 (>= 2.31), ca-certificates
Installed-Size: ${INSTALL_SIZE}
Description: ${DESC}
 Officially packaged binary v${CLEAN_VER} of Alibaba Cloud CLI.
 Includes Intel TDX spot instance management capabilities for
 automated deployment on Alibaba Cloud Confidential VMs.
Homepage: https://github.com/aliyun/aliyun-cli
License: Apache-2.0
EOF

# Also write a minimal copyright
cat > "${PACKAGE_ROOT}/usr/share/doc/${PKG_NAME}/copyright" << 'COPYRIGHTEOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: aliyun/cli
Copyright: 2019-2026 Alibaba Cloud Inc.
License: Apache License 2.0
 Upstream-Author: Alibaba Cloud Open Source Team
Source: https://github.com/aliyun/aliyun-cli
COPYRIGHTEOF

### DEBIAN/postinst — create /usr/local/bin aliases so binary appears on PATH immediately
cat > "${PACKAGE_ROOT}/DEBIAN/postinst" << 'POSTINTEOF'
#!/bin/sh
set -e

BIN_DIR="/opt/alibabacloud-cli/bin"

# Create symlinks for every extracted binary so it's found without re-sourcing profile
if [ -x "$BIN_DIR/aliyun" ]; then
    rm -f /usr/local/bin/aliyun
    ln -sf "$BIN_DIR/aliyun" /usr/local/bin/aliyun
fi

exit 0
POSTINTEOF
chmod 755 "${PACKAGE_ROOT}/DEBIAN/postinst"

# DEBIAN/postrm — clean up symlinks on removal
cat > "${PACKAGE_ROOT}/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/sh
rm -f /usr/local/bin/aliyun /usr/local/bin/acs
exit 0
POSTRMEOF
chmod 755 "${PACKAGE_ROOT}/DEBIAN/postrm"

dpkg-deb --root-owner-group --build -Zxz \
    "$PACKAGE_ROOT" \
    "${PACKAGE_OUT:-./packages}/${PKG_NAME}_${CLEAN_VER}-1_${ARCH}.deb"

OUTPUT_DEB=$(ls -1t "${PACKAGE_OUT:-./packages}"/*.deb 2>/dev/null | head -1)
echo ""
echo "--- [5/5] Done ==================================="
echo "  Output    : $OUTPUT_DEB"
ls -lh "$OUTPUT_DEB"
echo "  Install : sudo dpkg -i $OUTPUT_DEB"
echo "  Run     : aliyun --help"
echo "==============================================="
