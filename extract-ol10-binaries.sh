#!/bin/bash
# =============================================================================
# extract-ol10-binaries.sh — Oracle Linux 10 (UEK8) boot binaries for OCI
#
# Runs INSIDE the oraclelinux:10 container stage of Dockerfile.oci.
#
# Why Oracle Linux 10 + UEK8: the OCI support matrix for confidential
# VM.Standard.E5.Flex (AMD SEV-SNP) lists "Oracle Linux 10 (UEK8)" as the
# supported OS — this script extracts the exact same kernel/shim/grub package
# content the OCI platform image ships, from Oracle's own yum repositories.
#
# All package versions are pinned to exact NEVRAs for reproducibility.
# The UEK8 repo (yum.oracle.com/repo/OracleLinux/OL10/UEKR8) hosts the
# Oracle Linux 10 UEK packages (older versions remain available).
# =============================================================================
set -euo pipefail

OUT="${1:-/ol10}"

# --- Pinned package NEVRAs (bump deliberately, together with VERSIONS.txt) ---
KERNEL_NVR="6.12.0-207.111.5.1.el10uek"     # UEK Release 8 for OL10
SHIM_NVR="16.1-1.0.2.el10"                  # shim-x64 (Microsoft UEFI CA signed)
GRUB_NVR="2.12-46.0.1.el10_2"               # grub2-efi-x64 (Oracle SB CA signed)

# --- UEK8 repository ---------------------------------------------------------
# The oraclelinux:10 image ships a UEKR8 repo file but with enabled=0 — define
# our own uniquely-ID'd enabled repo against the fixed yum.oracle.com host
# (no $ociregion variables, fully deterministic).
cat > /etc/yum.repos.d/ol10-uekr8-build.repo <<'REPO'
[ol10_UEKR8_build]
name=Oracle Linux 10 UEK Release 8 ($basearch)
baseurl=https://yum.oracle.com/repo/OracleLinux/OL10/UEKR8/$basearch/
gpgkey=https://yum.oracle.com/RPM-GPG-KEY-oracle-ol10
gpgcheck=1
enabled=1
REPO

# --- Install pinned packages -------------------------------------------------
# tsflags=noscripts: skip dracut/depmod/%post — this container never boots the
# kernel; we only copy payload files and run our own depmod in the initramfs.
echo "📦 Installing pinned Oracle Linux 10 UEK8 packages..."
dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=noscripts \
    "kernel-uek-core-${KERNEL_NVR}" \
    "kernel-uek-modules-core-${KERNEL_NVR}" \
    "kernel-uek-modules-${KERNEL_NVR}" \
    "kernel-uek-modules-extra-${KERNEL_NVR}" \
    "shim-x64-${SHIM_NVR}" \
    "grub2-efi-x64-${GRUB_NVR}"
dnf clean all
rm -rf /var/cache/dnf /var/cache/yum

# --- Stage extracted binaries ------------------------------------------------
# /lib/modules dir = kernel NVR + arch suffix (e.g. 6.12.0-207.111.5.1.el10uek.x86_64)
KERNEL_VERSION="$(ls -1 /lib/modules | grep -m1 "^${KERNEL_NVR}" || true)"
if [ -z "$KERNEL_VERSION" ] || [ ! -f "/lib/modules/${KERNEL_VERSION}/vmlinuz" ]; then
    echo "❌ /lib/modules/${KERNEL_NVR}*/vmlinuz missing after install" >&2
    ls -la /lib/modules/ >&2 || true
    exit 1
fi

mkdir -p "$OUT/modules"
cp "/lib/modules/${KERNEL_VERSION}/vmlinuz" "$OUT/vmlinuz"
cp -a "/lib/modules/${KERNEL_VERSION}" "$OUT/modules/"

# shim fallback path = what UEFI firmware executes as \EFI\BOOT\BOOTX64.EFI
cp /boot/efi/EFI/BOOT/BOOTX64.EFI "$OUT/BOOTX64.EFI"
# grub as installed by the grub2-efi-x64 package (Oracle SB CA chain)
cp /boot/efi/EFI/redhat/grubx64.efi "$OUT/grubx64.efi"

# --- Provenance manifest (deterministic: no timestamps) ----------------------
{
    echo "# Oracle Linux 10 UEK8 boot binaries (extracted by extract-ol10-binaries.sh)"
    rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' \
        kernel-uek-core kernel-uek-modules-core kernel-uek-modules \
        kernel-uek-modules-extra shim-x64 grub2-efi-x64
    echo "# sha256 of extracted boot artifacts:"
    (cd "$OUT" && sha256sum vmlinuz BOOTX64.EFI grubx64.efi)
} > "$OUT/VERSIONS.txt"

echo "✅ Extracted OL10 UEK8 binaries to ${OUT}:"
cat "$OUT/VERSIONS.txt"
