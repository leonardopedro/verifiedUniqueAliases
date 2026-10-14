#!/bin/bash
# ==============================================================================
# build-oci-image.sh - Reproducible Bootable QCOW2 for Oracle Cloud (AMD SEV-SNP)
# Strategy: build ESP → extract contents → normalize → rebuild ESP → pack disk
# OCI image import accepts QCOW2 only (raw is rejected).
# ==============================================================================
set -e

export SOURCE_DATE_EPOCH=1712260800
export TZ=UTC
export LC_ALL=C.UTF-8

IMAGE_NAME="paypal-auth-vm-oci.qcow2"
RAW_IMAGE="disk.raw"
ESP_IMAGE="esp.img"
ESP_MOUNT="$(pwd)/esp_mount"

echo "💿 Assembling Oracle Cloud Reproducible QCOW2 Image Stack..."

# Artifacts from output/
KERNEL="./output/vmlinuz"
INITRD="./output/initramfs-paypal-auth.img"
SHIM="./output/shimx64.efi"
GRUB="./output/grubx64.efi"

if [ ! -f "$KERNEL" ] || [ ! -f "$INITRD" ] || [ ! -f "$SHIM" ] || [ ! -f "$GRUB" ]; then
    echo "❌ Missing artifacts in output/! Run docker build first."
    exit 1
fi

# Normalize all input artifact timestamps
touch -d "@$SOURCE_DATE_EPOCH" "$KERNEL" "$INITRD" "$SHIM" "$GRUB"

# v160 (plan Pillar 1): kernel command line SINGLE-SOURCED — the GRUB menu
# entry below and the UKI .cmdline section carry byte-identical args, so boot
# parameters cannot drift between the chain-boot and direct-boot profiles.
KERNEL_CMDLINE="root=tmpfs rootok=1 console=tty0 console=ttyS0,115200n8 selinux=0 panic=1 net.ifnames=0 biosdevname=0 mem_encryption=on lockdown=confidentiality"

# =============================================================================
# PHASE 0 (Pillar 1): Unified Kernel Image + pinned measurement firmware
# -----------------------------------------------------------------------------
# UKI = one PE/COFF (EFI stub + .cmdline + .linux + .initrd): the boot payload
# becomes a single deterministic artifact whose sha256 CI publishes and whose
# (firmware, kernel, initrd, cmdline) tuple feeds sev-snp-measure.
# OCI still boots the shim+grub chain below — the hypervisor measures only its
# own OVMF either way (AGENTS.md "measurement scope"), so the UKI is shipped as
# the direct-boot profile artifact (QEMU -kernel / kernel-hashes=on platforms,
# plan §3.3 profile 1) rather than silently swapping an untested boot path.
# Gated honestly: a missing tool prints an explicit [gap], never a silent skip.
# UKI_STUB_PATH: override for local dry-runs (the container path is the default)
STUB="${UKI_STUB_PATH:-/usr/lib/systemd/boot/efi/linuxx64.efi.stub}"
UKI_OUTPUT="./output/enclave-uki.efi"

# v161 (plan §3.2): the OCI ESP boots the UKI DIRECTLY (BOOTX64.EFI = UKI,
# no shim/GRUB chain) — the unmeasured multi-file handoff is collapsed into
# ONE PE/COFF whose sha256 CI Sigstore-attests. The stub is therefore a hard
# requirement: a missing stub aborts the build (no silent [gap] fallback).
if [ ! -f "$STUB" ]; then
    echo "❌ UKI stub missing at $STUB (systemd-boot-efi — provided by the Dockerfile.oci image-builder stage)."
    echo "   Direct-boot ESP layout REQUIRES the stub — refusing to build a chain-boot image."
    exit 1
fi
{
    echo "🧩 Assembling monolithic UKI (Pillar 1)..."
    CMDLINE_FILE="$(mktemp)"
    printf '%s' "$KERNEL_CMDLINE" > "$CMDLINE_FILE"

    # Explicit non-overlapping section VMAs are REQUIRED: GNU objcopy's
    # automatic PE placement puts every added section at the image base
    # (validated locally against the real Debian stub: three sections sharing
    # one VMA + "section below image base" warnings = corrupt image). Each VMA
    # is computed above the stub's own highest section end, 64 KiB-aligned —
    # a pure function of the pinned inputs, unlike the plan snippet's literal
    # VMAs (0x30000/0x2000000/0x6000000) which overlap real stub/kernel sizes.
    stub_max_end() {
        objdump -h "$1" | awk '/^ *[0-9]+ / {print $3, $4}' | while read -r size vma; do
            echo $(( 0x$vma + 0x$size ))
        done | sort -n | tail -1
    }
    align_up() { local v=$1 a=$((0x10000)); echo $(( (v + a - 1) & ~(a - 1) )); }
    CMDLINE_VMA=$(align_up "$(stub_max_end "$STUB")")
    LINUX_VMA=$(align_up $(( CMDLINE_VMA + $(stat -c%s "$CMDLINE_FILE") )))
    INITRD_VMA=$(align_up $(( LINUX_VMA + $(stat -c%s "$KERNEL") )))

    objcopy \
        --add-section .cmdline="$CMDLINE_FILE" \
            --change-section-vma .cmdline=$(printf '0x%x' "$CMDLINE_VMA") \
        --add-section .linux="$KERNEL" \
            --change-section-vma .linux=$(printf '0x%x' "$LINUX_VMA") \
        --add-section .initrd="$INITRD" \
            --change-section-vma .initrd=$(printf '0x%x' "$INITRD_VMA") \
        "$STUB" "$UKI_OUTPUT"
    rm -f "$CMDLINE_FILE"
    if command -v add-det >/dev/null; then
        add-det "$UKI_OUTPUT"
    fi
    touch -d "@$SOURCE_DATE_EPOCH" "$UKI_OUTPUT"
    echo "✅ UKI built: $(sha256sum "$UKI_OUTPUT" | cut -d' ' -f1)  ($UKI_OUTPUT)"
}

# Pinned measurement firmware for the CI sev-snp-measure step. OCI/GCP launch
# with PROVIDER-supplied OVMF (their fleet digest is not computable here — it
# stays pinned from a live capture); this file pins the firmware of the
# direct-boot profile so CI can publish its expected digest deterministically.
# ONLY the amdsev build is accepted: direct-boot measurement needs the
# SNP_KERNEL_HASHES section, which none of Debian's generic OVMF_CODE*.fd
# variants carry (sev-snp-measure --kernel errors out on them), so staging a
# section-less fallback would guarantee a hard CI failure later — a missing
# amdsev file is an explicit [gap] instead.
# UKI_OVMF_PATH: override for local dry-runs/tests (container path is default).
OVMF_SRC=""
c="${UKI_OVMF_PATH:-/usr/share/ovmf/OVMF.amdsev.fd}"
if [ -f "$c" ]; then OVMF_SRC="$c"; fi
if [ -n "$OVMF_SRC" ]; then
    cp "$OVMF_SRC" ./output/OVMF.fd
    touch -d "@$SOURCE_DATE_EPOCH" ./output/OVMF.fd
    echo "📦 Staged measurement firmware: $OVMF_SRC → output/OVMF.fd ($(sha256sum ./output/OVMF.fd | cut -d' ' -f1))"
    # Regression guard (Pillar 1): assert the staged OVMF carries the
    # SNP_KERNEL_HASHES metadata section (type 0x10) BEFORE shipping it — a
    # section-less file makes `sev-snp-measure --kernel` fail in CI much
    # later with a cryptic error. Mirrors sev-snp-measure's own OVMF
    # metadata check (sevsnpmeasure/guest.py + ovmf.py) on the exact bytes
    # CI will consume.
    if command -v python3 >/dev/null; then
        python3 - ./output/OVMF.fd <<'PYEOF'
import struct, sys, uuid

path = sys.argv[1]
data = open(path, 'rb').read()
FOOTER = uuid.UUID('{96b582de-1fb2-45f7-baea-a366c55a082d}').bytes_le
META = uuid.UUID('{dc886566-984a-4798-a75e-5585a7bf67cc}')
EH = 18  # OvmfFooterTableEntry: u16 size + 16-byte GUID (pack=1)

def die(msg):
    print('❌ SNP_KERNEL_HASHES guard: ' + msg, file=sys.stderr)
    sys.exit(1)

if len(data) < 32 + EH:
    die('OVMF image too small: ' + path)
pos = len(data) - 32 - EH
if data[pos + 2:pos + 18] != FOOTER:
    die('OVMF table footer GUID not found — not an OVMF image? ' + path)
table_size = struct.unpack_from('<H', data, pos)[0] - EH
if table_size < 0:
    die('invalid OVMF footer table size')
tb = data[pos - table_size:pos]
entries = {}
while len(tb) >= EH:
    size = struct.unpack_from('<H', tb, len(tb) - EH)[0]
    if size < EH:
        die('invalid OVMF table entry size')
    guid = uuid.UUID(bytes_le=bytes(tb[len(tb) - EH + 2:len(tb)])).hex
    entries[guid] = tb[len(tb) - size:len(tb) - EH]
    tb = tb[:-size]
if META.hex not in entries:
    die('OVMF SEV metadata GUID absent — no SNP_KERNEL_HASHES section; sev-snp-measure --kernel will refuse this file: ' + path)
entry = entries[META.hex]
start = len(data) - struct.unpack_from('<I', entry)[0]
if data[start:start + 4] != b'ASEV':
    die('bad SEV metadata signature (expected ASEV) in ' + path)
size, version, num_items = struct.unpack_from('<III', data, start + 4)
if version != 1:
    die('unsupported SEV metadata version %d' % version)
items = data[start + 16:start + size]
found = any(struct.unpack_from('<I', items, i * 12 + 8)[0] == 0x10
            for i in range(num_items))
if not found:
    die('staged OVMF lacks the SNP_KERNEL_HASHES (0x10) metadata section — '
        'sev-snp-measure --kernel will refuse it; use ovmf-amdsev '
        '(pinned fetch in Dockerfile.oci): ' + path)
print('✅ SNP_KERNEL_HASHES metadata section present: ' + path)
PYEOF
    else
        echo "⚠️ python3 unavailable — SNP_KERNEL_HASHES guard skipped (image-builder stage provides python3; CI's sev-snp-measure re-checks)"
    fi
else
    echo "[gap] OVMF not staged: ovmf-amdsev missing (pinned fetch in the Dockerfile.oci image-builder stage); CI will report the direct-profile launch digest as not-computable"
fi

# ==============================================================================
# PHASE 1: Build the ESP partition image
# ==============================================================================
echo "🔨 Formatting EFI System Partition (FAT32)..."
truncate -s 512M $ESP_IMAGE
# --invariant: replaces all random/time-based values with constants
mkfs.vfat -F 32 -i 12345678 --invariant -n "EFI" $ESP_IMAGE

echo "📦 Populating ESP via mtools (v161: DIRECT UKI BOOT — plan §3.2)..."
echo "mtools_skip_check=1" > .mtoolsrc
MTOOLSRC="$(pwd)/.mtoolsrc"
export MTOOLSRC
export MTOOLS_NO_CONF=1

mmd -i $ESP_IMAGE ::/EFI
mmd -i $ESP_IMAGE ::/EFI/BOOT
# The ESP carries EXACTLY ONE payload: the monolithic UKI. No shim, no GRUB,
# no loose kernel/initrd/cmdline — every byte the firmware can load is inside
# the single CI-attested PE/COFF, so the auditor's "Enclave UKI" provenance
# lookup covers the entire boot payload.
mcopy -v -m -i $ESP_IMAGE "$UKI_OUTPUT" ::/EFI/BOOT/BOOTX64.EFI

# grub.cfg is still generated (NOT installed on the ESP): it is the SINGLE
# SOURCE of the kernel cmdline for CI's sev-snp-measure direct-boot digest
# computation (grub-<platform>.cfg is docker-cp'd from the container), and a
# human-readable record of the exact boot arguments baked into the UKI.
# v155 (SEC-02 Phase 2): lockdown=confidentiality puts the kernel in
# lockdown mode the moment it starts — unsigned kernel modules cannot be
# loaded, /dev/mem and kexec are blocked, and the already-measured
# initramfs cannot be augmented at runtime. This is safe on OCI because
# every module in the initramfs comes from Oracle's UEK RPM (signed by
# Oracle's module-signing key, present in the running kernel's builtin
# keyring); the GCP/Debian image deliberately does NOT get this flag
# (Debian modules are unsigned and would fail to load — validated in the
# qemu smoke test where module loading happens before any network step).
cat <<EOF > grub.cfg
set default=0
set timeout=0
menuentry "Oracle Cloud Confidential PayPal Auth (AMD SEV-SNP)" {
    linux /EFI/BOOT/vmlinuz ${KERNEL_CMDLINE}
    initrd /EFI/BOOT/initrd.img
}
EOF
touch -d "@$SOURCE_DATE_EPOCH" grub.cfg

# ==============================================================================
# PHASE 2: Extract contents → normalize at file level → rebuild ESP
# This is the key step: extract all files, sort them, reinject deterministically
# ==============================================================================
echo "🔄 Normalizing ESP: extract → sort → rebuild..."

# Create a fresh, normalized ESP image
ESP_NORM="esp_norm.img"
truncate -s 512M $ESP_NORM
mkfs.vfat -F 32 -i 12345678 --invariant -n "EFI" $ESP_NORM

# Extract all files from esp.img to a temp dir (sorted order)
mkdir -p "$ESP_MOUNT"
# Use mtools to list and copy each file in deterministic alphabetical order
for RPATH in \
    "EFI/BOOT/BOOTX64.EFI"; do
    mkdir -p "$ESP_MOUNT/$(dirname $RPATH)"
    mcopy -n -i $ESP_IMAGE "::/$RPATH" "$ESP_MOUNT/$RPATH"
    # Normalize file timestamp
    touch -d "@$SOURCE_DATE_EPOCH" "$ESP_MOUNT/$RPATH"
done

# Re-inject into the fresh normalized ESP in deterministic order
mmd -i $ESP_NORM ::/EFI
mmd -i $ESP_NORM ::/EFI/BOOT
for RPATH in \
    "EFI/BOOT/BOOTX64.EFI"; do
    mcopy -v -m -i $ESP_NORM "$ESP_MOUNT/$RPATH" "::/$RPATH"
done

# Replace original ESP with normalized one
mv $ESP_NORM $ESP_IMAGE

# ==============================================================================
# PHASE 3: Assemble the raw disk with fixed GPT metadata
# Use sgdisk with explicit fixed UUIDs for a deterministic GPT header and Protective MBR
# ==============================================================================
echo "🏗️  Constructing GPT disk with fixed UUIDs using sgdisk..."
# Create 1GB image to be safe
dd if=/dev/zero of=$RAW_IMAGE bs=1M count=1024 status=none

# ~512MiB ESP starting at sector 2048 (1MiB offset)
# with size 1048576 sectors (512MiB), type ef00 (EFI System), and fixed GUIDs.
sgdisk --clear -g \
       --disk-guid=00000000-0000-0000-0000-000000000001 \
       --new=1:2048:1050623 \
       --typecode=1:ef00 \
       --partition-guid=1:00000000-0000-0000-0000-000000000002 \
       --change-name=1:"EFI System Partition" \
       $RAW_IMAGE >/dev/null

# Inject normalized ESP into partition slot (proven: bs=1M seek=1)
dd if=$ESP_IMAGE of=$RAW_IMAGE bs=1M seek=1 conv=notrunc status=none

# ==============================================================================
# PHASE 4: Normalize the final raw disk image
# ==============================================================================
echo "🔍 Final normalization of RAW disk..."
touch -d "@$SOURCE_DATE_EPOCH" "$RAW_IMAGE"

if command -v add-det >/dev/null; then
    add-det "$RAW_IMAGE"
fi

# Keep grub.cfg available in output for attestation. v161: it is NOT on the
# ESP (single-UKI layout) — copy the locally generated single-source file
# (still present here; cleaned up below) that the UKI's .cmdline derives from.
mkdir -p output
cp grub.cfg "output/grub.cfg"

# Final Cleanup
rm -rf "$ESP_MOUNT"
rm -f .mtoolsrc grub.cfg $ESP_IMAGE

# ==============================================================================
# PHASE 5: Convert to QCOW2 (OCI image import format)
# ==============================================================================
echo "🔄 Converting to QCOW2..."
rm -f $IMAGE_NAME
qemu-img convert -f raw -O qcow2 $RAW_IMAGE $IMAGE_NAME
if command -v add-det >/dev/null; then
    add-det "$IMAGE_NAME"
fi

echo ""
echo "✅ Synthesis Complete."
sha256sum "$RAW_IMAGE" "$IMAGE_NAME"
