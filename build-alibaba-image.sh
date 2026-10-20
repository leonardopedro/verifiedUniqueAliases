#!/bin/bash
# =============================================================================
# build-alibaba-image.sh - Minimal, reproducible EFI RAW disk image for
# Alibaba Cloud ECS (Intel TDX). Ported from l-branch-1 (2026-07-20) where it
# was proven against the real assembler stage.
#
# Produces: output-alibaba/disk-alibaba.raw  (GPT + single EFI System Partition)
# The ESP holds only: shim (BOOTX64.EFI), grubx64.efi, vmlinuz, initrd.img,
# grub.cfg. Runs inside the container assembler stage (no loop devices needed:
# mtools + parted work on plain files, rootless).
#
# Note: the whole OS IS the initramfs (enclave binary is /init = PID 1), so the
# kernel cmdline carries no root= — the ESP is only the UEFI boot payload.
# =============================================================================
set -e

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1712260800}"
export TZ=UTC
export LC_ALL=C.UTF-8

SRC_ROOT="$(pwd)"
OUTPUT_DIR="$SRC_ROOT/output-alibaba"
RAW_IMAGE="$OUTPUT_DIR/disk-alibaba.raw"
mkdir -p "$OUTPUT_DIR"

# Artifacts (produced by build-initramfs-tools.sh inside image-builder stage)
KERNEL="./output/vmlinuz"
INITRD="./output/initramfs-paypal-auth.img"
SHIM="./output/shimx64.efi"
GRUB="./output/grubx64.efi"

for f in "$KERNEL" "$INITRD" "$SHIM" "$GRUB"; do
    [ -f "$f" ] || { echo "MISSING: $f"; exit 1; }
done

# --- Compute minimal ESP size -----------------------------------------------
# Sum of file sizes + margin, rounded up to 1 MiB, min 32 MiB (FAT32 floor)
TOTAL=$(( $(stat -c%s "$KERNEL") + $(stat -c%s "$INITRD") + $(stat -c%s "$SHIM") + $(stat -c%s "$GRUB") + 4096 ))
MARGIN_TOTAL=$(( TOTAL * 12 / 10 ))          # +20% margin for FAT tables / dirs
ESP_BYTES=$(( (MARGIN_TOTAL / 1048576 + 1) * 1048576 ))
if [ "$ESP_BYTES" -lt 33554432 ]; then ESP_BYTES=33554432; fi   # FAT32 floor 32 MiB
ESP_MB=$(( ESP_BYTES / 1048576 ))
echo "ESP size: ${ESP_MB} MiB (contents ~$(( TOTAL / 1024 )) KiB + margin)"

# --- Build ESP (FAT32, invariant for reproducibility) ------------------------
ESP_IMAGE="$OUTPUT_DIR/esp.img"
truncate -s "$ESP_BYTES" "$ESP_IMAGE"
mkfs.vfat -F 32 -i 12345678 --invariant -n "EFI" "$ESP_IMAGE" >/dev/null

echo "mtools_skip_check=1" > "$OUTPUT_DIR/.mtoolsrc"
export MTOOLSRC="$OUTPUT_DIR/.mtoolsrc"
export MTOOLS_NO_CONF=1

# Normalize all ESP source timestamps so the FAT image is byte-reproducible
touch -d "@$SOURCE_DATE_EPOCH" "$SHIM" "$GRUB" "$KERNEL" "$INITRD"

mmd -i "$ESP_IMAGE" ::/EFI
mmd -i "$ESP_IMAGE" ::/EFI/BOOT
mcopy -i "$ESP_IMAGE" "$SHIM"   ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$ESP_IMAGE" "$GRUB"   ::/EFI/BOOT/grubx64.efi
mcopy -i "$ESP_IMAGE" "$KERNEL" ::/EFI/BOOT/vmlinuz
mcopy -i "$ESP_IMAGE" "$INITRD" ::/EFI/BOOT/initrd.img

# grub.cfg sits NEXT TO grubx64.efi ($cmdpath) so Debian's signed grub finds it
# regardless of its embedded prefix. No root= — the initramfs is the rootfs.
cat > "$OUTPUT_DIR/grub.cfg" <<'GRUBEOF'
set default=0
set timeout=0
menuentry "PayPal Auth VM (Alibaba Cloud Intel TDX)" {
    linux /EFI/BOOT/vmlinuz console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0
    initrd /EFI/BOOT/initrd.img
}
GRUBEOF
touch -d "@$SOURCE_DATE_EPOCH" "$OUTPUT_DIR/grub.cfg"
mcopy -i "$ESP_IMAGE" "$OUTPUT_DIR/grub.cfg" ::/EFI/BOOT/grub.cfg

# --- Assemble GPT RAW disk, exactly sized --------------------------------
ESP_SECTORS=$(( ESP_BYTES / 512 ))
# disk = 1 MiB GPT gap (2048 sectors) + ESP + tail margin
DISK_SECTORS=$(( 2048 + ESP_SECTORS + 8192 ))
# round disk up to 1 MiB boundary
DISK_SECTORS=$(( (DISK_SECTORS + 2047) / 2048 * 2048 ))
DISK_BYTES=$(( DISK_SECTORS * 512 ))
echo "Disk size: $(( DISK_BYTES / 1048576 )) MiB ($DISK_SECTORS sectors)"

dd if=/dev/zero of="$RAW_IMAGE" bs=512 count=0 seek="$DISK_SECTORS" status=none

# GPT partition table + single EFI System Partition (type EF00)
PART_END_SECTOR=$(( 2048 + ESP_SECTORS - 1 ))
parted -s "$RAW_IMAGE" mklabel gpt
parted -s "$RAW_IMAGE" mkpart ESP fat32 2048s "${PART_END_SECTOR}s"
parted -s "$RAW_IMAGE" set 1 esp on
# Fixed, reproducible GUIDs (overwrites the random ones parted assigns).
# FAIL CLOSED (audit 2026-10-20): these used to be `2>/dev/null || true`, and
# sfdisk was missing from the assembler image (Debian ships it in the `fdisk`
# package, not util-linux) — so every build silently kept parted's RANDOM
# GUIDs and no two builds (operator host vs CI) were byte-identical, which is
# why no GitHub attestation ever existed for a locally built disk.
sfdisk --part-uuid "$RAW_IMAGE" 1 00000000-0000-0000-0000-000000000002
sfdisk --disk-id "$RAW_IMAGE" 00000000-0000-0000-0000-000000000001
# Read back and verify the pins actually landed (byte-level reproducibility
# gate — a silently-random GUID produces an unattestable disk image).
READ_DISK_ID=$(sfdisk --disk-id "$RAW_IMAGE")
READ_PART_ID=$(sfdisk --part-uuid "$RAW_IMAGE" 1)
case "$READ_DISK_ID" in
    *[!0-9A-Fa-f-]*|'') echo "FAIL: cannot read disk GUID"; exit 1 ;;
esac
if [[ "${READ_DISK_ID,,}" != "00000000-0000-0000-0000-000000000001" ]]; then
    echo "FAIL: disk GUID not pinned (got $READ_DISK_ID)"; exit 1
fi
if [[ "${READ_PART_ID,,}" != "00000000-0000-0000-0000-000000000002" ]]; then
    echo "FAIL: partition GUID not pinned (got $READ_PART_ID)"; exit 1
fi
echo "GPT GUIDs pinned: disk=$READ_DISK_ID part1=$READ_PART_ID"

dd if="$ESP_IMAGE" of="$RAW_IMAGE" bs=512 seek=2048 conv=notrunc status=none
touch -d "@$SOURCE_DATE_EPOCH" "$RAW_IMAGE"

# NOTE: keep $OUTPUT_DIR/grub.cfg — Dockerfile.alibaba ships it to /grub.cfg so
# the CI workflow can attest its digest. verify.html's "Boot Config (grub.cfg)"
# provenance row looks that digest up in the GitHub attestation ledger; deleting
# the file here left the alibabacloud leg with nothing to extract (`docker cp
# /grub.cfg … || true` silently skipped) and every TDX audit failed the row.
rm -f "$OUTPUT_DIR/.mtoolsrc" "$ESP_IMAGE"

# --- Report ----------------------------------------------------------------
SHA=$(sha256sum "$RAW_IMAGE" | cut -d' ' -f1)
echo "✅ Built $RAW_IMAGE"
echo "   Size   : $(( DISK_BYTES / 1048576 )) MiB"
echo "   SHA256 : $SHA"
