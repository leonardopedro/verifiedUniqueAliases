#!/bin/bash
# Execute this script inside the Confidential VM after boot
# It verifies the enclave's attestation capabilities
#
# Platform detection mirrors quote() in src/main.rs:
#   * TPM device present (/dev/tpmrm0 | /dev/tpm0) → GCP-style TPM attestation (strict)
#   * No TPM device                                → Oracle Cloud AMD SEV-SNP, TPM-less
#     by design: no EK certificate, no NVRAM, no PCR 15. Evidence = SNP report
#     (report_data = session nonce) + AMD VCEK chain instead.

set -e

echo "============================================================"
echo "Enclave Runtime Verification Tool"
echo "Run this INSIDE the VM (via SSH or serial console)"
echo "============================================================"

# Helper functions
ok() { echo -e "\033[0;32m✓\033[0m $1"; }
warn() { echo -e "\033[0;33m⚠\033[0m $1"; }
fail() { echo -e "\033[0;31m✗\033[0m $1"; exit 1; }
note() { echo -e "\033[0;36mℹ\033[0m $1"; }

# ------------------------------------------------------------------
# Platform detection (before any section runs)
# ------------------------------------------------------------------
TPM_FOUND=0
for dev in /dev/tpmrm0 /dev/tpm0; do
    if [ -c "$dev" ]; then
        TPM_FOUND=1
    fi
done

if [ $TPM_FOUND -eq 1 ]; then
    PLATFORM="tpm"
    PLATFORM_LABEL="GCP Confidential VM (AMD SEV-SNP behind vTPM — TPM attestation)"
else
    PLATFORM="snp"
    PLATFORM_LABEL="Oracle Cloud (AMD SEV-SNP — TPM-less SNP attestation)"
fi

echo ""
echo "Detected platform: $PLATFORM_LABEL"

echo ""
echo "1. Kernel Module Loading"
echo "--------------------------------------------------------------"

# Check for sev-guest module
MODULE_FOUND=0
for mod in sev-guest sev_guest; do
    if lsmod | grep -q "^$mod "; then
        ok "Module $mod is loaded"
        MODULE_FOUND=1
    fi
done

if [ $MODULE_FOUND -eq 0 ]; then
    warn "No SEV guest module found in lsmod"
    echo "  Trying modprobe..."
    modprobe sev-guest 2>/dev/null || modprobe sev_guest 2>/dev/null || true
    if lsmod | grep -q "sev"; then
        ok "SEV module loaded after modprobe"
        MODULE_FOUND=1
    elif [ -c /dev/sev-guest ]; then
        # Device node present even if lsmod does not show a loadable module
        ok "/dev/sev-guest present (module built-in or loaded)"
        MODULE_FOUND=1
    elif [ "$PLATFORM" = "snp" ]; then
        fail "Cannot load SEV guest module and /dev/sev-guest is missing"
    else
        warn "Cannot load SEV guest module (GCP abstracts SNP behind vTPM — TPM checks below remain authoritative)"
    fi
fi

if modinfo sev-guest 2>/dev/null | grep -q "GCP"; then
    ok "Module built for GCP environment"
fi

echo ""
echo "2. Hardware Interface Check"
echo "--------------------------------------------------------------"

if [ "$PLATFORM" = "tpm" ]; then
    # --- GCP path: strict TPM checks (unchanged) ---
    if [ $TPM_FOUND -eq 0 ]; then
        fail "No TPM device nodes found"
    fi
    for dev in /dev/tpmrm0 /dev/tpm0; do
        if [ -c "$dev" ]; then
            ok "TPM device exists: $dev"
        fi
    done

    if tpm2 getcap properties-fixed 2>/dev/null | grep -q "TPM"; then
        ok "TPM is responding to commands"
    else
        fail "TPM commands are failing"
    fi
else
    # --- OCI path: no TPM by design; the root of trust is /dev/sev-guest ---
    if [ -c /dev/sev-guest ]; then
        ok "SNP guest device exists: /dev/sev-guest"
        if [ -r /dev/sev-guest ]; then
            ok "SNP guest device is readable"
        else
            fail "/dev/sev-guest exists but is not readable"
        fi
    elif [ -d /sys/kernel/config/tsm/report ]; then
        warn "No /dev/sev-guest — falling back to ConfigFS TSM report interface"
    else
        fail "No TPM device and no SNP hardware root (/dev/sev-guest / ConfigFS TSM) — attestation impossible"
    fi
    note "No TPM on this platform — TPM/EK/PCR checks are skipped by design (see AGENTS.md)"
fi

echo ""
echo "3. TSM ConfigFS Interface"
echo "--------------------------------------------------------------"

if [ -d "/sys/kernel/config/tsm" ]; then
    ok "ConfigFS TSM directory exists"

    # Check for report interface
    if [ -d "/sys/kernel/config/tsm/report" ]; then
        ok "Report interface available"
    else
        warn "Report interface not available (sev-guest may not be fully bound)"
    fi
else
    warn "ConfigFS TSM not mounted"
    echo "  Attempting to mount..."
    mount -t configfs none /sys/kernel/config 2>/dev/null || true
    if [ -d "/sys/kernel/config/tsm" ]; then
        ok "ConfigFS TSM mounted"
    fi
fi

CERT_SIZE=0
PERSISTENT=0
QUOTE_MSG=""

if [ "$PLATFORM" = "tpm" ]; then

echo ""
echo "4. NVRAM Index Discovery"
echo "--------------------------------------------------------------"

# List all NV indices
echo "Available NV Indices:"
tpm2 getcap handles-nv-indices 2>/dev/null || warn "Cannot list NV indices"

# Try to read Google AK Cert (should be ~1560 bytes)
echo ""
echo "Attempting to read Google AK Cert from 0x01c00002..."
CERT_SIZE=$(tpm2 nvread 0x01c00002 -C o 2>/dev/null | wc -c 2>/dev/null || echo "0")

if [ "$CERT_SIZE" -gt 1500 ] && [ "$CERT_SIZE" -lt 1600 ]; then
    ok "Google AK Cert retrieved: ${CERT_SIZE} bytes (correct!)"
    echo "  First 100 bytes (hex):"
    tpm2 nvread 0x01c00002 -C o 2>/dev/null | head -c 100 | xxd
elif [ "$CERT_SIZE" -gt 0 ]; then
    warn "Google AK Cert retrieved: ${CERT_SIZE} bytes (expected ~1560, got $CERT_SIZE)"
else
    fail "Cannot read Google AK Cert from 0x01c00002"
    echo "  This is a fatal error - attestations will fail"
fi

echo ""
echo "5. Persistent Handles (AK Discovery)"
echo "--------------------------------------------------------------"

# GCP vTPM should NOT have persistent handles
PERSISTENT=$(tpm2 getcap handles-persistent 2>/dev/null | wc -l)

if [ "$PERSISTENT" -eq 0 ] || [ -z "$PERSISTENT" ]; then
    ok "No persistent handles (expected on GCP)"
    echo "  Session AK will be created via tpm2_createprimary"
else
    warn "Found persistent handles: $PERSISTENT"
    echo "  Listing:"
    tpm2 getcap handles-persistent 2>/dev/null
fi

echo ""
echo "6. TPM Quote (Attestation)"
echo "--------------------------------------------------------------"

# Create a test nonce
TEST_NONCE=$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')
WORK_DIR="/tmp/test_quote_$$"
mkdir -p "$WORK_DIR"

echo "Creating session AK and signing quote with nonce: ${TEST_NONCE:0:16}..."

# Create primary (session AK)
AK_CTX="$WORK_DIR/ak.ctx"
if tpm2 createprimary -C e -g sha256 -G rsa2048 \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
    -c "$AK_CTX" 2>/dev/null; then

    ok "Session AK created"

    # Create quote
    QUOTE_MSG="$WORK_DIR/quote.msg"
    QUOTE_SIG="$WORK_DIR/quote.sig"
    AUXBLOB="$WORK_DIR/auxblob"

    if tpm2 quote -c "$AK_CTX" -l sha256:0,4,8,9,15 -q "$TEST_NONCE" \
        -m "$QUOTE_MSG" -s "$QUOTE_SIG" -o "$AUXBLOB" 2>/dev/null; then

        MSG_SIZE=$(stat -c%s "$QUOTE_MSG" 2>/dev/null || echo "0")
        SIG_SIZE=$(stat -c%s "$QUOTE_SIG" 2>/dev/null || echo "0")
        AUX_SIZE=$(stat -c%s "$AUXBLOB" 2>/dev/null || echo "0")

        ok "TPM Quote created"
        echo "  Quote message: $MSG_SIZE bytes"
        echo "  Quote signature: $SIG_SIZE bytes"
        echo "  Aux blob: $AUX_SIZE bytes"

        if [ "$AUX_SIZE" -gt 1000 ]; then
            ok "Aux blob contains SNP report (size: $AUX_SIZE)"
            # Try to find SNP header
            if xxd "$AUXBLOB" | grep -q "0100 0000 0000 0000"; then
                ok "SNP report header detected in aux blob"
            fi
        else
            warn "Aux blob is small ($AUX_SIZE bytes), may not contain SNP report"
        fi

        # Read PCR 15
        echo ""
        echo "PCR Values:"
        tpm2 pcrread sha256:0,4,8,9,15 2>/dev/null | grep -E "^[0-9]+:" || warn "PCR read failed"
    else
        fail "TPM quote creation failed"
    fi
else
    fail "Session AK creation failed"
fi

# Cleanup
rm -rf "$WORK_DIR"

else # PLATFORM = snp

echo ""
echo "4-6. TPM Evidence Skipped (TPM-less Platform)"
echo "--------------------------------------------------------------"
note "No TPM on this platform — NVRAM/EK cert, persistent AK handles and TPM quote do not apply"
note "Evidence path instead:"
echo "    Session nonce → SNP report_data[0..32] (via /dev/sev-guest ioctl)"
echo "    → AMD VCEK (kdsintf.amd.com) → ASK → ARK, ECDSA P-384/SHA-384 over report[0..672)"
echo "    → verified by verify.html against the downloaded report"

# Best-effort live evidence: ask the enclave for an attestation report
if [ -n "${EXPECTED_HOST:-}" ]; then
    echo ""
    echo "Querying https://${EXPECTED_HOST}/debug/attestation ..."
    DEBUG_JSON=$(curl -sk -m 15 "https://${EXPECTED_HOST}/debug/attestation" 2>/dev/null || true)
    if [ -z "$DEBUG_JSON" ]; then
        warn "Enclave debug endpoint unreachable at https://${EXPECTED_HOST}/debug/attestation"
    elif echo "$DEBUG_JSON" | grep -q "snp_report_b64"; then
        ok "Enclave produced an AMD SEV-SNP report (snp_report_b64 present)"
        QUOTE_MSG="snp-report"
    elif echo "$DEBUG_JSON" | grep -q "tpm_quote_msg"; then
        warn "Endpoint answered but report has TPM fields — unexpected for a TPM-less platform"
    else
        warn "Endpoint answered but no attestation evidence found in response"
    fi
else
    echo ""
    note "Set EXPECTED_HOST=<your.domain> to also verify the live /debug/attestation report"
fi

fi

echo ""
echo "7. Cloud Metadata Identity"
echo "--------------------------------------------------------------"

if [ "$PLATFORM" = "tpm" ]; then
    # Test GCP identity endpoint
    IDENTITY=$(curl -s -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/identity?audience=paypal-auditor&format=full" 2>/dev/null || echo "")

    if [ -n "$IDENTITY" ] && [ "$IDENTITY" != "{}" ]; then
        ok "GCP Identity Token retrieved"
        echo "  Token (first 80 chars): ${IDENTITY:0:80}..."

        # Check if it's a valid JWT
        if echo "$IDENTITY" | grep -qE "^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$"; then
            ok "Token is valid JWT format"
        else
            warn "Token format unusual"
        fi
    else
        fail "GCP Identity Token is empty or failed"
        echo "  This indicates configuration issues:"
        echo "  - Guest attributes not enabled"
        echo "  - IAM permissions missing"
        echo "  - VM is not Confidential Space"
    fi

    # Test without audience
    IDENTITY_NO_AUD=$(curl -s -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/identity?format=full" 2>/dev/null || echo "")

    if [ -n "$IDENTITY_NO_AUD" ] && [ "$IDENTITY_NO_AUD" != "{}" ]; then
        ok "Identity endpoint works without audience"
    else
        warn "Identity endpoint fails without audience too"
    fi
else
    # OCI Instance Metadata Service (IMDS v2 with Bearer token, v1 fallback)
    IMDS=$(curl -s -m 5 -H "Authorization: Bearer Oracle" \
        "http://169.254.169.254/opc/v2/instance/" 2>/dev/null || echo "")

    if [ -z "$IMDS" ]; then
        IMDS=$(curl -s -m 5 "http://169.254.169.254/opc/v1/instance/" 2>/dev/null || echo "")
    fi

    if echo "$IMDS" | grep -q '"id"'; then
        ok "OCI instance metadata retrieved"
        echo "  Instance: $(echo "$IMDS" | grep -o '"displayName"[^,]*' | head -1 || true)"
        IDENTITY="imds"
    else
        fail "OCI IMDS not reachable — config delivery will fail"
    fi

    # Config delivery via instance user_data (no cloud-init)
    USER_DATA=$(curl -s -m 5 -H "Authorization: Bearer Oracle" \
        "http://169.254.169.254/opc/v2/instance/metadata/user_data" 2>/dev/null || echo "")

    if [ -n "$USER_DATA" ]; then
        ok "Enclave config (user_data) present"
    else
        warn "user_data empty — enclave may be running with env-based config only"
    fi
fi

echo ""
echo "8. Boot Manifest vs PCR 15"
echo "--------------------------------------------------------------"

if [ "$PLATFORM" = "snp" ]; then
    note "PCR 15 is TPM-only — on this platform the disk manifest is bound through"
    note "the SNP report (GitHub provenance + report_data), not a PCR bank"
else
    # Check if boot manifest exists
    if [ -f "/tmp/boot_manifest.json" ]; then
        ok "Boot manifest exists"
        EXPECTED_PCR=$(cat /tmp/boot_manifest.json | grep -o '"pcr_15":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$EXPECTED_PCR" ]; then
            echo "  Expected PCR 15: $EXPECTED_PCR"
            ACTUAL_PCR=$(tpm2 pcrread sha256:15 2>/dev/null | grep "15:" | awk '{print $2}')
            echo "  Actual PCR 15:   $ACTUAL_PCR"
            if [ "$EXPECTED_PCR" = "$ACTUAL_PCR" ]; then
                ok "PCR 15 matches disk manifest"
            else
                warn "PCR 15 mismatch (disk may have changed)"
            fi
        fi
    else
        warn "Boot manifest not found (may be normal if called externally)"
    fi
fi

echo ""
echo "============================================================"
echo "Verification Complete"
echo "============================================================"
echo ""
echo "Summary of critical results ($PLATFORM platform):"
if [ "$PLATFORM" = "tpm" ]; then
    echo "  • TPM device: $([ $TPM_FOUND -eq 1 ] && echo "✅" || echo "❌")"
    echo "  • SEV module: $([ $MODULE_FOUND -eq 1 ] && echo "✅" || echo "❌")"
    echo "  • Google AK Cert: $([ $CERT_SIZE -gt 1500 ] && echo "✅" || echo "❌")"
    echo "  • TPM Quote: $([ -n "$QUOTE_MSG" ] && [ -f "$QUOTE_MSG" ] && echo "✅" || echo "❌")"
    echo "  • GCP Identity: $([ -n "$IDENTITY" ] && [ "$IDENTITY" != "{}" ] && echo "✅" || echo "❌")"
    echo ""
    echo "If all checks pass → Attestation is working correctly!"
    echo "If any critical check fails → See GCP_ATTESTATION_FIX.md"
else
    echo "  • SEV guest device: $([ -c /dev/sev-guest ] && echo "✅" || echo "⚠️  (ConfigFS fallback)")"
    echo "  • SEV module: $([ $MODULE_FOUND -eq 1 ] && echo "✅" || echo "❌")"
    echo "  • OCI IMDS: $([ "$IDENTITY" = "imds" ] && echo "✅" || echo "❌")"
    echo "  • Live SNP report: $([ -n "$QUOTE_MSG" ] && echo "✅" || echo "ℹ️  (EXPECTED_HOST not set)")"
    echo ""
    echo "If all checks pass → TPM-less SEV-SNP attestation path is healthy!"
    echo "Full audit: download the report from the callback page and open verify.html"
fi
