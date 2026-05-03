#!/bin/bash
# Execute this script inside the GCP Confidential VM after boot
# It verifies the enclave's attestation capabilities

set -e

echo "============================================================"
echo "Enclave Runtime Verification Tool"
echo "Run this INSIDE the VM (via SSH or serial console)"
echo "============================================================"

# Helper functions
ok() { echo -e "\033[0;32m✓\033[0m $1"; }
warn() { echo -e "\033[0;33m⚠\033[0m $1"; }
fail() { echo -e "\033[0;31m✗\033[0m $1"; exit 1; }

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
    else
        fail "Cannot load SEV guest module"
    fi
fi

# Check module info
if modinfo sev-guest 2>/dev/null | grep -q "GCP"; then
    ok "Module built for GCP environment"
fi

echo ""
echo "2. Hardware Interface Check"
echo "--------------------------------------------------------------"

# Check for TPM devices
TPM_FOUND=0
for dev in /dev/tpmrm0 /dev/tpm0; do
    if [ -c "$dev" ]; then
        ok "TPM device exists: $dev"
        TPM_FOUND=1
    fi
done

if [ $TPM_FOUND -eq 0 ]; then
    fail "No TPM device nodes found"
fi

# Check if TPM is responding
if tpm2 getcap properties-fixed 2>/dev/null | grep -q "TPM"; then
    ok "TPM is responding to commands"
else
    fail "TPM commands are failing"
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

echo ""
echo "7. GCP Metadata Identity"
echo "--------------------------------------------------------------"

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

echo ""
echo "8. Boot Manifest vs PCR 15"
echo "--------------------------------------------------------------

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

echo ""
echo "============================================================"
echo "Verification Complete"
echo "============================================================"
echo ""
echo "Summary of critical results:"
echo "  • TPM device: $([ $TPM_FOUND -eq 1 ] && echo "✅" || echo "❌")"
echo "  • SEV module: $([ $MODULE_FOUND -eq 1 ] && echo "✅" || echo "❌")"
echo "  • Google AK Cert: $([ $CERT_SIZE -gt 1500 ] && echo "✅" || echo "❌")"
echo "  • TPM Quote: $([ -f "$QUOTE_MSG" ] && echo "✅" || echo "❌")"
echo "  • GCP Identity: $([ -n "$IDENTITY" ] && [ "$IDENTITY" != "{}" ] && echo "✅" || echo "❌")"
echo ""
echo "If all checks pass → Attestation is working correctly!"
echo "If any critical check fails → See GCP_ATTESTATION_FIX.md"
