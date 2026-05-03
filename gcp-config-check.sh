#!/bin/bash
# GCP Confidential VM Attestation Configuration Debugger
# This script verifies all required settings for AMD SEV-SNP attestation

set -e

echo "============================================================"
echo "GCP Confidential VM Attestation Diagnostic Tool"
echo "============================================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_ID="project-ae136ba1-3cc9-42cf-a48"
ZONE="europe-west4-a"
VM_NAME="paypal-auth-vm-v60"

check_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
}

check_warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
}

check_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
}

echo ""
echo "1. Checking GCP APIs..."
echo "--------------------------------------------------------------"

# Check if confidentialcomputing API is enabled
if gcloud services list --project="$PROJECT_ID" --filter="name:confidentialcomputing.googleapis.com" 2>/dev/null | grep -q "confidentialcomputing.googleapis.com"; then
    check_pass "Confidential Computing API is enabled"
else
    check_fail "Confidential Computing API is NOT enabled"
    echo "   Run: gcloud services enable confidentialcomputing.googleapis.com --project=$PROJECT_ID"
fi

echo ""
echo "2. Checking VM Instance Configuration..."
echo "--------------------------------------------------------------"

# Get VM details
VM_INFO=$(gcloud compute instances describe "$VM_NAME" --project="$PROJECT_ID" --zone="$ZONE" 2>/dev/null || echo "")

if [ -z "$VM_INFO" ]; then
    check_fail "VM '$VM_NAME' not found in zone '$ZONE'"
    exit 1
fi

# Check confidential compute type
CONFIDENTIAL_TYPE=$(echo "$VM_INFO" | grep -A 2 "confidentialInstanceConfig" | grep "confidentialComputeType" | awk '{print $2}')

if [ "$CONFIDENTIAL_TYPE" = "SEV_SNP" ]; then
    check_pass "Confidential Compute Type: SEV_SNP"
else
    check_fail "Confidential Compute Type is not SEV_SNP (got: $CONFIDENTIAL_TYPE)"
fi

# Check guest attributes
GUEST_ATTR=$(echo "$VM_INFO" | grep -A 10 "metadata" | grep "enable-guest-attributes")

if echo "$GUEST_ATTR" | grep -q "enable-guest-attributes.*TRUE"; then
    check_pass "Guest Attributes: ENABLED"
else
    check_fail "Guest Attributes: MISSING or FALSE"
    echo "   This is required for sev-guest driver!"
    echo ""
    echo "   To fix (VM will need restart):"
    echo "   gcloud compute instances add-metadata $VM_NAME \\"
    echo "     --project=$PROJECT_ID --zone=$ZONE \\"
    echo "     --metadata=enable-guest-attributes=TRUE"
fi

# Check service account
SA=$(echo "$VM_INFO" | grep "serviceAccount" -A 2 | grep "email" | awk '{print $2}' | tr -d ',')
if [ -n "$SA" ]; then
    check_pass "Service Account: $SA"
    
    # Check if it has token creator role
    echo ""
    echo "3. Checking IAM Permissions..."
    echo "--------------------------------------------------------------"
    
    if gcloud projects get-iam-policy "$PROJECT_ID" --flatten="bindings[].members" --format="table(bindings.role,bindings.members)" --filter="bindings.members:$SA" 2>/dev/null | grep -q "Service Account Token Creator"; then
        check_pass "Service Account has Token Creator role"
    else
        check_warn "Service Account may lack Token Creator role"
        echo "   Required for metadata identity endpoint"
        echo "   Run: gcloud projects add-iam-policy-binding $PROJECT_ID \\"
        echo "        --member=\"serviceAccount:$SA\" \\"
        echo "        --role=\"roles/iam.serviceAccountTokenCreator\""
    fi
fi

echo ""
echo "4. Testing VM Runtime (if running)..."
echo "--------------------------------------------------------------"

# Try to get serial output to check for boot issues
SERIAL_LOG=$(gcloud compute instances get-serial-port-output "$VM_NAME" --project="$PROJECT_ID" --zone="$ZONE" 2>/dev/null | tail -100 || echo "")

if echo "$SERIAL_LOG" | grep -q "TPM Device present: true"; then
    check_pass "TPM device detected in VM logs"
else
    check_warn "Cannot verify TPM status from serial logs (VM may not be running or accessing logs failed)"
fi

if echo "$SERIAL_LOG" | grep -q "Successfully read SNP report"; then
    check_pass "SNP report successfully retrieved"
else
    check_warn "No SNP report success found in logs yet"
fi

if echo "$SERIAL_LOG" | grep -q "Attestation Token:"; then
    JWT=$(echo "$SERIAL_LOG" | grep "ATTESTATION TOKEN:" | tail -1 | sed 's/.*ATTESTATION TOKEN: //' | tr -d '\n')
    if [ -n "$JWT" ] && [ "$JWT" != "{}" ]; then
        check_pass "GCP Identity Token accessible"
        echo "   Token preview: ${JWT:0:50}..."
    else
        check_warn "GCP Identity Token empty or missing"
    fi
else
    check_warn "GCP Identity Token not found in logs"
fi

echo ""
echo "5. Manual Verification Checklist (for SSH into VM)"
echo "--------------------------------------------------------------"
echo "After VM boots, SSH and run these commands:"
echo ""
echo "# Check for sev-guest kernel module:"
echo "  lsmod | grep sev"
echo ""
echo "# Check TPM device:"
echo "  ls -la /dev/tpm*"
echo ""
echo "# Read NVRAM index for Google AK Cert (should return ~1560 bytes):"
echo "  tpm2 nvread 0x01c00002 -C o"
echo ""
echo "# List all NV indices:"
echo "  tpm2 getcap handles-nv-indices"
echo ""
echo "# Test GCP metadata identity:"
echo '  curl -H "Metadata-Flavor: Google" \'
echo '    "http://metadata.google.internal/computeMetadata/v1/instance/identity?audience=paypal-auditor&format=full"'
echo ""
echo "# Check if TSM interface exists:"
echo "  ls -la /sys/kernel/config/tsm/"
echo ""

echo ""
echo "============================================================"
echo "Summary"
echo "============================================================"
echo ""
echo "The most common issue is missing '--metadata=enable-guest-attributes=TRUE'"
echo "which prevents the sev-guest kernel module from binding."
echo ""
echo "After fixing configuration and restarting VM:"
echo "1. Monitor serial logs for 'TPM Device present: true'"
echo "2. Check for 'Successfully read SNP report'"
echo "3. Verify identity token is returned"
