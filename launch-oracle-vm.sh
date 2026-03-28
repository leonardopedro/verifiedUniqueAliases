#!/bin/bash
# Script to launch the Confidential dstack VM into Oracle Cloud 

set -e

# ==========================================
# 1. Oracle Cloud Pre-configured Variables
# ==========================================
# Discovered from your Oracle Tenancy environment
COMPARTMENT_ID="ocid1.tenancy.oc1..aaaaaaaap7i6pzmk2hhziqjhurqekvmulaimukxh3e3ljb4j7r4k7jhz5pxa"
SUBNET_ID="ocid1.subnet.oc1.eu-frankfurt-1.aaaaaaaaghbjrkxsxcdvzzvpchyd26a62radfsas5aolot2a43eg3zp52jka"
AD="kBBq:EU-FRANKFURT-1-AD-1"

# The Custom Image we just uploaded and started importing
IMAGE_OCID="ocid1.image.oc1.eu-frankfurt-1.aaaaaaaana4vrejsn3wztbariqhzq466unao64smxil3euqn5uu6dbve7cga"

# Based on your .dstack.yml configs
PAYPAL_CLIENT_ID="${PAYPAL_CLIENT_ID:-your-paypal-client-id}"
DOMAIN="${DOMAIN:-auth.airma.de}"

# Ensure image has finished importing
STATUS=$(oci compute image get --image-id "$IMAGE_OCID" --query 'data."lifecycle-state"' --raw-output)
if [ "$STATUS" != "AVAILABLE" ]; then
    echo "⚠️  The image is currently: $STATUS. Please wait until it is AVAILABLE before launching the VM."
    echo "You can check status using:"
    echo "  oci compute image get --image-id $IMAGE_OCID --query 'data.\"lifecycle-state\"' --raw-output"
    exit 1
fi

echo "🚀 Launching Confidential VM instance on OCI..."

# Disable metadata timeout since creating instance will spawn multiple block resources.
export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True

oci compute instance launch \
    --compartment-id "$COMPARTMENT_ID" \
    --availability-domain "$AD" \
    --shape "VM.Standard.E4.Flex" \
    --shape-config '{"ocpus": 1, "memoryInGBs": 2}' \
    --platform-config '{"type": "AMD_VM", "isMemoryEncryptionEnabled": true}' \
    --subnet-id "$SUBNET_ID" \
    --assign-public-ip true \
    --display-name "paypal-auth-v18-uki-vm" \
    --image-id "$IMAGE_OCID" \
    --boot-volume-size-in-gbs 50 \
    --metadata "{
        \"paypal_client_id\": \"$PAYPAL_CLIENT_ID\",
        \"domain\": \"$DOMAIN\"
    }"

echo "✅ Instance launched successfully!"
