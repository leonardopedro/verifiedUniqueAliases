#!/bin/sh
# parse-paypal-auth.sh - Early boot configuration

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Fetch metadata from OCI
fetch_metadata() {
    local key=$1
    curl -sf -H "Authorization: Bearer Oracle" \
        "http://169.254.169.254/opc/v1/instance/metadata/$key"
}

# Wait for network
while ! curl -sf http://169.254.169.254/ >/dev/null 2>&1; do
    echo "Waiting for metadata service..."
    sleep 1
done

# Export configuration
# Here is what each variable is for:
# PAYPAL_CLIENT_ID: The unique ID of the PayPal client. The app uses this ID to know exactly which client to fetch to get the PAYPAL_SECRET.
# DOMAIN: The domain name (e.g., auth.example.com). The Rust app needs this to tell Let's Encrypt which domain it wants a certificate for.
# SECRET_OCID: The unique ID of the secret in OCI Vault. The app uses this ID to know exactly which secret to fetch to get the PAYPAL_SECRET.
# OCI_REGION: The cloud region (e.g., us-ashburn-1). The app needs this to connect to the correct OCI Vault endpoint.
# Note: This one is actually fetched from a standard Oracle endpoint (opc/v2/instance/region), so you don't even need to provide it manually!
# NOTIFICATION_TOPIC_ID: The ID for the OCI Notification system. This allows the app to send you an email alert if something goes wrong (like a failed login attempt).
export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
export DOMAIN=$(fetch_metadata domain)
export SECRET_OCID=$(fetch_metadata secret_ocid)
export OCI_REGION=$(curl -sf http://169.254.169.254/opc/v2/instance/region)
export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)

# Persist for later stages
{
    echo "PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID"
    echo "DOMAIN=$DOMAIN"
    echo "SECRET_OCID=$SECRET_OCID"
    echo "OCI_REGION=$OCI_REGION"
    echo "NOTIFICATION_TOPIC_ID=$NOTIFICATION_TOPIC_ID"
} > /run/paypal-auth.env
