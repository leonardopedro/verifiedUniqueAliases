#!/bin/bash
# upload-secrets.sh - Upload secrets from KeePassXC to GCP Secret Manager
# Usage: 
#   ./upload-secrets.sh --kdbx /path/to/keepassxc.kdbx --entry paypal-old --entry-verified paypal-verified --domain yourdomain.com
#
# Options:
#   --kdbx              Path to KeePassXC database
#   --entry             Entry name for full PayPal credentials
#   --entry-verified    Entry name for verified-only PayPal credentials  
#   --domain            Your domain
#   --staging           Set to "true" for sandbox mode

set -eo pipefail

PROJECT_ID="project-ae136ba1-3cc9-42cf-a48"
SECRET_NAME="PAYPAL_AUTH_CONFIG"

# Parse arguments
KDBX=""
ENTRY_OLD=""
ENTRY_VERIFIED=""
DOMAIN=""
STAGING="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --kdbx) KDBX="$2"; shift 2;;
        --entry) ENTRY_OLD="$2"; shift 2;;
        --entry-verified) ENTRY_VERIFIED="$2"; shift 2;;
        --domain) DOMAIN="$2"; shift 2;;
        --staging) STAGING="$2"; shift 2;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

# Validate required args
if [[ -z "$KDBX" ]] || [[ -z "$ENTRY_OLD" ]] || [[ -z "$ENTRY_VERIFIED" ]] || [[ -z "$DOMAIN" ]]; then
    echo "Error: Missing required arguments"
    echo "Usage: $0 --kdbx <db> --entry <old-entry> --entry-verified <verified-entry> --domain <domain> [--staging true]"
    exit 1
fi

echo "============================================================"
echo "🔐 Pulling secrets from KeePassXC and uploading to GCP"
echo "============================================================"

# Function to get secret from KeePassXC (requires database to be opened in KeePassXC or using key file)
get_secret() {
    local db="$1"
    local entry="$2"
    local attr="$3"
    
    # Try with environment variable for password if set
    if [[ -n "$KEEPASSXC_PASSWORD" ]]; then
        echo "$KEEPASSXC_PASSWORD" | keepassxc-cli show -a "$attr" "$db" "$entry" 2>/dev/null || echo ""
    else
        # Use stdin for password - will prompt if needed
        keepassxc-cli show -a "$attr" "$db" "$entry" 2>/dev/null || echo ""
    fi
}

# Pull secrets from KeePassXC
echo "📂 Reading from KeePassXC database: $KDBX"

# Get old PayPal credentials
PAYPAL_CLIENT_ID=$(get_secret "$KDBX" "$ENTRY_OLD" "client_id")
PAYPAL_CLIENT_SECRET=$(get_secret "$KDBX" "$ENTRY_OLD" "client_secret")

# Get verified PayPal credentials  
PAYPAL_VERIFIED_CLIENT_SECRET=$(get_secret "$KDBX" "$ENTRY_VERIFIED" "client_secret")

# Validate we got the secrets
if [[ -z "$PAYPAL_CLIENT_ID" ]] || [[ -z "$PAYPAL_CLIENT_SECRET" ]] || [[ -z "$PAYPAL_VERIFIED_CLIENT_SECRET" ]]; then
    echo "Error: Failed to retrieve one or more secrets from KeePassXC"
    echo "Make sure:"
    echo "  1. KeePassXC is running with the database unlocked"
    echo "  2. Entries have the required attributes (client_id, client_secret)"
    echo "  3. Or set KEEPASSXC_PASSWORD environment variable"
    exit 1
fi

echo "✅ Retrieved secrets from KeePassXC"

# Verified client ID is fixed
PAYPAL_VERIFIED_CLIENT_ID="AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p"

# Create JSON payload
PAYLOAD=$(cat <<EOF
{
  "paypal_client_id": "$PAYPAL_CLIENT_ID",
  "paypal_client_secret": "$PAYPAL_CLIENT_SECRET",
  "paypal_verified_client_id": "$PAYPAL_VERIFIED_CLIENT_ID",
  "paypal_verified_client_secret": "$PAYPAL_VERIFIED_CLIENT_SECRET",
  "domain": "$DOMAIN",
  "staging": $STAGING
}
EOF
)

echo "📝 Uploading to GCP Secret Manager..."

# Upload to GCP
if gcloud secrets describe "$SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
    echo -n "$PAYLOAD" | gcloud secrets versions add "$SECRET_NAME" --project="$PROJECT_ID" --data-file=-
else
    echo -n "$PAYLOAD" | gcloud secrets create "$SECRET_NAME" --project="$PROJECT_ID" --data-file=-
fi

echo "============================================================"
echo "✅ Secrets uploaded to GCP Secret Manager"
echo "   Secret: projects/$PROJECT_ID/secrets/$SECRET_NAME/versions/latest"
echo "============================================================"