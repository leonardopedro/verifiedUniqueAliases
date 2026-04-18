#!/bin/bash
# upload-secrets.sh - Interactive secrets uploader to GCP Secret Manager
# Usage: 
#   ./upload-secrets.sh --domain login.airma.de
#
# This script will interactively prompt for:
#   - PayPal Client ID (old app)
#   - PayPal Client Secret (old app)  
#   - PayPal Verified Client Secret
#   - Domain
#   - Staging (optional)

set -eo pipefail

PROJECT_ID="project-ae136ba1-3cc9-42cf-a48"
SECRET_NAME="PAYPAL_AUTH_CONFIG"

# Parse arguments
DOMAIN=""
STAGING="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --domain) DOMAIN="$2"; shift 2;;
        --staging) STAGING="$2"; shift 2;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

echo "============================================================"
echo "🔐 Upload Secrets to GCP Secret Manager"
echo "============================================================"
echo ""

# Prompt for required values
read -p "PayPal Client ID (old app): " PAYPAL_CLIENT_ID
read -sp "PayPal Client Secret (old app): " PAYPAL_CLIENT_SECRET
echo ""
read -sp "PayPal Verified Client Secret: " PAYPAL_VERIFIED_CLIENT_SECRET
echo ""

# Domain from args or prompt
if [[ -z "$DOMAIN" ]]; then
    read -p "Domain (e.g., login.airma.de): " DOMAIN
fi

# Validate
if [[ -z "$PAYPAL_CLIENT_ID" ]] || [[ -z "$PAYPAL_CLIENT_SECRET" ]] || [[ -z "$PAYPAL_VERIFIED_CLIENT_SECRET" ]] || [[ -z "$DOMAIN" ]]; then
    echo "Error: All fields are required"
    exit 1
fi

# TODO: Set via environment variable
PAYPAL_VERIFIED_CLIENT_ID=""

echo ""
echo "📝 Uploading to GCP Secret Manager..."

# Create payload
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
echo "🔐 Pulling secrets from KeePassXC and uploading to GCP"
echo "============================================================"
echo "📂 Database: $KDBX"
echo "📂 Entry (Old): $ENTRY_OLD"
echo "📂 Entry (Verified): $ENTRY_VERIFIED"

# Function to get secret from KeePassXC
get_password() {
    local db="$1"
    local entry="$2"
    
    if [[ -n "$KEEPASSXC_PASSWORD" ]]; then
        echo "$KEEPASSXC_PASSWORD" | keepassxc-cli show "$db" "$entry" 2>/dev/null | grep -i "password:" | cut -d: -f2- | xargs
    else
        keepassxc-cli show "$db" "$entry" 2>/dev/null | grep -i "password:" | cut -d: -f2- | xargs
    fi
}

get_username() {
    local db="$1"
    local entry="$2"
    
    if [[ -n "$KEEPASSXC_PASSWORD" ]]; then
        echo "$KEEPASSXC_PASSWORD" | keepassxc-cli show "$db" "$entry" 2>/dev/null | grep -i "username:" | cut -d: -f2- | xargs
    else
        keepassxc-cli show "$db" "$entry" 2>/dev/null | grep -i "username:" | cut -d: -f2- | xargs
    fi
}

# Test if we can access KeePassXC - try listing entries first
echo ""
echo "🔍 Testing KeePassXC access..."

# First try to list entries to see if database is accessible
LIST_OUTPUT=$(keepassxc-cli ls "$KDBX" 2>&1) || true
if echo "$LIST_OUTPUT" | grep -qi "password\|unlock\|key\|error"; then
    echo "⚠️  Database is locked or inaccessible. Options:"
    echo ""
    echo "   Option 1: Open the database in KeePassXC first, then run this script"
    echo ""
    echo "   Option 2: Set KEEPASSXC_PASSWORD environment variable:"
    echo "      KEEPASSXC_PASSWORD=yourpassword $0 --kdbx \"$KDBX\" --entry \"$ENTRY_OLD\" --entry-verified \"$ENTRY_VERIFIED\" --client-id-file \"$CLIENT_ID_FILE\" --domain $DOMAIN"
    echo ""
    echo "   Note: KeePassXC must be running for CLI access to work"
    exit 1
fi

# Show entries found (debug)
echo "   Found database entries (first 5):"
echo "$LIST_OUTPUT" | head -5

# Pull secrets from KeePassXC
echo ""
echo "📥 Pulling secrets..."

# Get Client ID from entry username
PAYPAL_CLIENT_ID=$(get_username "$KDBX" "$ENTRY_OLD")
echo "   Client ID: from entry username"

# Get client_secret from entry password
PAYPAL_CLIENT_SECRET=$(get_password "$KDBX" "$ENTRY_OLD")

# Get verified PayPal client_secret  
PAYPAL_VERIFIED_CLIENT_SECRET=$(get_password "$KDBX" "$ENTRY_VERIFIED")

# Check if we got the values
if [[ -z "$PAYPAL_CLIENT_ID" ]]; then
    echo "❌ Failed to get client_id"
    exit 1
fi

if [[ -z "$PAYPAL_CLIENT_SECRET" ]]; then
    echo "❌ Failed to get client_secret from entry '$ENTRY_OLD'"
    exit 1
fi

if [[ -z "$PAYPAL_VERIFIED_CLIENT_SECRET" ]]; then
    echo "❌ Failed to get secret from entry '$ENTRY_VERIFIED'"
    exit 1
fi

echo "✅ Retrieved secrets from KeePassXC"
echo "   Old App: client_id + client_secret"
echo "   Verified App: client_secret only (client_id is fixed)"

# TODO: Set via environment variable
PAYPAL_VERIFIED_CLIENT_ID=""

# Create JSON payload (hide secrets in output)
echo "📝 Payload prepared, uploading to GCP Secret Manager..."

# Upload to GCP
if gcloud secrets describe "$SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
    UPLOAD_PAYLOAD=$(cat <<EOF
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
    echo -n "$UPLOAD_PAYLOAD" | gcloud secrets versions add "$SECRET_NAME" --project="$PROJECT_ID" --data-file=-
else
    UPLOAD_PAYLOAD=$(cat <<EOF
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
    echo -n "$UPLOAD_PAYLOAD" | gcloud secrets create "$SECRET_NAME" --project="$PROJECT_ID" --data-file=-
fi

echo "============================================================"
echo "✅ Secrets uploaded to GCP Secret Manager"
echo "   Secret: projects/$PROJECT_ID/secrets/$SECRET_NAME/versions/latest"
echo "============================================================"