set -eo pipefail

info() {
    echo -e "\033[0;32m[INFO]\033[0m $*"
}

warn() {
    echo -e "\033[0;33m[WARN]\033[0m $*"
}

error() {
    echo -e "\033[0;31m[ERROR]\033[0m $*"
}

PROJECT_ID="project-ae136ba1-3cc9-42cf-a48"

echo "============================================================"
echo "🔐 Vault Manager: PayPal & Google CA Secrets"
echo "============================================================"
echo "Project: $PROJECT_ID"
echo ""

# Helper to check if a secret exists
secret_exists() {
    gcloud secrets describe "$1" --project="$PROJECT_ID" &>/dev/null
}

# Helper to get current secret value (optional, requires jq)
get_current_secret() {
    if command -v jq &>/dev/null; then
        gcloud secrets versions access latest --secret="$1" --project="$PROJECT_ID" 2>/dev/null | jq . || echo "{}"
    else
        echo "{}"
    fi
}

# Helper to generate and return EAB keys as JSON
generate_eab_keys() {
    info "🏗️  Auto-generating fresh Google Public CA EAB Keys..."
    # Use quiet and specifically extract the JSON block skipping headers
    gcloud publicca external-account-keys create --project="$PROJECT_ID" --format="json" --quiet | sed -n '/^{/,$p'
}

# Ask which mode to configure
echo "What do you want to do?"
echo "  1) Configure Staging"
echo "  2) Configure Production"
echo "  3) Switch Active Mode (Stage/Prod)"
echo "  4) Generate Google Public CA EAB Keys (Manual)"
read -p "Choice (1-4): " CHOICE

PAYPAL_VERIFIED_CLIENT_ID="AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p"

if [[ "$CHOICE" == "4" ]]; then
    echo "🏗️  Generating Google Public CA EAB Keys..."
    EAB_OUTPUT=$(gcloud publicca external-account-keys create --project="$PROJECT_ID" --format="json")
    echo "Successfully generated keys:"
    echo "$EAB_OUTPUT"
    echo ""
    echo "Save these values! They can only be shown once."
    exit 0
fi

if [[ "$CHOICE" == "3" ]]; then
    echo "--- Switch Active Mode ---"
    echo "  1) Staging"
    echo "  2) Production"
    read -p "Active Mode: " MODE_CHOICE
    if [[ "$MODE_CHOICE" == "1" ]]; then
        MODE_PAYLOAD='{"active_mode": "staging"}'
    else
        MODE_PAYLOAD='{"active_mode": "production"}'
    fi
    if secret_exists "PAYPAL_AUTH_MODE"; then
        echo -n "$MODE_PAYLOAD" | gcloud secrets versions add "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --data-file=-
    else
        echo -n "$MODE_PAYLOAD" | gcloud secrets create "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --data-file=-
    fi
    echo "✅ Active mode updated"
    # Don't exit here, fall through to the reset at the end
    SHOULD_RESET=true
fi

# Skip configuration prompts if we already did Choice 3
if [[ "$SHOULD_RESET" != "true" ]]; then

# ==================== CONFIGURATION BLOCKS ====================

if [[ "$CHOICE" == "1" ]]; then
    SECRET="PAYPAL_AUTH_STAGING"
    IS_STAGING="true"
    echo "--- Staging Configuration ---"
elif [[ "$CHOICE" == "2" ]]; then
    SECRET="PAYPAL_AUTH_PRODUCTION"
    IS_STAGING="false"
    echo "--- Production Configuration ---"
else
    echo "Invalid choice"
    exit 1
fi

# Try to load existing values
CURRENT_JSON=$(get_current_secret "$SECRET")

# Helper to extract value from JSON
extract_val() {
    local key="$1"
    if command -v jq &>/dev/null; then
        echo "$CURRENT_JSON" | jq -r ".$key // \"\""
    else
        echo "$CURRENT_JSON" | grep -oP "\"$key\":\s*\"\K[^\"]+" || echo ""
    fi
}

# Load current values as defaults
DEFAULT_DOMAIN=$(extract_val "domain")
DEFAULT_PAYPAL_ID=$(extract_val "paypal_client_id")
DEFAULT_PAYPAL_SEC=$(extract_val "paypal_client_secret")
DEFAULT_VERIFIED_ID=$(extract_val "paypal_verified_client_id")
DEFAULT_VERIFIED_SEC=$(extract_val "paypal_verified_client_secret")
DEFAULT_EAB_ID=$(extract_val "eab_key_id")
DEFAULT_EAB_SEC=$(extract_val "eab_hmac_key")

read -p "Domain (default: $DEFAULT_DOMAIN): " DOMAIN
read -p "PayPal Client ID (default: $DEFAULT_PAYPAL_ID): " PAYPAL_CLIENT_ID
read -p "PayPal Client Secret (default: $DEFAULT_PAYPAL_SEC): " PAYPAL_CLIENT_SECRET
read -p "Verified App Client ID (default: ${DEFAULT_VERIFIED_ID:-$PAYPAL_VERIFIED_CLIENT_ID}): " INPUT_VERIFIED_ID
read -p "Verified App Client Secret (default: $DEFAULT_VERIFIED_SEC): " VERIFIED_SECRET
echo ""
read -p "🔄 Do you want to generate FRESH Google CA EAB keys? (y/N): " ROTATE_EAB
echo ""

# Logic for EAB Generation/Retention
if [[ "$ROTATE_EAB" =~ ^[Yy]$ ]] || [[ -z "$DEFAULT_EAB_ID" && -z "$EAB_KEY_ID" ]]; then
    info "🏗️  Auto-generating fresh Google Public CA EAB Keys..."
    # Get raw values tab-separated: keyId then b64MacKey
    EAB_VALUES=$(gcloud publicca external-account-keys create --project="$PROJECT_ID" --format="value(keyId,b64MacKey)" --quiet 2>/dev/null)
    EAB_KEY_ID=$(echo "$EAB_VALUES" | awk '{print $1}')
    EAB_HMAC_KEY=$(echo "$EAB_VALUES" | awk '{print $2}')
    
    if [[ -z "$EAB_KEY_ID" ]]; then
        error "Failed to generate EAB keys. Please check gcloud permissions."
        exit 1
    fi
    echo "✨ Detected New Key ID: $EAB_KEY_ID"
    # Show only first 10 and last 10 of HMAC for verification
    HMAC_LEN=${#EAB_HMAC_KEY}
    HMAC_START=${EAB_HMAC_KEY:0:10}
    HMAC_END=${EAB_HMAC_KEY:HMAC_LEN-10:10}
    echo "✨ Detected New HMAC: ${HMAC_START}...${HMAC_END}"
else
    # Prompt for manual entry or Enter to keep existing
    read -p "Google CA EAB Key ID (default: $DEFAULT_EAB_ID): " INPUT_EAB_ID
    read -p "Google CA EAB HMAC Key (default: $DEFAULT_EAB_SEC): " INPUT_EAB_SEC
    EAB_KEY_ID=${INPUT_EAB_ID:-$DEFAULT_EAB_ID}
    EAB_HMAC_KEY=${INPUT_EAB_SEC:-$DEFAULT_EAB_SEC}
fi

echo ""
echo "📝 Final check before upload to $SECRET:"
echo "   - Domain: $DOMAIN"
echo "   - EAB ID: $EAB_KEY_ID"
echo "   - Mode  : $([[ "$IS_STAGING" == "true" ]] && echo "Staging/Sandbox" || echo "Production")"
echo ""

# Use defaults for other fields if empty

# Use defaults for other fields if empty
DOMAIN=${DOMAIN:-$DEFAULT_DOMAIN}
PAYPAL_CLIENT_ID=${PAYPAL_CLIENT_ID:-$DEFAULT_PAYPAL_ID}
PAYPAL_CLIENT_SECRET=${PAYPAL_CLIENT_SECRET:-$DEFAULT_PAYPAL_SEC}
PAYPAL_VERIFIED_CLIENT_ID=${INPUT_VERIFIED_ID:-${DEFAULT_VERIFIED_ID:-$PAYPAL_VERIFIED_CLIENT_ID}}
VERIFIED_SECRET=${VERIFIED_SECRET:-$DEFAULT_VERIFIED_SEC}

# Cleanup inputs: strip quotes, whitespace, and potential duplications
clean_input() {
    local val="$1"
    # Remove quotes, spaces, and specific prefixes
    val=$(echo "$val" | sed 's/keyId: //g' | sed 's/b64MacKey: //g' | tr -d '"'\'' ')
    # Check for duplication: if string is long and starts with its second half
    local len=${#val}
    if (( len > 40 && len % 2 == 0 )); then
        local half=$(( len / 2 ))
        local first=${val:0:half}
        local second=${val:half}
        if [[ "$first" == "$second" ]]; then
            warn "Detected and fixed duplicated input for value (repeated twice)."
            val="$first"
        fi
    fi
    echo "$val"
}

DOMAIN=$(clean_input "$DOMAIN")
PAYPAL_CLIENT_ID=$(clean_input "$PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET=$(clean_input "$PAYPAL_CLIENT_SECRET")
PAYPAL_VERIFIED_CLIENT_ID=$(clean_input "$PAYPAL_VERIFIED_CLIENT_ID")
VERIFIED_SECRET=$(clean_input "$VERIFIED_SECRET")
EAB_KEY_ID=$(clean_input "$EAB_KEY_ID")
EAB_HMAC_KEY=$(clean_input "$EAB_HMAC_KEY")

PAYLOAD=$(cat <<EOF
{
  "staging": $IS_STAGING,
  "domain": "$DOMAIN",
  "paypal_client_id": "$PAYPAL_CLIENT_ID",
  "paypal_client_secret": "$PAYPAL_CLIENT_SECRET",
  "paypal_verified_client_id": "$PAYPAL_VERIFIED_CLIENT_ID",
  "paypal_verified_client_secret": "$VERIFIED_SECRET",
  "eab_key_id": "$EAB_KEY_ID",
  "eab_hmac_key": "$EAB_HMAC_KEY"
}
EOF
)

if secret_exists "$SECRET"; then
    echo -n "$PAYLOAD" | gcloud secrets versions add "$SECRET" --project="$PROJECT_ID" --data-file=-
else
    echo -n "$PAYLOAD" | gcloud secrets create "$SECRET" --project="$PROJECT_ID" --data-file=-
fi
fi # End of SHOULD_RESET=false block

echo "✅ $SECRET updated."

info "🔄 Restarting VM to apply changes in 3s..."
sleep 3
gcloud compute instances reset paypal-auth-vm-v60 --project="$PROJECT_ID" --zone=europe-west4-a
