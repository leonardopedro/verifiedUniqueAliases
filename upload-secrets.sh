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

# Helper to get current secret value (raw)
get_secret_val() {
    gcloud secrets versions access latest --secret="$1" --project="$PROJECT_ID" 2>/dev/null || echo ""
}

# Helper to clean ANSI codes and control characters from inputs
clean_input() {
    # Remove ANSI escape codes, null bytes, carriage returns, tabs and spaces
    # Then take ONLY the first line to prevent doubling
    echo "$1" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0\r\n\t ' | head -n 1 | head -c 1024 || echo "$1"
}

# Helper to extract value from JSON using grep fallback if jq missing
extract_json_val() {
    local json="$1"
    local key="$2"
    if command -v jq &>/dev/null && [[ -n "$json" ]]; then
        # Take only the first occurrence to prevent doubling
        echo "$json" | jq -r ".$key // \"\"" 2>/dev/null | head -n 1 || echo ""
    else
        echo "$json" | grep -oP "\"$key\":\s*\"\K[^\"]+" | head -n 1 || echo ""
    fi
}

# Ask which mode to configure
echo "What do you want to do?"
echo "  1) Configure Staging/Sandbox"
echo "  2) Configure Production"
echo "  3) Switch Active Mode (Stage/Prod)"
echo "  4) Generate Google Public CA EAB Keys (Manual Display)"
read -p "Choice (1-4): " CHOICE

PAYPAL_VERIFIED_CLIENT_ID="AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p"
PAYPAL_VERIFIED_CLIENT_SECRET="EHSSIjy5sUHPYrBA1tN-UqDLfuTe-FSSdxRVJ6CCvNcwK6QphDUExRPGurFvA4DibvFNA-LvnHFUY7vP"

if [[ "$CHOICE" == "4" ]]; then
    info "🏗️  Generating Google Public CA EAB Keys..."
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
    read -p "Active Mode (1-2): " MODE_CHOICE
    if [[ "$MODE_CHOICE" == "1" ]]; then
        MODE_PAYLOAD='{"active_mode": "staging"}'
    else
        MODE_PAYLOAD='{"active_mode": "production"}'
    fi
    if secret_exists "PAYPAL_AUTH_MODE"; then
        printf '%s' "$MODE_PAYLOAD" | gcloud secrets versions add "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --data-file=- --quiet
    else
        gcloud secrets create "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --replication-policy="automatic" --quiet
        printf '%s' "$MODE_PAYLOAD" | gcloud secrets versions add "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --data-file=- --quiet
    fi
    info "✅ Active mode updated to: $MODE_PAYLOAD"
    info "🔄 VM will restart after configuration step."
    SHOULD_RESTART=true
fi

# ==================== CONFIGURATION BLOCKS ====================

if [[ "$CHOICE" == "1" ]]; then
    SECRET="PAYPAL_AUTH_STAGING"
    IS_STAGING="true"
    echo "--- Staging/Sandbox Configuration ---"
elif [[ "$CHOICE" == "2" ]]; then
    SECRET="PAYPAL_AUTH_PRODUCTION"
    IS_STAGING="false"
    echo "--- Production Configuration ---"
elif [[ "$CHOICE" == "3" ]]; then
    read -p "Continue to update config for this mode? (y/N): " CONT
    if [[ ! "$CONT" =~ ^[Yy]$ ]]; then
        if [[ "$SHOULD_RESTART" == "true" ]]; then
            info "🔄 Restarting VM..."
            gcloud compute instances reset paypal-auth-vm-v60 --project="$PROJECT_ID" --zone=europe-west4-a
        fi
        exit 0
    fi
    if [[ "$MODE_CHOICE" == "1" ]]; then
        SECRET="PAYPAL_AUTH_STAGING"; IS_STAGING="true"
    else
        SECRET="PAYPAL_AUTH_PRODUCTION"; IS_STAGING="false"
    fi
else
    error "Invalid choice"
    exit 1
fi

# 1. Fetch current JSON and individual EAB secrets for defaults
CURRENT_JSON=$(get_secret_val "$SECRET")
EXT_EAB_ID=$(get_secret_val "EAB_KEY_ID")
EXT_EAB_SEC=$(get_secret_val "EAB_HMAC_KEY")

# 2. Extract defaults from JSON
DEFAULT_DOMAIN=$(extract_json_val "$CURRENT_JSON" "domain")
DEFAULT_PAYPAL_ID=$(extract_json_val "$CURRENT_JSON" "paypal_client_id")
DEFAULT_PAYPAL_SEC=$(extract_json_val "$CURRENT_JSON" "paypal_client_secret")
DEFAULT_VERIFIED_ID=$(extract_json_val "$CURRENT_JSON" "paypal_verified_client_id")
DEFAULT_VERIFIED_SEC=$(extract_json_val "$CURRENT_JSON" "paypal_verified_client_secret")
JSON_EAB_ID=$(extract_json_val "$CURRENT_JSON" "eab_key_id")
JSON_EAB_SEC=$(extract_json_val "$CURRENT_JSON" "eab_hmac_key")

# Prioritize individual secrets over JSON for EAB defaults
EAB_ID_DEF=${EXT_EAB_ID:-$JSON_EAB_ID}
EAB_SEC_DEF=${EXT_EAB_SEC:-$JSON_EAB_SEC}

# 3. User Prompts
read -p "Domain (default: ${DEFAULT_DOMAIN:-login.airma.de}): " DOMAIN
read -p "PayPal Client ID (default: $DEFAULT_PAYPAL_ID): " PAYPAL_CLIENT_ID
read -p "PayPal Client Secret (default: $DEFAULT_PAYPAL_SEC): " PAYPAL_CLIENT_SECRET
read -p "Verified App Client ID (default: ${DEFAULT_VERIFIED_ID:-$PAYPAL_VERIFIED_CLIENT_ID}): " INPUT_VERIFIED_ID
read -p "Verified App Client Secret (default: ${DEFAULT_VERIFIED_SEC:-$PAYPAL_VERIFIED_CLIENT_SECRET}): " VERIFIED_SECRET
echo ""
read -p "🔄 Do you want to generate FRESH Google CA EAB keys now? (y/N): " ROTATE_EAB
echo ""

if [[ "$ROTATE_EAB" =~ ^[Yy]$ ]] || [[ -z "$EAB_ID_DEF" ]]; then
    info "🏗️  Auto-generating fresh Google Public CA EAB Keys..."
    EAB_VALUES=$(gcloud publicca external-account-keys create --project="$PROJECT_ID" --format="value(keyId,b64MacKey)" --quiet 2>/dev/null || true)
    if [[ -z "$EAB_VALUES" ]]; then
        warn "Failed to generate keys via gcloud automatically."
        read -p "EAB Key ID (current: $EAB_ID_DEF): " FINAL_EAB_ID
        read -p "EAB HMAC Key (current: $EAB_SEC_DEF): " FINAL_EAB_SEC
        FINAL_EAB_ID=${FINAL_EAB_ID:-$EAB_ID_DEF}
        FINAL_EAB_SEC=${FINAL_EAB_SEC:-$EAB_SEC_DEF}
    else
        FINAL_EAB_ID=$(echo "$EAB_VALUES" | awk '{print $1}')
        FINAL_EAB_SEC=$(echo "$EAB_VALUES" | awk '{print $2}')
        info "✨ Generated New Key ID: $FINAL_EAB_ID"
    fi
else
    FINAL_EAB_ID=$EAB_ID_DEF
    FINAL_EAB_SEC=$EAB_SEC_DEF
fi

# 4. Final Values & Sanitization
DOMAIN=$(clean_input "${DOMAIN:-${DEFAULT_DOMAIN:-login.airma.de}}")
PAYPAL_CLIENT_ID=$(clean_input "${PAYPAL_CLIENT_ID:-$DEFAULT_PAYPAL_ID}")
PAYPAL_CLIENT_SECRET=$(clean_input "${PAYPAL_CLIENT_SECRET:-$DEFAULT_PAYPAL_SEC}")
PAYPAL_VERIFIED_CLIENT_ID=$(clean_input "${INPUT_VERIFIED_ID:-${DEFAULT_VERIFIED_ID:-$PAYPAL_VERIFIED_CLIENT_ID}}")
VERIFIED_SECRET=$(clean_input "${VERIFIED_SECRET:-${DEFAULT_VERIFIED_SEC:-$PAYPAL_VERIFIED_CLIENT_SECRET}}")
FINAL_EAB_ID=$(clean_input "$FINAL_EAB_ID")
FINAL_EAB_SEC=$(clean_input "$FINAL_EAB_SEC")

DOMAIN=$(clean_input "$DOMAIN")
PAYPAL_CLIENT_ID=$(clean_input "$PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET=$(clean_input "$PAYPAL_CLIENT_SECRET")
PAYPAL_VERIFIED_CLIENT_ID=$(clean_input "$PAYPAL_VERIFIED_CLIENT_ID")
VERIFIED_SECRET=$(clean_input "$VERIFIED_SECRET")
FINAL_EAB_ID=$(clean_input "$FINAL_EAB_ID")
FINAL_EAB_SEC=$(clean_input "$FINAL_EAB_SEC")

# 5. Build and Upload
# Build JSON payload using jq to ensure it is valid and clean of shell warnings
PAYLOAD=$(jq -n \
    --arg st "$IS_STAGING" \
    --arg dom "$DOMAIN" \
    --arg cid "$PAYPAL_CLIENT_ID" \
    --arg csec "$PAYPAL_CLIENT_SECRET" \
    --arg vcid "$PAYPAL_VERIFIED_CLIENT_ID" \
    --arg vcsec "$VERIFIED_SECRET" \
    --arg ekid "$FINAL_EAB_ID" \
    --arg ehmac "$FINAL_EAB_SEC" \
    '{
        staging: ($st == "true"),
        domain: $dom,
        paypal_client_id: $cid,
        paypal_client_secret: $csec,
        paypal_verified_client_id: $vcid,
        paypal_verified_client_secret: $vcsec,
        eab_key_id: $ekid,
        eab_hmac_key: $ehmac
    }')

info "📤 Uploading to $SECRET..."
if secret_exists "$SECRET"; then
    printf '%s' "$PAYLOAD" | gcloud secrets versions add "$SECRET" --project="$PROJECT_ID" --data-file=- --quiet
else
    gcloud secrets create "$SECRET" --project="$PROJECT_ID" --replication-policy="automatic" --quiet
    printf '%s' "$PAYLOAD" | gcloud secrets versions add "$SECRET" --project="$PROJECT_ID" --data-file=- --quiet
fi

# Also sync individual EAB secrets for main.rs override
info "📤 Syncing individual EAB secrets..."
if secret_exists "EAB_KEY_ID"; then
    printf '%s' "$FINAL_EAB_ID" | gcloud secrets versions add "EAB_KEY_ID" --project="$PROJECT_ID" --data-file=- --quiet
else
    gcloud secrets create "EAB_KEY_ID" --project="$PROJECT_ID" --replication-policy="automatic" --quiet
    printf '%s' "$FINAL_EAB_ID" | gcloud secrets versions add "EAB_KEY_ID" --project="$PROJECT_ID" --data-file=- --quiet
fi

if secret_exists "EAB_HMAC_KEY"; then
    printf '%s' "$FINAL_EAB_SEC" | gcloud secrets versions add "EAB_HMAC_KEY" --project="$PROJECT_ID" --data-file=- --quiet
else
    gcloud secrets create "EAB_HMAC_KEY" --project="$PROJECT_ID" --replication-policy="automatic" --quiet
    printf '%s' "$FINAL_EAB_SEC" | gcloud secrets versions add "EAB_HMAC_KEY" --project="$PROJECT_ID" --data-file=- --quiet
fi

info "✅ $SECRET and EAB secrets updated."

info "🔄 Restarting VM to apply changes in 3s..."
sleep 3
gcloud compute instances reset paypal-auth-vm-v60 --project="$PROJECT_ID" --zone=europe-west4-a
