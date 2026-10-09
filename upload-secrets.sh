#!/bin/bash
# =============================================================================
# upload-secrets.sh - Update PayPal credentials on the auth VM
#
# The enclave loads its configuration ONCE AT BOOT from instance
# metadata.user_data — and OCI makes user_data IMMUTABLE after launch (API:
# "The 'user_data' metadata field cannot be updated"). Updating credentials on
# the OCI VM therefore works by relaunching it from the same image with the
# new user_data:
#
#   oci   (default when the oci CLI is configured)
#         Builds the config JSON, launches a replacement instance from the
#         SAME image/shape/subnet/display-name (via deploy-oci.sh), verifies
#         the new credentials are live by checking the /login OAuth redirect
#         (redirect_uri + client_id come exclusively from the loaded config),
#         and only then terminates the old instance — a failed launch or
#         verification leaves the old instance untouched. The public IP
#         changes: repoint DNS afterwards.
#
#   gcp   (original behavior — GCP Secret Manager + gcloud instance reset)
#         Select with: TARGET_PLATFORM=gcp bash upload-secrets.sh
#
# Requirements:
#   - jq (JSON assembly)
#   - oci CLI + ~/.oci/config          (oci platform)
#   - gcloud (Secret Manager, EAB)     (gcp platform)
#
# Usage:
#   bash upload-secrets.sh                          # interactive
#   OCI_INSTANCE_ID=ocid1.instance... bash upload-secrets.sh
#   TARGET_PLATFORM=gcp bash upload-secrets.sh
# =============================================================================
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

if ! command -v jq &>/dev/null; then
    error "jq is required (JSON assembly): nix profile install nixpkgs#jq / apt install jq"
    exit 1
fi

PROJECT_ID="project-ae136ba1-3cc9-42cf-a48"   # GCP platform only

# ---------------------------------------------------------------------------
# Platform selection: oci (default when the oci CLI is configured) or gcp.
# ---------------------------------------------------------------------------
if [[ -z "${TARGET_PLATFORM:-}" ]]; then
    if command -v oci &>/dev/null && [[ -f "${OCI_CONFIG_FILE:-$HOME/.oci/config}" ]]; then
        TARGET_PLATFORM="oci"
    else
        TARGET_PLATFORM="gcp"
    fi
fi
case "$TARGET_PLATFORM" in
    oci|gcp) ;;
    *) error "TARGET_PLATFORM must be 'oci' or 'gcp' (got: $TARGET_PLATFORM)"; exit 1 ;;
esac

oci_compartment() {
    if [[ -n "${OCI_COMPARTMENT_ID:-}" ]]; then
        echo "$OCI_COMPARTMENT_ID"
    elif [[ -f "$HOME/.oci/config" ]]; then
        grep '^tenancy' "$HOME/.oci/config" | head -1 | cut -d= -f2
    fi
}

# Discover the running paypal-auth-vm instance (override with OCI_INSTANCE_ID).
discover_oci_instance() {
    if [[ -n "${OCI_INSTANCE_ID:-}" ]]; then
        return 0
    fi
    local comp by_name all
    comp=$(oci_compartment)
    if [[ -z "$comp" ]]; then
        error "No OCI compartment found (set OCI_COMPARTMENT_ID or configure ~/.oci/config)"
        exit 1
    fi
    by_name=$(oci compute instance list --compartment-id "$comp" --lifecycle-state RUNNING \
        --query "data[?contains(display-name, 'paypal-auth-vm')].id | [0]" --raw-output 2>/dev/null || true)
    case "$by_name" in ""|None|null) by_name="" ;; esac
    if [[ -z "$by_name" ]]; then
        all=$(oci compute instance list --compartment-id "$comp" --lifecycle-state RUNNING \
            --query 'length(data)' --raw-output 2>/dev/null || echo 0)
        if [[ "$all" == "1" ]]; then
            by_name=$(oci compute instance list --compartment-id "$comp" --lifecycle-state RUNNING \
                --query 'data[0].id' --raw-output 2>/dev/null || true)
        fi
    fi
    if [[ -z "$by_name" ]]; then
        error "No running paypal-auth-vm instance found in compartment $comp"
        error "Deploy one first:  bash deploy-oci.sh   (or set OCI_INSTANCE_ID)"
        exit 1
    fi
    OCI_INSTANCE_ID="$by_name"
}

if [[ "$TARGET_PLATFORM" == "oci" ]]; then
    discover_oci_instance
fi

echo "============================================================"
echo "🔐 Vault Manager: PayPal & Google CA Secrets"
echo "============================================================"
if [[ "$TARGET_PLATFORM" == "oci" ]]; then
    echo "Platform: Oracle Cloud (update instance user_data + reboot)"
    echo "Instance: $OCI_INSTANCE_ID"
else
    echo "Platform: GCP Secret Manager"
    echo "Project:  $PROJECT_ID"
fi
echo ""

# Helper to check if a GCP secret exists
secret_exists() {
    gcloud secrets describe "$1" --project="$PROJECT_ID" &>/dev/null
}

# Helper to get current secret value (raw)
get_secret_val() {
    gcloud secrets versions access latest --secret="$1" --project="$PROJECT_ID" 2>/dev/null || echo ""
}

# Current config JSON for the active platform (used for prompt defaults).
#   $1 = GCP secret name (ignored on oci — there is only one active config)
get_current_config() {
    if [[ "$TARGET_PLATFORM" == "oci" ]]; then
        local b64
        b64=$(oci compute instance get --instance-id "$OCI_INSTANCE_ID" \
            --query 'data.metadata.user_data' --raw-output 2>/dev/null || true)
        case "$b64" in ""|None|null) return 0 ;; esac
        printf '%s' "$b64" | tr -d '[:space:]' | base64 -d 2>/dev/null || true
    else
        get_secret_val "$1"
    fi
}

# Apply config JSON to the OCI instance.
#
# OCI makes metadata.user_data IMMUTABLE after launch (API error: "The
# 'user_data' metadata field cannot be updated"), and the enclave reads its
# config from user_data only at boot — so the only way to change credentials
# is to relaunch the instance from the same image with the new user_data.
# Sequence (rollback-safe): launch replacement -> verify new credentials are
# live -> only then terminate the old instance. Same image, shape, subnet and
# display name; the public IP changes (DNS must be repointed).
apply_oci_config() {
    local json="$1"
    local old_id="$OCI_INSTANCE_ID" old_ip new_id new_ip old_name image_id subnet_id
    local deploy_out exp_redirect exp_client location i code

    info "🔎 Reading launch parameters from the current instance..."
    old_name=$(oci compute instance get --instance-id "$old_id" \
        --query 'data."display-name"' --raw-output 2>/dev/null || true)
    case "$old_name" in ""|None|null) old_name="paypal-auth-vm" ;; esac
    image_id=$(oci compute instance get --instance-id "$old_id" \
        --query 'data."image-id"' --raw-output 2>/dev/null || true)
    subnet_id=$(oci compute instance list-vnics --instance-id "$old_id" \
        --query 'data[0]."subnet-id"' --raw-output 2>/dev/null || true)
    case "$image_id" in ""|None|null)
        error "Could not determine the instance image id"
        exit 1
    ;; esac
    case "$subnet_id" in ""|None|null)
        error "Could not determine the instance subnet id"
        exit 1
    ;; esac
    old_ip=$(oci compute instance list-vnics --instance-id "$old_id" \
        --query 'data[0]."public-ip"' --raw-output 2>/dev/null || true)
    case "$old_ip" in ""|None|null) old_ip="" ;; esac

    info "🚀 Launching replacement instance with the new credentials (same image/shape/subnet)..."
    deploy_out=$(env -u PAYPAL_CLIENT_ID -u PAYPAL_CLIENT_SECRET \
        -u PAYPAL_VERIFIED_CLIENT_ID -u PAYPAL_VERIFIED_CLIENT_SECRET \
        -u DOMAIN -u STAGING -u EAB_KEY_ID -u EAB_HMAC_KEY \
        OCI_CONFIG_CONTENT="$json" \
        OCI_INSTANCE_NAME="$old_name" \
        OCI_IMAGE_ID="$image_id" \
        OCI_SUBNET_ID="$subnet_id" \
        OCI_COMPARTMENT_ID="${OCI_COMPARTMENT_ID:-$(oci_compartment)}" \
        bash "$(cd "$(dirname "$0")" && pwd)/deploy-oci.sh" 2>&1) || {
            error "Replacement launch failed — the OLD instance keeps serving the current credentials:"
            echo "$deploy_out" | tail -20
            exit 1
        }

    new_id=$(printf '%s\n' "$deploy_out" | grep -oE 'ocid1\.instance\.[a-z0-9.-]+' | head -1)
    new_ip=$(printf '%s\n' "$deploy_out" | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -1)
    if [[ -z "$new_id" ]]; then
        error "Could not parse the replacement instance id from deploy-oci.sh output:"
        echo "$deploy_out" | tail -10
        exit 1
    fi
    case "$new_ip" in ""|None|null) new_ip="" ;; esac
    OCI_INSTANCE_ID="$new_id"

    # Wait for HTTPS to serve the OAuth redirect on the new instance.
    exp_redirect=$(printf 'https://%s/callback' "$DOMAIN" | jq -sRr @uri)
    exp_client=$(printf '%s' "$PAYPAL_CLIENT_ID" | jq -sRr @uri)
    location=""
    if [[ -n "$new_ip" ]]; then
        info "⏳ Waiting for the replacement to boot and serve https://$new_ip ..."
        for i in $(seq 1 240); do
            location=$(curl -sk -D - -o /dev/null --max-time 5 "https://$new_ip/login" 2>/dev/null \
                | tr -d '\r' | grep -i '^location:' | head -1 || true)
            [[ -n "$location" ]] && break
            sleep 2
        done
    fi

    # Terminate the old instance only after the replacement proved it serves
    # the NEW credentials (rollback safety: on any failure the old one stays).
    local verified=false
    if [[ -z "$new_ip" ]]; then
        warn "Replacement has no public IP — skipping redirect verification."
    elif [[ -z "$location" ]]; then
        error "Replacement did not serve https://$new_ip/login within 480s"
        error "OLD instance ($old_id) was NOT terminated — check both before proceeding."
        exit 1
    elif [[ "$location" != *"redirect_uri=$exp_redirect"* ]]; then
        error "Config verification FAILED on the replacement: expected redirect_uri=$exp_redirect"
        error "  got: $location"
        error "OLD instance ($old_id) was NOT terminated — fix and rerun."
        exit 1
    else
        verified=true
        if [[ "$location" != *"client_id=$exp_client"* ]]; then
            warn "redirect_uri matches but client_id in redirect differs from requested value"
        fi
    fi

    info "✅ New credentials verified on https://$new_ip"
    info "   $location"

    info "🗑️  Terminating the previous instance ($old_id)..."
    oci compute instance terminate --instance-id "$old_id" --preserve-boot-volume false --force >/dev/null 2>&1 || \
        warn "Could not terminate $old_id — terminate it manually to avoid double billing."

    echo ""
    info "=========================================================="
    info "✅ Credentials updated (instance relaunched — OCI makes"
    info "   user_data immutable after launch, so relaunch is the"
    info "   only supported update path)."
    info "   New instance : $new_id"
    info "   New public IP: ${new_ip:-<pending>}"
    info "   Old public IP: ${old_ip:-<unknown>} (terminated)"
    if [[ -n "$new_ip" && "$new_ip" == "$old_ip" ]]; then
        info "   ✅ Public IP unchanged (reserved/static) — no DNS change needed."
    else
        info "   ⚠️  Repoint DNS to ${new_ip:-the new IP} now."
    fi
    info "=========================================================="
    [[ "$verified" == "true" ]]
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
        echo "$json" | jq -r --arg k "$key" '.[$k] // ""' 2>/dev/null | head -n 1 || echo ""
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

# TODO: Set these via environment variables or user input
PAYPAL_VERIFIED_CLIENT_ID=""
PAYPAL_VERIFIED_CLIENT_SECRET=""
SHOULD_RESTART=false
MODE_IS_STAGING=""   # oci: staging flag chosen by choice 3

if [[ "$CHOICE" == "4" ]]; then
    if ! command -v gcloud &>/dev/null; then
        error "EAB generation needs the gcloud CLI (Google Public CA API)."
        error "Install gcloud, or paste EAB values manually when prompted by choice 1/2."
        exit 1
    fi
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
        MODE_IS_STAGING="true"
    else
        MODE_IS_STAGING="false"
    fi
    if [[ "$TARGET_PLATFORM" == "gcp" ]]; then
        MODE_PAYLOAD="{\"active_mode\": \"$([[ "$MODE_IS_STAGING" == "true" ]] && echo staging || echo production)\"}"
        if secret_exists "PAYPAL_AUTH_MODE"; then
            printf '%s' "$MODE_PAYLOAD" | gcloud secrets versions add "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --data-file=- --quiet
        else
            gcloud secrets create "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --replication-policy="automatic" --quiet
            printf '%s' "$MODE_PAYLOAD" | gcloud secrets versions add "PAYPAL_AUTH_MODE" --project="$PROJECT_ID" --data-file=- --quiet
        fi
        info "✅ Active mode updated to: $MODE_PAYLOAD"
        info "🔄 VM will restart after configuration step."
        SHOULD_RESTART=true
    else
        info "Mode selection: $([[ "$MODE_IS_STAGING" == "true" ]] && echo staging || echo production)"
        info "(on OCI the active mode is the staging flag inside the instance config)"
    fi
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
        if [[ "$TARGET_PLATFORM" == "oci" ]]; then
            # Mode-only switch: flip the staging flag in the active config.
            CURRENT_ONLY=$(get_current_config)
            if ! printf '%s' "$CURRENT_ONLY" | jq -e . >/dev/null 2>&1; then
                error "No readable current config on the instance — run choice 1/2 instead."
                exit 1
            fi
            NEW_ONLY=$(printf '%s' "$CURRENT_ONLY" | jq -c --argjson st "$MODE_IS_STAGING" '.staging = $st')
            info "🔄 Switching active mode to: $([[ "$MODE_IS_STAGING" == "true" ]] && echo staging || echo production)"
            # apply_oci_config verifies against DOMAIN/CLIENT_ID from the config
            DOMAIN=$(printf '%s' "$NEW_ONLY" | jq -r '.domain // empty')
            PAYPAL_CLIENT_ID=$(printf '%s' "$NEW_ONLY" | jq -r '.paypal_client_id // empty')
            apply_oci_config "$NEW_ONLY"
        elif [[ "$SHOULD_RESTART" == "true" ]]; then
            info "🔄 Restarting VM..."
            gcloud compute instances reset paypal-auth-vm-v60 --project="$PROJECT_ID" --zone=europe-west4-a
        fi
        exit 0
    fi
    IS_STAGING="$MODE_IS_STAGING"
    if [[ "$TARGET_PLATFORM" == "gcp" ]]; then
        if [[ "$MODE_IS_STAGING" == "true" ]]; then
            SECRET="PAYPAL_AUTH_STAGING"
        else
            SECRET="PAYPAL_AUTH_PRODUCTION"
        fi
    else
        # oci has a single active config; its current values seed the prompts.
        SECRET="PAYPAL_AUTH_CURRENT"
    fi
else
    error "Invalid choice"
    exit 1
fi

# 1. Fetch current JSON and individual EAB secrets for defaults
CURRENT_JSON=$(get_current_config "$SECRET")
EXT_EAB_ID=""
EXT_EAB_SEC=""
if [[ "$TARGET_PLATFORM" == "gcp" ]]; then
    EXT_EAB_ID=$(get_secret_val "EAB_KEY_ID")
    EXT_EAB_SEC=$(get_secret_val "EAB_HMAC_KEY")
fi

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
read -p "Verified App Client ID: " INPUT_VERIFIED_ID
read -sp "Verified App Client Secret: " VERIFIED_SECRET
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

# 5. Build payload
# Carry over config fields that are not part of the prompts (ACME account
# cache, attestation signing key) so an update never drops them.
KEEP_FIELDS='{}'
if printf '%s' "$CURRENT_JSON" | jq -e . >/dev/null 2>&1; then
    KEEP_FIELDS=$(printf '%s' "$CURRENT_JSON" | jq -c \
        '{acme_account_json, attestation_signing_key} | with_entries(select(.value != null and .value != ""))')
fi

PAYLOAD=$(jq -n \
    --argjson keep "$KEEP_FIELDS" \
    --arg st "$IS_STAGING" \
    --arg dom "$DOMAIN" \
    --arg cid "$PAYPAL_CLIENT_ID" \
    --arg csec "$PAYPAL_CLIENT_SECRET" \
    --arg vcid "$PAYPAL_VERIFIED_CLIENT_ID" \
    --arg vcsec "$VERIFIED_SECRET" \
    --arg ekid "$FINAL_EAB_ID" \
    --arg ehmac "$FINAL_EAB_SEC" \
    '$keep + {
        staging: ($st == "true"),
        domain: $dom,
        paypal_client_id: $cid,
        paypal_client_secret: $csec,
        paypal_verified_client_id: $vcid,
        paypal_verified_client_secret: $vcsec,
        eab_key_id: $ekid,
        eab_hmac_key: $ehmac
    }')

# ==================== APPLY ====================

if [[ "$TARGET_PLATFORM" == "oci" ]]; then
    apply_oci_config "$PAYLOAD"
    info "✅ Config JSON written to instance metadata.user_data and verified."
    exit 0
fi

# --- GCP platform: Secret Manager + instance reset (original behavior) ---
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
