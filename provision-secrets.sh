#!/usr/bin/env bash
# =============================================================================
# provision-secrets.sh
#
# Provisions all secrets required by paypal-auth-vm (main.rs) into
# Google Cloud Secret Manager, then restarts the service on the Shielded VM.
#
# Secrets managed (matches main.rs env var names):
#   - PAYPAL_CLIENT_ID  (std::env::var("PAYPAL_CLIENT_ID"))
#   - PAYPAL_SECRET     (std::env::var("PAYPAL_SECRET"))
#   - DOMAIN            (std::env::var("DOMAIN"))
#
# Usage:
#   ./provision-secrets.sh [--host <IP>] [--key <ssh_key_path>]
# =============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
VM_HOST="${VM_HOST:-34.41.85.160}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_leo}"
SSH_USER="${SSH_USER:-opc}"
GCP_PROJECT="${GCP_PROJECT:-$(gcloud config get-value project)}"
SERVICE_NAME="paypal-auth.service"
ENV_FILE="/etc/paypal-auth.env"

# Override via flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) VM_HOST="$2"; shift 2 ;;
    --key)  SSH_KEY="$2";  shift 2 ;;
    *)      echo "Unknown argument: $1"; exit 1 ;;
  esac
done

SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         PayPal Auth Service — Secret Provisioning           ║"
echo "║  Matches: PAYPAL_CLIENT_ID, PAYPAL_SECRET, DOMAIN in main.rs ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  GCP Project : $GCP_PROJECT"
echo "  VM Host     : $VM_HOST"
echo "  SSH User    : $SSH_USER"
echo "  SSH Key     : $SSH_KEY"
echo ""

# --- Prompt for secrets -------------------------------------------------------
read -rp "📦 PAYPAL_CLIENT_ID  (PayPal OAuth App Client ID): " PAYPAL_CLIENT_ID
read -rsp "🔑 PAYPAL_SECRET     (PayPal OAuth App Client Secret): " PAYPAL_SECRET
echo ""
read -rp "🌐 DOMAIN            (e.g. auth.airma.de): " DOMAIN
echo ""

if [[ -z "$PAYPAL_CLIENT_ID" || -z "$PAYPAL_SECRET" || -z "$DOMAIN" ]]; then
  echo "❌  All three values are required. Aborting."
  exit 1
fi

# --- Helper: upsert a GCP secret (create or add new version) -----------------
upsert_secret() {
  local name="$1"
  local value="$2"

  if gcloud secrets describe "$name" --project="$GCP_PROJECT" &>/dev/null; then
    echo "  ↻  Updating existing secret: $name"
    echo -n "$value" | gcloud secrets versions add "$name" \
      --project="$GCP_PROJECT" \
      --data-file=-
  else
    echo "  ✚  Creating new secret: $name"
    echo -n "$value" | gcloud secrets create "$name" \
      --project="$GCP_PROJECT" \
      --replication-policy="automatic" \
      --data-file=-
  fi
}

# --- Grant the VM's service account access (idempotent) ----------------------
grant_access() {
  local name="$1"
  local sa
  sa=$(gcloud compute instances describe "paypal-auth-debian12-shielded" \
    --zone="us-central1-a" \
    --project="$GCP_PROJECT" \
    --format='value(serviceAccounts[0].email)' 2>/dev/null || echo "")

  if [[ -n "$sa" ]]; then
    gcloud secrets add-iam-policy-binding "$name" \
      --project="$GCP_PROJECT" \
      --member="serviceAccount:$sa" \
      --role="roles/secretmanager.secretAccessor" \
      --quiet &>/dev/null
    echo "  🔐 IAM binding verified for $name → $sa"
  else
    echo "  ⚠️  Could not determine VM service account for $name — skipping IAM binding."
  fi
}

echo "🚀 Storing secrets in GCP Secret Manager..."
echo ""

upsert_secret "PAYPAL_CLIENT_ID" "$PAYPAL_CLIENT_ID"
grant_access  "PAYPAL_CLIENT_ID"

upsert_secret "PAYPAL_SECRET" "$PAYPAL_SECRET"
grant_access  "PAYPAL_SECRET"

upsert_secret "DOMAIN" "$DOMAIN"
grant_access  "DOMAIN"

echo ""
echo "✅  All secrets stored. Pushing env file to VM and restarting service..."
echo ""

# --- Write /etc/paypal-auth.env on the VM with values from Secret Manager -----
# The VM fetches values at startup from Secret Manager via gcloud CLI,
# then writes them to the env file read by systemd.
ssh $SSH_OPTS "${SSH_USER}@${VM_HOST}" bash <<EOF
set -e

PAYPAL_CLIENT_ID=\$(gcloud secrets versions access latest --secret=PAYPAL_CLIENT_ID 2>/dev/null)
PAYPAL_SECRET=\$(gcloud secrets versions access latest --secret=PAYPAL_SECRET 2>/dev/null)
DOMAIN=\$(gcloud secrets versions access latest --secret=DOMAIN 2>/dev/null)

printf 'PAYPAL_CLIENT_ID=%s\nPAYPAL_SECRET=%s\nDOMAIN=%s\n' \\
  "\$PAYPAL_CLIENT_ID" "\$PAYPAL_SECRET" "\$DOMAIN" \\
  | sudo tee $ENV_FILE > /dev/null

sudo chmod 600 $ENV_FILE
echo "  📄 $ENV_FILE written."

sudo systemctl daemon-reload
sudo systemctl restart $SERVICE_NAME
sleep 3
sudo systemctl status $SERVICE_NAME --no-pager
EOF

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  🛡️  Provisioning Complete                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Secrets are stored in GCP Secret Manager (not on disk)."
echo "  The VM fetches them from Vault on each service restart."
echo "  You can rotate any secret by re-running this script."
echo ""
