#!/bin/bash
set -euo pipefail

# ==============================================================================
# deploy-berlin.sh — Deploy PayPal Auth VM in GCP Berlin (europe-west10)
# with a reserved static public IPv6 address.
#
# Prerequisites:
#   - gcloud CLI authenticated with the target project
#   - Secrets already in Secret Manager (PAYPAL_SECRET, ORG_SIGNING_KEY)
#   - Firewall rules already exist (allow-ipv6-http-https, allow-ssh-ingress-from-iap)
#   - Binaries available or fetched from build
#
# Usage:
#   ./deploy-berlin.sh [--build]   (--build compiles the Rust binary first)
# ==============================================================================

PROJECT_ID="$(gcloud config get-value project 2>/dev/null)"
ZONE="europe-west10-a"
REGION="europe-west10"
VM_NAME="paypal-auth-berlin"
SUBNET="default"
NETWORK="default"

# Environment config
PAYPAL_CLIENT_ID="ARDDrFepkPcuh-bWdtKPLeMNptSHp2BvhahGiPNt3n317a-Uu68Xu4c9F_4N0hPI5YK60R3xRMNYr-B0"
DOMAIN="auth.airma.de"
SECRET_NAME="PAYPAL_SECRET"
ORG_KEY_NAME="ORG_SIGNING_KEY"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     PayPal Auth VM — Berlin (europe-west10) Deployment      ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Project   : $PROJECT_ID"
echo "║  Zone      : $ZONE"
echo "║  Domain    : $DOMAIN"
echo "║  IPv6      : Static reserved"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# --- Optional build step ---
if [[ "${1:-}" == "--build" ]]; then
    echo "🏗️  Building Rust binary (release, musl static)..."
    cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null \
        || cargo build --release
    echo "✅ Build complete."
    echo ""
fi

# ==============================================================================
# 1. Enable IPv6 on the europe-west10 subnet (dual-stack)
# ==============================================================================
echo "📡 Step 1: Configuring dual-stack IPv6 on $REGION subnet..."

# Check if subnet already has IPv6
STACK_TYPE=$(gcloud compute networks subnets describe "$SUBNET" \
    --region="$REGION" \
    --format='value(stackType)' 2>/dev/null || echo "IPV4_ONLY")

if [[ "$STACK_TYPE" != "IPV4_IPV6" ]]; then
    echo "  Enabling IPv4+IPv6 dual-stack on $SUBNET subnet in $REGION..."
    gcloud compute networks subnets update "$SUBNET" \
        --region="$REGION" \
        --stack-type=IPV4_IPV6 \
        --ipv6-access-type=EXTERNAL
    echo "  ✅ Dual-stack enabled."
else
    echo "  ✅ Subnet already has IPv4+IPv6 dual-stack."
fi

# ==============================================================================
# 2. Reserve a static external IPv6 address
# ==============================================================================
echo ""
echo "🔒 Step 2: Reserving static IPv6 address in $REGION..."

# Check if address already exists
if gcloud compute addresses describe "paypal-auth-berlin-ipv6" \
    --region="$REGION" &>/dev/null; then
    echo "  ✅ Static IPv6 address 'paypal-auth-berlin-ipv6' already reserved."
else
    gcloud compute addresses create "paypal-auth-berlin-ipv6" \
        --region="$REGION" \
        --network-tier=PREMIUM \
        --ip-version=IPV6 \
        --endpoint-type=VM
    echo "  ✅ Static IPv6 address reserved."
fi

# Get the reserved IPv6 address
IPV6_ADDR=$(gcloud compute addresses describe "paypal-auth-berlin-ipv6" \
    --region="$REGION" \
    --format='value(address)')
echo "  📍 IPv6 Address: $IPV6_ADDR"

# ==============================================================================
# 3. Delete existing VM if it exists (to recreate with static IPv6)
# ==============================================================================
echo ""
echo "🗑️  Step 3: Cleaning up any existing VM '$VM_NAME'..."

if gcloud compute instances describe "$VM_NAME" --zone="$ZONE" &>/dev/null; then
    echo "  Deleting existing VM..."
    gcloud compute instances delete "$VM_NAME" --zone="$ZONE" --quiet
    echo "  ✅ Existing VM deleted."
else
    echo "  ✅ No existing VM found."
fi

# ==============================================================================
# 4. Provision domain secret to Secret Manager
# ==============================================================================
echo ""
echo "🔐 Step 4: Updating DOMAIN secret in Secret Manager..."

# Ensure DOMAIN secret has the correct value
if gcloud secrets describe "DOMAIN" &>/dev/null; then
    echo -n "$DOMAIN" | gcloud secrets versions add "DOMAIN" --data-file=-
    echo "  ✅ DOMAIN secret updated."
else
    echo -n "$DOMAIN" | gcloud secrets create "DOMAIN" \
        --replication-policy="automatic" --data-file=-
    echo "  ✅ DOMAIN secret created."
fi

# Ensure PAYPAL_CLIENT_ID secret has the correct value
if gcloud secrets describe "PAYPAL_CLIENT_ID" &>/dev/null; then
    echo -n "$PAYPAL_CLIENT_ID" | gcloud secrets versions add "PAYPAL_CLIENT_ID" --data-file=-
    echo "  ✅ PAYPAL_CLIENT_ID secret updated."
else
    echo -n "$PAYPAL_CLIENT_ID" | gcloud secrets create "PAYPAL_CLIENT_ID" \
        --replication-policy="automatic" --data-file=-
    echo "  ✅ PAYPAL_CLIENT_ID secret created."
fi

# Grant service account access to all secrets
SA_EMAIL="paypal-secure-sa@${PROJECT_ID}.iam.gserviceaccount.com"
for SECRET in PAYPAL_CLIENT_ID PAYPAL_SECRET DOMAIN ORG_SIGNING_KEY; do
    gcloud secrets add-iam-policy-binding "$SECRET" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="roles/secretmanager.secretAccessor" \
        --quiet &>/dev/null
done
echo "  ✅ IAM bindings verified for $SA_EMAIL"

# ==============================================================================
# 5. Create the Shielded VM with static IPv6 in Berlin
# ==============================================================================
echo ""
echo "🖥️  Step 5: Creating Shielded VM in $ZONE with static IPv6..."

gcloud compute instances create "$VM_NAME" \
    --zone="$ZONE" \
    --machine-type=n2d-highcpu-2 \
    --subnet="$SUBNET" \
    --stack-type=IPV4_IPV6 \
    --create-disk=auto-delete=yes,boot=yes,size=10,type=pd-standard,image=projects/debian-cloud/global/images/family/debian-12 \
    --confidential-compute-type=SEV \
    --service-account="$SA_EMAIL" \
    --scopes=https://www.googleapis.com/auth/cloud-platform \
    --tags=http-server,https-server \
    --metadata=block-project-ssh-keys=TRUE \
    --provisioning-model=SPOT \
    --instance-termination-action=DELETE

# Assign the reserved static IPv6 address
gcloud compute instances network-interfaces update "$VM_NAME" \
    --zone="$ZONE" \
    --external-ipv6-address="2600:1901:81f0:383::" \
    --external-ipv6-prefix-length=96

echo "  ✅ VM created."

# ==============================================================================
# 6. Deploy the application via IAP SSH
# ==============================================================================
echo ""
echo "📡 Step 6: Deploying application to VM via IAP..."

# Wait for VM to be ready
echo "  ⏳ Waiting for VM to be ready..."
sleep 15

# Build and upload the Rust binary
BINARY_PATH="target/release/paypal-auth-vm"
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "  ❌ Binary not found at $BINARY_PATH. Run 'cargo build --release' first."
    exit 1
fi

echo "  📦 Uploading binary..."
gcloud compute scp "$BINARY_PATH" \
    "${VM_NAME}:/tmp/paypal-auth-vm" \
    --zone="$ZONE" \
    --tunnel-through-iap \
    --quiet

echo "  🔧 Provisioning VM..."
gcloud compute ssh "$VM_NAME" \
    --zone="$ZONE" \
    --tunnel-through-iap \
    --command="bash -s" <<'REMOTE_SCRIPT'
set -e

# Install dependencies
sudo apt-get update -qq
sudo apt-get install -y -qq tpm2-tools openssl

# Move binary
sudo mv /tmp/paypal-auth-vm /usr/local/bin/paypal-auth-vm
sudo chmod +x /usr/local/bin/paypal-auth-vm

# Fetch secrets from Secret Manager and write env file
sudo bash -c 'cat > /etc/paypal-auth.env << ENVEOF
PAYPAL_CLIENT_ID=$(gcloud secrets versions access latest --secret=PAYPAL_CLIENT_ID 2>/dev/null)
PAYPAL_SECRET=$(gcloud secrets versions access latest --secret=PAYPAL_SECRET 2>/dev/null)
DOMAIN=$(gcloud secrets versions access latest --secret=DOMAIN 2>/dev/null)
ORG_KEY_NAME=ORG_SIGNING_KEY
ENVEOF'
sudo chmod 600 /etc/paypal-auth.env

# Create systemd service
sudo bash -c 'cat > /etc/systemd/system/paypal-auth.service << SVCEOF
[Unit]
Description=PayPal Auth Confidential Service (Berlin)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/paypal-auth-vm
Restart=always
RestartSec=5
User=root
EnvironmentFile=/etc/paypal-auth.env

# Security hardening
NoNewPrivileges=true
ProtectSystem=false
PrivateTmp=false

[Install]
WantedBy=multi-user.target
SVCEOF'

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable paypal-auth.service
sudo systemctl start paypal-auth.service

echo "✅ Service started. Status:"
sudo systemctl status paypal-auth.service --no-pager -l
REMOTE_SCRIPT

# ==============================================================================
# 7. Update DNS AAAA record
# ==============================================================================
echo ""
echo "🌐 Step 7: DNS Configuration Required"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Add the following DNS AAAA record to your domain registrar:"
echo ""
echo "  Type: AAAA"
echo "  Name: auth"
echo "  Value: $IPV6_ADDR"
echo "  TTL: 300"
echo ""
echo "  Full domain: $DOMAIN"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║               ✅ Berlin Deployment Complete                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  VM        : $VM_NAME"
echo "║  Zone      : $ZONE"
echo "║  IPv6      : $IPV6_ADDR"
echo "║  Domain    : $DOMAIN"
echo "║  Service   : paypal-auth.service"
echo "║                                                              ║"
echo "║  SSH Access: gcloud compute ssh $VM_NAME \\                  ║"
echo "║              --zone=$ZONE --tunnel-through-iap              ║"
echo "║                                                              ║"
echo "║  Logs      : gcloud compute ssh $VM_NAME \\                  ║"
echo "║              --zone=$ZONE --tunnel-through-iap \\            ║"
echo "║              --command='sudo journalctl -u paypal-auth -f'  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
