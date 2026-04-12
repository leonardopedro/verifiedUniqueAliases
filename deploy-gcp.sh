#!/bin/bash
set -eo pipefail

echo "============================================================"
echo "🚀 Deploying GCP Confidential Auth VM (End-to-End)"
echo "============================================================"

# --- Configuration ---
PROJECT_ID="project-ae136ba1-3cc9-42cf-a48"
ZONE="europe-west4-a"
REGION="europe-west4"
BUILD_VM="build-vm-paypal-n2d"

BUCKET="gs://${PROJECT_ID}-images"
IMAGE_NAME="paypal-auth-custom-v28"
VM_NAME="paypal-auth-vm-v60"
SERVICE_ACCOUNT="paypal-auth-sa@${PROJECT_ID}.iam.gserviceaccount.com"
STATIC_IP="34.7.107.227"
SUBNET="default"

echo "✅ Configuration Loaded:"
echo "   - Project: $PROJECT_ID"
echo "   - Target VM: $VM_NAME ($STATIC_IP)"

# --- Phase 1: Local Docker Source Build & Disk Synthesis ---
echo ""
echo "📦 [1/6] Building reproducing Rust binary and Disk locally..."
docker build -f Dockerfile.repro -t paypal-auth-vm-repro .

echo "📥 Extracting disk.tar.gz from reproducing container..."
docker rm -f tmp_disk 2>/dev/null || true
docker create --name tmp_disk paypal-auth-vm-repro
docker cp tmp_disk:/disk.tar.gz ./disk.tar.gz
docker rm tmp_disk

# --- Phase 3: Uploading the Image ---
echo ""
echo "📤 Uploading disk.tar.gz to GCS Bucket (${BUCKET})..."
gsutil cp ./disk.tar.gz ${BUCKET}/disk.tar.gz

# --- Phase 4: Image Registration ---
echo ""
echo "💿 [2/3] Registering GCP Custom Image..."
echo "Removing old image (if exists)..."
gcloud compute images delete ${IMAGE_NAME} --project=${PROJECT_ID} --quiet || true

echo "Creating new custom image..."
gcloud compute images create ${IMAGE_NAME} \
    --project=${PROJECT_ID} \
    --source-uri=${BUCKET}/disk.tar.gz \
    --guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,GVNIC \
    --storage-location=${REGION} \
    --quiet

# --- Phase 5: Launching the Confidential VM ---
echo ""
echo "🔒 [3/3] Launching Confidential VM..."
echo "Releasing Static IP ($STATIC_IP) from any previous instances..."
OLD_INSTANCE=$(gcloud compute instances list --project=${PROJECT_ID} --filter="networkInterfaces.accessConfigs.natIP=${STATIC_IP}" --format="value(name)")
if [ -n "$OLD_INSTANCE" ]; then
    echo "Found old instance '$OLD_INSTANCE' holding IP. Deleting..."
    gcloud compute instances delete ${OLD_INSTANCE} \
        --project=${PROJECT_ID} --zone=${ZONE} --quiet || true
else
    echo "No existing instances found holding IP $STATIC_IP."
fi
echo "Provisioning AMD SEV-SNP Enclave..."
# We explicitly set the TLS_CACHE_SECRET tee-env attribute so the service knows where to find/store the sealed DEK
gcloud compute instances create ${VM_NAME} \
    --project=${PROJECT_ID} \
    --zone=${ZONE} \
    --machine-type=n2d-highcpu-2 \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --image=${IMAGE_NAME} \
    --service-account=${SERVICE_ACCOUNT} \
    --subnet=${SUBNET} \
    --address=${STATIC_IP} \
    --scopes=cloud-platform \
    --tags=http-server,https-server \
    --metadata=tee-env-TLS_CACHE_SECRET=projects/${PROJECT_ID}/secrets/PAYPAL_TLS_CACHE,tee-env-FORCE_SANDBOX=true

echo "============================================================"
echo "🎉 Deployment Complete!"
echo "   Endpoint: https://${STATIC_IP}/"
echo "   Monitor : gcloud compute instances get-serial-port-output ${VM_NAME} --project=${PROJECT_ID} --zone=${ZONE}"
echo "============================================================"
