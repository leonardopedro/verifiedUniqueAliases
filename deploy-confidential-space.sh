#!/bin/bash
set -ex

# Ensure PROJECT_ID and PROJECT_NUMBER are set
if [ -z "$PROJECT_ID" ] || [ -z "$PROJECT_NUMBER" ]; then
    echo "Please set PROJECT_ID and PROJECT_NUMBER environment variables."
    exit 1
fi

export LOCATION="europe-west3"
export KEY_RING="paypal-hsm-ring"
export KEY_NAME="paypal-master-key"
export SA_NAME="paypal-secure-sa"

# Phase 1: Create the FIPS-140-2 Level 3 HSM Key
gcloud kms keyrings create $KEY_RING --location $LOCATION || true
gcloud kms keys create $KEY_NAME \
    --location $LOCATION \
    --keyring $KEY_RING \
    --purpose encryption \
    --protection-level hsm || true

# Phase 2: Create the "Attestation Bridge" (Workload Identity)
gcloud iam service-accounts create $SA_NAME || true

gcloud kms keys add-iam-policy-binding $KEY_NAME \
    --location $LOCATION \
    --keyring $KEY_RING \
    --member "serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role "roles/cloudkms.cryptoKeyDecrypter"

gcloud iam workload-identity-pools create confidential-space-pool \
    --location global \
    --description "Pool for hardware-attested Confidential VMs" || true

# Replace sha256:cce0175e449917ee405b4d43197b9f19ce0f95a246891d55cb3936e3cc4af824 with the actual sha256 of the Rust Docker container
CONTAINER_HASH=${1:-"sha256:cce0175e449917ee405b4d43197b9f19ce0f95a246891d55cb3936e3cc4af824"}

gcloud iam workload-identity-pools providers create-oidc confidential-provider \
    --location global \
    --workload-identity-pool confidential-space-pool \
    --issuer-uri "https://confidentialcomputing.googleapis.com/" \
    --allowed-audiences "https://sts.googleapis.com/" \
    --attribute-mapping "google.subject=assertion.sub,attribute.image_digest=assertion.swname" \
    --attribute-condition "attribute.image_digest == '${CONTAINER_HASH}'" || true

gcloud iam service-accounts add-iam-policy-binding ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
    --role "roles/iam.workloadIdentityUser" \
    --member "principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/confidential-space-pool/*"

# Phase 3: Create the 2GB N2D Spot Confidential VM
gcloud compute instances create paypal-auth-vm \
    --zone ${LOCATION}-a \
    --machine-type n2d-custom-2-2048 \
    --provisioning-model SPOT \
    --confidential-compute \
    --maintenance-policy TERMINATE \
    --image-family confidential-space \
    --image-project confidential-space-images \
    --service-account ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
    --metadata "^~^tee-image-reference=eu.gcr.io/${PROJECT_ID}/paypal-rust-app:latest~tee-container-log-redirect=true"
