#!/bin/bash
set -ex

[ -z "$PROJECT_ID" ] && { echo "Set PROJECT_ID"; exit 1; }
[ -z "$PROJECT_NUMBER" ] && { echo "Set PROJECT_NUMBER"; exit 1; }

LOCATION="europe-west4"
SA_NAME="paypal-auth-sa"

# Service account
gcloud iam service-accounts create $SA_NAME --display-name "PayPal Auth" 2>/dev/null || true

# Permissions
for ROLE in roles/secretmanager.secretAccessor roles/publicca.externalAccountKeyCreator roles/storage.objectViewer roles/logging.logWriter roles/confidentialcomputing.workloadUser; do
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member "serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
        --role "$ROLE" --condition=None 2>/dev/null || true
done

# Deploy VM
gcloud compute instances delete paypal-auth-vm --zone=${LOCATION}-a --quiet 2>/dev/null || true

gcloud compute instances create paypal-auth-vm \
    --zone ${LOCATION}-a \
    --machine-type n2d-standard-2 \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy TERMINATE \
    --image-family confidential-space \
    --image-project confidential-space-images \
    --service-account ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
    --subnet=default \
    --address=34.7.107.227 \
    --scopes=cloud-platform \
    --tags http-server,https-server \
    --shielded-secure-boot \
    --metadata=tee-image-reference=eu.gcr.io/${PROJECT_ID}/paypal-auth-vm:latest,tee-env-SECRET_NAME=projects/${PROJECT_ID}/secrets/PAYPAL_AUTH_CONFIG/versions/latest,tee-env-RUST_LOG=trace,tee-container-log-redirect=true

echo "Deployed. IP: 34.7.107.227"
