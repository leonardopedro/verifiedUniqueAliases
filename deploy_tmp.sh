set -ex
PROJECT="REDACTED_GCP_PROJECT"
ZONE="europe-west4-a"

echo "Uploading new disk image to GCS..."
gsutil cp disk.tar.gz gs://$PROJECT-images/ || true

gcloud compute instances delete paypal-auth-vm-v28 --zone=$ZONE --project=$PROJECT --quiet || true
gcloud compute images delete paypal-auth-custom-v28 --project=$PROJECT --quiet || true

gcloud compute images create paypal-auth-custom-v28 \
    --project=$PROJECT \
    --source-uri=gs://$PROJECT-images/disk.tar.gz \
    --guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,GVNIC \
    --storage-location=europe-west4 --quiet

gcloud compute instances create paypal-auth-vm-v28 \
    --project=$PROJECT --zone=$ZONE \
    --machine-type=n2d-highcpu-2 \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --image=paypal-auth-custom-v28 \
    --service-account=REDACTED-SVC-ACCT@REDACTED_GCP_PROJECT.iam.gserviceaccount.com \
    --subnet=default --address=REDACTED_STATIC_IP \
    --scopes=cloud-platform \
    --tags http-server,https-server \
    --shielded-secure-boot \
    --metadata=tee-env-SECRET_NAME=projects/REDACTED_GCP_PROJECT/secrets/PAYPAL_AUTH_CONFIG/versions/latest,tee-env-TLS_CACHE_SECRET=***REMOVED***,tee-env-RUST_LOG=trace --quiet
