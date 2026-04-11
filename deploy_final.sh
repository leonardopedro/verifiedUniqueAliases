set -e
PROJECT="project-ae136ba1-3cc9-42cf-a48"
ZONE="europe-west4-a"
VERSION="v49"

echo "=== Deploying with build VM disk image ==="

# Copy disk from build VM (initramfs built there with correct kernel)
echo "Getting disk image from build VM..."
gcloud compute scp build-vm-paypal-n2d:~/disk.tar.gz ./disk.tar.gz --project=$PROJECT --zone=$ZONE

echo "Uploading new disk image to GCS..."
gsutil cp disk.tar.gz gs://$PROJECT-images/ || true

echo "Deleting old instances and images..."
gcloud compute instances delete paypal-auth-vm-$VERSION --zone=$ZONE --project=$PROJECT --quiet || true
gcloud compute images delete paypal-auth-custom-$VERSION --project=$PROJECT --quiet || true
gcloud compute instances delete paypal-auth-vm-v48 --zone=$ZONE --project=$PROJECT --quiet || true
gcloud compute images delete paypal-auth-custom-v48 --project=$PROJECT --quiet || true

echo "Waiting for GCP to clear caches..."
sleep 15

echo "Recreating image from GCS..."
gcloud compute images create paypal-auth-custom-${VERSION} \
    --project=$PROJECT \
    --source-uri=gs://$PROJECT-images/disk.tar.gz \
    --guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,GVNIC \
    --storage-location=europe-west4 --quiet

echo "Launching VM..."
gcloud compute instances create paypal-auth-vm-${VERSION} \
    --project=$PROJECT --zone=$ZONE \
    --machine-type=n2d-highcpu-2 \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --image=paypal-auth-custom-${VERSION} \
    --service-account=paypal-auth-sa@project-ae136ba1-3cc9-42cf-a48.iam.gserviceaccount.com \
    --subnet=default --address=34.7.107.227 \
    --scopes=cloud-platform \
    --tags http-server,https-server \
    --shielded-secure-boot \
    --metadata=tee-env-SECRET_NAME=projects/project-ae136ba1-3cc9-42cf-a48/secrets/PAYPAL_AUTH_CONFIG/versions/latest,tee-env-TLS_CACHE_SECRET=projects/project-ae136ba1-3cc9-42cf-a48/secrets/PAYPAL_TLS_CACHE,tee-env-RUST_LOG=trace --quiet

echo "Done!"
