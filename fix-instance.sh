set -ex
PROJECT="REDACTED_GCP_PROJECT"
ZONE="europe-west4-a"

gcloud compute instances delete paypal-auth-vm-v28 --zone=$ZONE --project=$PROJECT --quiet || true
sleep 15
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
