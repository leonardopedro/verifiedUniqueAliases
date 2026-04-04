This is a specification of this project, to be implemented in Google Cloud: I want to build a simple website using Rust for the backend, which has a real "Login with Paypal" button. After Logging in Paypal, Paypal redirects the user to a Google Cloud Shielded VM which is always on. This confidential VM will be always on (as much as possible), it uses Rust, receives the Paypal's code, uses it to access the User's info available in the Paypal's userinfo API and it returns to the user a webpage with this User's info (and an attestation from the vTPM that the VM image running is the one in a public registry) signed with a public key whose private key is a secret environment variable. 

# GCP Confidential VM with PayPal OAuth

## Architecture Overview

```text
┌─────────────┐
│   User      │
└─────┬───────┘
      │ HTTPS
      ▼
┌──────────────────────────────────────────┐
│   GCP Confidential Space VM (N2D)        │
│   (AMD SEV-SNP Attestation)              │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Docker Container (distroless)     │ │
│  │  ✅ Rust Binary                    │ │
│  │  ✅ Hardware Attestation           │ │
│  └────────────────────────────────────┘ │
│           ↓ Everything runs from here   │
│                                         │
│  ┌────────────────────────────────────┐ │
│  │  RAM (tmpfs)                       │ │
│  │  - PAYPAL_SECRET (GCP Secret Mgr)  │ │
│  │  - Active TLS certificate          │ │
│  │  - ACME account credentials        │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
      │
      ▼
┌──────────────────┐
│ PayPal OAuth API │
└──────────────────┘
```

### Key Security Features
- **Confidential Computing**: Google Confidential Space VM with **AMD SEV-SNP** hardware isolation and attestation.
- **Hardware-Rooted Secrets**: Fetches `PAYPAL_SECRET` from **GCP Secret Manager** using the VM's hardware-verified Service Account identity (WIF).
- **RAM-Only TLS**: Uses **Google Public CA (ACME + EAB)** for certificates. Private keys are never written to persistent disk; they live entirely in RAM.
- **Verified Build Pipeline**: The Docker builder leverages `debian:12-slim` to compile the statically compatible binary, ensuring the `glibc 2.36` matches the `distroless/cc-debian12` runner image perfectly to prevent legacy `GLIBC_2.38 not found` crashes.

---

## 🚀 Deployment Guide (GCP)

### 1. Secret Management (Vault)
Store your configurable secrets securely in **GCP Secret Manager**.
Create a JSON payload encompassing fields like `paypal_client_secret` and your `eab_hmac_key`. Grant the **"Secret Manager Secret Accessor"** role to the Service Account.

### 2. Required GCP Permissions
Ensure the underlying Service Account has the following IAM roles:
- `roles/secretmanager.secretAccessor`
- `roles/publicca.externalAccountKeyCreator`
- `roles/logging.logWriter`
- `roles/confidentialcomputing.workloadUser`

---

## 🛠️ Build & Re-Deploy

### 1. Build the Docker Image
Due to compatibility, compile the Rust application within Docker using `debian:12-slim` to match the `distroless` glibc version:

```bash
export PROJECT_ID=my-project

# Build and Push
docker build -f Dockerfile.confidential-space -t eu.gcr.io/$PROJECT_ID/paypal-auth-vm:latest .
docker push eu.gcr.io/$PROJECT_ID/paypal-auth-vm:latest
```

### 2. Deploy Confidential Space VM
Once pushed up to GCR, deploy directly to a fresh Confidential Space instance in `europe-west4`:

```bash
PROJECT_ID=my-project PROJECT_NUMBER=123456 ./deploy-confidential-space.sh
```

*(Note: The deployment script provisions an `n2d-highcpu-2` instance running Google's secure Confidential Space image, configuring the TEE image and metadata on top of a fresh boot.)*