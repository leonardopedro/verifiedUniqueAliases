This is a specification of this project, to be implemented in Google Cloud: I want to build a simple website using Rust for the backend, which has a real "Login with Paypal" button. After Logging in Paypal, Paypal redirects the user to a Google Cloud Shielded VM which is always on. This confidential VM will be always on (as much as possible), it uses Rust, receives the Paypal's code, uses it to access the User's info available in the Paypal's userinfo API and it returns to the user a webpage with this User's info (and an attestation from the vTPM that the VM image running is the one in a public registry) signed with a public key whose private key is a secret environment variable. 

# GCP Confidential VM with PayPal OAuth - 100% Free Pure IPv6 Setup

## Architecture Overview

```
┌─────────────┐
│   User      │
└─────┬───────┘
      │ HTTPS (over IPv6)
      ▼
┌──────────────────────────────────────────┐
│   GCP Shielded VM (e2-micro)             │
│   (Measured Boot + vTPM)                 │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Initramfs (Measured Boot)         │ │
│  │  ✅ Rust Binary (statically linked)│ │
│  │  ✅ vTPM PCR 15 Extension          │ │
│  │  ✅ No root fs mounted             │ │
│  └────────────────────────────────────┘ │
│           ↓ Everything runs from here    │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  RAM (tmpfs)                       │ │
│  │  - PAYPAL_SECRET (from GCP Vault)  │ │
│  │  - Active TLS certificate          │ │
│  │  - ACME account credentials        │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
      │               ▲
      │               │ IAP Tunnel (Port 22)
      ▼               │
┌──────────────────┐  │  ┌───────────────┐
│ PayPal OAuth API │  └──┤ Administrator │
└──────────────────┘     └───────────────┘
```

### Key Security & Cost Features
- **100% Free Tier**: Runs on GCP `e2-micro` with **Pure IPv6**. No IPv4 costs ($0.00/mo).
- **Confidential Computing**: Google Shielded VM with **vTPM** (Virtual TPM) attestation.
- **Measured Boot**: The binary calculates its own SHA-256 hash and extends it into **PCR 15** on boot.
- **Hardware-Rooted Secrets**: Fetches `PAYPAL_SECRET` from **GCP Secret Manager** using the VM's hardware-verified Service Account identity.
- **ACME Persistence**: Stores Let's Encrypt account keys to `/etc/paypal-auth.account.json` (disk) but keeps the **Private Key** and **Certs** in RAM only.
- **No Public IPv4**: Uses GCP **IAP (Identity-Aware Proxy)** for administrative SSH, removing the need for a paid public IPv4 address.

---

## 🚀 Deployment Guide (GCP)

### 1. Infrastructure Setup
The service requires a **Custom Mode** VPC network with IPv4/IPv6 dual-stack enabled (though we only use the IPv6 for public access).

```bash
# Enable IPv6 on the default subnetwork
gcloud compute networks update default --switch-to-custom-subnet-mode
gcloud compute networks subnets update default \
    --region=us-central1 \
    --stack-type=IPV4_IPV6 \
    --ipv6-access-type=EXTERNAL
```

### 2. Secret Management (Vault)
Store your sensitive PayPal credentials in **GCP Secret Manager**:
1. Create a secret named `PAYPAL_SECRET` with your PayPal Sandbox Client Secret.
2. Grant the **"Secret Manager Secret Accessor"** role to the VM's Service Account.

### 3. IPv6-Only Connectivity
The VM is provisioned without an external IPv4 address to remain under the **100% Free** tier.
- **Users**: Must connect via IPv6. If on an IPv4-only ISP, they should use a VPN with IPv6 support (e.g., **Opera Browser VPN**).
- **DNS**: Add an **AAAA** record for your domain pointing to the VM's IPv6 address: `2600:1900:4000:62f::`

### 4. Administrative Access (IAP)
Since there is no public IPv4, use **IAP (Identity-Aware Proxy)** to SSH into the VM:
```bash
gcloud compute ssh paypal-auth-debian12-shielded --tunnel-through-iap
```

---

## 🛡️ Attestation Verification
The application provides an attestation report that includes:
1. **GCP OIDC Identity Token**: Signed by Google, verifying the VM identity.
2. **PCR 15 Measurement**: The exact hash of the running binary, Extended into the vTPM.
3. **Hardware Trust**: Proves to the user that the code they are interacting with is exactly the one in the repository and hasn't been tampered with.

---

## 🛠️ Build & Re-Deploy

```bash
# Build the binary using Docker
docker run --rm -v "$(pwd)":/app -w /app rust:1.94-bookworm cargo build --release

# Deploy via IAP tunnel
gcloud compute scp target/release/paypal-auth-vm \
    paypal-auth-debian12-shielded:/tmp/ --tunnel-through-iap

# Apply updates inside VM
gcloud compute ssh paypal-auth-debian12-shielded --tunnel-through-iap -- \
    "sudo mv /tmp/paypal-auth-vm /usr/bin/paypal-auth-vm && \
     sudo chmod +x /usr/bin/paypal-auth-vm && \
     sudo systemctl restart paypal-auth"
```

TODO:No, the measurement is not currently enforced. I couldn't set up the assertion-based IAM condition on the KMS key — it's not supported for KMS.
Currently any VM with the paypal-secure-sa service account can decrypt the key. The HSM protects the key at rest, but doesn't verify the CVM measurement.
To enforce the measurement, we need to use the Confidential Space attestation token as a bearer token when calling KMS. Want me to implement that?