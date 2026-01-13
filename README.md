## 🎯 Current Project Goals
- **Reproducible Initramfs**: Ensure the entire boot environment is bit-for-bit reproducible using Nix.
- **GCP Migration**: Optimize for GCP `e2-micro` instances.
- **Project IDX Integration**: Use Nix-based environments for consistent builds across machines.
- **Nix Environment Pinning**: Pin the exact commit of Nixpkgs to detect and prevent software update drifts.
- **Standalone Reproducibility**: Provide a `flake.nix` to reproduce the exact environment outside Project IDX if needed.
- **Measured Boot & Attestation**: Focus on reporting the `initramfs` measurement (SHA256) for verification.

---

## 🚀 Getting Started in Project IDX

Google Project IDX provides a Nix-based environment that matches our production build requirements.

### 1. Environment Setup
The environment is defined in `.idx/dev.nix` and pinned to a specific Nixpkgs commit for stability. When you open the workspace in IDX, it will automatically install:
- Rust (stable, pinned toolchain)
- Nix tools & Flakes
- `diffoscope` (for reproducibility analysis)
- Musl toolchain for static linking (Fix pending)
- VirtIO drivers and boot tools

### 2. Standalone Reproduction (Outside IDX)
To reproduce the environment on any Linux system with Nix installed:
```bash
nix develop # Enters the pinned environment
# OR
nix build .#initramfs # Builds the initramfs directly
```

```bash
chmod +x rebuild.sh
./rebuild.sh
```

### 3. Current Status & Known Issues
> [!WARNING]
> **Build Blocker**: The current build fails because `x86_64-unknown-linux-musl-gcc` is missing in the environment. This is needed for static linking of the Rust binary.
> **Fix needed**: Update `.idx/dev.nix` or `shell.nix` to correctly provide the `pkgsStatic.stdenv.cc` or `musl` toolchain.

---

## 🛠 Project Structure

- `src/main.rs`: Pure Rust implementation of the PayPal Auth server.
- `initramfs.nix`: Nix derivation defining the initramfs content and GCP boot script.
- `.idx/dev.nix`: IDX environment configuration.
- `rebuild.sh`: Consolidated build script for the reproducible image.

---

## ☁️ GCP Deployment (e2-micro)

### Metadata Configuration
The VM expects the following attributes in its metadata (`http://metadata.google.internal/computeMetadata/v1/instance/attributes/`):
- `paypal_client_id`: Your PayPal REST App Client ID.
- `domain`: The domain name where the VM will be accessible.
- `paypal_client_secret`: (Optional/Planned) Secret for OAuth.

### Networking
- **Reserved IP**: Use a static external IP in GCP.
- **Firewall**: Allow traffic on ports 80 (ACME challenge) and 443 (HTTPS).

---

## 🧪 Verification & Reproducibility

### Bit-for-bit Check
To verify that your build is identical to others:
1. Run `./rebuild.sh`.
2. Compare the SHA256 of `initramfs-gcp.img`.
3. Use `diffoscope` if there are differences:
   ```bash
   diffoscope build1/initramfs-gcp.img build2/initramfs-gcp.img
   ```

---

- [ ] Pin Nix environment in `.idx/dev.nix` to a specific commit hash.
- [ ] Create `flake.nix` for the standalone build engine.
- [ ] Fix the `musl-gcc` toolchain issue in IDX.
- [ ] Successfully run `rebuild.sh` and verify the output hash.
- [ ] Test the generated image in QEMU simulating GCP metadata.
- [ ] Document the final GCP `gcloud` commands for image import and instance launch.

---

## 🔒 Security Architecture
- **RAM-only**: No persistent root filesystem. All logic runs from the measured initramfs.
- **Sealed**: No SSH, no TTY, no user logins.
- **Acme**: Pure Rust Let's Encrypt integration using `instant-acme`.
- **Dynamic Secrets**: Secrets are fetched from metadata/vault at runtime and never stored on disk.

export TOPIC_ID="<output-topic-id>"

# Subscribe email
oci ons subscription create \
    --compartment-id $COMPARTMENT_ID \
    --topic-id $TOPIC_ID \
    --protocol "EMAIL" \
    --subscription-endpoint "your-email@example.com"
```


### Step 7.2: Deploy Traffic Monitor ("Traffic Cop")

We have implemented a "Traffic Cop" function to automatically shut down the instance if egress traffic exceeds 9.5 TB (just under the 10 TB free tier limit).

**1. Configure Environment:**
```bash
export COMPARTMENT_ID="<your-compartment-id>"
export INSTANCE_ID="$INSTANCE_ID" # From Step 5.3
export SUBNET_ID="$SUBNET_ID"     # From Step 1.2
```

**2. Deploy the Function:**
We have provided a script to automate the deployment:

```bash
./deploy-monitor.sh
```

**3. Schedule the Function:**
The script will output specific instructions to schedule the function using OCI Events or specific `fn` commands if the automated part needs manual intervention. Ensure the function allows you to create a trigger that runs every 5-15 minutes.

The function logic is located in `oci-monitor/func.py` and performs the following:
- Calculates start of the current month.
- Queries `oci_internet_gateway` metrics for `BytesToIgw`.
- Checks if usage > 9.5 TB.
- Stops the Compute Instance if the limit is exceeded.