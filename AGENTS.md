# AGENTS.md - Guidelines for AI Coding Agents

## Project Overview

`paypal-auth-vm` is a Rust application that runs in a Docker container on **GCP Confidential Space** (AMD SEV-SNP TEE). It provides PayPal OAuth authentication with cryptographic attestation. TLS certificates come from **Google Public CA** via ACME. The PayPal client secret is fetched from **GCP Secret Manager**. TLS private keys are held in RAM only.

## Build & Run Commands

```bash
# Standard debug build
cargo build

# Release build (used in production)
cargo build --release

# Run locally (requires env vars: PAYPAL_CLIENT_ID, DOMAIN, PAYPAL_SECRET_NAME, GOOGLE_PUBLIC_CA_EAB_KEY_ID, GOOGLE_PUBLIC_CA_EAB_HMAC_KEY)
cargo run --release

# Check compilation
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Docker build for Confidential Space
docker build -f Dockerfile.confidential-space -t eu.gcr.io/$PROJECT_ID/paypal-auth-vm:latest .
docker push eu.gcr.io/$PROJECT_ID/paypal-auth-vm:latest

# Deploy to Confidential Space (europe-west4, Spot, SEV-SNP)
PROJECT_ID=my-project PROJECT_NUMBER=123456 ./deploy-confidential-space.sh
```

## Environment Variables

| Variable | Description |
|---|---|
| `PAYPAL_CLIENT_ID` | PayPal OAuth client ID |
| `DOMAIN` | Public domain for this service |
| `PAYPAL_SECRET_NAME` | GCP Secret Manager resource path, e.g. `projects/X/secrets/Y/versions/latest` |
| `GOOGLE_PUBLIC_CA_EAB_KEY_ID` | EAB key ID from `gcloud publicca external-account-keys create` |
| `GOOGLE_PUBLIC_CA_EAB_HMAC_KEY` | EAB HMAC key from same command |
| `GOOGLE_PUBLIC_CA_STAGING` | Set to `true` for staging CA (testing only) |

## Architecture

- **Runtime**: Docker container on GCP Confidential Space (AMD SEV-SNP)
- **TLS CA**: Google Public CA via ACME with External Account Binding
- **Secrets**: PayPal client secret from GCP Secret Manager via REST API + metadata server auth
- **No HSM**: No vTPM private key generation or storage
- **RAM only**: TLS private keys never written to persistent disk
- **Location**: europe-west4 (Netherlands), N2D Spot VM

## Code Style Guidelines

### Imports
- Group imports: standard library, third-party crates, then local modules
- Use explicit imports; avoid glob imports (`use foo::*`)
- Re-import `Engine` trait for base64 locally where used: `use base64::{Engine as _, engine::general_purpose::STANDARD};`

### Formatting
- 4-space indentation (Rust default)
- Use `cargo fmt` defaults
- Section headers: `// === SECTION NAME ===`

### Error Handling
- Error type: `Box<dyn std::error::Error>`
- Return `Result<T, Box<dyn std::error::Error>>` from fallible functions
- Use `expect()` for env var misconfiguration
- Use `match` on `Result` in HTTP handlers for user-friendly HTML errors

### Dependencies
- All dependencies pinned exact versions (`= "x.y.z"`) for reproducibility
- Key crates: `axum`, `tokio`, `rustls`, `instant-acme`, `reqwest`, `sha2`

### Security
- Never log or expose secrets
- Secrets fetched from GCP Secret Manager, held only in RAM
- TLS private keys in memory only (`Vec<u8>`)
- Use `html_escape::encode_text()` for all user-provided data in HTML
