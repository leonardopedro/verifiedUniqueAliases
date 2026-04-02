# AGENTS.md - Guidelines for AI Coding Agents

## Project Overview

`paypal-auth-vm` is a single-file Rust application that runs entirely from initramfs on a GCP Shielded VM. It provides PayPal OAuth authentication with cryptographic attestation (vTPM PCR measurements) and dual-signed proof (Ed25519 + GCP IAM). It uses ACME for Let's Encrypt TLS certificates in pure Rust.

## Build & Run Commands

```bash
# Standard debug build
cargo build

# Release build (used in production/deployment)
cargo build --release

# Run the binary locally (requires PAYPAL_CLIENT_ID, DOMAIN, PAYPAL_SECRET_NAME env vars)
cargo run --release

# Run a specific binary (test utility)
cargo run --bin test_gcp_iam

# Check compilation without building
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Docker build for initramfs image (reproducible)
docker buildx build --output type=local,dest=./docker-output .

# Native build on target VM
./build-native.sh
```

## Testing

There is no formal test suite (`#[test]` or `#[cfg(test)]` blocks). The project uses:
- `cargo run --bin test_gcp_iam` for GCP IAM integration testing on the live VM
- `test-repro/` directory for reproducibility testing
- `test-binary-reproducibility.sh` for build artifact verification

To add tests, use `#[cfg(test)] mod tests` blocks within `src/main.rs` or create a `tests/` directory with integration tests.

## Code Style Guidelines

### Imports
- Group imports in this order: standard library, then third-party crates, then local modules
- Use explicit imports; avoid glob imports (`use foo::*`)
- Import specific items: `use serde::{Deserialize, Serialize}`
- Re-import `Engine` trait for base64 locally where used: `use base64::{Engine as _, engine::general_purpose::STANDARD};`

### Formatting
- 4-space indentation (Rust default)
- No `rustfmt.toml` or `.clippy.toml` exists; use `cargo fmt` defaults
- Keep lines under ~100 chars; use method chaining with one method per line for readability
- Section headers use comment blocks: `// === SECTION NAME ===`

### Naming Conventions
- Structs: `PascalCase` (e.g., `AppState`, `TokenResponse`, `PayPalUserInfo`)
- Functions: `snake_case` (e.g., `generate_attestation`, `fetch_secret_from_vault`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `HTML_TEMPLATE`, `PAYPAL_TLS_CERT`)
- Use descriptive names; no abbreviations except well-known ones (e.g., `sa_email`, `tls_config`)

### Types & Error Handling
- Error type: `Box<dyn std::error::Error>` (no custom error types)
- Return `Result<T, Box<dyn std::error::Error>>` from fallible functions
- Use `.map_err(|e| e.to_string())?` or `.map_err(|e| format!("context: {}", e))?` for error context
- Use `expect()` for errors that indicate misconfiguration (env vars, key parsing)
- Use `unwrap_or_else` with fallback values for non-fatal errors (e.g., measurements)
- Use `match` on `Result` for complex error handling in HTTP handlers; return user-friendly HTML errors

### Async Patterns
- All HTTP handlers are `async fn`
- Use `tokio::spawn` for concurrent tasks (HTTP server on port 80)
- Use `tokio::fs` for async file I/O; `std::fs` is acceptable in blocking contexts (TPM operations)
- `#[tokio::main]` as the async runtime entry point

### Dependencies
- All dependencies use pinned exact versions (`= "x.y.z"`) for reproducibility
- Key crates: `axum` (web framework), `tokio` (async runtime), `rustls` (TLS), `ed25519-dalek` (crypto), `instant-acme` (ACME client), `ring` (crypto primitives)

### Security Practices
- Never log or expose secrets (`PAYPAL_CLIENT_SECRET`, signing keys)
- Secrets are fetched from GCP Secret Manager at runtime, held only in RAM
- TLS private keys never touch persistent disk (stored only in memory via `Vec<u8>`)
- Use `html_escape::encode_text()` for all user-provided data in HTML output
- Pin TLS certificates for PayPal API communication

### HTTP Handler Patterns
- Handlers accept `State<Arc<AppState>>` for shared state
- Use axum extractors: `Query<T>`, `Path<T>`, `State<T>`
- Return `Html<String>` for pages, `impl IntoResponse` or `Response` for complex returns
- Build HTML content with `format!` macros, inject via `HTML_TEMPLATE.replace("{{CONTENT}}", ...)`
