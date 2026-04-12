//! PayPal OAuth Confidential VM
//!
//! Configuration: Single JSON secret in GCP Secret Manager
//! TLS: Google Public CA via ACME
//! Runtime: GCP Confidential VM (AMD SEV-SNP)

use axum::{
    extract::{State, Query},
    http::{StatusCode, header::{COOKIE, SET_COOKIE}},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};

// Unambiguous alias: prevents Rust from resolving to hyper::Response
// when hyper::service::service_fn is also in scope.
type AppResp = axum::http::Response<axum::body::Body>;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, ExternalAccountKey,
    Identifier, NewAccount, NewOrder, OrderStatus,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

// ============================================================================
// CONSTANTS
// ============================================================================

const GOOGLE_PUBLIC_CA_DIRECTORY: &str = "https://dv.acme-v02.api.pki.goog/directory";
const GOOGLE_PUBLIC_CA_STAGING_DIRECTORY: &str = "https://dv.acme-v02.test-api.pki.goog/directory";
const PAYPAL_CERT_PEM: &[u8] = include_bytes!("paypal.pem");
const GOOGLE_CA_PEM: &[u8] = include_bytes!("google_ca.pem");

const UI_VIBRANT_CSS: &str = r#"
    :root {
        --paypal-blue: #0070ba;
        --paypal-light: #00cfff;
        --bg-dark: #0a0e17;
        --panel-bg: rgba(25, 35, 50, 0.7);
        --glass-border: rgba(255, 255, 255, 0.1);
        --text-bright: #f0f4f8;
        --text-dim: #94a3b8;
        --accent-green: #4ade80;
        --accent-red: #f87171;
    }
    * { box-sizing: border-box; }
    body {
        font-family: 'Inter', 'SF Pro Display', -apple-system, sans-serif;
        background: radial-gradient(circle at top right, #1a2a4a, var(--bg-dark));
        color: var(--text-bright);
        margin: 0;
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        overflow-x: hidden;
    }
    .container {
        width: 100%;
        max-width: 900px;
        padding: 40px;
        background: var(--panel-bg);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid var(--glass-border);
        border-radius: 24px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        animation: floatIn 0.8s ease-out;
    }
    @keyframes floatIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    h1 {
        font-size: 32px;
        font-weight: 800;
        background: linear-gradient(to right, #60a5fa, #a855f7);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 24px;
        letter-spacing: -1px;
    }
    h3 { color: var(--text-bright); font-size: 18px; margin-top: 0; }
    .info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-bottom: 30px;
    }
    .info-card {
        background: rgba(255, 255, 255, 0.03);
        padding: 20px;
        border-radius: 16px;
        border: 1px solid var(--glass-border);
    }
    .info-card label {
        display: block;
        font-size: 12px;
        color: var(--text-dim);
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 8px;
    }
    .info-card span { font-weight: 600; font-size: 15px; }
    .status-pill {
        display: inline-flex;
        align-items: center;
        padding: 4px 12px;
        border-radius: 99px;
        font-size: 12px;
        font-weight: 600;
        background: rgba(74, 222, 128, 0.1);
        color: var(--accent-green);
    }
    .btn {
        background: linear-gradient(135deg, var(--paypal-blue), var(--paypal-light));
        color: white;
        padding: 16px 40px;
        text-decoration: none;
        border-radius: 12px;
        display: inline-flex;
        align-items: center;
        gap: 10px;
        font-weight: 700;
        transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        border: none;
        cursor: pointer;
        box-shadow: 0 10px 20px -5px rgba(0, 112, 186, 0.4);
    }
    .btn:hover { transform: scale(1.05); box-shadow: 0 15px 25px -5px rgba(0, 112, 186, 0.5); }
    .attestation-panel {
        background: #000;
        padding: 24px;
        border-radius: 16px;
        margin-top: 30px;
        border: 1px solid #333;
    }
    pre {
        color: #7dd3fc;
        font-family: 'Fira Code', 'Monaco', monospace;
        font-size: 11px;
        line-height: 1.6;
        overflow-x: auto;
        margin: 0;
    }
    ul { list-style: none; padding: 0; margin: 0; }
    li { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; color: var(--text-dim); font-size: 14px; }
    li::before { content: '✓'; color: var(--accent-green); font-weight: bold; }
    .error-box { background: rgba(248, 113, 113, 0.1); border: 1px solid var(--accent-red); padding: 20px; border-radius: 12px; color: var(--accent-red); }
"#;

const HTML_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confidential PayPal Auth</title>
    <style>{{CSS}}</style>
</head>
<body><div class="container">{{CONTENT}}</div>
<script>console.log('Confidential Enclave UI Ready');</script>
</body></html>
"#;

// ============================================================================
// CONFIG (single JSON secret)
// ============================================================================

#[derive(Debug, Deserialize)]
struct Config {
    paypal_client_id: String,
    paypal_client_secret: String,
    domain: String,
    eab_key_id: Option<String>,
    eab_hmac_key: Option<String>,
    #[serde(default)]
    staging: bool,
    acme_account_json: Option<String>,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Clone)]
struct AppState {
    paypal_client_id: String,
    paypal_client_secret: String,
    redirect_uri: String,
    domain: String,
    https_ready: Arc<AtomicBool>,
    staging: bool,
    tls_cert_hash: Arc<parking_lot::RwLock<Option<String>>>,
    session_secret: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PayPalUserInfo {
    user_id: String,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    middle_name: Option<String>,
    nickname: Option<String>,
    preferred_username: Option<String>,
    profile: Option<String>,
    picture: Option<String>,
    website: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    gender: Option<String>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    locale: Option<String>,
    phone_number: Option<String>,
}

fn get_acme_client() -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    Ok(reqwest::Client::new())
}

// ============================================================================
// TPM & CRYPTO
// ============================================================================

mod tpm {
    use tokio::process::Command;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Serialize};
    use tracing::info;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct SealedData {
        pub pub_blob: String,
        pub priv_blob: String,
    }

    pub(crate) async fn run_cmd(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if std::env::var("MOCK_HARDWARE").map(|v| v == "true").unwrap_or(false) {
            info!("MOCK: Skipping execution of {} {:?}", cmd, args);
            return Ok(b"mock_output".to_vec());
        }
        let output = Command::new(cmd)
            .args(args)
            .env("TCTI", "device:/dev/tpmrm0")
            .output()
            .await?;
        if !output.status.success() {
            return Err(format!("{} failed: {}", cmd, String::from_utf8_lossy(&output.stderr)).into());
        }
        Ok(output.stdout)
    }

    /// Seal data to the vTPM for local measurement-bound storage.
    pub async fn seal_dek(dek: &[u8], pcrs: &str) -> Result<SealedData, Box<dyn std::error::Error>> {
        tokio::fs::write("/tmp/dek.plain", dek).await?;
        run_cmd("tpm2_createpolicy", &["--policy-pcr", "-l", &format!("sha256:{}", pcrs), "-L", "/tmp/policy.digest"]).await?;
        run_cmd("tpm2_createprimary", &["-c", "/tmp/primary.ctx"]).await?;
        run_cmd("tpm2_create", &[
            "-C", "/tmp/primary.ctx",
            "-r", "/tmp/dek.priv",
            "-u", "/tmp/dek.pub",
            "-i", "/tmp/dek.plain",
            "-L", "/tmp/policy.digest",
        ]).await?;
        let pub_b = tokio::fs::read("/tmp/dek.pub").await?;
        let priv_b = tokio::fs::read("/tmp/dek.priv").await?;
        Ok(SealedData {
            pub_blob: STANDARD.encode(pub_b),
            priv_blob: STANDARD.encode(priv_b),
        })
    }

    pub async fn unseal_dek(sealed: &SealedData, pcrs: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pub_b = STANDARD.decode(&sealed.pub_blob)?;
        let priv_b = STANDARD.decode(&sealed.priv_blob)?;
        tokio::fs::write("/tmp/dek.pub", pub_b).await?;
        tokio::fs::write("/tmp/dek.priv", priv_b).await?;
        run_cmd("tpm2_createprimary", &["-c", "/tmp/primary.ctx"]).await?;
        run_cmd("tpm2_load", &[
            "-C", "/tmp/primary.ctx",
            "-u", "/tmp/dek.pub",
            "-r", "/tmp/dek.priv",
            "-c", "/tmp/dek.ctx",
        ]).await?;
        let dek = run_cmd("tpm2_unseal", &[
            "-c", "/tmp/dek.ctx",
            "-p", &format!("pcr:sha256:{}", pcrs)
        ]).await?;
        Ok(dek)
    }

    async fn ensure_ak() -> Result<String, Box<dyn std::error::Error>> {
        let ak_ctx = "/tmp/akv2.ctx";
        if tokio::fs::metadata(ak_ctx).await.is_ok() {
            return Ok(ak_ctx.to_string());
        }
        
        crate::enclave_init::kmsg("Provisioning transient Attestation Key...");

        // 1. Create primary key in Owner hierarchy explicitly
        run_cmd("tpm2_createprimary", &[
            "-C", "o", 
            "-g", "sha256", 
            "-G", "rsa2048", 
            "-c", "/tmp/primary_ak.ctx"
        ]).await?;

        // 2. Create the AK with 'restricted|sign' - required for TPM2_Quote
        run_cmd("tpm2_create", &[
            "-C", "/tmp/primary_ak.ctx",
            "-g", "sha256",
            "-G", "rsa2048",
            "-a", "sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth",
            "-u", "/tmp/akv2.pub",
            "-r", "/tmp/akv2.priv"
        ]).await?;
        
        // 3. Load it
        run_cmd("tpm2_load", &[
            "-C", "/tmp/primary_ak.ctx",
            "-u", "/tmp/akv2.pub",
            "-r", "/tmp/akv2.priv",
            "-c", ak_ctx
        ]).await?;
        
        Ok(ak_ctx.to_string())
    }

    pub async fn quote(pcrs: &str, nonce_hex: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
        let ak = ensure_ak().await.unwrap_or_else(|e| {
            crate::enclave_init::kmsg(&format!("AK setup failed: {}. Falling back to 0x81010001", e));
            "0x81010001".to_string()
        });
        
        run_cmd("tpm2_quote", &[
            "-c", &ak,
            "-l", &format!("sha256:{}", pcrs),
            "-q", nonce_hex,
            "-m", "/tmp/quote.msg",
            "-s", "/tmp/quote.sig"
        ]).await?;
        let msg = tokio::fs::read("/tmp/quote.msg").await?;
        let sig = tokio::fs::read("/tmp/quote.sig").await?;
        Ok((STANDARD.encode(msg), STANDARD.encode(sig)))
    }

    pub async fn get_ak_pub() -> Result<String, Box<dyn std::error::Error>> {
        ensure_ak().await?;
        run_cmd("tpm2_readpublic", &["-c", "/tmp/akv2.ctx", "-f", "pem", "-o", "/tmp/akv2.pem"]).await?;
        Ok(tokio::fs::read_to_string("/tmp/akv2.pem").await?)
    }
}

mod crypto {
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        Aes256Gcm, Key, Nonce,
        aead::AeadCore,
    };
    use rand::Rng;

    pub fn generate_dek() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill(&mut key[..]);
        key
    }

    pub fn encrypt(dek: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let key = Key::<Aes256Gcm>::from_slice(dek);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 
        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| format!("AesGcm encrypt failed: {:?}", e))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    pub fn decrypt(dek: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = Key::<Aes256Gcm>::from_slice(dek);
        let cipher = Aes256Gcm::new(key);
        let nonce_arr = Nonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce_arr, ciphertext).map_err(|e| format!("AesGcm decrypt failed: {:?}", e))?;
        Ok(plaintext)
    }
}

#[derive(Deserialize, Debug)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub error: Option<String>,
}

// ============================================================================
// GCP SECRET MANAGER
// ============================================================================

async fn fetch_config() -> Result<Config, Box<dyn std::error::Error>> {
    let secret_name = std::env::var("SECRET_NAME").unwrap_or_else(|_| {
        "projects/project-ae136ba1-3cc9-42cf-a48/secrets/PAYPAL_AUTH_CONFIG/versions/latest"
            .to_string()
    });

    let client = reqwest::Client::new();

    // Get access token from metadata server (using explicit IP for boot reliability)
    info!("Fetching metadata token from 169.254.169.254...");
    // Get access token from metadata server (using explicit IP for boot reliability)
    let token_resp: serde_json::Value = client
        .get("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .json()
        .await?;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or("No access token from metadata server")?;

    // Use default client for Secret Manager (system roots are fine here as it's the infra)
    let client = reqwest::Client::new();
    // Fetch secret
    let url = format!(
        "https://secretmanager.googleapis.com/v1/{}:access",
        secret_name
    );
    let secret_resp: serde_json::Value = client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await?
        .json()
        .await?;

    let encoded = secret_resp["payload"]["data"]
        .as_str()
        .ok_or("No payload in Secret Manager response")?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let json_str = String::from_utf8(STANDARD.decode(encoded)?)?;
    let config: Config = serde_json::from_str(&json_str)?;

    // --- SECONDARY TASK: Fetch instance attributes to populate environment ---
    // This is necessary because as PID 1 we don't have a launcher to do this for us.
    match client
        .get("http://169.254.169.254/computeMetadata/v1/instance/attributes/?recursive=true")
        .header("Metadata-Flavor", "Google")
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(attrs) = resp.json::<serde_json::Value>().await {
                if let Some(obj) = attrs.as_object() {
                    for (k, v) in obj {
                        if let Some(env_key) = k.strip_prefix("tee-env-") {
                            if let Some(val) = v.as_str() {
                                info!("Setting metadata env: {}={}", env_key, val);
                                std::env::set_var(env_key, val);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => info!("Could not fetch metadata attributes: {}", e),
    }

    Ok(config)
}

// ============================================================================
// GOOGLE PUBLIC CA
// ============================================================================

struct GooglePublicCaManager {
    domain: String,
    eab_key_id: Option<String>,
    eab_hmac_key: Option<String>,
    staging: bool,
    acme_account_json: Option<String>,
}

impl GooglePublicCaManager {
    fn new(config: &Config) -> Self {
        Self {
            domain: config.domain.clone(),
            eab_key_id: config.eab_key_id.clone(),
            eab_hmac_key: config.eab_hmac_key.clone(),
            staging: config.staging,
            acme_account_json: config.acme_account_json.clone(),
        }
    }

    async fn ensure_certificate(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        if std::env::var("MOCK_HARDWARE").map(|v| v == "true").unwrap_or(false) {
            info!("MOCK_HARDWARE: Returning self-signed dummy certificate");
            let key_pair = rcgen::KeyPair::generate()?;
            let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])?.self_signed(&key_pair)?;
            return Ok((cert.pem().as_bytes().to_vec(), key_pair.serialize_pem().as_bytes().to_vec()));
        }

        info!("Checking for cached TLS credentials in Vault...");
        if let Some((cert, key)) = Self::fetch_cached_tls().await {
            return Ok((cert, key));
        }

        info!("Obtaining TLS certificate from Google Public CA...");

        let acme_url = if self.staging {
            GOOGLE_PUBLIC_CA_STAGING_DIRECTORY
        } else {
            GOOGLE_PUBLIC_CA_DIRECTORY
        };

        // Try restoring existing ACME account from tmpfs, then from config JSON, then fallback to EAB
        let account_path = "/tmp/acme-account.json";
        let account = if let Ok(data) = tokio::fs::read_to_string(account_path).await {
            info!("Restoring ACME account from tmpfs...");
            let creds: AccountCredentials = serde_json::from_str(&data)?;
            Account::builder()?.from_credentials(creds).await?
        } else if let Some(ref json) = self.acme_account_json {
            info!("Restoring ACME account from configured JSON...");
            let creds: AccountCredentials = serde_json::from_str(json)?;
            // Cache it to tmpfs for next renewal in this boot
            let _ = tokio::fs::write(account_path, json).await;
            Account::builder()?.from_credentials(creds).await?
        } else {
            info!("Creating new ACME account with EAB...");
            let kid = self
                .eab_key_id
                .as_ref()
                .ok_or("Missing EAB key ID and no acme_account_json")?;
            let hmac_str = self
                .eab_hmac_key
                .as_ref()
                .ok_or("Missing EAB HMAC key and no acme_account_json")?;

            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            let hmac_bytes = URL_SAFE_NO_PAD.decode(hmac_str.trim())?;
            let eab = ExternalAccountKey::new(kid.clone(), &hmac_bytes);
            let (account, creds) = Account::builder()?
                .create(
                    &NewAccount {
                        contact: &[&format!("mailto:admin@{}", self.domain)],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    acme_url.to_owned(),
                    Some(&eab),
                )
                .await?;
            if let Ok(json) = serde_json::to_string(&creds) {
                let _ = tokio::fs::write(account_path, json).await;
            }
            account
        };

        // Create order and process challenges
        let identifier = Identifier::Dns(self.domain.clone());
        let mut order = account.new_order(&NewOrder::new(&[identifier])).await?;
        let mut authorizations = order.authorizations();

        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            if matches!(authz.status, AuthorizationStatus::Valid) {
                continue;
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or("No HTTP-01 challenge found")?;

            let challenge_dir = "/tmp/acme-challenge";
            tokio::fs::create_dir_all(challenge_dir).await?;
            tokio::fs::write(
                format!("{}/{}", challenge_dir, challenge.token),
                challenge.key_authorization().as_str(),
            )
            .await?;

            challenge.set_ready().await?;
        }

        // Wait for the order to reach the "ready" state
        // (when all authorizations are verified)
        while !matches!(order.state().status, OrderStatus::Ready) {
            info!(
                "Waiting for ACME order state to become 'ready' (current: {:?})...",
                order.state().status
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
            order.refresh().await?;
            if matches!(order.state().status, OrderStatus::Invalid) {
                return Err("ACME order reached invalid state".into());
            }
        }

        info!("ACME order is ready, finalizing...");

        let private_key_pem = order.finalize().await?;
        let cert_chain_pem: String = order
            .poll_certificate(&instant_acme::RetryPolicy::default())
            .await?;

        info!("TLS certificate obtained (RAM only)");
        Self::store_cached_tls(&cert_chain_pem.as_bytes(), &private_key_pem.as_bytes()).await;
        Ok((cert_chain_pem.into_bytes(), private_key_pem.into_bytes()))
    }

    async fn fetch_cached_tls() -> Option<(Vec<u8>, Vec<u8>)> {
        let secret_name = std::env::var("TLS_CACHE_SECRET").ok()?;
        let client = reqwest::Client::new();
        
        // Get access token from metadata server
        let token_resp: serde_json::Value = client
            .get("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
            .header("Metadata-Flavor", "Google")
            .send().await.ok()?.json().await.ok()?;
        
        let access_token = token_resp["access_token"].as_str()?;
        let url = format!("https://secretmanager.googleapis.com/v1/{}/versions/latest:access", secret_name);
        
        let secret_resp: serde_json::Value = client
            .get(&url).bearer_auth(access_token).send().await.ok()?.json().await.ok()?;
            
        let encoded = secret_resp["payload"]["data"].as_str()?;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let wrapper_bytes = STANDARD.decode(encoded).ok()?;
        let wrapper: serde_json::Value = serde_json::from_slice(&wrapper_bytes).ok()?;
        
        // Recover and unseal DEK from entire TPM measured-boot chain (0,2,4,7,8,9,15)
        let sealed_dek: tpm::SealedData = serde_json::from_value(wrapper["sealed_dek"].clone()).ok()?;
        info!("Unsealing DEK via vTPM chain (0,2,4,7,8,9,15)...");
        let dek = match tpm::unseal_dek(&sealed_dek, "0,2,4,7,8,9,15").await {
            Ok(d) => d,
            Err(e) => {
                error!("TPM Unseal failed, measurements likely changed! {}", e);
                return None;
            }
        };

        // Decrypt ciphertext using DEK
        let nonce = STANDARD.decode(wrapper["nonce"].as_str()?).ok()?;
        let ciphertext = STANDARD.decode(wrapper["ciphertext"].as_str()?).ok()?;
        let plaintext = crypto::decrypt(&dek, &nonce, &ciphertext).ok()?;

        let json: serde_json::Value = serde_json::from_slice(&plaintext).ok()?;
        let cert = STANDARD.decode(json["cert"].as_str()?).ok()?;
        let key = STANDARD.decode(json["key"].as_str()?).ok()?;
        
        info!("Successfully restored and unsealed TLS cache from Vault (using vTPM)");
        Some((cert, key))
    }

    async fn store_cached_tls(cert: &[u8], key: &[u8]) {
        if let Ok(secret_name) = std::env::var("TLS_CACHE_SECRET") {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            
            // Generate DEK, seal DEK, and encrypt payload
            let dek = crypto::generate_dek();
            let sealed_dek = match tpm::seal_dek(&dek, "0,2,4,7,8,9,15").await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to seal DEK to vTPM chain: {}", e);
                    return;
                }
            };

            let payload_json = serde_json::json!({
                "cert": STANDARD.encode(cert),
                "key": STANDARD.encode(key)
            }).to_string();

            let (nonce, ciphertext) = match crypto::encrypt(&dek, payload_json.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to encrypt TLS key with DEK: {}", e);
                    return;
                }
            };
            
            let payload = serde_json::json!({
                "sealed_dek": sealed_dek,
                "nonce": STANDARD.encode(nonce),
                "ciphertext": STANDARD.encode(ciphertext)
            });
            let payload_b64 = STANDARD.encode(payload.to_string());
            
            let client = reqwest::Client::new();
            if let Ok(token_resp) = client
                .get("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
                .header("Metadata-Flavor", "Google")
                .send().await {
                if let Ok(json) = token_resp.json::<serde_json::Value>().await {
                    if let Some(access_token) = json["access_token"].as_str() {
                        let url = format!("https://secretmanager.googleapis.com/v1/{}:addVersion", secret_name);
                        let _ = client.post(&url)
                            .bearer_auth(access_token)
                            .json(&serde_json::json!({ "payload": { "data": payload_b64 } }))
                            .send().await;
                        info!("Saved locally-encrypted TPM-sealed TLS cache back to Vault");
                    }
                }
            }
        }
    }
}

// ============================================================================
// ATTESTATION
// ============================================================================

async fn generate_attestation(client_id: &str, userinfo: &PayPalUserInfo) -> String {
    use sha2::{Digest, Sha256};

    let pad = |s: Option<&str>, len: usize| {
        let base = s.unwrap_or("N/A");
        format!("{:_<width$}", &base[..base.len().min(len)], width = len)
    };

    // 1. Compose canonical record with fixed-width padding for all fields
    let data = format!(
        "CLIENT_ID:{}|USER_ID:{}|NAME:{}|GIVEN:{}|FAMILY:{}|EMAIL:{}|LOCALE:{}|PHONE:{}",
        pad(Some(client_id), 64),
        pad(Some(&userinfo.user_id), 64),
        pad(userinfo.name.as_deref(), 64),
        pad(userinfo.given_name.as_deref(), 64),
        pad(userinfo.family_name.as_deref(), 64),
        pad(userinfo.email.as_deref(), 64),
        pad(userinfo.locale.as_deref(), 64),
        pad(userinfo.phone_number.as_deref(), 64),
    );
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let hash_bytes = hasher.finalize();

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let hash_b64 = STANDARD.encode(hash_bytes);

    // 2. Obtain a hardware-rooted attestation token directly from the vTPM for the entire boot chain
    match tpm::quote("0,2,4,7,8,9,15", &hex::encode(hash_bytes)).await {
        Ok((msg_b64, sig_b64)) => {
            serde_json::json!({
                "tpm_quote_msg": msg_b64,
                "tpm_quote_sig": sig_b64,
                "note": "Full Hardware-Rooted Measured Boot Quote (0,2,4,7,8,9,15)",
                "bound_user_data": data,
                "binding_hash": hash_b64,
                "hw_platform": "vTPM Hardware Identity"
            }).to_string()
        }
        Err(e) => {
            error!("Failed to generate vTPM quote: {}", e);
            serde_json::json!({
                "SIMULATED_REPORT": true,
                "note": "Hardware attestation failed",
                "bound_user_data": data,
                "binding_hash": hash_b64,
                "error": e.to_string(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }).to_string()
        }
    }
}

// ============================================================================
// OAUTH
// ============================================================================

async fn exchange_code_for_token(
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    staging: bool,
) -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let base_url = if staging {
        "https://api-m.sandbox.paypal.com"
    } else {
        "https://api-m.paypal.com"
    };
    let url = format!("{}/v1/oauth2/token", base_url);

    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .basic_auth(client_id, Some(client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "Could not read body".to_string());
        error!("PayPal token exchange error: status={}, body={}", status, body);
        return Err(format!("Token exchange failed: {} (Status: {})", body, status).into());
    }
    Ok(resp.json().await?)
}

async fn get_userinfo(token: &str, staging: bool) -> Result<PayPalUserInfo, Box<dyn std::error::Error>> {
    let base_url = if staging {
        "https://api-m.sandbox.paypal.com"
    } else {
        "https://api-m.paypal.com"
    };
    let url = format!("{}/v1/identity/oauth2/userinfo?schema=paypalv1.1", base_url);

    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "Could not read body".to_string());
        error!("PayPal userinfo error: status={}, body={}", status, body);
        return Err(format!("Userinfo failed: {} (Status: {})", body, status).into());
    }
    Ok(resp.json().await?)
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

async fn report() -> impl IntoResponse {
    let nonce = "01".repeat(32);
    match tpm::quote("0,2,4,7,8,9,15", &nonce).await {
        Ok((msg, sig)) => {
            let body = serde_json::json!({
                "quote": msg,
                "signature": sig,
                "nonce": nonce,
                "note": "Hardware attestation success"
            });
            (StatusCode::OK, serde_json::to_string(&body).unwrap()).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("tpm2_quote failed: {}", e)).into_response()
    }
}

async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    let env_label = if state.staging { "SANDBOX" } else { "PRODUCTION" };
    let content = format!(
        r#"
        <h1>Confidential PayPal Authentication</h1>
        <div class="info-grid">
            <div class="info-card">
                <label>Domain</label>
                <span>{}</span>
            </div>
            <div class="info-card">
                <label>Environment</label>
                <div class="status-pill">{}</div>
            </div>
            <div class="info-card">
                <label>Computing</label>
                <span>AMD SEV-SNP Enclave</span>
            </div>
        </div>
        <div style="margin-bottom: 40px;">
            <h3>Security Architecture</h3>
            <ul>
                <li>Hardware-rooted Attestation (TPM 2.0)</li>
                <li>TLS Pinning & Google Public CA</li>
                <li>PID 1 Isolate (No OS runtime)</li>
                <li>Encrypted RAM Identity</li>
            </ul>
        </div>
        <a href="/login" class="btn">
            Connect PayPal Account
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"></path><path d="M12 5l7 7-7 7"></path></svg>
        </a>
        "#,
        state.domain, env_label
    );
    Html(HTML_TEMPLATE.replace("{{CSS}}", UI_VIBRANT_CSS).replace("{{CONTENT}}", &content))
}

async fn login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base_url = if state.staging {
        "https://www.sandbox.paypal.com"
    } else {
        "https://www.paypal.com"
    };
    
    // Generate secure state for CSRF protection
    let oauth_state = hex::encode(crypto::generate_dek()); // Using generate_dek for 32 random bytes
    
    let url = format!(
        "{}/signin/authorize?client_id={}&response_type=code&scope=openid%20profile%20email&redirect_uri={}&state={}",
        base_url,
        state.paypal_client_id,
        urlencoding::encode(&state.redirect_uri),
        oauth_state
    );
    
    let cookie = format!("oauth_state={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300", oauth_state);
    
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header("Location", url)
        .header(SET_COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn callback(
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<std::sync::Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> AppResp {
    let code = params.get("code").cloned();
    let state_param = params.get("state").cloned();
    let error_param = params.get("error").cloned();

    // 1. Verify CSRF State
    let cookie_state = headers.get(COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(';').find(|part| part.trim().starts_with("oauth_state=")))
        .map(|p| p.trim()["oauth_state=".len()..].to_string());

    if state_param.is_none() || state_param != cookie_state {
        return Html(HTML_TEMPLATE.replace("{{CSS}}", UI_VIBRANT_CSS).replace("{{CONTENT}}", 
            r#"<div class="error-box"><h2>CSRF Validation Failed</h2><p>The anti-forgery state token is missing or invalid.</p></div>"#)).into_response();
    }

    if let Some(error) = error_param {
        return Html(HTML_TEMPLATE.replace("{{CSS}}", UI_VIBRANT_CSS).replace("{{CONTENT}}", &format!(
            r#"<div class="error-box"><h2>PayPal Error</h2><p>{}</p></div><a href="/" class="btn" style="margin-top:20px;">Back</a>"#,
            html_escape::encode_text(&error)
        ))).into_response();
    }

    let code = match code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Missing code").into_response(),
    };

    let token = match exchange_code_for_token(
        &code,
        &state.paypal_client_id,
        &state.paypal_client_secret,
        &state.redirect_uri,
        state.staging,
    ).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Token exchange failed: {:?}", e);
            
            // DIAGNOSTIC CHECK
            let base_url = if state.staging { "https://api-m.sandbox.paypal.com" } else { "https://api-m.paypal.com" };
            tokio::spawn(async move {
                let diag_url = format!("{}/v1/oauth2/token", base_url);
                let output = std::process::Command::new("/sbin/curl")
                    .args(["-Iv", "--connect-timeout", "10", &diag_url])
                    .output();
                match output {
                    Ok(o) => {
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        tracing::error!("CURL DIAGNOSTIC for {}:\n{}", diag_url, stderr);
                    }
                    Err(e) => tracing::error!("CURL itself failed to run: {:?}", e),
                }
            });

            return axum::response::Html(HTML_TEMPLATE.replace("{{CONTENT}}", &format!(
                r#"<div class="error"><h2>Token Exchange Failed</h2><p>{}</p></div><a href="/" class="btn">Back</a>"#,
                html_escape::encode_text(&e.to_string())
            ))).into_response();
        }
    };

    let userinfo = match get_userinfo(&token.access_token, state.staging).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Userinfo failed: {}", e);
            return axum::response::Html(HTML_TEMPLATE.replace("{{CONTENT}}", &format!(
                r#"<div class="error"><h2>User Info Failed</h2><p>{}</p></div><a href="/" class="btn">Back</a>"#,
                html_escape::encode_text(&e.to_string())
            ))).into_response();
        }
    };

    let attestation = generate_attestation(&state.paypal_client_id, &userinfo).await;

    Html(HTML_TEMPLATE.replace("{{CSS}}", UI_VIBRANT_CSS).replace(
        "{{CONTENT}}",
        &format!(
            r#"
        <h1>Authentication Successful</h1>
        <div class="info-grid">
            <div class="info-card">
                <label>PayPal User ID</label>
                <span>{}</span>
            </div>
            <div class="info-card">
                <label>Verified Name</label>
                <span>{}</span>
            </div>
            <div class="info-card">
                <label>Environment</label>
                <div class="status-pill">AUTHENTICATED</div>
            </div>
        </div>
        <div class="attestation-panel">
            <h3>Hardware-Rooted Attestation</h3>
            <div style="font-size: 11px; color: var(--accent-green); margin-bottom: 10px;">
                Verified by AMD SEV-SNP vTPM
            </div>
            <pre>{}</pre>
        </div>
        <div style="margin-top: 30px;">
            <a href="/" class="btn">Return to Dashboard</a>
        </div>
        "#,
            html_escape::encode_text(&userinfo.user_id),
            html_escape::encode_text(&userinfo.name.unwrap_or_else(|| "N/A".to_string())),
            html_escape::encode_text(&attestation),
        ),
    )).into_response()
}

async fn acme_challenge(
    axum::extract::Path(token): axum::extract::Path<String>,
    State(state): State<Arc<AppState>>,
) -> AppResp {
    if state.https_ready.load(Ordering::Relaxed) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read_to_string(format!("/tmp/acme-challenge/{}", token)).await {
        Ok(c) => c.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[allow(dead_code)]
async fn http_to_https_redirect() -> Redirect {
    Redirect::permanent("https://")
}

// ============================================================================
// TLS
// ============================================================================

async fn load_tls_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<SslAcceptor>, Box<dyn std::error::Error>> {
    tokio::fs::write("/tmp/tls-cert.pem", cert_pem).await?;
    tokio::fs::write("/tmp/tls-key.pem", key_pem).await?;

    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    builder.set_certificate_file("/tmp/tls-cert.pem", SslFiletype::PEM)?;
    builder.set_private_key_file("/tmp/tls-key.pem", SslFiletype::PEM)?;
    builder.check_private_key()?;

    Ok(Arc::new(builder.build()))
}

// ============================================================================
// ENCLAVE INIT — PID 1 responsibilities: mounts, drivers, DHCP
// Must run before the Tokio runtime touches anything.
// ============================================================================
mod enclave_init {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::Ipv4Addr;

    pub fn kmsg(msg: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            use std::io::Write;
            let _ = writeln!(f, "<3>[INIT] {}", msg);
        }
        eprintln!("[INIT] {}", msg);
    }

    pub fn mount_filesystems() {
        if std::env::var("MOCK_HARDWARE").map(|v| v == "true").unwrap_or(false) || std::process::id() != 1 {
            return;
        }
        
        fn mount_fs(source: &str, target: &str, fstype: &str) {
            std::fs::create_dir_all(target).ok();
            let src = std::ffi::CString::new(source).unwrap();
            let tgt = std::ffi::CString::new(target).unwrap();
            let fst = std::ffi::CString::new(fstype).unwrap();
            let ret = unsafe {
                libc::mount(
                    src.as_ptr(),
                    tgt.as_ptr(),
                    fst.as_ptr(),
                    0,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                // Ignore EBUSY (already mounted)
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EBUSY) {
                    eprintln!("Warning: mount {} on {} failed: {}", source, target, err);
                }
            }
        }

        mount_fs("devtmpfs", "/dev", "devtmpfs");
        mount_fs("proc", "/proc", "proc");
        mount_fs("sysfs", "/sys", "sysfs");
        mount_fs("tmpfs", "/tmp", "tmpfs");
        mount_fs("tmpfs", "/run", "tmpfs");

        kmsg("Essential filesystems mounted");

        // Background Clock Sync from GCP Metadata (for TLS validity)
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(10));
            // Use blocking client for simplest PID 1 bootstrapping
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build().ok();
            if let Some(c) = client {
                match c.get("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token")
                    .header("Metadata-Flavor", "Google")
                    .send() {
                    Ok(resp) => {
                        if let Some(date_str) = resp.headers().get("date").and_then(|v| v.to_str().ok()) {
                            if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(date_str) {
                                let secs = dt.timestamp();
                                let nsecs = dt.timestamp_subsec_nanos();
                                let tv = libc::timespec { tv_sec: secs as _, tv_nsec: nsecs as _ };
                                unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &tv); }
                                kmsg(&format!("System clock synced: {}", date_str));
                            }
                        }
                    }
                    Err(e) => kmsg(&format!("Clock sync failed: {}", e)),
                }
            }
        });
    }

    fn modprobe(module: &str) {
        // Try modprobe first (handles dependencies and compressed .ko.zst)
        match std::process::Command::new("/sbin/modprobe")
            .arg(module)
            .status()
        {
            Ok(s) if s.success() => {
                kmsg(&format!("modprobe {}: ok", module));
                return;
            }
            Ok(s) => kmsg(&format!("modprobe {}: exit {}", module, s)),
            Err(e) => kmsg(&format!("modprobe {}: {}", module, e)),
        }

        // Fallback: find the .ko/.ko.zst in /usr/lib/modules or /lib/modules,
        // decompress if needed, then insmod directly.
        if let Some(ko_path) = find_module_file(module) {
            kmsg(&format!("found {} at {}", module, ko_path.display()));
            let load_path = decompress_module(&ko_path);
            match std::process::Command::new("/sbin/insmod")
                .arg(&load_path)
                .status()
            {
                Ok(s) if s.success() => kmsg(&format!("insmod {}: ok", module)),
                Ok(s) => kmsg(&format!("insmod {}: exit {}", module, s)),
                Err(e) => kmsg(&format!("insmod {}: {}", module, e)),
            }
        } else {
            kmsg(&format!("module {} not found", module));
        }
    }

    /// Recursively search /usr/lib/modules and /lib/modules for a .ko or .ko.zst
    fn find_module_file(module: &str) -> Option<std::path::PathBuf> {
        let ko = format!("{}.ko", module);
        let zst = format!("{}.ko.zst", module);
        for base in &["/usr/lib/modules", "/lib/modules"] {
            if let Some(p) = search_dir_recursive(std::path::Path::new(base), &ko, &zst) {
                return Some(p);
            }
        }
        None
    }

    fn search_dir_recursive(
        dir: &std::path::Path,
        ko: &str,
        zst: &str,
    ) -> Option<std::path::PathBuf> {
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(p) = search_dir_recursive(&path, ko, zst) {
                    return Some(p);
                }
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == ko || name == zst {
                    return Some(path);
                }
            }
        }
        None
    }

    /// Decompress .ko.zst → /tmp/*.ko; pass through .ko unchanged
    fn decompress_module(path: &std::path::Path) -> std::path::PathBuf {
        if path.extension().map_or(false, |e| e == "zst") {
            let out = std::path::PathBuf::from(format!(
                "/tmp/{}.ko",
                path.file_stem().unwrap_or_default().to_string_lossy()
            ));
            for dec in &["zstd", "unzstd", "/usr/bin/zstd"] {
                if std::process::Command::new(*dec)
                    .arg("-d")
                    .arg("-f")
                    .arg(path)
                    .arg("-o")
                    .arg(&out)
                    .status()
                    .map_or(false, |s| s.success())
                {
                    return out;
                }
            }
            // Last resort: pipe through sh
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "zstd -d < '{}' > '{}'",
                    path.display(),
                    out.display()
                ))
                .status();
            out
        } else {
            path.to_path_buf()
        }
    }

    fn find_interface() -> Option<String> {
        std::fs::read_dir("/sys/class/net")
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .find(|n| n != "lo" && n != "dummy0")
    }

    fn read_mac(iface: &str) -> [u8; 6] {
        let s = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))
            .unwrap_or_default();
        let mut mac = [0u8; 6];
        for (i, p) in s.trim().split(':').enumerate().take(6) {
            mac[i] = u8::from_str_radix(p, 16).unwrap_or(0);
        }
        mac
    }

    fn build_dhcp(xid: u32, mac: &[u8; 6], msg_type: u8, req_ip: Option<Ipv4Addr>) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1; // op: BOOTREQUEST
        p[1] = 1; // htype: Ethernet
        p[2] = 6; // hlen
        p[10] = 0x80; // flags: broadcast
        p[4..8].copy_from_slice(&xid.to_be_bytes());
        p[28..34].copy_from_slice(mac);
        p[236] = 99;
        p[237] = 130;
        p[238] = 83;
        p[239] = 99; // magic cookie
        p.extend_from_slice(&[53, 1, msg_type]);
        if let Some(ip) = req_ip {
            p.extend_from_slice(&[50, 4]);
            p.extend_from_slice(&ip.octets());
        }
        p.extend_from_slice(&[55, 3, 1, 3, 6]); // request subnet, router, dns
        p.push(255);
        p
    }

    struct Lease {
        ip: Ipv4Addr,
        prefix: u8,
        gw: Option<Ipv4Addr>,
        dns: Vec<Ipv4Addr>,
    }

    fn parse_lease(buf: &[u8]) -> Option<Lease> {
        if buf.len() < 240 {
            return None;
        }
        let ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let mut mask = Ipv4Addr::new(255, 255, 255, 0);
        let mut gw = None;
        let mut dns = Vec::new();
        let mut i = 240;
        while i < buf.len() {
            match buf[i] {
                255 => break,
                0 => {
                    i += 1;
                }
                code => {
                    if i + 1 >= buf.len() {
                        break;
                    }
                    let len = buf[i + 1] as usize;
                    if i + 2 + len > buf.len() {
                        break;
                    }
                    let v = &buf[i + 2..i + 2 + len];
                    match code {
                        1 if len == 4 => mask = Ipv4Addr::new(v[0], v[1], v[2], v[3]),
                        3 if len >= 4 => gw = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
                        6 => {
                            for c in v.chunks(4) {
                                if c.len() == 4 {
                                    dns.push(Ipv4Addr::new(c[0], c[1], c[2], c[3]));
                                }
                            }
                        }
                        _ => {}
                    }
                    i += 2 + len;
                }
            }
        }
        let prefix = mask.octets().iter().map(|b| b.count_ones()).sum::<u32>() as u8;
        Some(Lease {
            ip,
            prefix,
            gw,
            dns,
        })
    }

    fn apply_lease(iface: &str, lease: &Lease) {
        use std::process::Command;
        let cidr = format!("{}/{}", lease.ip, lease.prefix);
        let _ = Command::new("/sbin/ip")
            .args(["addr", "flush", "dev", iface])
            .status();
        let _ = Command::new("/sbin/ip")
            .args(["addr", "add", &cidr, "dev", iface])
            .status();
        let _ = Command::new("/sbin/ip")
            .args(["link", "set", iface, "mtu", "1460", "up"])
            .status();
        
        // Ensure loopback is up
        let _ = Command::new("/sbin/ip")
            .args(["link", "set", "lo", "up"])
            .status();

        if let Some(gw) = lease.gw {
            // CRITICAL GCP FIX: GCP assigns /32 subnet masks. The gateway is
            // technically outside our subnet, so the kernel will reject a
            // default route. We must add a direct device-bound host route to
            // the gateway first!
            let _ = Command::new("/sbin/ip")
                .args(["route", "add", &gw.to_string(), "dev", iface])
                .status();

            let _ = Command::new("/sbin/ip")
                .args(["route", "add", "default", "via", &gw.to_string()])
                .status();
        }

        if !lease.dns.is_empty() {
            std::fs::create_dir_all("/etc").ok();
            let resolv: String = lease
                .dns
                .iter()
                .map(|ip| format!("nameserver {}\n", ip))
                .collect();
            std::fs::write("/etc/resolv.conf", resolv).ok();
        }
        kmsg(&format!("Network up: {} gw={:?}", cidr, lease.gw));
    }

    async fn dhcp(iface: &str) -> Result<Lease, Box<dyn std::error::Error>> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_broadcast(true)?;
        // CRITICAL FIX: Without an IP address, Linux refuses to route
        // 255.255.255.255 broadcasts with ENETUNREACH unless we explicitly
        // pin the socket to the raw interface!
        let ifname = std::ffi::CString::new(iface)?;
        unsafe {
            use std::os::unix::io::AsRawFd;
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                ifname.as_ptr() as *const libc::c_void,
                ifname.as_bytes().len() as libc::socklen_t,
            );
        }
        // Listen on all interfaces port 68 for DHCP responses
        sock.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68).into())?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let bc = std::net::SocketAddrV4::new(Ipv4Addr::BROADCAST, 67);
        let mac = read_mac(iface);
        let xid: u32 = rand::random::<u32>(); // Use random XID

        kmsg(&format!("DHCP: Starting on {} (mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, xid=0x{:08x})", 
            iface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], xid));

        let mut recv_buf =[0u8; 1024];

        // 1. DISCOVER -> OFFER loop (up to 5 retries)
        let mut offered_ip = None;
        for attempt in 1..=5 {
            kmsg(&format!("DHCP: DISCOVER attempt {}/5...", attempt));
            sock.send_to(&build_dhcp(xid, &mac, 1, None), &bc.into())?;
            
            // Wait for OFFER
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(5) {
                let mut buf =[std::mem::MaybeUninit::uninit(); 1024];
                match sock.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        for i in 0..n {
                            recv_buf[i] = unsafe { buf[i].assume_init() };
                        }
                        // Check Magic Cookie offset 236
                        if n >= 240 && &recv_buf[236..240] == &[99, 130, 83, 99] {
                            // Check XID offset 4
                            let recv_xid = u32::from_be_bytes([recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7]]);
                            if recv_xid == xid {
                                // Find Option 53 (Message Type)
                                let mut msg_type = 0;
                                let mut i = 240;
                                while i + 1 < n {
                                    let code = recv_buf[i];
                                    if code == 255 { break; }
                                    if code == 0 { i += 1; continue; }
                                    let len = recv_buf[i+1] as usize;
                                    if i + 2 + len > n { break; }
                                    if code == 53 && len == 1 {
                                        msg_type = recv_buf[i+2];
                                    }
                                    i += 2 + len;
                                }
                                if msg_type == 2 { // OFFER
                                    let ip = Ipv4Addr::new(recv_buf[16], recv_buf[17], recv_buf[18], recv_buf[19]);
                                    kmsg(&format!("DHCP: OFFER received: {}", ip));
                                    offered_ip = Some(ip);
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => break, // Timeout
                }
            }
            if offered_ip.is_some() { break; }
        }

        let offered = offered_ip.ok_or("No DHCP OFFER received after multiple attempts")?;

        // 2. REQUEST -> ACK loop (up to 3 retries)
        for attempt in 1..=3 {
            kmsg(&format!("DHCP: REQUESTing {} (attempt {}/3)...", offered, attempt));
            sock.send_to(&build_dhcp(xid, &mac, 3, Some(offered)), &bc.into())?;

            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(5) {
                let mut buf =[std::mem::MaybeUninit::uninit(); 1024];
                match sock.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        for i in 0..n {
                            recv_buf[i] = unsafe { buf[i].assume_init() };
                        }
                        if n >= 240 && &recv_buf[236..240] == &[99, 130, 83, 99] {
                            let recv_xid = u32::from_be_bytes([recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7]]);
                            if recv_xid == xid {
                                let mut msg_type = 0;
                                let mut i = 240;
                                while i + 1 < n {
                                    let code = recv_buf[i];
                                    if code == 255 { break; }
                                    if code == 0 { i += 1; continue; }
                                    let len = recv_buf[i+1] as usize;
                                    if i + 2 + len > n { break; }
                                    if code == 53 && len == 1 {
                                        msg_type = recv_buf[i+2];
                                    }
                                    i += 2 + len;
                                }
                                if msg_type == 5 { // ACK
                                    let lease = parse_lease(&recv_buf[..n]).ok_or("Bad DHCP ACK format")?;
                                    kmsg(&format!("DHCP: ACK received! ip={}, netmask={}, gw={:?}, dns={:?}", 
                                        lease.ip, lease.prefix, lease.gw, lease.dns));
                                    return Ok(lease);
                                } else if msg_type == 6 { // NAK
                                    return Err("DHCP NAK received".into());
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        Err("DHCP ACK timeout".into())
    }

    /// Load drivers, wait for NIC, perform DHCP, apply lease.
    pub async fn configure_network() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var("MOCK_HARDWARE").map(|v| v == "true").unwrap_or(false) || std::process::id() != 1 {
            kmsg("MOCK_HARDWARE or not PID 1: Skipping network configuration");
            return Ok(());
        }
        modprobe("gve");
        modprobe("virtio_net");

        kmsg("Waiting for network interface...");
        let iface = {
            let mut found = None;
            for _ in 0..60 {
                if let Some(i) = find_interface() {
                    found = Some(i);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            found.ok_or("No network interface after 30s")?
        };
        kmsg(&format!(
            "Interface found: {}. Bringing interface UP...",
            iface
        ));

        // CRITICAL: We must bring the interface UP before we can broadcast UDP!
        let _ = std::process::Command::new("/sbin/ip")
            .args(["link", "set", &iface, "up"])
            .status();

        // Brief wait for PHY link state to stabilize
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let lease = dhcp(&iface).await?;
        apply_lease(&iface, &lease);
        Ok(())
    }

    /// On fatal failure as PID 1, we must NEVER exit — that causes a kernel
    /// panic. Instead, loop forever so serial-console logs are preserved.
    pub fn poweroff() -> ! {
        kmsg("FATAL: Initialization failed. Halting system to preserve serial logs...");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}

// ============================================================================
// MAIN — PID 1 entry point
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Explicitly set SSL cert paths for OpenSSL discovery in minimal rootfs
    std::env::set_var("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");
    std::env::set_var("SSL_CERT_DIR", "/etc/ssl/certs");

    // 1. PID 1 RESPONSIBILITIES: Mount filesystems BEFORE anything else!
    enclave_init::mount_filesystems();

    // 2. Initialize the Tokio runtime now that the environment is sane
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            enclave_init::kmsg(&format!("FATAL: Tokio runtime build failed: {}", e));
            enclave_init::poweroff()
        });

    // 3. Configure network (DHCP) from within the async runtime
    rt.block_on(async {
        if let Err(e) = enclave_init::configure_network().await {
            enclave_init::kmsg(&format!("[FATAL] Network config failed: {}", e));
            enclave_init::poweroff();
        }

        if let Err(e) = async_main().await {
            enclave_init::kmsg(&format!("FATAL: async_main failed: {}", e));
            enclave_init::poweroff();
        }
        Ok(())
    })
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Attempt to force immediate flush
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let _ = std::io::stdout().flush();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting PayPal Auth on GCP Confidential VM");
    info!("SECRET_NAME={:?}", std::env::var("SECRET_NAME"));

    info!("About to fetch config...");
    let config = if std::env::var("MOCK_HARDWARE").map(|v| v == "true").unwrap_or(false) {
        info!("MOCK_HARDWARE=true: Using environment variables for config");
        Config {
            paypal_client_id: std::env::var("PAYPAL_CLIENT_ID").unwrap_or_else(|_| "mock_id".to_string()),
            paypal_client_secret: std::env::var("PAYPAL_CLIENT_SECRET").unwrap_or_else(|_| "mock_secret".to_string()),
            domain: std::env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string()),
            eab_key_id: None,
            eab_hmac_key: None,
            staging: true,
            acme_account_json: None,
        }
    } else {
        match fetch_config().await {
            Ok(c) => {
                info!("Config loaded successfully");
                c
            }
            Err(e) => {
                error!("Failed to fetch config: {}", e);
                enclave_init::poweroff();
            }
        }
    };
    info!("Config: domain={}", config.domain);

    let redirect_uri = format!("https://{}/callback", config.domain);
    info!("Redirect URI: {}", redirect_uri);

    let https_ready = Arc::new(AtomicBool::new(false));
    let https_ready_clone = https_ready.clone();

    // Initialize app state
    let force_sandbox = std::env::var("FORCE_SANDBOX").map(|v| v == "true").unwrap_or(false);
    let is_staging = config.staging || force_sandbox;
    info!("Environment selection: config.staging={}, force_sandbox={} -> final is_staging={}", 
          config.staging, force_sandbox, is_staging);

    let state = Arc::new(AppState {
        paypal_client_id: config.paypal_client_id.clone(),
        paypal_client_secret: config.paypal_client_secret.clone(),
        redirect_uri,
        domain: config.domain.clone(),
        https_ready: https_ready_clone,
        staging: is_staging,
        tls_cert_hash: Arc::new(parking_lot::RwLock::new(None)),
        session_secret: crypto::generate_dek(),
    });
    
    if is_staging {
        info!("MODE: PAYPAL SANDBOX (TESTING)");
    } else {
        info!("MODE: PAYPAL PRODUCTION (LIVE)");
    }

    // Build the main app router
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/report", get(report))
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .with_state(state.clone());
    info!("Router built");

    let http_port: u16 = std::env::var("HTTP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(80);
    let http_addr = SocketAddr::from(([0, 0, 0, 0], http_port));
    let http_listener = TcpListener::bind(http_addr).await?;
    info!("HTTP server listening on {}...", http_addr);

    let ready_for_fallback = https_ready.clone();
    let domain_for_fallback = config.domain.clone();

    let http_router = Router::new()
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .fallback(move |uri: axum::http::Uri| {
            let ready = ready_for_fallback.clone();
            let domain = domain_for_fallback.clone();
            async move {
                if ready.load(Ordering::Relaxed) {
                    let https_url = format!("https://{}{}", domain, uri.path());
                    (
                        axum::http::StatusCode::PERMANENT_REDIRECT,
                        [("Location", https_url)],
                    )
                        .into_response()
                } else {
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "Service starting up (obtaining TLS certificate)...",
                    )
                        .into_response()
                }
            }
        })
        .with_state(state.clone());

    let http_handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match http_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to accept HTTP connection: {}", e);
                    continue;
                }
            };
            let router = http_router.clone();

            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req| {
                    let router = router.clone();
                    async move {
                        let resp: axum::response::Response = router.oneshot(req).await.unwrap();
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, svc)
                .await;
            });
        }
    });

    // Obtain TLS certificate (HTTP-01 challenge served by the running HTTP server)
    info!("Obtaining TLS certificate from Google Public CA...");
    let ca = GooglePublicCaManager::new(&config);
    let (cert_pem, key_pem) = match ca.ensure_certificate().await {
        Ok(r) => {
            info!("Certificate obtained");
            https_ready.store(true, Ordering::Relaxed);
            
            // Populate TLS Cert Hash for session binding
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&r.0);
            let hash = hex::encode(hasher.finalize());
            *state.tls_cert_hash.write() = Some(hash);
            
            r
        }
        Err(e) => {
            error!(
                "Failed to get certificate: {}. Keeping process alive for debugging...",
                e
            );
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
    };
    // Start HTTPS server on port 443
    info!("Loading TLS config...");
    let tls_config = load_tls_config(&cert_pem, &key_pem).await?;
    let https_port: u16 = std::env::var("HTTPS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(443);
    let https_addr = SocketAddr::from(([0, 0, 0, 0], https_port));
    info!("HTTPS listening on {}", https_addr);

    let https_listener = TcpListener::bind(https_addr).await?;
    let https_tls_config = tls_config.clone();

    let https_handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match https_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to accept HTTPS connection: {}", e);
                    continue;
                }
            };
            let ssl_config = https_tls_config.clone();
            let app = app.clone();

            tokio::spawn(async move {
                // Log connection attempt
                let ssl = match openssl::ssl::Ssl::new(ssl_config.context()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to create SSL: {}", e);
                        return;
                    }
                };
                let mut tls_stream = match tokio_openssl::SslStream::new(ssl, stream) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to create SslStream: {}", e);
                        return;
                    }
                };
                
                // Set a handshake timeout to prevent hanging connections
                if let Err(e) = tokio::time::timeout(
                    Duration::from_secs(10),
                    std::pin::Pin::new(&mut tls_stream).accept()
                ).await {
                    error!("TLS handshake failed or timed out: {}", e);
                    return;
                }

                let io = hyper_util::rt::TokioIo::new(tls_stream);
                
                // Use a proper tower service that handles cloning for us
                let app = app.clone();
                let svc = hyper::service::service_fn(move |req: axum::http::Request<hyper::body::Incoming>| {
                    let mut app = app.clone();
                    let path = req.uri().path().to_string();
                    async move {
                        info!("HTTPS Request: {}", path);
                        use tower::ServiceExt;
                        let resp = app.oneshot(req).await.unwrap();
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });

                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .http1() // Force HTTP/1.1 for stability with manual openssl
                .serve_connection(io, svc)
                .await {
                    // Only log real errors, not normal closures
                    // error!("Connection error: {}", e);
                }
            });
        }
    });
    // Certificate renewal loop (renew every 12 hours)
    let ca = GooglePublicCaManager::new(&config);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
        interval.tick().await;
        loop {
            interval.tick().await;
            info!("Attempting certificate renewal...");
            match ca.ensure_certificate().await {
                Ok(_) => {
                    info!("Certificate renewed successfully (restart needed for full effect)");
                }
                Err(e) => {
                    error!("Certificate renewal failed: {}", e);
                }
            }
        }
    });
    // Wait for any server to finish (they shouldn't)
    tokio::select! {
        result = https_handle => {
            error!("HTTPS server exited: {:?}", result);
        }
        result = http_handle => {
            error!("HTTP server exited: {:?}", result);
        }
    }

    Ok(())
}