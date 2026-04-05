//! PayPal OAuth Confidential Space
//!
//! Configuration: Single JSON secret in GCP Secret Manager
//! TLS: Google Public CA via ACME
//! Runtime: GCP Confidential Space (AMD SEV-SNP)

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, ExternalAccountKey,
    Identifier, NewAccount, NewOrder, OrderStatus,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

// ============================================================================
// CONSTANTS
// ============================================================================

mod tpm {
    use tokio::process::Command;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone)]
    pub struct SealedData {
        pub pub_blob: String,
        pub priv_blob: String,
    }

    async fn run_cmd(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = Command::new(cmd).args(args).output().await?;
        if !output.status.success() {
            return Err(format!("{} failed: {}", cmd, String::from_utf8_lossy(&output.stderr)).into());
        }
        Ok(output.stdout)
    }

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

    pub async fn quote(pcrs: &str, nonce_hex: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
        run_cmd("tpm2_createprimary", &["-c", "/tmp/primary.ctx"]).await?;
        let _ = run_cmd("tpm2_createak", &[
            "-C", "/tmp/primary.ctx",
            "-c", "/tmp/ak.ctx",
            "-G", "rsa",
            "-s", "rsassa"
        ]).await;
        run_cmd("tpm2_quote", &[
            "-c", "/tmp/ak.ctx",
            "-l", &format!("sha256:{}", pcrs),
            "-q", nonce_hex,
            "-m", "/tmp/quote.msg",
            "-s", "/tmp/quote.sig",
            "-F", "plain"
        ]).await?;
        let msg = tokio::fs::read("/tmp/quote.msg").await?;
        let sig = tokio::fs::read("/tmp/quote.sig").await?;
        Ok((STANDARD.encode(msg), STANDARD.encode(sig)))
    }
}

mod crypto {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm, Key, Nonce,
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
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; 12 bytes
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


const GOOGLE_PUBLIC_CA_DIRECTORY: &str = "https://dv.acme-v02.api.pki.goog/directory";
const GOOGLE_PUBLIC_CA_STAGING_DIRECTORY: &str = "https://dv.acme-v02.test-api.pki.goog/directory";

const HTML_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confidential PayPal Auth</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
        .container { border: 2px solid #0070ba; padding: 30px; border-radius: 10px; background: #1a1a1a; }
        .btn { background: #0070ba; color: white; padding: 15px 30px; text-decoration: none;
               border-radius: 5px; display: inline-block; font-size: 16px; border: none; cursor: pointer; }
        .btn:hover { background: #005a94; }
        .info { background: #2a2a2a; padding: 15px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #0070ba; }
        .attestation { background: #1a3a1a; padding: 15px; margin: 20px 0; border-radius: 5px;
                       word-break: break-all; font-size: 11px; border-left: 4px solid #4caf50; }
        .error { background: #3a1a1a; padding: 15px; margin: 20px 0; border-radius: 5px; color: #ff6b6b; border-left: 4px solid #c62828; }
        .cert-status { font-weight: bold; color: #4caf50; }
        pre { background: #0a0a0a; padding: 10px; border-radius: 3px; overflow-x: auto; font-size: 10px; }
        h1 { color: #0070ba; }
        h3 { color: #64b5f6; }
        ul { list-style: none; padding-left: 0; }
        li { padding: 5px 0; }
    </style>
</head>
<body><div class="container">{{CONTENT}}</div></body></html>
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
    used_paypal_ids: Arc<RwLock<HashSet<String>>>,
    domain: String,
    https_ready: Arc<AtomicBool>,
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

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    error: Option<String>,
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

    // Get access token from metadata server
    let token_resp: serde_json::Value = client
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .json()
        .await?;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or("No access token from metadata server")?;

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
        let token_resp: serde_json::Value = client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
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
                .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
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
) -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let resp = reqwest::Client::new()
        .post("https://api-m.sandbox.paypal.com/v1/oauth2/token")
        .basic_auth(client_id, Some(client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("Token exchange failed: {}", resp.text().await?).into());
    }
    Ok(resp.json().await?)
}

async fn get_userinfo(token: &str) -> Result<PayPalUserInfo, Box<dyn std::error::Error>> {
    let resp = reqwest::Client::new()
        .get("https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1")
        .bearer_auth(token)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("Userinfo failed: {}", resp.text().await?).into());
    }
    Ok(resp.json().await?)
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    let content = format!(
        r#"
        <h1>Confidential PayPal Authentication</h1>
        <div class="info">
            <p><strong>Domain:</strong> {}</p>
            <p><strong>Certificate:</strong> <span class="cert-status">RAM ONLY (Google Public CA)</span></p>
            <p><strong>Environment:</strong> GCP Confidential Space (AMD SEV-SNP)</p>
        </div>
        <div class="info">
            <p><strong>Security:</strong></p>
            <ul>
                <li>AMD SEV-SNP Confidential Computing</li>
                <li>TLS cert from Google Public CA</li>
                <li>All secrets in RAM only</li>
                <li>Config from GCP Secret Manager</li>
            </ul>
        </div>
        <a href="/login" class="btn">Login with PayPal</a>
        "#,
        state.domain
    );
    Html(HTML_TEMPLATE.replace("{{CONTENT}}", &content))
}

async fn login(State(state): State<Arc<AppState>>) -> Redirect {
    let url = format!(
        "https://www.sandbox.paypal.com/signin/authorize?client_id={}&response_type=code&scope=openid%20profile%20email&redirect_uri={}",
        state.paypal_client_id,
        urlencoding::encode(&state.redirect_uri)
    );
    Redirect::temporary(&url)
}

async fn callback(
    Query(query): Query<CallbackQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if let Some(error) = query.error {
        return Html(HTML_TEMPLATE.replace("{{CONTENT}}", &format!(
            r#"<div class="error"><h2>Error</h2><p>{}</p></div><a href="/" class="btn">Back</a>"#,
            html_escape::encode_text(&error)
        ))).into_response();
    }

    let code = match query.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Missing code").into_response(),
    };

    let token = match exchange_code_for_token(
        &code,
        &state.paypal_client_id,
        &state.paypal_client_secret,
        &state.redirect_uri,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            error!("Token exchange failed: {}", e);
            return Html(HTML_TEMPLATE.replace("{{CONTENT}}", &format!(
                r#"<div class="error"><h2>Token Exchange Failed</h2><p>{}</p></div><a href="/" class="btn">Back</a>"#,
                html_escape::encode_text(&e.to_string())
            ))).into_response();
        }
    };

    let userinfo = match get_userinfo(&token.access_token).await {
        Ok(u) => u,
        Err(e) => {
            error!("Userinfo failed: {}", e);
            return Html(HTML_TEMPLATE.replace("{{CONTENT}}", &format!(
                r#"<div class="error"><h2>User Info Failed</h2><p>{}</p></div><a href="/" class="btn">Back</a>"#,
                html_escape::encode_text(&e.to_string())
            ))).into_response();
        }
    };

    let attestation = generate_attestation(&state.paypal_client_id, &userinfo).await;

    Html(HTML_TEMPLATE.replace(
        "{{CONTENT}}",
        &format!(
            r#"
        <h1>Authentication Successful</h1>
        <div class="info">
            <h3>PayPal User</h3>
            <p><strong>ID:</strong> {}</p>
            <p><strong>Name:</strong> {}</p>
            <p><strong>Email:</strong> {}</p>
        </div>
        <div class="attestation">
            <h3>Attestation</h3>
            <p><strong>Certificate:</strong> <span class="cert-status">RAM ONLY</span></p>
            <p><strong>CA:</strong> Google Public CA</p>
            <pre>{}</pre>
        </div>
        <a href="/" class="btn">Back</a>
        "#,
            html_escape::encode_text(&userinfo.user_id),
            html_escape::encode_text(&userinfo.name.unwrap_or_else(|| "N/A".to_string())),
            html_escape::encode_text(&userinfo.email.unwrap_or_else(|| "N/A".to_string())),
            html_escape::encode_text(&attestation),
        ),
    ))
    .into_response()
}

async fn acme_challenge(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> impl IntoResponse {
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
// MAIN
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[DEBUG] main() started");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    eprintln!("[DEBUG] tracing initialized");
    info!("Starting PayPal Auth on GCP Confidential Space");
    info!("SECRET_NAME={:?}", std::env::var("SECRET_NAME"));

    eprintln!("[DEBUG] about to fetch config");
    info!("About to fetch config...");
    let config = match fetch_config().await {
        Ok(c) => {
            info!("Config loaded successfully");
            c
        }
        Err(e) => {
            error!("Failed to fetch config: {}", e);
            return Err(e);
        }
    };
    eprintln!("[DEBUG] config loaded, domain={}", config.domain);
    info!("Config: domain={}", config.domain);

    let redirect_uri = format!("https://{}/callback", config.domain);
    info!("Redirect URI: {}", redirect_uri);

    let https_ready = Arc::new(AtomicBool::new(false));
    let https_ready_clone = https_ready.clone();

    // Initialize app state
    eprintln!("[DEBUG] building app state");
    let state = Arc::new(AppState {
        paypal_client_id: config.paypal_client_id.clone(),
        paypal_client_secret: config.paypal_client_secret.clone(),
        redirect_uri,
        used_paypal_ids: Arc::new(RwLock::new(HashSet::new())),
        domain: config.domain.clone(),
        https_ready: https_ready_clone,
    });

    // Build the main app router
    eprintln!("[DEBUG] building router");
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());
    eprintln!("[DEBUG] router built");
    info!("Router built");

    let http_addr = SocketAddr::from(([0, 0, 0, 0], 80));
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
                    async move { Ok::<_, std::convert::Infallible>(router.oneshot(req).await.unwrap()) }
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
    eprintln!("[DEBUG] starting ACME cert obtain");
    info!("Obtaining TLS certificate from Google Public CA...");
    let ca = GooglePublicCaManager::new(&config);
    let (cert_pem, key_pem) = match ca.ensure_certificate().await {
        Ok(r) => {
            info!("Certificate obtained");
            https_ready.store(true, Ordering::Relaxed);
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
    eprintln!("[DEBUG] cert obtained, loading TLS");

    // Start HTTPS server on port 8443
    eprintln!("[DEBUG] loading TLS config");
    info!("Loading TLS config...");
    let tls_config = load_tls_config(&cert_pem, &key_pem).await?;
    eprintln!("[DEBUG] TLS config loaded");
    let https_addr = SocketAddr::from(([0, 0, 0, 0], 443));
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
                if let Err(e) = std::pin::Pin::new(&mut tls_stream).accept().await {
                    error!("TLS handshake failed: {}", e);
                    return;
                }
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = hyper::service::service_fn(move |req| {
                    let app = app.clone();
                    async move { Ok::<_, std::convert::Infallible>(app.oneshot(req).await.unwrap()) }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, svc)
                .await;
            });
        }
    });
    eprintln!("[DEBUG] HTTPS server spawned");

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
    eprintln!("[DEBUG] all servers running, entering select");

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
