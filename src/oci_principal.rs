//! Instance-principal authentication + OCI Secret Management retrieval (Option A).
//!
//! Eliminates plaintext PayPal credentials in instance `user_data` (audit
//! Vuln 2): the user_data config carries only `secret_ocid` + non-secret
//! fields; the enclave resolves the real config from the Secret Management
//! service using an instance principal — whose identity private key is
//! served exclusively over link-local IMDS and is therefore invisible to
//! anyone who reads instance metadata from the control plane.
//!
//! Protocol is byte-compatible with oci-python-sdk 2.165.1
//! (auth/federation_client.py, auth/signers/security_token_signer.py,
//! signer.py) as verified against the operator's local SDK:
//!
//! 1. IMDS `Authorization: Bearer Oracle` (v2, v1 fallback):
//!    /instance/region, /identity/cert.pem, /identity/key.pem,
//!    /identity/intermediate.pem
//! 2. POST https://auth.{region}.oraclecloud.com/v1/x509
//!    body: {"certificate", "publicKey", "intermediateCertificates"} where
//!    cert/key values are sanitized (markers + newlines stripped)
//!    signed with the *identity* key over
//!    date, (request-target), content-length, content-type, x-content-sha256
//!    keyId = "{tenancy}/fed-x509/{sha1-fingerprint-colon-upper}"
//!    → response {"token": "..."}
//! 3. API calls signed with a per-boot RSA-2048 *session* key over
//!    date, (request-target), host  (GET) — keyId = "ST${token}"
//!    Authorization = Signature algorithm="rsa-sha256",headers="...",
//!                    keyId="...",signature="...",version="1"
//!
//! Secrets endpoint: GET https://secrets.{region}.oraclecloud.com/20190301/
//! secrets/{secretOcid}/bundle?versionStage=CURRENT
//! → {"secretBundleContent": {"contentType": "BASE64", "content": "..."}}

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::X509;
use sha2::{Digest, Sha256};
use std::time::Duration;

const IMDS_V2: &str = "http://169.254.169.254/opc/v2";
const IMDS_V1: &str = "http://169.254.169.254/opc/v1";

/// Strip PEM markers and newlines — the exact transform the OCI auth
/// service expects inside the x509 token request (`sanitize_certificate_string`).
fn sanitize_pem(pem: &str) -> String {
    pem.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace('\n', "")
}

fn http_date() -> String {
    // RFC 1123 / RFC 7231 IMF-fixdate, GMT literal — matches
    // email.utils.formatdate(usegmt=True) used by the Python SDK.
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn rsa_sha256_b64(key: &PKey<Private>, msg: &str) -> Result<String, String> {
    let mut signer = Signer::new(MessageDigest::sha256(), key)
        .map_err(|e| format!("signer init: {e}"))?;
    signer
        .update(msg.as_bytes())
        .map_err(|e| format!("signer update: {e}"))?;
    let sig = signer
        .sign_to_vec()
        .map_err(|e| format!("sign: {e}"))?;
    Ok(B64.encode(sig))
}

/// OCI Signature v1 Authorization header — attribute order matches the SDK
/// template exactly: algorithm, headers, keyId, signature, version.
fn authorization_header(headers_attr: &str, key_id: &str, signature: &str) -> String {
    format!(
        "Signature algorithm=\"rsa-sha256\",headers=\"{headers_attr}\",keyId=\"{key_id}\",signature=\"{signature}\",version=\"1\""
    )
}

pub struct InstancePrincipal {
    http: reqwest::Client,
    region: String,
    tenancy: String,
    fingerprint: String,
    leaf_sanitized: String,
    intermediate_sanitized: Option<String>,
    identity_key: PKey<Private>,
    session_key: PKey<Private>,
}

async fn imds_get(path: &str) -> Result<String, String> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("imds client: {e}"))?;
    let mut last = String::new();
    for base in [IMDS_V2, IMDS_V1] {
        match http
            .get(format!("{base}{path}"))
            .header("Authorization", "Bearer Oracle")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                return resp
                    .text()
                    .await
                    .map_err(|e| format!("imds body {path}: {e}"));
            }
            Ok(resp) => last = format!("{base}{path} → HTTP {}", resp.status()),
            Err(e) => last = format!("{base}{path} → {e}"),
        }
    }
    Err(format!("IMDS {path} unavailable: {last}"))
}

impl InstancePrincipal {
    pub async fn new() -> Result<Self, String> {
        let region = imds_get("/instance/region").await?.trim().to_string();
        let leaf_pem = imds_get("/identity/cert.pem").await?;
        let key_pem = imds_get("/identity/key.pem").await?;
        let inter_pem = imds_get("/identity/intermediate.pem").await.ok();

        let cert = X509::from_pem(leaf_pem.as_bytes())
            .map_err(|e| format!("parse identity cert: {e}"))?;
        let identity_key = PKey::private_key_from_pem(key_pem.as_bytes())
            .map_err(|e| format!("parse identity key: {e}"))?;

        // Tenancy OCID lives in a subject attribute prefixed "opc-tenant:"
        // (or "opc-identity:").
        let mut tenancy = None;
        for entry in cert.subject_name().entries() {
            let val = String::from_utf8_lossy(entry.data().as_slice()).into_owned();
            if let Some(rest) = val.strip_prefix("opc-tenant:") {
                tenancy = Some(rest.to_string());
                break;
            }
            if let Some(rest) = val.strip_prefix("opc-identity:") {
                tenancy = Some(rest.to_string());
                break;
            }
        }
        let tenancy = tenancy.ok_or("identity certificate has no opc-tenant subject")?;

        // SHA-1 fingerprint, colon-separated uppercase hex.
        let digest = cert
            .digest(MessageDigest::sha1())
            .map_err(|e| format!("cert digest: {e}"))?;
        let fingerprint = digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");

        // Per-boot session keypair (RSA-2048, e=65537 — SessionKeySupplier).
        let rsa = Rsa::generate(2048).map_err(|e| format!("session key: {e}"))?;
        let session_key = PKey::from_rsa(rsa).unwrap();

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("http client: {e}"))?;

        Ok(Self {
            http,
            region,
            tenancy,
            fingerprint,
            leaf_sanitized: sanitize_pem(&leaf_pem),
            intermediate_sanitized: inter_pem.as_deref().map(sanitize_pem),
            identity_key,
            session_key,
        })
    }

    /// Exchange the instance identity for a short-lived security token.
    async fn fetch_token(&self) -> Result<String, String> {
        let date = http_date();

        let pubkey_spki = self
            .session_key
            .public_key_to_pem()
            .map_err(|e| format!("session pubkey pem: {e}"))?;
        let pubkey_spki = String::from_utf8(pubkey_spki)
            .map_err(|e| format!("session pubkey utf8: {e}"))?;
        let mut payload = serde_json::Map::new();
        payload.insert("certificate".into(), self.leaf_sanitized.clone().into());
        payload.insert("publicKey".into(), sanitize_pem(&pubkey_spki).into());
        if let Some(inter) = &self.intermediate_sanitized {
            payload.insert(
                "intermediateCertificates".into(),
                serde_json::json!([inter]),
            );
        }
        let body = serde_json::to_string(&serde_json::Value::Object(payload))
            .map_err(|e| format!("token body: {e}"))?;
        let body_bytes = body.as_bytes();
        let content_sha = B64.encode(Sha256::digest(body_bytes));

        // Signing-string header order: generic [date, (request-target)] then
        // body [content-length, content-type, x-content-sha256].
        let signing = format!(
            "date: {date}\n\
             (request-target): post /v1/x509\n\
             content-length: {}\n\
             content-type: application/json\n\
             x-content-sha256: {content_sha}",
            body_bytes.len()
        );
        let sig = rsa_sha256_b64(&self.identity_key, &signing)?;
        let key_id = format!("{}/fed-x509/{}", self.tenancy, self.fingerprint);
        let auth = authorization_header(
            "date (request-target) content-length content-type x-content-sha256",
            &key_id,
            &sig,
        );

        let url = format!("https://auth.{}.oraclecloud.com/v1/x509", self.region);
        let resp = self
            .http
            .post(&url)
            .header("Date", &date)
            .header("Content-Type", "application/json")
            .header("x-content-sha256", &content_sha)
            .header("Authorization", auth)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("token request: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("token body: {e}"))?;
        if !status.is_success() {
            return Err(format!("token endpoint HTTP {status}: {}", &text[..text.len().min(300)]));
        }
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("token json: {e}"))?;
        v.get("token")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("token endpoint response has no 'token' field"))
    }

    /// GET a secret bundle and return its decoded content.
    pub async fn get_secret_bundle(secret_ocid: &str) -> Result<String, String> {
        let principal = InstancePrincipal::new().await?;
        let mut token = principal.fetch_token().await?;

        let host = format!("secrets.{}.oraclecloud.com", principal.region);
        let path = format!("/20190301/secrets/{secret_ocid}/bundle?versionStage=CURRENT");
        let url = format!("https://{host}{path}");

        for attempt in 0..2 {
            let date = http_date();
            let signing = format!("date: {date}\n(request-target): get {path}\nhost: {host}");
            let sig = rsa_sha256_b64(&principal.session_key, &signing)?;
            let auth =
                authorization_header("date (request-target) host", &format!("ST${token}"), &sig);

            let resp = principal
                .http
                .get(&url)
                .header("Date", &date)
                .header("Authorization", auth)
                .send()
                .await
                .map_err(|e| format!("secret bundle request: {e}"))?;
            let status = resp.status();

            if status.as_u16() == 401 && attempt == 0 {
                // Token rejected (expired/revoked) — refresh once and retry.
                token = principal.fetch_token().await?;
                continue;
            }
            let text = resp
                .text()
                .await
                .map_err(|e| format!("secret bundle body: {e}"))?;
            if !status.is_success() {
                return Err(format!(
                    "secret bundle HTTP {status}: {}",
                    &text[..text.len().min(300)]
                ));
            }
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("bundle json: {e}"))?;
            let content = v
                .pointer("/secretBundleContent/content")
                .and_then(|c| c.as_str())
                .ok_or("bundle response has no secretBundleContent.content")?;
            return match B64.decode(content.trim()) {
                Ok(bytes) => String::from_utf8(bytes)
                    .map_err(|_| "decoded bundle content is not UTF-8".to_string()),
                // Tolerate plaintext content types.
                Err(_) => Ok(content.to_string()),
            };
        }
        Err("secret bundle fetch failed after token refresh".to_string())
    }
}

/// One-shot convenience used by `fetch_config()` (Option A resolution).
pub async fn get_secret_bundle(secret_ocid: &str) -> Result<String, String> {
    InstancePrincipal::get_secret_bundle(secret_ocid).await
}
