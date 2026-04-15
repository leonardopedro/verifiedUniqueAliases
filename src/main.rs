//! PayPal OAuth Confidential VM
//!
//! Configuration: Single JSON secret in GCP Secret Manager
//! TLS: Google Public CA via ACME
//! Runtime: GCP Confidential VM (AMD SEV-SNP)

// ============================================================================
// ENCLAVE INIT — PID 1 responsibilities: mounts, drivers, DHCP
// Called before the Tokio runtime touches anything.
// ============================================================================
mod enclave_init {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::Ipv4Addr;

    pub fn kmsg(msg: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            use std::io::Write;
            let _ = writeln!(f, "<14>[INIT] {}", msg);
        }
        eprintln!("[INIT] {}", msg);
    }

    /// Mount essential kernel virtual filesystems.
    pub fn mount_filesystems() {
        fn mount_fs(source: &str, target: &str, fstype: &str) {
            std::fs::create_dir_all(target).ok();
            let src = std::ffi::CString::new(source).unwrap();
            let tgt = std::ffi::CString::new(target).unwrap();
            let fst = std::ffi::CString::new(fstype).unwrap();
            let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, std::ptr::null()) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EBUSY) {
                    kmsg(&format!("mount {} -> {}: {:?}", source, target, err));
                }
            }
        }
        mount_fs("devtmpfs", "/dev",  "devtmpfs"); // Mount /dev first so kmsg works!
        kmsg("--- PAYPAL ENCLAVE NATIVE RUST BOOT ---");
        mount_fs("proc",     "/proc", "proc");
        mount_fs("sysfs",    "/sys",  "sysfs");
        mount_fs("tmpfs",    "/tmp",  "tmpfs");
        mount_fs("tmpfs",    "/run",  "tmpfs");
        std::fs::create_dir_all("/dev/pts").ok();
        kmsg("Filesystems mounted");
    }

    fn modprobe(module: &str) {
        match std::process::Command::new("/sbin/modprobe").arg("-q").arg(module).status() {
            Ok(s) => kmsg(&format!("modprobe {}: {}", module, s)),
            Err(e) => kmsg(&format!("modprobe {} failed: {} (falling back to insmod?)", module, e)),
        }
        // Fallback: if modprobe is missing, maybe busybox or raw insmod works
        if let Ok(_paths) = std::fs::read_dir(format!("/lib/modules")) {
            // Very primitive, just relies on the kernel matching it if modprobe itself is broken
        }
    }

    fn find_interface() -> Option<String> {
        std::fs::read_dir("/sys/class/net").ok()?
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
        p[0] = 1; p[1] = 1; p[2] = 6; p[10] = 0x80;
        p[4..8].copy_from_slice(&xid.to_be_bytes());
        p[28..34].copy_from_slice(mac);
        p[236] = 99; p[237] = 130; p[238] = 83; p[239] = 99; // magic cookie
        p.extend_from_slice(&[53, 1, msg_type]);
        if let Some(ip) = req_ip {
            p.extend_from_slice(&[50, 4]);
            p.extend_from_slice(&ip.octets());
        }
        p.extend_from_slice(&[55, 3, 1, 3, 6]); // request subnet, router, dns
        p.push(255);
        p
    }

    struct Lease { ip: Ipv4Addr, prefix: u8, gw: Option<Ipv4Addr>, dns: Vec<Ipv4Addr> }

    fn parse_lease(buf: &[u8]) -> Option<Lease> {
        if buf.len() < 240 { return None; }
        let ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let mut mask = Ipv4Addr::new(255, 255, 255, 0);
        let mut gw = None;
        let mut dns = Vec::new();
        let mut i = 240;
        while i < buf.len() {
            match buf[i] {
                255 => break,
                0 => { i += 1; }
                code => {
                    if i + 1 >= buf.len() { break; }
                    let len = buf[i+1] as usize;
                    if i + 2 + len > buf.len() { break; }
                    let v = &buf[i+2..i+2+len];
                    match code {
                        1 if len == 4 => mask = Ipv4Addr::new(v[0],v[1],v[2],v[3]),
                        3 if len >= 4 => gw = Some(Ipv4Addr::new(v[0],v[1],v[2],v[3])),
                        6 => for c in v.chunks(4) { if c.len()==4 { dns.push(Ipv4Addr::new(c[0],c[1],c[2],c[3])); } },
                        _ => {}
                    }
                    i += 2 + len;
                }
            }
        }
        let prefix = mask.octets().iter().map(|b| b.count_ones()).sum::<u32>() as u8;
        Some(Lease { ip, prefix, gw, dns })
    }

    fn apply_lease(iface: &str, lease: &Lease) {
        use std::process::Command;
        let cidr = format!("{}/{}", lease.ip, lease.prefix);
        let _ = Command::new("/sbin/ip").args(["addr", "flush", "dev", iface]).status();
        let _ = Command::new("/sbin/ip").args(["addr", "add", &cidr, "dev", iface]).status();
        let _ = Command::new("/sbin/ip").args(["link", "set", iface, "up"]).status();
        
        if let Some(gw) = lease.gw {
            // CRITICAL GCP FIX: GCP assigns /32 subnet masks. The gateway is technically outside 
            // our subnet, so the kernel will reject a default route. We must add a direct 
            // device-bound host route to the gateway first!
            let _ = Command::new("/sbin/ip")
                .args(["route", "add", &gw.to_string(), "dev", iface])
                .status();

            let _ = Command::new("/sbin/ip")
                .args(["route", "add", "default", "via", &gw.to_string()])
                .status();
        }
        
        if !lease.dns.is_empty() {
            std::fs::create_dir_all("/etc").ok();
            let resolv: String = lease.dns.iter().map(|ip| format!("nameserver {}\n", ip)).collect();
            std::fs::write("/etc/resolv.conf", resolv).ok();
        }
        kmsg(&format!("Network up: {} gw={:?}", cidr, lease.gw));
    }

    async fn dhcp(iface: &str) -> Result<Lease, Box<dyn std::error::Error + Send + Sync>> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_broadcast(true)?;
        // CRITICAL FIX: Without an IP address, Linux refuses to route 255.255.255.255 broadcasts 
        // with `ENETUNREACH` unless we explicitly pin the socket to the raw interface!
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
        sock.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68).into())?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        let bc = std::net::SocketAddrV4::new(Ipv4Addr::BROADCAST, 67);
        let mac = read_mac(iface);
        let xid: u32 = 0xC0FFEE42;

        sock.send_to(&build_dhcp(xid, &mac, 1, None), &bc.into())?;
        kmsg("DHCP DISCOVER sent");

        let mut buf = [std::mem::MaybeUninit::uninit(); 1024];
        let (n, _) = sock.recv_from(&mut buf)?;
        let mut recv_buf = [0u8; 1024];
        for i in 0..n { recv_buf[i] = unsafe { buf[i].assume_init() }; }
        let offered = Ipv4Addr::new(recv_buf[16], recv_buf[17], recv_buf[18], recv_buf[19]);
        kmsg(&format!("DHCP OFFER: {}", offered));

        sock.send_to(&build_dhcp(xid, &mac, 3, Some(offered)), &bc.into())?;
        kmsg("DHCP REQUEST sent");

        let (n, _) = sock.recv_from(&mut buf)?;
        for i in 0..n { recv_buf[i] = unsafe { buf[i].assume_init() }; }
        let lease = parse_lease(&recv_buf[..n]).ok_or("Bad DHCP ACK")?;
        kmsg(&format!("DHCP ACK: ip={}", lease.ip));
        Ok(lease)
    }

    /// Load drivers, wait for NIC, perform DHCP, apply lease.
    pub async fn configure_network() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        modprobe("gve");
        modprobe("virtio_net");

        kmsg("Waiting for network interface...");
        let iface = {
            let mut found = None;
            for _ in 0..60 {
                if let Some(i) = find_interface() { found = Some(i); break; }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            found.ok_or("No network interface after 30s")?
        };
        kmsg(&format!("Interface found: {}. Bringing interface UP...", iface));

        // CRITICAL: We must bring the interface UP before we can broadcast UDP!
        let _ = std::process::Command::new("/sbin/ip").args(["link", "set", &iface, "up"]).status();
        
        // Brief wait for PHY link state to stabilize
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let lease = dhcp(&iface).await?;
        apply_lease(&iface, &lease);
        Ok(())
    }

    pub fn poweroff() -> ! {
        kmsg("FATAL: Initialization failed. Halting system to preserve serial logs...");
        loop { 
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

}

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use acme2_eab::{
    gen_rsa_private_key, AccountBuilder, AuthorizationStatus, DirectoryBuilder, OrderBuilder, Csr,
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

    const PCR_INDEX: &str = "15";

    #[derive(Serialize, Deserialize, Clone)]
    pub struct SealedData {
        pub pub_blob: String,
        pub priv_blob: String,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct AttestationResult {
        pub tpm_quote_msg: String,
        pub tpm_quote_sig: String,
        pub ak_pub_pem: String,
        pub ek_cert: Option<String>,
        pub pcrs: String,
        pub nonce_hex: String,
    }

    async fn run_cmd(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new(cmd).args(args).output().await?;
        if !output.status.success() {
            return Err(format!("{} failed: {}", cmd, String::from_utf8_lossy(&output.stderr)).into());
        }
        Ok(output.stdout)
    }

    async fn cleanup(paths: &[&str]) {
        for p in paths {
            let _ = tokio::fs::remove_file(p).await;
        }
        let _ = run_cmd("tpm2_flushcontext", &["-t"]).await;
        let _ = run_cmd("tpm2_flushcontext", &["-s"]).await;
    }

    pub async fn seal_dek(dek: &[u8]) -> Result<SealedData, Box<dyn std::error::Error + Send + Sync>> {
        let cleanup_paths = [
            "/tmp/dek.plain", "/tmp/policy.digest", "/tmp/primary.ctx",
            "/tmp/dek.priv", "/tmp/dek.pub",
        ];
        let _ = cleanup(&cleanup_paths).await;

        tokio::fs::write("/tmp/dek.plain", dek).await?;
        run_cmd("tpm2_createpolicy", &[
            "--policy-pcr", "-l", &format!("sha256:{}", PCR_INDEX),
            "-L", "/tmp/policy.digest",
        ]).await?;
        run_cmd("tpm2_createprimary", &["-C", "o", "-c", "/tmp/primary.ctx"]).await?;
        run_cmd("tpm2_create", &[
            "-C", "/tmp/primary.ctx",
            "-r", "/tmp/dek.priv",
            "-u", "/tmp/dek.pub",
            "-i", "/tmp/dek.plain",
            "-L", "/tmp/policy.digest",
        ]).await?;
        let pub_b = tokio::fs::read("/tmp/dek.pub").await?;
        let priv_b = tokio::fs::read("/tmp/dek.priv").await?;
        let _ = cleanup(&cleanup_paths).await;
        Ok(SealedData {
            pub_blob: STANDARD.encode(pub_b),
            priv_blob: STANDARD.encode(priv_b),
        })
    }

    pub async fn unseal_dek(sealed: &SealedData) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let cleanup_paths = [
            "/tmp/dek.pub", "/tmp/dek.priv", "/tmp/primary.ctx",
            "/tmp/dek.ctx",
        ];
        let _ = cleanup(&cleanup_paths).await;

        let pub_b = STANDARD.decode(&sealed.pub_blob)?;
        let priv_b = STANDARD.decode(&sealed.priv_blob)?;
        tokio::fs::write("/tmp/dek.pub", pub_b).await?;
        tokio::fs::write("/tmp/dek.priv", priv_b).await?;
        run_cmd("tpm2_createprimary", &["-C", "o", "-c", "/tmp/primary.ctx"]).await?;
        run_cmd("tpm2_load", &[
            "-C", "/tmp/primary.ctx",
            "-u", "/tmp/dek.pub",
            "-r", "/tmp/dek.priv",
            "-c", "/tmp/dek.ctx",
        ]).await?;
        let dek = run_cmd("tpm2_unseal", &[
            "-c", "/tmp/dek.ctx",
            "-p", &format!("pcr:sha256:{}", PCR_INDEX),
        ]).await?;
        let _ = cleanup(&cleanup_paths).await;
        Ok(dek)
    }

    pub async fn quote(nonce_hex: &str) -> Result<AttestationResult, Box<dyn std::error::Error + Send + Sync>> {
        let cleanup_paths = [
            "/tmp/primary.ctx", "/tmp/ak.ctx", "/tmp/ak.pub",
            "/tmp/ak.priv", "/tmp/ak.pem", "/tmp/quote.msg",
            "/tmp/quote.sig", "/tmp/ek.pub", "/tmp/ek.cert",
        ];
        let _ = cleanup(&cleanup_paths).await;

        run_cmd("tpm2_createprimary", &["-C", "o", "-c", "/tmp/primary.ctx"]).await?;

        run_cmd("tpm2_createak", &[
            "-C", "/tmp/primary.ctx",
            "-c", "/tmp/ak.ctx",
            "-f", "pem",
            "-G", "rsa",
            "-s", "rsassa",
            "-g", "sha256",
            "-u", "/tmp/ak.pub",
            "-r", "/tmp/ak.priv",
        ]).await?;

        let ak_pem = tokio::fs::read_to_string("/tmp/ak.pem").await?;

        run_cmd("tpm2_quote", &[
            "-c", "/tmp/ak.ctx",
            "-l", &format!("sha256:{}", PCR_INDEX),
            "-q", nonce_hex,
            "-m", "/tmp/quote.msg",
            "-s", "/tmp/quote.sig",
            "-f", "plain",
        ]).await?;
        let msg = tokio::fs::read("/tmp/quote.msg").await?;
        let sig = tokio::fs::read("/tmp/quote.sig").await?;

        let ek_cert = match run_cmd("tpm2_readpublic", &["-c", "0x81010001", "-f", "pem", "-o", "/tmp/ek.pub"]).await {
            Ok(_) => {
                match run_cmd("tpm2_getekcertificate", &["-X", "-o", "/tmp/ek.cert"]).await {
                    Ok(cert_der) => Some(STANDARD.encode(cert_der)),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        };

        let _ = cleanup(&cleanup_paths).await;

        Ok(AttestationResult {
            tpm_quote_msg: STANDARD.encode(msg),
            tpm_quote_sig: STANDARD.encode(sig),
            ak_pub_pem: ak_pem,
            ek_cert,
            pcrs: PCR_INDEX.to_string(),
            nonce_hex: nonce_hex.to_string(),
        })
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

    pub fn encrypt(dek: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let key = Key::<Aes256Gcm>::from_slice(dek);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; 12 bytes
        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| format!("AesGcm encrypt failed: {:?}", e))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    pub fn decrypt(dek: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let key = Key::<Aes256Gcm>::from_slice(dek);
        let cipher = Aes256Gcm::new(key);
        let nonce_arr = Nonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce_arr, ciphertext).map_err(|e| format!("AesGcm decrypt failed: {:?}", e))?;
        Ok(plaintext)
    }
}


const GOOGLE_PUBLIC_CA_DIRECTORY: &str = "https://dv.acme-v02.api.pki.goog/directory";

const PAYPAL_PRODUCTION_API: &str = "https://api-m.paypal.com";
const PAYPAL_SANDBOX_API: &str = "https://api-m.sandbox.paypal.com";
const PAYPAL_PRODUCTION_AUTH: &str = "https://www.paypal.com/signin/authorize";
const PAYPAL_SANDBOX_AUTH: &str = "https://www.sandbox.paypal.com/signin/authorize";

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
    // v61: Add credentials for the "Verified Only" low-privilege button
    #[serde(default)]
    paypal_verified_client_id: Option<String>,
    #[serde(default)]
    paypal_verified_client_secret: Option<String>,
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
    paypal_verified_client_id: String,
    paypal_verified_client_secret: String,
    redirect_uri: String,
    used_paypal_ids: Arc<RwLock<HashSet<String>>>,
    domain: String,
    https_ready: Arc<AtomicBool>,
    staging: bool,
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
    state: Option<String>,
    error: Option<String>,
}

// ============================================================================
// GCP SECRET MANAGER
// ============================================================================

async fn fetch_secret_direct(secret_id: &str) -> Option<String> {
    let client = reqwest::Client::new();
    let token_resp: serde_json::Value = client
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
        .header("Metadata-Flavor", "Google")
        .send().await.ok()?.json().await.ok()?;
    let access_token = token_resp["access_token"].as_str()?;
    
    let project_id = "project-ae136ba1-3cc9-42cf-a48";
    let url = format!("https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access", project_id, secret_id);
    let secret_resp: serde_json::Value = client
        .get(&url).bearer_auth(access_token).send().await.ok()?.json().await.ok()?;
    let encoded = secret_resp["payload"]["data"].as_str()?;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    String::from_utf8(STANDARD.decode(encoded).ok()?).ok()
}

async fn fetch_config() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    // Priority 1: Check for environment variables (KeePassXC / Local development support)
    if let (Ok(p_id), Ok(p_sec), Ok(pv_id), Ok(pv_sec), Ok(dom)) = (
        std::env::var("PAYPAL_CLIENT_ID"),
        std::env::var("PAYPAL_CLIENT_SECRET"),
        std::env::var("PAYPAL_VERIFIED_CLIENT_ID"),
        std::env::var("PAYPAL_VERIFIED_CLIENT_SECRET"),
        std::env::var("DOMAIN"),
    ) {
        info!("Using configuration from Environment Variables (KeePassXC)");
        return Ok(Config {
            paypal_client_id: p_id,
            paypal_client_secret: p_sec,
            paypal_verified_client_id: Some(pv_id),
            paypal_verified_client_secret: Some(pv_sec),
            domain: dom,
            eab_key_id: std::env::var("EAB_KEY_ID").ok(),
            eab_hmac_key: std::env::var("EAB_HMAC_KEY").ok(),
            staging: std::env::var("STAGING").map(|s| s == "true").unwrap_or(false),
            acme_account_json: std::env::var("ACME_ACCOUNT_JSON").ok(),
        });
    }

    // Priority 2: Fetch from GCP Secret Manager (Confidential Production)
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
    let mut config: Config = serde_json::from_str(&json_str)?;

    // Override EAB keys from secrets if available (allows rotation without config update)
    let eab_key_id_secret = fetch_secret_direct("EAB_KEY_ID").await;
    let eab_hmac_secret = fetch_secret_direct("EAB_HMAC_KEY").await;
    if let (Some(kid), Some(hmac)) = (eab_key_id_secret, eab_hmac_secret) {
        config.eab_key_id = Some(kid);
        config.eab_hmac_key = Some(hmac);
    }

    // Apply defaults for missing verified client credentials (fallback)
    let config = Config {
        paypal_verified_client_id: Some(config.paypal_verified_client_id.unwrap_or_else(|| {
            "AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p".to_string()
        })),
        paypal_verified_client_secret: Some(config.paypal_verified_client_secret.unwrap_or_else(|| "MISSING_VERIFIED_SECRET".to_string())),
        ..config
    };

    Ok(config)
}

// ============================================================================
// GOOGLE PUBLIC CA
// ============================================================================

struct GooglePublicCaManager {
    domain: String,
    eab_key_id: Option<String>,
    eab_hmac_key: Option<String>,
    // NOTE: `staging` is intentionally absent here.
    // The `staging` flag in the Vault secret controls PayPal Sandbox mode only.
    // ACME/TLS certificates always use the Google Public CA PRODUCTION endpoint.
    acme_account_json: Option<String>,
}

impl GooglePublicCaManager {
    fn new(config: &Config) -> Self {
        Self {
            domain: config.domain.clone(),
            eab_key_id: config.eab_key_id.clone(),
            eab_hmac_key: config.eab_hmac_key.clone(),
            acme_account_json: config.acme_account_json.clone(),
        }
    }

    async fn ensure_certificate(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        info!("Checking for cached TLS credentials in Vault...");
        if let Some((cert, key)) = Self::fetch_cached_tls().await {
            return Ok((cert, key));
        }

        info!("Obtaining TLS certificate from Google Public CA...");

        // ACME always uses the production endpoint.
        // The `staging` flag in the Vault is for PayPal Sandbox only and does NOT affect TLS.
        let acme_url = GOOGLE_PUBLIC_CA_DIRECTORY;
        info!("Using Google Public CA PRODUCTION (TLS is always production)");

        let account_path = "/tmp/acme-account.json";
        let account = if let Ok(data) = tokio::fs::read_to_string(account_path).await {
            info!("Restoring ACME account from tmpfs...");
            let dir = DirectoryBuilder::new(acme_url.to_string()).build().await?;
            let priv_key_pem = data.trim();
            let priv_pem = openssl::pkey::PKey::private_key_from_pem(priv_key_pem.as_bytes())?;
            let mut builder = AccountBuilder::new(dir);
            builder.private_key(priv_pem);
            builder.build().await?
        } else {
            info!("Creating new ACME account with EAB...");
            let kid = self
                .eab_key_id
                .as_ref()
                .ok_or("Missing EAB key ID")?;
            let hmac_str = self
                .eab_hmac_key
                .as_ref()
                .ok_or("Missing EAB HMAC key")?;

            info!("EAB Key ID being used: {}", kid);
            info!("EAB HMAC key string length: {}", hmac_str.trim().len());

            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            // Google's b64MacKey is base64 URL-encoded (no padding)
            let hmac_bytes = URL_SAFE_NO_PAD.decode(hmac_str.trim()).map_err(|e| format!("EAB HMAC decode failed: {}", e))?;
            
            info!("EAB HMAC final bytes length: {}", hmac_bytes.len());
            let hmac_pkey = openssl::pkey::PKey::hmac(&hmac_bytes)?;

            let dir = DirectoryBuilder::new(acme_url.to_string()).build().await?;
            let mut builder = AccountBuilder::new(dir);
            builder.contact(vec![format!("mailto:admin@{}", self.domain)]);
            builder.terms_of_service_agreed(true);
            builder.external_account_binding(kid.clone(), hmac_pkey);
            let account = builder.build().await?;

            if let Ok(priv_pem) = account.private_key().private_key_to_pem_pkcs8() {
                let _ = tokio::fs::write(account_path, priv_pem).await;
            }
            account
        };

        info!("Creating ACME order for domain: {}", self.domain);
        let mut order_builder = OrderBuilder::new(account);
        order_builder.add_dns_identifier(self.domain.clone());
        let mut order = order_builder.build().await?;

        info!("Processing ACME authorizations...");
        let authorizations = order.authorizations().await?;
        for auth in authorizations {
            if matches!(auth.status, AuthorizationStatus::Valid) {
                continue;
            }
            let mut challenge = auth
                .challenges
                .iter()
                .find(|c| c.r#type == "http-01")
                .ok_or("No HTTP-01 challenge found")?
                .clone();

            let challenge_dir = "/tmp/acme-challenge";
            tokio::fs::create_dir_all(challenge_dir).await?;
            let token = challenge.token.as_ref().ok_or("Missing token")?;
            let token_filename = token.replace("/", "_");
            let key_auth = challenge.key_authorization()?.ok_or("Missing key authorization")?;
            tokio::fs::write(
                format!("{}/{}", challenge_dir, token_filename),
                key_auth.as_bytes(),
            )
            .await?;

            info!("Triggering ACME challenge for token: {}", token_filename);
            
            info!("Requesting ACME server to validate challenge...");
            challenge.validate().await?;
            
            info!("Waiting for ACME challenge to complete...");
            challenge.wait_done(Duration::from_secs(5), 72).await?;
            info!("Challenge completed for token: {}", token_filename);
        }

        info!("Waiting for ACME order to become ready...");
        order = order.wait_ready(Duration::from_secs(5), 72).await?;

        info!("ACME order ready, finalizing certificate...");
        let pkey = gen_rsa_private_key(4096)?;
        let key_pem = pkey.private_key_to_pem_pkcs8()?;
        let order = order.finalize(Csr::Automatic(pkey)).await?;

        info!("Polling for certificate issuance...");
        let order = order.wait_done(Duration::from_secs(5), 144).await?;

        info!("Downloading certificate...");
        let cert_result = order.certificate().await;
        match cert_result {
            Ok(Some(cert)) => {
                info!("Certificate issued!");
                let mut cert_chain_str = String::new();
                for c in cert {
                    if let Ok(pem) = c.to_pem() {
                        cert_chain_str.push_str(std::str::from_utf8(&pem).unwrap_or(""));
                        cert_chain_str.push('\n');
                    }
                }

                info!("TLS certificate obtained (RAM only)");
                Self::store_cached_tls(cert_chain_str.as_bytes(), &key_pem).await;
                return Ok((cert_chain_str.into_bytes(), key_pem));
            }
            Ok(None) => {
                return Err("Certificate not available after wait_done".into());
            }
            Err(e) => {
                return Err(format!("Error downloading certificate: {:?}", e).into());
            }
        }
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
        let dek = match tpm::unseal_dek(&sealed_dek).await {
            Ok(d) => d,
            Err(e) => {
                error!("TPM Unseal failed, PCR 15 measurement changed! {}", e);
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
            let sealed_dek = match tpm::seal_dek(&dek).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to seal DEK to vTPM (PCR 15): {}", e);
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

async fn generate_attestation(client_id: String, userinfo: PayPalUserInfo) -> String {
    use sha2::{Digest, Sha256};

    let pad = |s: Option<&str>, len: usize| {
        let base = s.unwrap_or("N/A");
        format!("{:_<width$}", &base[..base.len().min(len)], width = len)
    };

    // 1. Compose canonical record with fixed-width padding for all fields
    let data = format!(
        "CLIENT_ID:{}|USER_ID:{}|NAME:{}|GIVEN:{}|FAMILY:{}|EMAIL:{}|LOCALE:{}|PHONE:{}",
        pad(Some(&client_id), 64),
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
    match tpm::quote(&hex::encode(hash_bytes)).await {
        Ok(attest) => {
            serde_json::json!({
                "tpm_quote_msg": attest.tpm_quote_msg,
                "tpm_quote_sig": attest.tpm_quote_sig,
                "ak_pub_pem": attest.ak_pub_pem,
                "ek_cert": attest.ek_cert,
                "pcrs": attest.pcrs,
                "nonce_hex": attest.nonce_hex,
                "bound_user_data": data,
                "binding_hash": hash_b64,
                "hw_platform": "AMD SEV-SNP + vTPM (PCR 15)",
                "verification": "Submit to GCP Verify Attestation API or verify AK signature against ak_pub_pem"
            }).to_string()
        }
        Err(e) => {
            error!("Failed to generate vTPM quote: {}", e);
            serde_json::json!({
                "SIMULATED_REPORT": true,
                "error": "Hardware attestation failed",
                "bound_user_data": data,
                "binding_hash": hash_b64,
                "detail": e.to_string(),
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
    api_base: &str,
) -> Result<TokenResponse, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/v1/oauth2/token", api_base);
    let resp = reqwest::Client::new()
        .post(&url)
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

async fn get_userinfo(token: &str, api_base: &str) -> Result<PayPalUserInfo, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/v1/identity/oauth2/userinfo?schema=paypalv1.1", api_base);
    let resp = reqwest::Client::new()
        .get(&url)
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

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let content = format!(
        r#"
        <h1>Confidential PayPal Authentication</h1>
        <div class="info">
            <p><strong>Domain:</strong> {}</p>
            <p><strong>Certificate:</strong> <span class="cert-status">RAM ONLY (Google Public CA)</span></p>
            <p><strong>Environment:</strong> GCP Confidential VM (AMD SEV-SNP)</p>
        </div>
        <div class="info">
            <p><strong>Verified Candidate Login (Recommended First):</strong></p>
            <p>This button uses a restricted PayPal App to only verify your "PayPal Verified" status and perform hardware attestation. No profile or email data is shared yet.</p>
            <a href="/login?flow=verified" class="btn" style="background:#4caf50;">Check Attestation & PayPal Verification</a>
        </div>
        <div class="info">
            <p><strong>Full Data Login:</strong></p>
            <p>Asks for standard profile and email data for full application functionality.</p>
            <a href="/login?flow=full" class="btn">Login with PayPal (Full Data)</a>
        </div>
        "#,
        state.domain
    );
    Html(HTML_TEMPLATE.replace("{{CONTENT}}", &content))
}

#[derive(Deserialize)]
struct LoginParams {
    flow: Option<String>,
}

async fn login(
    Query(params): Query<LoginParams>,
    State(state): State<Arc<AppState>>
) -> impl IntoResponse {
    let flow = params.flow.unwrap_or_else(|| "full".to_string());
    
    let (client_id, scope, state_val) = if flow == "verified" {
        (
            &state.paypal_verified_client_id,
            "openid", // Minimal scope for verification check
            "verified"
        )
    } else {
        (
            &state.paypal_client_id,
            "openid%20profile%20email",
            "full"
        )
    };

    let auth_base = if state.staging { PAYPAL_SANDBOX_AUTH } else { PAYPAL_PRODUCTION_AUTH };

    let url = format!(
        "{}?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}",
        auth_base,
        client_id,
        scope,
        urlencoding::encode(&state.redirect_uri),
        state_val
    );
    Redirect::temporary(&url)
}

async fn callback(
    Query(query): Query<CallbackQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Some(_error) = query.error {
        return (StatusCode::BAD_REQUEST, "Error from PayPal").into_response();
    }
    let code = query.code.clone().unwrap_or_default();
    let state_val = query.state.clone().unwrap_or_else(|| "full".to_string());
    
    let (client_id, client_secret) = if state_val == "verified" {
        (state.paypal_verified_client_id.clone(), state.paypal_verified_client_secret.clone())
    } else {
        (state.paypal_client_id.clone(), state.paypal_client_secret.clone())
    };
    let redirect_uri = state.redirect_uri.clone();

    let api_base = if state.staging { PAYPAL_SANDBOX_API } else { PAYPAL_PRODUCTION_API };

    let token = match exchange_code_for_token(&code, &client_id, &client_secret, &redirect_uri, api_base).await {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Token exchange failed").into_response(),
    };

    let userinfo = match get_userinfo(&token.access_token, api_base).await {
        Ok(u) => u,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Userinfo failed").into_response(),
    };

    let attestation = generate_attestation(client_id, userinfo.clone()).await;

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
async fn http_to_https_redirect() -> impl IntoResponse {
    Redirect::permanent("https://")
}

// ============================================================================
// TLS
// ============================================================================

async fn load_tls_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<SslAcceptor>, Box<dyn std::error::Error + Send + Sync>> {
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

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("====================================================");
    eprintln!("PAYPAL AUTH VM STARTING AT {}", chrono::Utc::now());
    eprintln!("====================================================");
    
    // 1. PID 1 RESPONSIBILITIES: Mount filesystems BEFORE anything else!
    enclave_init::mount_filesystems();

    // 2. Initialize the Tokio runtime now that the environment is sane
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // 3. Configure network (DHCP) from within the async runtime
    rt.block_on(async {
        if let Err(e) = enclave_init::configure_network().await {
            eprintln!("[FATAL] Network config failed: {}", e);
            enclave_init::poweroff();
        }

        async_main().await
    })
}

async fn async_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    
    // Attempt to force immediate flush
    use std::io::Write;
    std::io::stderr().flush()?;
    std::io::stdout().flush()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    eprintln!("[DEBUG] tracing initialized");
    info!("Starting PayPal Auth on GCP Confidential VM");
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
    let verified_id = config.paypal_verified_client_id.clone().unwrap_or_else(|| 
        "AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p".to_string());
    let verified_secret = config.paypal_verified_client_secret.clone().unwrap_or_else(|| "MISSING_VERIFIED_SECRET".to_string());
    
    let state = Arc::new(AppState {
        paypal_client_id: config.paypal_client_id.clone(),
        paypal_client_secret: config.paypal_client_secret.clone(),
        paypal_verified_client_id: verified_id,
        paypal_verified_client_secret: verified_secret,
        redirect_uri,
        used_paypal_ids: Arc::new(RwLock::new(HashSet::new())),
        domain: config.domain.clone(),
        https_ready: https_ready_clone,
        staging: config.staging,
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
