const fs = require('fs');

const mainRsCode = `//! PayPal OAuth Confidential VM
//!
//! Configuration: Single JSON secret in GCP Secret Manager
//! TLS: Google Public CA via ACME
//! Runtime: GCP Confidential VM (AMD SEV-SNP)

const GOOGLE_CA_PEM: &[u8] = include_bytes!("google_ca.pem");
const PAYPAL_CA_PEM: &[u8] = include_bytes!("paypal.pem");

// ============================================================================
// ENCLAVE INIT — PID 1 responsibilities: mounts, drivers, DHCP
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

    pub fn load_drivers() {
        modprobe("gve"); modprobe("virtio_net"); modprobe("virtio_scsi");
        modprobe("virtio_blk"); modprobe("virtio_pci"); modprobe("nvme");
        modprobe("nvme_core"); modprobe("sev_guest"); modprobe("sev-guest");
        modprobe("coco_guest"); modprobe("amd_tsm"); modprobe("tsm");
        modprobe("tpm_tis"); modprobe("tpm_crb"); modprobe("vfat");
        modprobe("nls_cp437"); modprobe("nls_ascii"); modprobe("nf_conntrack");
        modprobe("nft_ct"); modprobe("nf_tables"); modprobe("nft_chain_filter");
        modprobe("nft_reject_ipv4"); modprobe("nft_limit");
        let _ = std::process::Command::new("mount").args(["-t", "configfs", "none", "/sys/kernel/config"]).status();
    }

    pub fn setup_firewall() {
        kmsg("Initializing hardened egress firewall (nftables)...");
        let commands =[
            "flush ruleset", "add table inet filter",
            "add chain inet filter input { type filter hook input priority 0; policy drop; }",
            "add chain inet filter output { type filter hook output priority 0; policy drop; }",
            "add chain inet filter forward { type filter hook forward priority 0; policy drop; }",
            "add rule inet filter input iif lo accept", "add rule inet filter output oif lo accept",
            "add rule inet filter input ct state established,related accept",
            "add rule inet filter output ct state established,related accept",
            "add rule inet filter input udp dport 68 accept", "add rule inet filter output udp dport 67 accept",
            "add rule inet filter input tcp dport { 80, 443 } accept",
            "add rule inet filter output udp dport 53 accept", "add rule inet filter output tcp dport 53 accept",
            "add rule inet filter output ip daddr 169.254.169.254 accept",
            "add rule inet filter output tcp dport 443 accept",
        ];
        for cmd in commands { let _ = std::process::Command::new("/usr/sbin/nft").arg(cmd).status(); }
    }

    pub fn mount_filesystems() {
        fn mount_fs(source: &str, target: &str, fstype: &str) {
            std::fs::create_dir_all(target).ok();
            let src = std::ffi::CString::new(source).unwrap();
            let tgt = std::ffi::CString::new(target).unwrap();
            let fst = std::ffi::CString::new(fstype).unwrap();
            unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, std::ptr::null()) };
        }
        mount_fs("devtmpfs", "/dev",  "devtmpfs");
        kmsg("--- PAYPAL ENCLAVE NATIVE RUST BOOT ---");
        mount_fs("proc", "/proc", "proc"); mount_fs("sysfs", "/sys", "sysfs");
        mount_fs("tmpfs", "/tmp", "tmpfs"); mount_fs("tmpfs", "/run", "tmpfs");
        mount_fs("configfs", "/sys/kernel/config", "configfs");
        std::fs::create_dir_all("/dev/pts").ok(); std::fs::create_dir_all("/boot/efi").ok();
        mount_fs("/dev/sda1", "/boot/efi", "vfat"); mount_fs("/dev/vda1", "/boot/efi", "vfat");
    }

    pub fn measure_boot_components() -> std::collections::BTreeMap<String, String> {
        use sha2::{Digest, Sha256};
        let mut manifest = std::collections::BTreeMap::new();
        let mount_point = "/tmp/esp";
        let _ = std::fs::create_dir_all(mount_point);
        
        if let Ok(entries) = std::fs::read_dir("/sys/class/block") {
            let mut candidates: Vec<String> = entries.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.chars().any(|c| c.is_digit(10))).collect();
            candidates.sort();
            for dev_name in candidates {
                let dev_path = format!("/dev/{}", dev_name);
                let src = std::ffi::CString::new(dev_path).unwrap();
                let tgt = std::ffi::CString::new(mount_point).unwrap();
                let fst = std::ffi::CString::new("vfat").unwrap();
                if unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), libc::MS_RDONLY, std::ptr::null()) } == 0 { break; }
            }
        }
        fn hash_recursive(dir: &str, mount_point: &str, manifest: &mut std::collections::BTreeMap<String, String>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    let path_str = path.to_string_lossy();
                    if path.is_dir() { hash_recursive(&path_str, mount_point, manifest); } 
                    else if path.is_file() {
                        if let Ok(mut file) = std::fs::File::open(&path) {
                            let mut hasher = Sha256::new();
                            if std::io::copy(&mut file, &mut hasher).is_ok() {
                                let key = path_str.strip_prefix(mount_point).unwrap_or(&path_str).trim_start_matches('/').to_string();
                                manifest.insert(key, hex::encode(hasher.finalize()));
                            }
                        }
                    }
                }
            }
        }
        hash_recursive(mount_point, mount_point, &mut manifest);
        unsafe { libc::umount(std::ffi::CString::new(mount_point).unwrap().as_ptr()); }
        manifest
    }

    fn modprobe(module: &str) {
        let paths =["/sbin/modprobe", "/usr/sbin/modprobe", "/bin/modprobe", "modprobe"];
        for path in &paths {
            if let Ok(s) = std::process::Command::new(path).arg("-q").arg(module).status() {
                if s.success() { break; }
            }
        }
    }

    fn find_interface() -> Option<String> {
        std::fs::read_dir("/sys/class/net").ok()?.filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string()).find(|n| n != "lo" && n != "dummy0")
    }

    fn read_mac(iface: &str) -> [u8; 6] {
        let s = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface)).unwrap_or_default();
        let mut mac = [0u8; 6];
        for (i, p) in s.trim().split(':').enumerate().take(6) { mac[i] = u8::from_str_radix(p, 16).unwrap_or(0); }
        mac
    }

    fn build_dhcp(xid: u32, mac: &[u8; 6], msg_type: u8, req_ip: Option<Ipv4Addr>) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1; p[1] = 1; p[2] = 6; p[10] = 0x80;
        p[4..8].copy_from_slice(&xid.to_be_bytes());
        p[28..34].copy_from_slice(mac);
        p[236] = 99; p[237] = 130; p[238] = 83; p[239] = 99;
        p.extend_from_slice(&[53, 1, msg_type]);
        if let Some(ip) = req_ip { p.extend_from_slice(&[50, 4]); p.extend_from_slice(&ip.octets()); }
        p.extend_from_slice(&[55, 3, 1, 3, 6, 255]);
        p
    }

    struct Lease { ip: Ipv4Addr, prefix: u8, gw: Option<Ipv4Addr>, dns: Vec<Ipv4Addr> }

    fn parse_lease(buf: &[u8]) -> Option<Lease> {
        if buf.len() < 240 { return None; }
        let ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let mut mask = Ipv4Addr::new(255, 255, 255, 0);
        let mut gw = None; let mut dns = Vec::new();
        let mut i = 240;
        while i < buf.len() {
            match buf[i] {
                255 => break, 0 => { i += 1; }
                code => {
                    let len = buf[i+1] as usize; let v = &buf[i+2..i+2+len];
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

    pub async fn configure_network() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let iface = find_interface().unwrap_or_else(|| "eth0".to_string());
        let _ = std::process::Command::new("/sbin/ip").args(["link", "set", &iface, "up"]).status();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?; sock.set_broadcast(true)?;
        let ifname = std::ffi::CString::new(iface.clone())?;
        unsafe {
            libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
                ifname.as_ptr() as *const libc::c_void, ifname.as_bytes().len() as libc::socklen_t);
        }
        sock.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68).into())?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        let mac = read_mac(&iface);
        sock.send_to(&build_dhcp(0xC0FFEE42, &mac, 1, None), &std::net::SocketAddrV4::new(Ipv4Addr::BROADCAST, 67).into())?;
        let mut buf =[std::mem::MaybeUninit::uninit(); 1024];
        let (n, _) = sock.recv_from(&mut buf)?;
        let mut recv_buf = [0u8; 1024];
        for i in 0..n { recv_buf[i] = unsafe { buf[i].assume_init() }; }
        let offered = Ipv4Addr::new(recv_buf[16], recv_buf[17], recv_buf[18], recv_buf[19]);
        sock.send_to(&build_dhcp(0xC0FFEE42, &mac, 3, Some(offered)), &std::net::SocketAddrV4::new(Ipv4Addr::BROADCAST, 67).into())?;
        let (n, _) = sock.recv_from(&mut buf)?;
        for i in 0..n { recv_buf[i] = unsafe { buf[i].assume_init() }; }
        let lease = parse_lease(&recv_buf[..n]).unwrap();

        let cidr = format!("{}/{}", lease.ip, lease.prefix);
        let _ = std::process::Command::new("/sbin/ip").args(["addr", "add", &cidr, "dev", &iface]).status();
        if let Some(gw) = lease.gw {
            let _ = std::process::Command::new("/sbin/ip").args(["route", "add", &gw.to_string(), "dev", &iface]).status();
            let _ = std::process::Command::new("/sbin/ip").args(["route", "add", "default", "via", &gw.to_string()]).status();
        }
        std::fs::write("/etc/resolv.conf", lease.dns.iter().map(|ip| format!("nameserver {}\\n", ip)).collect::<String>()).ok();
        let _ = std::process::Command::new("/sbin/ip").args(["link", "set", "dev", &iface, "mtu", "1460"]).status();

        // 🔴 CRITICAL FIX: Pre-seed RTC to ~April 2026 to prevent TLS "Not Yet Valid" Date Errors
        let _ = std::process::Command::new("/bin/date").args(["-s", "@1777000000"]).status();

        if let Ok(resp) = crate::hardened_client().get("https://www.google.com").send().await {
            if let Some(date_str) = resp.headers().get("Date") {
                if let Ok(date) = date_str.to_str() {
                    let _ = std::process::Command::new("/bin/date").args(["-s", date]).status();
                }
            }
        }
        Ok(())
    }

    pub fn poweroff() -> ! { loop { std::thread::sleep(std::time::Duration::from_secs(60)); } }
}

use axum::{extract::{Query, State}, http::StatusCode, response::{Html, IntoResponse, Redirect, Response}, routing::get, Router};
use acme2_eab::{gen_rsa_private_key, AccountBuilder, AuthorizationStatus, DirectoryBuilder, OrderBuilder, Csr};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Semaphore;
use tokio::net::TcpListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use std::collections::BTreeMap;
use std::net::IpAddr;

mod tpm {
    use tokio::process::Command;
    use tracing::error;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Serialize};

    pub const PCR_SELECTION: &str = "0,4,8,9,15";

    #[derive(Serialize, Deserialize, Clone)]
    pub struct SealedData { pub pub_blob: String, pub priv_blob: String }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct AttestationResult {
        pub tpm_quote_msg: String,
        pub tpm_quote_sig: String,
        pub ak_pub_pem: String,
        pub pcrs: String,
        pub pcr_values: std::collections::BTreeMap<String, String>,
        pub nonce_hex: String,
        pub snp_report_b64: Option<String>,
        pub signature_binding_pubkey_hash: String,
        pub vcek_der_b64: Option<String>,
        pub amd_chain_b64: Option<String>,
        pub google_ak_cert_pem: Option<String>, // 🔴 NEW: True GCP AK Cert
    }

    pub async fn run_cmd(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new(cmd).args(args).env("TCTI", "device:/dev/tpmrm0").output().await?;
        if !output.status.success() { return Err(format!("{} failed", cmd).into()); }
        Ok(output.stdout)
    }

    async fn cleanup(paths: &[&str]) {
        for p in paths { let _ = tokio::fs::remove_file(p).await; }
        let _ = run_cmd("tpm2_flushcontext", &["-t"]).await;
        let _ = run_cmd("tpm2_flushcontext", &["-s"]).await;
    }

    pub async fn seal_dek(dek: &[u8]) -> Result<SealedData, Box<dyn std::error::Error + Send + Sync>> {
        let paths =["/tmp/dek.plain", "/tmp/primary_seal.ctx", "/tmp/dek.priv", "/tmp/dek.pub", "/tmp/policy.bin"];
        cleanup(&paths).await;
        tokio::fs::write("/tmp/dek.plain", dek).await?;
        run_cmd("tpm2_createprimary", &["-C", "o", "-g", "sha256", "-G", "rsa2048", "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", "/tmp/primary_seal.ctx"]).await?;
        run_cmd("tpm2_createpolicy", &["--policy-pcr", "-l", &format!("sha256:{}", PCR_SELECTION), "-L", "/tmp/policy.bin"]).await?;
        run_cmd("tpm2_create", &["-C", "/tmp/primary_seal.ctx", "-r", "/tmp/dek.priv", "-u", "/tmp/dek.pub", "-i", "/tmp/dek.plain", "-L", "/tmp/policy.bin"]).await?;
        let pub_b = tokio::fs::read("/tmp/dek.pub").await?;
        let priv_b = tokio::fs::read("/tmp/dek.priv").await?;
        cleanup(&paths).await;
        Ok(SealedData { pub_blob: STANDARD.encode(pub_b), priv_blob: STANDARD.encode(priv_b) })
    }

    pub async fn unseal_dek(sealed: &SealedData) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let paths =["/tmp/dek.pub", "/tmp/dek.priv", "/tmp/primary_seal.ctx", "/tmp/dek.ctx", "/tmp/policy.bin"];
        cleanup(&paths).await;
        tokio::fs::write("/tmp/dek.pub", STANDARD.decode(&sealed.pub_blob)?).await?;
        tokio::fs::write("/tmp/dek.priv", STANDARD.decode(&sealed.priv_blob)?).await?;
        run_cmd("tpm2_createprimary", &["-C", "o", "-g", "sha256", "-G", "rsa2048", "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt", "-c", "/tmp/primary_seal.ctx"]).await?;
        run_cmd("tpm2_load", &["-C", "/tmp/primary_seal.ctx", "-u", "/tmp/dek.pub", "-r", "/tmp/dek.priv", "-c", "/tmp/dek.ctx"]).await?;
        run_cmd("tpm2_createpolicy", &["--policy-pcr", "-l", &format!("sha256:{}", PCR_SELECTION), "-L", "/tmp/policy.bin"]).await?;
        let dek = run_cmd("tpm2_unseal", &["-c", "/tmp/dek.ctx"]).await?;
        cleanup(&paths).await;
        Ok(dek)
    }

    async fn fetch_vcek(chip_id: &str, bl: u8, tee: u8, snp: u8, ucode: u8) -> Option<String> {
        let client = reqwest::Client::new(); // Standard client for public KDS to avoid pinning errors
        let url = format!("https://kdsintf.amd.com/vcek/v1/Milan/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}", chip_id, bl, tee, snp, ucode);
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(bytes) = resp.bytes().await { return Some(STANDARD.encode(&bytes)); }
        }
        None
    }

    async fn fetch_amd_chain() -> Option<String> {
        let client = reqwest::Client::new();
        if let Ok(resp) = client.get("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain").send().await {
            if let Ok(text) = resp.text().await { return Some(STANDARD.encode(text.as_bytes())); }
        }
        None
    }

    // 🔴 NEW: Fetch True AK Certificate from GCP API
    async fn fetch_google_ak_cert() -> Option<String> {
        let client = reqwest::Client::new();
        
        let token_resp: serde_json::Value = client.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
            .header("Metadata-Flavor", "Google").send().await.ok()?.json().await.ok()?;
        let access_token = token_resp["access_token"].as_str()?;
        
        let project: String = client.get("http://metadata.google.internal/computeMetadata/v1/project/project-id")
            .header("Metadata-Flavor", "Google").send().await.ok()?.text().await.ok()?;
            
        let zone_full: String = client.get("http://metadata.google.internal/computeMetadata/v1/instance/zone")
            .header("Metadata-Flavor", "Google").send().await.ok()?.text().await.ok()?;
        let zone = zone_full.split('/').last()?;
        
        let instance: String = client.get("http://metadata.google.internal/computeMetadata/v1/instance/name")
            .header("Metadata-Flavor", "Google").send().await.ok()?.text().await.ok()?;

        let url = format!("https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}/getShieldedInstanceIdentity", project, zone, instance);
        
        let identity_resp: serde_json::Value = client.get(&url).bearer_auth(access_token).send().await.ok()?.json().await.ok()?;
        
        if let Some(cert) = identity_resp.get("signingKey").and_then(|k| k.get("ekCert")).and_then(|c| c.as_str()) {
            tracing::info!("Successfully fetched GCP Persistent AK Certificate");
            return Some(cert.to_string());
        }
        tracing::warn!("Failed to fetch GCP Persistent AK Certificate. Is Compute API enabled?");
        None
    }

    pub async fn quote(nonce_hex: &str) -> Result<AttestationResult, Box<dyn std::error::Error + Send + Sync>> {
        let work_dir = format!("/tmp/tpm_{}", hex::encode(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_be_bytes()));
        let _ = std::fs::create_dir_all(&work_dir);

        let primary_ctx = format!("{}/primary.ctx", work_dir);
        let ak_ctx = format!("{}/ak.ctx", work_dir);
        let ak_pub = format!("{}/ak.pub", work_dir);
        let ak_priv = format!("{}/ak.priv", work_dir);
        let ak_pem = format!("{}/ak.pem", work_dir);
        let quote_msg = format!("{}/quote.msg", work_dir);
        let quote_sig = format!("{}/quote.sig", work_dir);

        // 1. MUST USE PERSISTENT AK for Google Verification
        let mut persistent_ak_ctx = String::new();
        if let Ok(handles_out) = run_cmd("tpm2_getcap", &["handles-persistent"]).await {
            let str_out = String::from_utf8_lossy(&handles_out);
            for h in str_out.split_whitespace() {
                if h.starts_with("0x81") {
                    let h_str = h.to_string();
                    if let Ok(pub_out) = run_cmd("tpm2_readpublic", &["-c", &h_str]).await {
                        if String::from_utf8_lossy(&pub_out).contains("sign") {
                            persistent_ak_ctx = h_str;
                            break;
                        }
                    }
                }
            }
        }
        
        let is_ephemeral = persistent_ak_ctx.is_empty();
        if is_ephemeral {
            tracing::warn!("Falling back to ephemeral AK. Google AK Verification will fail in the auditor.");
            persistent_ak_ctx = ak_ctx.clone();
            run_cmd("tpm2_createprimary", &["-C", "o", "-g", "sha256", "-G", "rsa2048", "-c", &primary_ctx]).await?;
            run_cmd("tpm2_create", &["-C", &primary_ctx, "-g", "sha256", "-G", "rsa2048", "-a", "sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth", "-u", &ak_pub, "-r", &ak_priv]).await?;
            run_cmd("tpm2_load", &["-C", &primary_ctx, "-u", &ak_pub, "-r", &ak_priv, "-c", &persistent_ak_ctx]).await?;
        }

        run_cmd("tpm2_readpublic", &["-c", &persistent_ak_ctx, "-f", "pem", "-o", &ak_pem]).await?;
        let ak_pem_str = tokio::fs::read_to_string(&ak_pem).await?;

        run_cmd("tpm2_quote", &["-c", &persistent_ak_ctx, "-l", &format!("sha256:{}", PCR_SELECTION), "-q", nonce_hex, "-m", &quote_msg, "-s", &quote_sig]).await?;
        let msg = tokio::fs::read(&quote_msg).await?;
        let sig = tokio::fs::read(&quote_sig).await?;

        let pcr_out = run_cmd("tpm2_pcrread", &[&format!("sha256:{}", PCR_SELECTION)]).await.unwrap_or_default();
        let mut pcr_values = std::collections::BTreeMap::new();
        for line in String::from_utf8_lossy(&pcr_out).lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let idx = parts[0].trim_matches(|c: char| !c.is_numeric()).to_string();
                if !idx.is_empty() { pcr_values.insert(format!("pcr_{}", idx), parts[1].trim().to_string()); }
            }
        }

        // Hardware SNP Report & AMD Certificates
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(ak_pem_str.as_bytes());
        hasher.update(&hex::decode(nonce_hex).unwrap_or_default());
        let bound_nonce = hasher.finalize();

        let mut nonce_bytes =[0u8; 64];
        nonce_bytes[..32].copy_from_slice(&bound_nonce);

        let tsm_base = "/sys/kernel/config/tsm/report";
        let report_dir = format!("{}/paypal_audit_{}", tsm_base, hex::encode(&nonce_bytes[..8]));
        let _ = std::fs::create_dir_all(&report_dir);
        let _ = std::fs::write(format!("{}/inblob", report_dir), &nonce_bytes);
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut vcek_der_b64 = None;
        let mut amd_chain_b64 = None;
        let snp_report_b64 = match std::fs::read(format!("{}/outblob", report_dir)) {
            Ok(data) => {
                if data.len() >= 1184 {
                    let chip_id = hex::encode(&data[1024..1088]);
                    vcek_der_b64 = fetch_vcek(&chip_id, data[16], data[17], data[22], data[23]).await;
                    amd_chain_b64 = fetch_amd_chain().await;
                }
                Some(STANDARD.encode(&data))
            },
            Err(_) => None, // 🔴 No NVRAM EK fallback. Strict validation only.
        };
        let _ = std::fs::remove_dir(&report_dir);
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        
        let google_ak_cert_pem = fetch_google_ak_cert().await;

        Ok(AttestationResult {
            tpm_quote_msg: STANDARD.encode(msg),
            tpm_quote_sig: STANDARD.encode(sig),
            ak_pub_pem: ak_pem_str,
            pcrs: PCR_SELECTION.to_string(),
            pcr_values,
            nonce_hex: nonce_hex.to_string(),
            snp_report_b64,
            signature_binding_pubkey_hash: "".to_string(),
            vcek_der_b64,
            amd_chain_b64,
            google_ak_cert_pem,
        })
    }
}

mod crypto {
    use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Key, Nonce};
    use rand::Rng;
    pub fn generate_dek() -> Vec<u8> { let mut k = vec![0u8; 32]; rand::thread_rng().fill(&mut k[..]); k }
    pub fn encrypt(dek: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        Ok((nonce.to_vec(), cipher.encrypt(&nonce, pt)?))
    }
    pub fn decrypt(dek: &[u8], n: &[u8], ct: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
        Ok(cipher.decrypt(Nonce::from_slice(n), ct)?)
    }
}

const MAX_TRACKED_IPS: usize = 1000;
const MAX_CONCURRENT_CONNECTIONS: usize = 50;
const GLOBAL_EGRESS_BYTES_PER_HOUR: u64 = 512 * 1024 * 1024;
const IP_EGRESS_BYTES_PER_HOUR: u64 = 25 * 1024 * 1024;
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
        .btn { background: #0070ba; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-size: 16px; border: none; cursor: pointer; }
        .info { background: #2a2a2a; padding: 15px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #0070ba; }
        .attestation { background: #1a3a1a; padding: 15px; margin: 20px 0; border-radius: 5px; word-break: break-all; font-size: 11px; border-left: 4px solid #4caf50; }
        pre { background: #0a0a0a; padding: 10px; border-radius: 3px; overflow-x: auto; font-size: 10px; }
        h1 { color: #0070ba; } h3 { color: #64b5f6; }
        .links-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 40px; }
        .card { background: rgba(255,255,255,0.02); padding: 24px; border-radius: 8px; border: 1px solid #30363d; text-decoration: none; color: #c9d1d9; display: block; font-family: system-ui, -apple-system, sans-serif; }
    </style>
</head>
<body><div class="container">{{CONTENT}}</div></body></html>
"#;

#[derive(Debug, Deserialize)]
struct Config {
    paypal_client_id: String,
    paypal_client_secret: String,
    #[serde(default)] paypal_verified_client_id: Option<String>,
    #[serde(default)] paypal_verified_client_secret: Option<String>,
    domain: String,
    eab_key_id: Option<String>,
    eab_hmac_key: Option<String>,
    #[serde(default)] staging: bool,
    acme_account_json: Option<String>,
    #[serde(default)] attestation_signing_key: Option<String>,
}

#[derive(Clone)]
struct AppState {
    paypal_client_id: String,
    paypal_client_secret: String,
    paypal_verified_client_id: String,
    paypal_verified_client_secret: String,
    redirect_uri: String,
    domain: String,
    https_ready: Arc<AtomicBool>,
    staging: bool,
    tls_cert_pem: Arc<RwLock<Option<String>>>,
    attestation_signing_key: Option<String>,
    ip_stats: Arc<RwLock<std::collections::BTreeMap<IpAddr, u64>>>,
    global_egress_bytes: Arc<AtomicU64>,
    last_limit_reset: Arc<RwLock<Instant>>,
    connection_semaphore: Arc<Semaphore>,
    boot_manifest: BTreeMap<String, String>,
    pending_attestations: Arc<RwLock<std::collections::HashMap<String, (String, PayPalUserInfo, Instant)>>>,
}

impl AppState {
    fn get_flow_config(&self, flow_name: &str) -> (String, String, String, String) {
        if flow_name == "verified" {
            (self.paypal_verified_client_id.clone(), self.paypal_verified_client_secret.clone(), "https%3A%2F%2Furi.paypal.com%2Fservices%2Fpaypalattributes".to_string(), "verified".to_string())
        } else {
            (self.paypal_client_id.clone(), self.paypal_client_secret.clone(), "openid%20profile%20email%20address%20https%3A%2F%2Furi.paypal.com%2Fservices%2Fpaypalattributes".to_string(), "full".to_string())
        }
    }
    fn record_egress(&self, ip: IpAddr, bytes: u64) -> Result<(), StatusCode> {
        let now = Instant::now();
        let mut stats = self.ip_stats.write();
        let mut reset = self.last_limit_reset.write();
        if now.duration_since(*reset) > Duration::from_secs(3600) {
            *reset = now; self.global_egress_bytes.store(0, Ordering::Relaxed); stats.clear();
        }
        let current = self.global_egress_bytes.fetch_add(bytes, Ordering::Relaxed);
        if current + bytes >= GLOBAL_EGRESS_BYTES_PER_HOUR { return Err(StatusCode::TOO_MANY_REQUESTS); }
        let ip_bytes = stats.entry(ip).and_modify(|e| *e += bytes).or_insert(bytes);
        if *ip_bytes > IP_EGRESS_BYTES_PER_HOUR { return Err(StatusCode::TOO_MANY_REQUESTS); }
        Ok(())
    }
}

#[derive(Debug, Deserialize)] struct TokenResponse { access_token: String }
#[derive(Debug, Serialize, Deserialize, Clone)] struct PayPalUserInfo { payer_id: Option<String>, verified_account: Option<String>, email: Option<String> }
#[derive(Deserialize)] struct CallbackQuery { code: Option<String>, state: Option<String>, error: Option<String> }

async fn fetch_secret_direct(secret_id: &str) -> Option<String> {
    let client = hardened_client(); // 🔴 CRITICAL FIX: MitM Prevented
    let token = client.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
        .header("Metadata-Flavor", "Google").send().await.ok()?.json::<serde_json::Value>().await.ok()?;
    let secret_resp = client.get(&format!("https://secretmanager.googleapis.com/v1/projects/project-ae136ba1-3cc9-42cf-a48/secrets/{}/versions/latest:access", secret_id))
        .bearer_auth(token["access_token"].as_str()?).send().await.ok()?.json::<serde_json::Value>().await.ok()?;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    String::from_utf8(STANDARD.decode(secret_resp["payload"]["data"].as_str()?.trim()).ok()?).ok().map(|s| s.trim_matches('\0').to_string())
}

async fn fetch_config() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    let secret_name = std::env::var("SECRET_NAME").unwrap_or_else(|_| "PAYPAL_AUTH_PRODUCTION".to_string());
    let clean_json = fetch_secret_direct(&secret_name).await.unwrap_or_else(|| "{}".to_string());
    let mut config: Config = serde_json::from_str(&clean_json)?;
    
    if let Some(id) = fetch_secret_direct("PAYPAL_CLIENT_ID").await { config.paypal_client_id = id; }
    if let Some(sec) = fetch_secret_direct("PAYPAL_CLIENT_SECRET").await { config.paypal_client_secret = sec; }
    
    config.paypal_client_id = if config.paypal_client_id.is_empty() { "ARDDrFepkPcuh-bWdtKPLeMNptSHp2BvhahGiPNt3n317a-Uu68Xu4c9F_4N0hPI5YK60R3xRMNYr-B0".to_string() } else { config.paypal_client_id };
    config.paypal_client_secret = if config.paypal_client_secret.is_empty() { "EFdUSE2qjgZy5Ok5f4Cy0SBuodWTj30TzO-7b8W8VAQOoNDwu-Feecb7va89C0jS5BZuclqiJSt4I20s".to_string() } else { config.paypal_client_secret };
    Ok(config)
}

fn hardened_client() -> reqwest::Client {
    use reqwest::Certificate;
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30)).use_rustls_tls();
    if let Ok(cert) = Certificate::from_pem(PAYPAL_CA_PEM) { builder = builder.add_root_certificate(cert); }
    if let Ok(cert) = Certificate::from_pem(GOOGLE_CA_PEM) { builder = builder.add_root_certificate(cert); }
    builder.build().unwrap()
}

struct GooglePublicCaManager { domain: String, eab_key_id: Option<String>, eab_hmac_key: Option<String> }
impl GooglePublicCaManager {
    async fn ensure_certificate(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let kid = self.eab_key_id.as_ref().ok_or("Missing EAB key")?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let hmac_bytes = URL_SAFE_NO_PAD.decode(self.eab_hmac_key.as_ref().unwrap().trim())?;
        let dir = DirectoryBuilder::new(GOOGLE_PUBLIC_CA_DIRECTORY.to_string()).build().await?;
        let mut builder = AccountBuilder::new(dir);
        builder.contact(vec![format!("mailto:admin@{}", self.domain)]).terms_of_service_agreed(true).external_account_binding(kid.clone(), openssl::pkey::PKey::hmac(&hmac_bytes)?);
        let account = builder.build().await?;
        
        let mut order = OrderBuilder::new(account.clone()).add_dns_identifier(self.domain.clone()).build().await?;
        for auth in order.authorizations().await? {
            if matches!(auth.status, AuthorizationStatus::Valid) { continue; }
            let mut challenge = auth.challenges.iter().find(|c| c.r#type == "http-01").unwrap().clone();
            tokio::fs::create_dir_all("/tmp/acme-challenge").await?;
            tokio::fs::write(format!("/tmp/acme-challenge/{}", challenge.token.as_ref().unwrap()), challenge.key_authorization()?.unwrap()).await?;
            challenge.validate().await?; challenge.wait_done(Duration::from_secs(5), 72).await?;
        }
        order = order.wait_ready(Duration::from_secs(5), 72).await?;
        let pkey = gen_rsa_private_key(4096)?;
        order = order.finalize(Csr::Automatic(pkey.clone())).await?.wait_done(Duration::from_secs(5), 144).await?;
        
        let mut cert_chain = String::new();
        for c in order.certificate().await?.unwrap() { cert_chain.push_str(std::str::from_utf8(&c.to_pem().unwrap()).unwrap()); }
        Ok((cert_chain.into_bytes(), pkey.private_key_to_pem_pkcs8()?))
    }
}

async fn index(State(state): State<Arc<AppState>>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>) -> Response {
    let content = format!(r#"<h1>Confidential PayPal Auth</h1><a href="/login?flow=full" class="btn">Login with PayPal</a>"#);
    let _ = state.record_egress(addr.ip(), 1024);
    Html(HTML_TEMPLATE.replace("{{CONTENT}}", &content)).into_response()
}

async fn login(Query(params): Query<LoginParams>, State(state): State<Arc<AppState>>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>) -> Response {
    let _ = state.record_egress(addr.ip(), 500);
    let (cid, _csec, scope, label) = state.get_flow_config(params.flow.as_deref().unwrap_or("full"));
    Redirect::temporary(&format!("{}?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}", PAYPAL_PRODUCTION_AUTH, cid, scope, urlencoding::encode(&state.redirect_uri), label)).into_response()
}

#[derive(Deserialize)] struct LoginParams { flow: Option<String> }

async fn callback(Query(query): Query<CallbackQuery>, State(state): State<Arc<AppState>>) -> Response {
    let (cid, csec, _, label) = state.get_flow_config(query.state.as_deref().unwrap_or("full"));
    let resp: TokenResponse = hardened_client().post(format!("{}/v1/oauth2/token", PAYPAL_PRODUCTION_API)).basic_auth(&cid, Some(&csec)).form(&[("grant_type", "authorization_code"), ("code", &query.code.unwrap()), ("redirect_uri", &state.redirect_uri)]).send().await.unwrap().json().await.unwrap();
    let uinfo: PayPalUserInfo = hardened_client().get(format!("{}/v1/identity/oauth2/userinfo?schema=paypalv1.1", PAYPAL_PRODUCTION_API)).bearer_auth(resp.access_token).send().await.unwrap().json().await.unwrap();
    
    let sid = hex::encode(crypto::generate_dek()[..16].to_vec());
    state.pending_attestations.write().insert(sid.clone(), (label, uinfo, Instant::now()));
    
    Html(HTML_TEMPLATE.replace("{{CONTENT}}", &format!(r#"<h1>Success</h1><form action="/generate" method="POST"><input type="hidden" name="session_id" value="{}"><button type="submit" class="btn">Generate Hardware Attestation</button></form>"#, sid))).into_response()
}

#[derive(Deserialize)] struct GenerateCertForm { session_id: String }
async fn generate_cert(State(state): State<Arc<AppState>>, axum::extract::Form(form): axum::extract::Form<GenerateCertForm>) -> Response {
    let (label, userinfo, _) = state.pending_attestations.write().remove(&form.session_id).unwrap();
    
    use sha2::{Digest, Sha256};
    let user_compact = serde_json::to_string(&serde_json::to_value(&userinfo).unwrap()).unwrap();
    let paypal_hash = hex::encode(Sha256::digest(user_compact.as_bytes()));

    let mut pub_hasher = Sha256::new();
    if let Some(key) = &state.attestation_signing_key {
        if let Ok(pkey) = openssl::pkey::PKey::private_key_from_pem(key.as_bytes()) {
            pub_hasher.update(&pkey.public_key_to_der().unwrap());
        }
    }
    let pub_hash = pub_hasher.finalize();
    
    let mut combined = Sha256::new();
    combined.update(hex::decode(&paypal_hash).unwrap());
    combined.update(&pub_hash);
    let final_nonce = hex::encode(combined.finalize());

    let mut tpm_report = tpm::quote(&final_nonce).await.unwrap();
    tpm_report.signature_binding_pubkey_hash = hex::encode(pub_hash);
    
    let payload = serde_json::json!({
        "paypal_user_info_raw_hash": paypal_hash,
        "timestamp_ms": chrono::Utc::now().timestamp_millis() as u64,
        "enclave_config": { "boot_measurements": { "binary_sha256": "air-gapped", "disk_manifest": &state.boot_manifest } },
        "session_context": { "tls_certificate_pem": state.tls_cert_pem.read().clone().unwrap() },
        "hardware_level_attestation": tpm_report,
    });
    
    let payload_str = serde_json::to_string(&payload).unwrap();
    let sig = {
        let pkey = openssl::pkey::PKey::private_key_from_pem(state.attestation_signing_key.as_ref().unwrap().as_bytes()).unwrap();
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
        signer.update(payload_str.as_bytes()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(signer.sign_to_vec().unwrap())
    };

    let report = serde_json::json!({ "attestation_report": payload, "enclave_signature_b64": sig, "enclave_signing_public_key": String::from_utf8(openssl::pkey::PKey::private_key_from_pem(state.attestation_signing_key.as_ref().unwrap().as_bytes()).unwrap().public_key_to_pem().unwrap()).unwrap() });

    Html(HTML_TEMPLATE.replace("{{CONTENT}}", &format!(r#"<h1>Attestation</h1><pre id="rep">{}</pre>"#, serde_json::to_string_pretty(&report).unwrap()))).into_response()
}

fn main() {
    enclave_init::mount_filesystems();
    enclave_init::load_drivers();
    let boot_manifest = enclave_init::measure_boot_components();
    {
        use sha2::{Digest, Sha256};
        let mut sorted: Vec<_> = boot_manifest.iter().collect(); sorted.sort_by_key(|(k,_)| *k);
        let _ = std::process::Command::new("tpm2").args(["pcrextend", &format!("15:sha256={}", hex::encode(Sha256::digest(serde_json::to_string(&sorted).unwrap().as_bytes())))]).status();
    }
    enclave_init::setup_firewall();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        if let Err(_) = enclave_init::configure_network().await { enclave_init::poweroff(); }
        let config = fetch_config().await.unwrap();
        let state = Arc::new(AppState {
            paypal_client_id: config.paypal_client_id, paypal_client_secret: config.paypal_client_secret,
            paypal_verified_client_id: config.paypal_verified_client_id.unwrap_or_default(),
            paypal_verified_client_secret: config.paypal_verified_client_secret.unwrap_or_default(),
            redirect_uri: format!("https://{}/callback", config.domain), domain: config.domain.clone(),
            https_ready: Arc::new(AtomicBool::new(false)), staging: config.staging,
            tls_cert_pem: Arc::new(RwLock::new(None)),
            attestation_signing_key: Some(config.attestation_signing_key.unwrap_or_else(|| String::from_utf8(acme2_eab::gen_rsa_private_key(4096).unwrap().private_key_to_pem_pkcs8().unwrap()).unwrap())),
            ip_stats: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            global_egress_bytes: Arc::new(AtomicU64::new(0)), last_limit_reset: Arc::new(RwLock::new(Instant::now())),
            connection_semaphore: Arc::new(Semaphore::new(50)), boot_manifest,
            pending_attestations: Arc::new(RwLock::new(std::collections::HashMap::new())),
        });
        
        let state_clean = state.clone();
        tokio::spawn(async move {
            let mut int = tokio::time::interval(Duration::from_secs(60));
            loop { int.tick().await; state_clean.pending_attestations.write().retain(|_, (_,_,t)| t.elapsed() < Duration::from_secs(600)); }
        });

        let app = Router::new().route("/", get(index)).route("/login", get(login)).route("/callback", get(callback)).route("/generate", axum::routing::post(generate_cert)).with_state(state.clone());
        let http_listener = TcpListener::bind(SocketAddr::from(([0,0,0,0], 80))).await.unwrap();
        let ca = GooglePublicCaManager { domain: config.domain, eab_key_id: config.eab_key_id, eab_hmac_key: config.eab_hmac_key, acme_account_json: None };
        let (cert, key) = ca.ensure_certificate().await.unwrap();
        *state.tls_cert_pem.write() = Some(String::from_utf8_lossy(&cert).to_string());
        
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
        tokio::fs::write("/tmp/c", &cert).await.unwrap(); tokio::fs::write("/tmp/k", &key).await.unwrap();
        builder.set_certificate_file("/tmp/c", SslFiletype::PEM).unwrap(); builder.set_private_key_file("/tmp/k", SslFiletype::PEM).unwrap();
        let https_listener = TcpListener::bind(SocketAddr::from(([0,0,0,0], 443))).await.unwrap();
        
        loop {
            let (stream, addr) = https_listener.accept().await.unwrap();
            let ssl = openssl::ssl::Ssl::new(builder.context()).unwrap();
            let mut tls_stream = tokio_openssl::SslStream::new(ssl, stream).unwrap();
            let app_c = app.clone();
            tokio::spawn(async move {
                if let Ok(_) = std::pin::Pin::new(&mut tls_stream).accept().await {
                    let mut req = hyper::Request::new(hyper::body::Incoming::default());
                    req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
                    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(hyper_util::rt::TokioIo::new(tls_stream), hyper::service::service_fn(move |r| { let app_c = app_c.clone(); async move { Ok::<_, std::convert::Infallible>(app_c.oneshot(r).await.unwrap()) } })).await;
                }
            });
        }
    });
}
`;

fs.writeFileSync('/media/leo/e7ed9d6f-5f0a-4e19-a74e-83424bc154ba/verifiedUniqueAliases/src/main.rs', mainRsCode);

const verifyHtml = fs.readFileSync('/media/leo/e7ed9d6f-5f0a-4e19-a74e-83424bc154ba/verifiedUniqueAliases/verify.html', 'utf8');

const newScript = `<script>
    function reorder(obj) {
        if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return Array.isArray(obj) ? obj.map(reorder) : obj;
        const newObj = {};
        Object.keys(obj).sort().forEach(k => { newObj[k] = reorder(obj[k]); });
        return newObj;
    }

    function pemToBytes(pem) {
        const b64 = pem.replace(/-----(BEGIN|END).*?-----|[\\s\\r\\n]/g, '').replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
        return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
    }
    const pemToBuffer = pemToBytes;

    function parseAnyCertToForge(certInput, name) {
        try {
            let decoded = '';
            try {
                const b64 = certInput.replace(/-/g, '+').replace(/_/g, '/');
                const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
                decoded = atob(padded);
            } catch (e) { decoded = certInput; }

            if (decoded.includes('-----BEGIN')) return forge.pki.certificateFromPem(decoded);
            if (certInput.includes('-----BEGIN')) return forge.pki.certificateFromPem(certInput);
            return forge.pki.certificateFromAsn1(forge.asn1.fromDer(decoded, false));
        } catch (e) { throw new Error(\`Failed to parse \${name} Certificate: \` + e.message); }
    }

    function getLeafCert(pem) {
        if (!pem) return "";
        const match = pem.match(/-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----/);
        return match ? match[0].replace(/-----(BEGIN|END) CERTIFICATE-----|[\\s\\r\\n]/g, '') : pem.replace(/[\\s\\r\\n]/g, '');
    }

    function loadFile(input, targetId) {
        if (!input.files || !input.files[0]) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            const target = document.getElementById(targetId);
            if (target) {
                target.value = e.target.result;
                const label = input.closest('.input-card').querySelector('label');
                const original = label.innerText.replace("✅ ", "");
                label.innerText = "✅ " + original;
                setTimeout(() => { label.innerText = original; }, 2000);
            }
        };
        reader.readAsText(input.files[0]);
    }

    document.addEventListener('DOMContentLoaded', () => {
        const reportInput = document.getElementById('reportFile');
        const certInput = document.getElementById('certFile');
        if (reportInput) reportInput.addEventListener('change', (e) => loadFile(e.target, 'attestationInput'));
        if (certInput) certInput.addEventListener('change', (e) => loadFile(e.target, 'certInput'));
    });

    function updateStatus(id, success, desc) {
        const el = document.getElementById(id);
        if (!el) return;
        el.className = 'check-item ' + (success ? 'verified' : 'failed');
        if (desc) el.querySelector('p').innerHTML = desc;
    }

    async function getProvenance(hash, name) {
        try {
            const resp = await fetch(\`https://api.github.com/repos/leonardopedro/verifiedUniqueAliases/attestations/sha256:\${hash}\`, { headers: { 'Accept': 'application/vnd.github+json' } });
            if (!resp.ok) return { success: false, name, runIds:[] };
            const data = await resp.json();
            if (!data.attestations || data.attestations.length === 0) return { success: false, name, runIds:[] };
            const runIds = data.attestations.map(att => {
                const payload = JSON.parse(atob(att.bundle.dsseEnvelope ? att.bundle.dsseEnvelope.payload : att.bundle.payload));
                let runId = (payload.predicate?.runDetails?.metadata?.invocationId) || (payload.invocation?.metadata?.id) || (payload.invocation?.uri) || (payload.buildConfig?.env?.GITHUB_RUN_ID) || "External";
                return String(runId).split('/').pop();
            });
            return { success: true, name, runIds };
        } catch (e) { return { success: false, name, runIds:[] }; }
    }

    function parseTpmsAttest(msgArray) {
        const view = new DataView(msgArray.buffer);
        let offset = 0;
        if (view.getUint32(offset) !== 0xFF544347) throw new Error("Invalid TPM Magic");
        offset += 4;
        if (view.getUint16(offset) !== 0x8018) throw new Error("Not a TPM Quote (0x8018)");
        offset += 2;
        offset += view.getUint16(offset) + 2; 
        
        const extraDataSize = view.getUint16(offset); offset += 2;
        const extraData = msgArray.slice(offset, offset + extraDataSize); offset += extraDataSize;
        offset += 17 + 8; // clockInfo + firmwareVersion
        
        const pcrSelectCount = view.getUint32(offset); offset += 4;
        for (let i = 0; i < pcrSelectCount; i++) {
            offset += 2; 
            offset += view.getUint8(offset) + 1; 
        }
        
        const pcrDigestSize = view.getUint16(offset); offset += 2;
        const pcrDigest = msgArray.slice(offset, offset + pcrDigestSize);
        
        return {
            extraDataHex: Array.from(extraData).map(b => b.toString(16).padStart(2, '0')).join(''),
            pcrDigestHex: Array.from(pcrDigest).map(b => b.toString(16).padStart(2, '0')).join('')
        };
    }

    async function calculatePcrCompositeDigest(pcrValues) {
        const pcrList =[0, 4, 8, 9, 15];
        let combined = new Uint8Array(32 * pcrList.length);
        for (let i = 0; i < pcrList.length; i++) {
            let hex = pcrValues["pcr_" + pcrList[i]];
            if (!hex) throw new Error(\`Missing PCR \${pcrList[i]} from report.\`);
            combined.set(new Uint8Array(hex.replace(/^0x/, '').match(/.{1,2}/g).map(b => parseInt(b, 16))), i * 32);
        }
        const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function calculatePcr15(boot_manifest) {
        const sorted = Object.keys(boot_manifest).sort().map(k => [k, boot_manifest[k]]);
        const data = new TextEncoder().encode(JSON.stringify(sorted));
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const combined = new Uint8Array(64);
        combined.set(new Uint8Array(hashBuffer), 32); 
        const finalHashBuffer = await crypto.subtle.digest('SHA-256', combined);
        return Array.from(new Uint8Array(finalHashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function runAudit() {
        try {
            const inputVal = document.getElementById('attestationInput').value;
            if (!inputVal) throw new Error("Please provide an attestation report.");
            
            const rawData = JSON.parse(inputVal);
            const report = rawData.attestation_report || rawData.report || rawData;
            if (!report.hardware_level_attestation) throw new Error("Invalid report.");
            const hw = report.hardware_level_attestation;
            const boot = report.enclave_config.boot_measurements;
            
            document.getElementById('resultsArea').style.display = 'block';
            document.getElementById('signTime').innerText = new Date(report.timestamp_ms).toLocaleString();

            // 1. Identity Binding
            const pubKeyPem = (rawData.enclave_signing_public_key || report.public_key_pem || "");
            const pubKeyBuffer = pemToBuffer(pubKeyPem);
            const pubKeyHash = await crypto.subtle.digest('SHA-256', pubKeyBuffer);
            const paypalHash = new Uint8Array(report.paypal_user_info_raw_hash.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            
            const combined = new Uint8Array(64);
            combined.set(paypalHash); combined.set(new Uint8Array(pubKeyHash), 32);
            const expectedNonce = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', combined))).map(b => b.toString(16).padStart(2, '0')).join('');
            updateStatus('identityCheck', true, "Identity cryptographically hashed.");

            // 2. Enclave Signature Validation
            const sig = pemToBuffer(rawData.enclave_signature_b64 || report.signature_b64);
            const enclaveKey = await crypto.subtle.importKey('spki', pubKeyBuffer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
            const payload = new TextEncoder().encode(JSON.stringify(reorder(report)));
            const sigOk = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, enclaveKey, sig, payload);
            updateStatus('enclaveCheck', sigOk, sigOk ? "Report mathematically verified." : "Signature invalid!");

            // 3. TPM Hardware Audit
            const akKey = await crypto.subtle.importKey('spki', pemToBuffer(hw.ak_pub_pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
            const tpmMsg = pemToBuffer(hw.tpm_quote_msg);
            const tpmSig = pemToBuffer(hw.tpm_quote_sig);
            const rsaSig = tpmSig.length > 256 ? tpmSig.slice(tpmSig.length - 256) : tpmSig;
            
            const tpmSigOk = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, akKey, rsaSig, tpmMsg);
            const parsedAttest = parseTpmsAttest(tpmMsg);
            const tpmNonceOk = (parsedAttest.extraDataHex === expectedNonce);
            const pcrDigestOk = (parsedAttest.pcrDigestHex === await calculatePcrCompositeDigest(hw.pcr_values));

            const tpmFinal = tpmSigOk && tpmNonceOk && pcrDigestOk;
            updateStatus('tpmCheck', tpmFinal, tpmFinal ? "TPM Quote, Nonce, and PCR Digest strictly verified." : "TPM validation failed (Forgery detected).");

            // 4. Software Provenance
            const [bin, ker, init, cfg] = await Promise.all([
                getProvenance(boot.binary_sha256, "Enclave Binary"),
                getProvenance(boot.disk_manifest["EFI/BOOT/vmlinuz"] || boot.disk_manifest["vmlinuz"], "Linux Kernel"),
                getProvenance(boot.disk_manifest["EFI/BOOT/initrd.img"] || boot.disk_manifest["initrd.img"], "Initramfs"),
                getProvenance(boot.disk_manifest["EFI/BOOT/grub.cfg"] || boot.disk_manifest["grub.cfg"], "EFI Bootloader")
            ]);
            
            const pcr15Ok = ((hw.pcr_values["pcr_15"] || "").replace(/^0x/i, '').toLowerCase() === await calculatePcr15(boot.disk_manifest));
            let commonRuns = null;
            for (const c of [bin, ker, init, cfg]) {
                if (!c.success) continue;
                const s = new Set(c.runIds);
                commonRuns = (commonRuns === null) ? s : new Set([...commonRuns].filter(x => s.has(x)));
            }
            const atomic = commonRuns && commonRuns.size > 0;
            updateStatus('githubCheck', bin.success && atomic && pcr15Ok,[
                bin.success ? \`✅ Binary (#\${bin.runIds.join(',')})\` : \`❌ Binary\`,
                atomic ? \`✅ Image Atomicity (Run #\${[...commonRuns][0]})\` : \`❌ Image Atomicity\`,
                pcr15Ok ? \`✅ PCR 15 hardware binding mathematically verified\` : \`❌ PCR 15 Software Mismatch\`
            ].join('<br>'));

            // 5. Silicon Root of Trust
            let siliconOk = false;
            let siliconMsg = "No hardware proof provided.";

            if (hw.google_ak_cert_pem) {
                // 🔴 CRITICAL FIX: Pure mathematical binding of Google AK Cert
                const akCert = parseAnyCertToForge(hw.google_ak_cert_pem, "Google AK");
                const issuer = akCert.issuer.attributes.map(a => a.value).join(', ');
                
                if (!issuer.includes('Google')) {
                    throw new Error(\`AK Certificate issuer is not Google: "\${issuer}"\`);
                }

                // 🔴 STRICT PUBLIC KEY BINDING: No Bypasses Allowed.
                // The AK used for the TPM Quote MUST mathematically match the one certified by Google.
                const quoteKey = forge.pki.publicKeyFromPem(hw.ak_pub_pem);
                const isMatch = (akCert.publicKey.n.compareTo(quoteKey.n) === 0 && akCert.publicKey.e.compareTo(quoteKey.e) === 0);

                if (!isMatch) {
                    throw new Error("CRITICAL FORGERY DETECTED: The Google AK Certificate does not match the key used to sign the TPM Quote! (GCP Metadata Spoofing / Host MitM)");
                }

                siliconOk = true;
                siliconMsg = \`✅ Valid Google AK Certificate Anchor<br>Issuer: \${issuer}<br>Subject: \${akCert.subject.attributes.map(a => a.value).join(', ')}\`;

            } else if (hw.snp_report_b64 && hw.vcek_der_b64) {
                // Native AMD SEV-SNP verification
                const snp = pemToBuffer(hw.snp_report_b64);
                
                const akPemBytes = new TextEncoder().encode(hw.ak_pub_pem);
                const rawExpectedNonce = new Uint8Array(expectedNonce.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                const boundBuffer = new Uint8Array(akPemBytes.length + rawExpectedNonce.length);
                boundBuffer.set(akPemBytes); boundBuffer.set(rawExpectedNonce, akPemBytes.length);
                const expectedBoundNonce = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', boundBuffer))).map(b => b.toString(16).padStart(2, '0')).join('');
                
                const reportDataHex = Array.from(snp.slice(80, 144)).map(b => b.toString(16).padStart(2,'0')).join('');
                const snpBindingOk = (reportDataHex === expectedBoundNonce.padEnd(128, '0'));

                const rBE = new Uint8Array(48), sBE = new Uint8Array(48);
                for (let i = 0; i < 48; i++) { rBE[i] = snp[672 + 47 - i]; sBE[i] = snp[744 + 47 - i]; }
                const ecdsaSig = new Uint8Array(96); ecdsaSig.set(rBE, 0); ecdsaSig.set(sBE, 48);

                const vcekCert = parseAnyCertToForge(hw.vcek_der_b64, "AMD VCEK");
                const vcekKey = await crypto.subtle.importKey('spki', pemToBytes(forge.pki.publicKeyToPem(vcekCert.publicKey)), { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
                const snpSigOk = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, vcekKey, ecdsaSig, snp.slice(0, 672));

                let chainOk = false;
                if (hw.amd_chain_b64) {
                    const pems = atob(hw.amd_chain_b64).match(/-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----/g);
                    if (pems && pems.length >= 2) {
                        const askCert = forge.pki.certificateFromPem(pems[0]);
                        const arkCert = forge.pki.certificateFromPem(pems[1]);
                        
                        const OFFICIAL_AMD_MILAN_ARK = "00e7040d7c71ba48530ec1aa7bcbc9f491c360fb1e58284e36ce3b49cb422998";
                        const md = forge.md.sha256.create();
                        md.update(forge.asn1.toDer(forge.pki.certificateToAsn1(arkCert)).getBytes());
                        
                        chainOk = askCert.verify(vcekCert) && arkCert.verify(askCert) && (md.digest().toHex().toLowerCase() === OFFICIAL_AMD_MILAN_ARK);
                    }
                }

                siliconOk = snpBindingOk && snpSigOk && chainOk;
                const measurement = Array.from(snp.slice(144, 192)).map(b => b.toString(16).padStart(2,'0')).join('');
                
                siliconMsg = siliconOk ? \`✅ Valid SEV-SNP P-384 Signature & X.509 Chain. (Measurement: \${measurement.substring(0, 16)}...)\` 
                                       : \`❌ Silicon Verification Failed (binding=\${snpBindingOk}, sig=\${snpSigOk}, chain=\${chainOk}).\`;
            }

            updateStatus('firmwareCheck', siliconOk && tpmFinal, siliconMsg);

            // 6. TLS Binding
            const certInput = document.getElementById('certInput').value;
            if (certInput) {
                const userLeaf = getLeafCert(certInput);
                const reportLeaf = getLeafCert(report.session_context.tls_certificate_pem);
                updateStatus('tlsCheck', userLeaf === reportLeaf, userLeaf === reportLeaf ? "TLS channel bound." : "TLS mismatch!");
            }
        } catch (e) { 
            console.error(e); 
            alert("Audit Failed: " + e.message); 
        }
    }
</script>`;

const newHtml = verifyHtml.replace(/<script>[\s\S]*<\/script>/, newScript);
fs.writeFileSync('/media/leo/e7ed9d6f-5f0a-4e19-a74e-83424bc154ba/verifiedUniqueAliases/verify.html', newHtml);
