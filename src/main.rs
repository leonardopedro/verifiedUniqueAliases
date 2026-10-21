//! PayPal OAuth Confidential Enclave (Intel TDX / Alibaba Cloud)
//!
//! Hardened Zero-Trust Implementation against Colluding Owner & Cloud Provider

mod intel_tdx;

const GOOGLE_CA_PEM: &[u8] = include_bytes!("google_ca.pem");
const PAYPAL_CA_PEM: &[u8] = include_bytes!("paypal.pem");

mod enclave_init {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::Ipv4Addr;
    use std::os::unix::io::AsRawFd;

    pub fn kmsg(msg: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            use std::io::Write;
            let _ = writeln!(f, "<14>[INIT] {}", msg);
        }
        eprintln!("[INIT] {}", msg);
    }

    pub fn load_drivers() {
        let _ = std::process::Command::new("/bin/mount").args(["-t", "proc", "none", "/proc"]).status();
        let _ = std::process::Command::new("/bin/mount").args(["-t", "sysfs", "none", "/sys"]).status();
        let _ = std::process::Command::new("/bin/mount").args(["-t", "configfs", "none", "/sys/kernel/config"]).status();

        insmod_all();

        #[cfg(feature = "alibabacloud")]
        {
            let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "intelpsfw"]).status();
            modprobe("configfs");
            let _ = std::process::Command::new("/bin/mount").args(["-t", "configfs", "none", "/sys/kernel/config"]).status();
            modprobe("virt_anchor");
            modprobe("coco");
            modprobe("tsm");
            modprobe("tdx-guest");
            modprobe("tdx_guest");
            let _ = std::process::Command::new("/bin/mount").args(["-t", "configfs", "none", "/sys/kernel/config"]).status();
        }

        modprobe("virtio_net");
        modprobe("virtio_scsi");
        modprobe("virtio_blk");
        modprobe("virtio_pci");
        modprobe("nvme");
        modprobe("nvme_core");
        modprobe("tpm_tis");
        modprobe("tpm_crb");
        modprobe("vfat");
        modprobe("nls_cp437");
        modprobe("nls_ascii");
        modprobe("nf_conntrack");
        modprobe("nft_ct");
        modprobe("nf_tables");
        modprobe("nft_chain_filter");
        modprobe("nft_reject_ipv4");
        modprobe("nft_limit");
    }

    pub fn setup_firewall() {
        kmsg("Initializing hardened egress firewall (nftables)...");
        let commands = [
            "flush ruleset",
            "add table inet filter",
            "add chain inet filter input { type filter hook input priority 0; policy drop; }",
            "add chain inet filter output { type filter hook output priority 0; policy drop; }",
            "add chain inet filter forward { type filter hook forward priority 0; policy drop; }",
            "add rule inet filter input iif lo accept",
            "add rule inet filter output oif lo accept",
            "add rule inet filter input ct state established,related accept",
            "add rule inet filter output ct state established,related accept",
            "add rule inet filter input udp dport 68 accept",
            "add rule inet filter output udp dport 67 accept",
            "add rule inet filter input tcp dport { 80, 443 } accept",
            "add rule inet filter output udp dport 53 accept",
            "add rule inet filter output tcp dport 53 accept",
            "add rule inet filter output ip daddr 169.254.169.254 accept",
            "add rule inet filter output ip daddr 100.100.100.200 accept",
            "add rule inet filter output tcp dport 443 accept",
            "add rule inet filter output tcp dport 80 accept",
        ];

        for cmd in commands {
            match std::process::Command::new("/usr/sbin/nft").arg(cmd).status() {
                Ok(s) if s.success() => {}
                _ => {
                    kmsg(&format!("FATAL: Failed to execute nft command '{}' — halting", cmd));
                    poweroff();
                }
            }
        }
    }

    pub fn mount_filesystems() {
        fn mount_fs(source: &str, target: &str, fstype: &str) {
            std::fs::create_dir_all(target).ok();
            let src = std::ffi::CString::new(source).unwrap();
            let tgt = std::ffi::CString::new(target).unwrap();
            let fst = std::ffi::CString::new(fstype).unwrap();
            let _ = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, std::ptr::null()) };
        }
        mount_fs("devtmpfs", "/dev", "devtmpfs");
        kmsg("--- PAYPAL ENCLAVE NATIVE RUST BOOT ---");
        mount_fs("proc", "/proc", "proc");
        mount_fs("sysfs", "/sys", "sysfs");
        mount_fs("tmpfs", "/tmp", "tmpfs");
        mount_fs("tmpfs", "/run", "tmpfs");
        modprobe("configfs");
        mount_fs("configfs", "/sys/kernel/config", "configfs");
        std::fs::create_dir_all("/dev/pts").ok();
        std::fs::create_dir_all("/boot/efi").ok();
        mount_fs("/dev/sda1", "/boot/efi", "vfat");
        mount_fs("/dev/vda1", "/boot/efi", "vfat");
    }

    pub fn measure_boot_components() -> std::collections::BTreeMap<String, String> {
        use sha2::{Digest, Sha256};
        let mut manifest = std::collections::BTreeMap::new();
        let mount_point = "/tmp/esp";
        let _ = std::fs::create_dir_all(mount_point);

        fn mount_device(source: &str, target: &str) -> bool {
            let src = std::ffi::CString::new(source).unwrap();
            let tgt = std::ffi::CString::new(target).unwrap();
            let fst = std::ffi::CString::new("vfat").unwrap();
            unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), libc::MS_RDONLY, std::ptr::null()) == 0 }
        }

        if let Ok(entries) = std::fs::read_dir("/sys/class/block") {
            let mut candidates: Vec<String> = entries.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.chars().any(|c| c.is_ascii_digit()))
                .collect();
            candidates.sort();

            for dev_name in candidates {
                let dev_path = format!("/dev/{}", dev_name);
                if mount_device(&dev_path, mount_point) {
                    break;
                }
            }
        }

        fn hash_recursive(dir: &str, root: &str, m: &mut std::collections::BTreeMap<String, String>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let path_str = path.to_string_lossy();
                    if path.is_dir() {
                        hash_recursive(&path_str, root, m);
                    } else if path.is_file() {
                        if let Ok(mut f) = std::fs::File::open(&path) {
                            let mut hasher = Sha256::new();
                            if std::io::copy(&mut f, &mut hasher).is_ok() {
                                let key = path_str.strip_prefix(root).unwrap_or(&path_str).trim_start_matches('/').to_string();
                                m.insert(key, hex::encode(hasher.finalize()));
                            }
                        }
                    }
                }
            }
        }
        hash_recursive(mount_point, mount_point, &mut manifest);
        let tgt = std::ffi::CString::new(mount_point).unwrap();
        unsafe { libc::umount(tgt.as_ptr()); }
        manifest
    }

    fn insmod_all() {
        let paths = ["/sbin/find", "/usr/bin/find", "/bin/find", "find"];
        for path in &paths {
            if let Ok(output) = std::process::Command::new(path).args(["/lib/modules", "-name", "*.ko"]).output() {
                let s = String::from_utf8_lossy(&output.stdout);
                for line in s.lines() {
                    if line.contains("tsm") || line.contains("sev") || line.contains("coco") || line.contains("virtio") || line.contains("tdx") {
                        let _ = std::process::Command::new("/sbin/insmod").arg(line).status();
                    }
                }
                break;
            }
        }
    }

    fn modprobe(module: &str) {
        let paths = ["/sbin/modprobe", "/usr/sbin/modprobe", "/bin/modprobe", "modprobe"];
        for path in &paths {
            if let Ok(s) = std::process::Command::new(path).arg("-q").arg(module).status() {
                if s.success() { break; }
            }
        }
    }

    fn find_interface() -> Option<String> {
        std::fs::read_dir("/sys/class/net").ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .find(|n| n != "lo" && n != "dummy0")
    }

    fn read_mac(iface: &str) -> [u8; 6] {
        let s = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface)).unwrap_or_default();
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
        p[236] = 99; p[237] = 130; p[238] = 83; p[239] = 99;
        p.extend_from_slice(&[53, 1, msg_type]);
        if let Some(ip) = req_ip {
            p.extend_from_slice(&[50, 4]);
            p.extend_from_slice(&ip.octets());
        }
        p.extend_from_slice(&[55, 3, 1, 3, 6]);
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
                        1 if len == 4 => mask = Ipv4Addr::new(v[0], v[1], v[2], v[3]),
                        3 if len >= 4 => gw = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
                        6 => for c in v.chunks(4) { if c.len() == 4 { dns.push(Ipv4Addr::new(c[0], c[1], c[2], c[3])); } },
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
        let iface = {
            let mut found = None;
            for _ in 0..60 {
                if let Some(i) = find_interface() { found = Some(i); break; }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            found.ok_or("No network interface after 30s")?
        };
        let _ = std::process::Command::new("/sbin/ip").args(["link", "set", &iface, "up"]).status();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_broadcast(true)?;
        let ifname = std::ffi::CString::new(iface.as_str())?;
        unsafe {
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
        let mac = read_mac(&iface);
        let xid: u32 = 0xC0FFEE42;

        sock.send_to(&build_dhcp(xid, &mac, 1, None), &bc.into())?;
        let mut buf = [std::mem::MaybeUninit::uninit(); 1024];
        let (n, _) = sock.recv_from(&mut buf)?;
        let mut recv_buf = [0u8; 1024];
        for i in 0..n { recv_buf[i] = unsafe { buf[i].assume_init() }; }
        let offered = Ipv4Addr::new(recv_buf[16], recv_buf[17], recv_buf[18], recv_buf[19]);

        sock.send_to(&build_dhcp(xid, &mac, 3, Some(offered)), &bc.into())?;
        let (n, _) = sock.recv_from(&mut buf)?;
        for i in 0..n { recv_buf[i] = unsafe { buf[i].assume_init() }; }
        let lease = parse_lease(&recv_buf[..n]).ok_or("Bad DHCP ACK")?;

        let cidr = format!("{}/{}", lease.ip, lease.prefix);
        let _ = std::process::Command::new("/sbin/ip").args(["addr", "add", &cidr, "dev", &iface]).status();
        if let Some(gw) = lease.gw {
            let _ = std::process::Command::new("/sbin/ip").args(["route", "add", "default", "via", &gw.to_string()]).status();
        }
        if !lease.dns.is_empty() {
            let resolv: String = lease.dns.iter().map(|ip| format!("nameserver {}\n", ip)).collect();
            std::fs::write("/etc/resolv.conf", resolv).ok();
        }
        let _ = std::process::Command::new("/bin/date").args(["-s", "@1777000000"]).status();

        let time_sources = ["https://www.cloudflare.com", "https://www.aliyun.com"];
        for src in &time_sources {
            if let Ok(out) = std::process::Command::new("/usr/bin/curl").args(["-sI", "--max-time", "5", src]).output() {
                let headers = String::from_utf8_lossy(&out.stdout);
                for line in headers.lines() {
                    if line.to_lowercase().starts_with("date:") {
                        let date = line[5..].trim();
                        let _ = std::process::Command::new("/bin/date").args(["-s", date]).status();
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn poweroff() -> ! {
        loop { std::thread::sleep(std::time::Duration::from_secs(60)); }
    }
}

// ============================================================================
// NON-BLOCKING LOG SINK (ported: the plan's info!/warn!/error! calls need a
// subscriber; tracing must never write to the serial console tty — see the
// original kmsg_log rationale in git history).
// ============================================================================
mod kmsg_log {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::OnceLock;

    fn kmsg_fd() -> Option<&'static std::fs::File> {
        static FD: OnceLock<Option<std::fs::File>> = OnceLock::new();
        FD.get_or_init(|| {
            std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open("/dev/kmsg")
                .ok()
        })
        .as_ref()
    }

    /// Write one line to the kernel log, never blocking. A line the ring
    /// buffer can't take right now is dropped — losing a log beats wedging
    /// the enclave. Embedded newlines are flattened: /dev/kmsg rejects
    /// multi-line writes.
    pub fn line(msg: &str) {
        let Some(fd) = kmsg_fd() else { return };
        let flat = msg.replace('\n', " | ");
        // <6> = KERN_INFO. Console echo is chosen by the kernel's console
        // loglevel, not by this write, so this cannot block on the UART.
        let mut buf = format!("<6>[paypal-auth] {}\n", flat);
        let _ = (&*fd).write(buf.as_bytes());
        buf.clear();
    }

    pub fn critical(msg: &str) {
        let Some(fd) = kmsg_fd() else { return };
        let flat = msg.replace('\n', " | ");
        let buf = format!("<2>[paypal-auth] CRITICAL: {}\n", flat);
        let _ = (&*fd).write(buf.as_bytes());
    }

    /// tracing_subscriber writer: accumulates one event, flushes to kmsg on
    /// completion (and on Drop), never touching the console tty.
    pub struct KmsgLineWriter {
        buf: Vec<u8>,
    }

    impl Write for KmsgLineWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(data);
            if self.buf.last() == Some(&b'\n') {
                self.flush_line();
            }
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_line();
            Ok(())
        }
    }

    impl Drop for KmsgLineWriter {
        fn drop(&mut self) {
            self.flush_line();
        }
    }

    impl KmsgLineWriter {
        fn flush_line(&mut self) {
            if self.buf.is_empty() {
                return;
            }
            let text = String::from_utf8_lossy(&self.buf).trim_end_matches('\n').to_string();
            self.buf.clear();
            line(&text);
        }
    }

    #[derive(Clone, Copy)]
    pub struct KmsgMakeWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for KmsgMakeWriter {
        type Writer = KmsgLineWriter;
        fn make_writer(&'a self) -> Self::Writer {
            KmsgLineWriter { buf: Vec::with_capacity(256) }
        }
    }
}

/// Run a synchronous subprocess with a hard wall-clock timeout.
///
/// (Ported: required by src/intel_tdx.rs via `crate::cmd_output_timeout`.)
/// `std::process::Child::wait` has no deadline of its own, so a hung child
/// (wedged TPM device, blocked kernel log, full pipe) would otherwise park the
/// calling thread forever — in an async handler that stalls a tokio worker.
/// On timeout the child is SIGKILLed and `None` is returned.
pub fn cmd_output_timeout(
    cmd: &str,
    args: &[&str],
    envs: &[(String, String)],
    timeout: std::time::Duration,
) -> Option<std::process::Output> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    let mut command = Command::new(cmd);
    command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in envs {
        command.env(k, v);
    }
    let mut child = command.spawn().ok()?;
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None; // timed out — never leave a zombie or a stuck thread
            }
        }
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut so) = child.stdout.take() { let _ = so.read_to_end(&mut stdout); }
    if let Some(mut se) = child.stderr.take() { let _ = se.read_to_end(&mut stderr); }
    let _ = child.wait();
    Some(std::process::Output { status, stdout, stderr })
}

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use openssl::ssl::{SslAcceptor, SslMethod};
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

// ----------------------------------------------------------------------------
// Ephemeral Cryptographic Identity in RAM (Never Logged / Never Persisted)
// ----------------------------------------------------------------------------
#[derive(Clone)]
pub struct EphemeralEnclaveIdentity {
    pub pkey: Arc<openssl::pkey::PKey<openssl::pkey::Private>>,
    pub pubkey_der: Vec<u8>,
    pub pubkey_pem: String,
    pub pubkey_sha256: [u8; 32],
}

impl EphemeralEnclaveIdentity {
    pub fn generate() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use sha2::{Digest, Sha256};
        let rsa = openssl::rsa::Rsa::generate(4096)?;
        let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
        let pubkey_der = pkey.public_key_to_der()?;
        let pubkey_pem = String::from_utf8(pkey.public_key_to_pem()?)?;
        let pubkey_sha256 = Sha256::digest(&pubkey_der).into();
        Ok(Self {
            pkey: Arc::new(pkey),
            pubkey_der,
            pubkey_pem,
            pubkey_sha256,
        })
    }
}

// ----------------------------------------------------------------------------
// Ephemeral In-RAM PKCE Session (Client-Bound)
// ----------------------------------------------------------------------------
pub struct PkceSession {
    pub code_verifier: String,
    pub code_challenge: String,
    pub client_ecdh_pub: Vec<u8>,
    pub client_nonce: [u8; 32],
    pub enclave_ecdh: openssl::pkey::PKey<openssl::pkey::Private>,
    // The user's custom_info chosen at pre-flight; the login (callback) report
    // binds it into the SEC-02 nonce so it matches the pre-flight binding.
    pub custom_info: String,
    pub created_at: Instant,
}

impl PkceSession {
    pub fn new(client_ecdh_pub: Vec<u8>, client_nonce: [u8; 32], custom_info: String) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use base64::Engine as _;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use rand::Rng;
        use sha2::{Digest, Sha256};

        let mut verifier_bytes = [0u8; 64];
        rand::thread_rng().fill(&mut verifier_bytes);
        let code_verifier = B64URL.encode(verifier_bytes);

        let challenge_hash = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = B64URL.encode(challenge_hash);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let enclave_ecdh = openssl::pkey::PKey::from_ec_key(ec_key)?;

        Ok(Self {
            code_verifier,
            code_challenge,
            client_ecdh_pub,
            client_nonce,
            enclave_ecdh,
            custom_info,
            created_at: Instant::now(),
        })
    }
}

// ----------------------------------------------------------------------------
// In-Memory End-to-End Cryptography Engine (Zero Plaintext Leakage)
// ----------------------------------------------------------------------------
mod crypto_e2ee {
    use super::*;
    use aes_gcm::{aead::{Aead, AeadCore, KeyInit, Payload}, Aes256Gcm, Key, Nonce};
    use openssl::derive::Deriver;
    use openssl::pkey::PKey;

    pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
        use openssl::sign::Signer;
        fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
            let k = PKey::hmac(key).expect("HMAC key");
            let mut s = Signer::new(openssl::hash::MessageDigest::sha256(), &k).expect("HMAC signer");
            s.update(data).expect("HMAC update");
            s.sign_to_vec().expect("HMAC sign")
        }
        let prk = hmac(salt, ikm);
        let mut t: Vec<u8> = Vec::new();
        let mut okm: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        while okm.len() < out.len() {
            let mut msg = t.clone();
            msg.extend_from_slice(info);
            msg.push(counter);
            t = hmac(&prk, &msg);
            okm.extend_from_slice(&t);
            counter = counter.wrapping_add(1).max(1);
        }
        let n = out.len().min(okm.len());
        out[..n].copy_from_slice(&okm[..n]);
    }

    pub fn derive_session_key(
        enclave_ecdh: &PKey<openssl::pkey::Private>,
        client_pub_der: &[u8],
        client_nonce: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let peer = PKey::public_key_from_der(client_pub_der)?;
        let mut deriver = Deriver::new(enclave_ecdh)?;
        deriver.set_peer(&peer)?;
        let mut ikm = deriver.derive_to_vec()?;

        let mut key = [0u8; 32];
        hkdf_sha256(&ikm, client_nonce, b"paypal-auth-vm/e2ee/v1", &mut key);
        ikm.iter_mut().for_each(|b| *b = 0);
        Ok(key)
    }

    pub fn encrypt_envelope(
        key_bytes: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|e| format!("AES-GCM encryption failed: {:?}", e))?;
        Ok((nonce.to_vec(), ciphertext))
    }
}

// ----------------------------------------------------------------------------
// Client-Bound Hardware Attestation Binding Formula
// ----------------------------------------------------------------------------
pub fn compute_preflight_binding(
    pubkey_der: &[u8],
    code_challenge: &str,
    client_pub_der: &[u8],
    client_nonce: &[u8; 32],
    custom_info: &str,
) -> [u8; 64] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey_der);
    hasher.update(code_challenge.as_bytes());
    hasher.update(client_pub_der);
    hasher.update(client_nonce);
    hasher.update(custom_info.as_bytes());
    let digest = hasher.finalize();

    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&digest);
    report_data
}

// ----------------------------------------------------------------------------
// SEC-02 / verify.html v160 — 5-component hardware-bound session nonce
// ----------------------------------------------------------------------------
// nonce = SHA-256 over the 160-byte concatenation:
//   [0..32]    sha256(compact sorted PayPal userinfo JSON)   (pre-login: published placeholder)
//   [32..64]   sha256(enclave signing pubkey SPKI DER)
//   [64..96]   sha256(custom_info; "NONE" when absent/empty)
//   [96..128]  boot_measurements.binary_sha256 (self-measure of /init)
//   [128..160] sha256(canonical compact JSON of sorted [path, sha256] manifest pairs)
// The TDX quote's report_data[0..32] (and the TPM quote's extraData) MUST
// equal this digest or the auditor fails the binding check. Byte-for-byte the
// same formula verify.html recomputes as `expectedNonce`.
fn sec02_nonce(
    paypal_user_raw_hash: &str,
    pubkey_der: &[u8],
    custom_info: &str,
    binary_sha256_hex: &str,
    manifest: &std::collections::BTreeMap<String, String>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let paypal = hex::decode(paypal_user_raw_hash.trim()).unwrap_or_default();
    let pubkey_hash = Sha256::digest(pubkey_der);
    let ci = if custom_info.trim().is_empty() { "NONE" } else { custom_info };
    let ci_hash = Sha256::digest(ci.as_bytes());
    let binary = hex::decode(binary_sha256_hex.trim()).unwrap_or_default();
    // Canonical manifest: sorted [path, sha256] pairs, compact JSON — must be
    // byte-identical to verify.html's `JSON.stringify(sorted.map(k=>[k,m[k]]))`.
    // BTreeMap iterates in sorted key order; serde_json emits compact arrays.
    let pairs: Vec<(&String, &String)> = manifest.iter().collect();
    let manifest_json = serde_json::to_string(&pairs).unwrap_or_default();
    let manifest_hash = Sha256::digest(manifest_json.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&paypal);
    hasher.update(&pubkey_hash);
    hasher.update(&ci_hash);
    hasher.update(&binary);
    hasher.update(&manifest_hash);
    hasher.finalize().into()
}

// Pre-login placeholder for paypal_user_info_raw_hash: there is no PayPal user
// yet when the standalone /debug/envelope or the pre-flight POST is generated.
// The auditor recomputes expectedNonce from whatever value we publish here, so
// any deterministic placeholder keeps the binding self-consistent; the real
// user hash is bound only at the login (callback) step. Self-documenting marker.
fn prelogin_paypal_hash() -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b"PRELOGIN_NO_USER"))
}

// Sign the canonical (sorted-key) JSON of an attestation_report with the
// enclave's ephemeral RSA key. serde_json's Map is a BTreeMap (sorted), so
// to_string() is byte-identical to verify.html's JSON.stringify(reorder(...)).
fn sign_report(state: &AppState, report: &serde_json::Value) -> String {
    use base64::engine::general_purpose::STANDARD as B64STD;
    use base64::Engine as _;
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;
    let report_str = serde_json::to_string(report).unwrap_or_default();
    let mut signer = Signer::new(MessageDigest::sha256(), &state.enclave_identity.pkey).unwrap();
    signer.update(report_str.as_bytes()).unwrap();
    B64STD.encode(signer.sign_to_vec().unwrap())
}

// ----------------------------------------------------------------------------
// TPM & Hardware Silicon Module
// ----------------------------------------------------------------------------
mod tpm {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Serialize};

    pub const PCR_SELECTION: &str = "0,4,8,9,15";

    #[derive(Serialize, Deserialize, Clone)]
    pub struct AttestationResult {
        pub tpm_quote_msg: String,
        pub tpm_quote_sig: String,
        pub ak_pub_pem: String,
        pub ek_cert: Option<String>,
        pub pcrs: String,
        pub pcr_values: std::collections::BTreeMap<String, String>,
        pub nonce_hex: String,
        pub snp_report_b64: Option<String>,
        pub auxblob_b64: Option<String>,
        pub signature_binding_pubkey_hash: String,
        pub vcek_der_b64: Option<String>,
        pub amd_chain_b64: Option<String>,
        pub google_ak_cert_pem: Option<String>,
        pub ak_der_sha256: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pck_cert_pem: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tdx_policy: Option<String>,
        pub platform_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub td_info: Option<serde_json::Value>,
        pub tdx_evidence_marker: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tdx_td_report_b64: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tdx_quote_b64: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tdx_evidence_source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tdx_evidence_probe: Option<serde_json::Value>,
    }

    pub fn quote(
        nonce_hex: &str,
        report_data_override: Option<[u8; 64]>,
    ) -> AttestationResult {
        let silicon = super::intel_tdx::collect_silicon_evidence(nonce_hex, report_data_override);
        let quote_present = silicon.quote_b64.is_some();
        let report_present = silicon.td_report_b64.is_some();

        let marker = serde_json::json!({
            "platform_type": "Intel TDX",
            "hardware_signed_tdx_quote": quote_present,
            "tdx_quote_status": if quote_present { "ok" } else { "unavailable_no_guest_device" },
            "tdx_td_report_present": report_present,
            "tdx_quote_source": silicon.quote_source.clone().unwrap_or_default(),
            "tdx_td_report_source": silicon.td_report_source.clone().unwrap_or_default(),
        });

        // Serialize while `silicon` is still fully owned (the struct below
        // moves individual fields out of it).
        let silicon_probe = serde_json::to_value(&silicon).unwrap_or_default();

        AttestationResult {
            tpm_quote_msg: String::new(),
            tpm_quote_sig: String::new(),
            ak_pub_pem: String::new(),
            ek_cert: None,
            pcrs: String::new(),
            pcr_values: std::collections::BTreeMap::new(),
            nonce_hex: nonce_hex.to_string(),
            snp_report_b64: None,
            auxblob_b64: None,
            signature_binding_pubkey_hash: String::new(),
            vcek_der_b64: None,
            amd_chain_b64: None,
            google_ak_cert_pem: None,
            ak_der_sha256: String::new(),
            pck_cert_pem: None,
            tdx_policy: None,
            platform_type: "Intel TDX".to_string(),
            td_info: None,
            tdx_evidence_marker: marker,
            tdx_td_report_b64: silicon.td_report_b64,
            tdx_quote_b64: silicon.quote_b64,
            tdx_evidence_source: silicon.quote_source,
            tdx_evidence_probe: Some(silicon_probe),
        }
    }
}

const MAX_TRACKED_IPS: usize = 1000;
const MAX_CONCURRENT_CONNECTIONS: usize = 50;
const GLOBAL_EGRESS_BYTES_PER_HOUR: u64 = 512 * 1024 * 1024;
const IP_EGRESS_BYTES_PER_HOUR: u64 = 25 * 1024 * 1024;
const ZEROSSL_CA_DIRECTORY: &str = "https://acme.zerossl.com/v2/DV90";
const LETSENCRYPT_CA_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

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
        .info p { margin: 10px 0; }
        .container { border: 2px solid #0070ba; padding: 30px; border-radius: 10px; background: #1a1a1a; }
        .btn { background: #0070ba; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-size: 16px; border: none; cursor: pointer; }
        .info { background: #2a2a2a; padding: 15px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #0070ba; }
        h1 { color: #0070ba; } h3 { color: #64b5f6; }
    </style>
</head>
<body><div class="container">{{CONTENT}}</div></body></html>
"#;

// The post-login success page. SECURITY (v164): this page performs NO crypto
// and renders NO plaintext — it hands the LOGIN-BOUND encrypted blob to the
// visitor's browser tab (sessionStorage on this origin); verify.html (same
// origin) then decrypts it fail-closed (S_enc signature + pre-flight P_enc
// pin), runs the full audit, and offers the report as a downloadable JSON the
// user can audit offline in ANY external auditor copy (GitHub Pages copy /
// saved local copy) — the copy served by this site is only a convenience.
// Abuse/DoS posture: NO new surface. Reports are ONLY minted after a completed
// PayPal code exchange (this route consumes a one-time pending_oauth state);
// nothing here generates attestations for unauthenticated callers.
const CALLBACK_CONTENT: &str = r#"<h1>Authentication Succeeded</h1>
            <div class="info">
                <h3>Hardware-Attested Delivery (Encrypted)</h3>
                <p>Your verified PayPal status has been sealed in RAM and encrypted to your local client key. This page renders nothing — decryption happens only inside your browser tab.</p>
                <p><a class="btn" href="/verify.html?afterlogin=1">💾 Get my attestation report &amp; run the audit</a></p>
                <p style="font-size:14px; color:#9e9e9e;">Your tab will decrypt the report, verify its hardware signature and pre-flight key pin, run the full audit, and save the report as a JSON file. That file audits offline in <b>any</b> copy of the auditor — the <a href="https://leonardopedro.github.io/verifiedUniqueAliases/verify.html" style="color:#64b5f6;">GitHub Pages auditor</a> or your own saved <code>verify.html</code>; the copy served by this site is only a convenience. No attestation report is ever generated without a completed PayPal login.</p>
                <p><a href="/verify.html" style="color:#64b5f6;">Open Local Auditor (report loads without auto-download)</a></p>
            </div>
            <script type="application/json" id="e2ee-blob">__E2EE_BLOB__</script>
            <script>try{sessionStorage.setItem('pav_e2ee_blob', document.getElementById('e2ee-blob').textContent);}catch(e){}</script>"#;

#[derive(Debug, Deserialize)]
struct Config {
    paypal_client_id: String,
    paypal_client_secret: String,
    #[serde(default)]
    paypal_verified_client_id: Option<String>,
    #[serde(default)]
    paypal_verified_client_secret: Option<String>,
    domain: String,
    eab_key_id: Option<String>,
    eab_hmac_key: Option<String>,
    #[serde(default)]
    staging: bool,
    #[serde(default, alias = "dns01_secret")]
    dns_api_token: Option<String>,
    #[serde(default, alias = "dns01")]
    dns_zone: Option<String>,
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
    enclave_identity: EphemeralEnclaveIdentity,
    ip_stats: Arc<RwLock<std::collections::BTreeMap<IpAddr, u64>>>,
    global_egress_bytes: Arc<AtomicU64>,
    last_limit_reset: Arc<RwLock<Instant>>,
    connection_semaphore: Arc<Semaphore>,
    boot_manifest: BTreeMap<String, String>,
    pending_oauth: Arc<RwLock<std::collections::HashMap<String, (String, PkceSession)>>>,
    pending_e2ee_blobs: Arc<RwLock<std::collections::HashMap<String, (serde_json::Value, Instant)>>>,
}

impl AppState {
    fn get_flow_config(&self, flow_name: &str) -> (String, String, String, String) {
        if flow_name == "verified" {
            (
                self.paypal_verified_client_id.clone(),
                self.paypal_verified_client_secret.clone(),
                "https%3A%2F%2Furi.paypal.com%2Fservices%2Fpaypalattributes".to_string(),
                "verified".to_string(),
            )
        } else {
            (
                self.paypal_client_id.clone(),
                self.paypal_client_secret.clone(),
                "openid%20profile%20email%20address%20profile%20email%20https%3A%2F%2Furi.paypal.com%2Fservices%2Fpaypalattributes".to_string(),
                "full".to_string(),
            )
        }
    }

    fn record_egress(&self, ip: IpAddr, bytes: u64) -> Result<(), StatusCode> {
        let now = Instant::now();
        let mut stats = self.ip_stats.write();
        let mut reset = self.last_limit_reset.write();
        if now.duration_since(*reset) > Duration::from_secs(3600) {
            *reset = now;
            self.global_egress_bytes.store(0, Ordering::Relaxed);
            stats.clear();
        }
        let current = self.global_egress_bytes.fetch_add(bytes, Ordering::Relaxed);
        if current + bytes >= GLOBAL_EGRESS_BYTES_PER_HOUR {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let ip_bytes = stats.entry(ip).and_modify(|e| *e += bytes).or_insert(bytes);
        if *ip_bytes > IP_EGRESS_BYTES_PER_HOUR {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct PayPalUserInfo {
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    verified_account: Option<String>,
    #[serde(default)]
    payer_id: Option<String>,
}

impl PayPalUserInfo {
    fn verified_only(self) -> Self {
        PayPalUserInfo {
            user_id: self.user_id,
            sub: self.sub,
            verified_account: self.verified_account,
            payer_id: self.payer_id,
        }
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn zeroize_str(s: &mut String) {
    unsafe {
        let bytes = s.as_bytes_mut();
        for b in bytes.iter_mut() {
            *b = 0;
        }
    }
    s.clear();
}

fn hardened_client() -> reqwest::Client {
    use reqwest::Certificate;
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .use_rustls_tls()
        .resolve("api-m.paypal.com", std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 16, 124, 74)), 443))
        .resolve("api-m.sandbox.paypal.com", std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(146, 75, 123, 1)), 443));

    if let Ok(cert) = Certificate::from_pem(PAYPAL_CA_PEM) {
        builder = builder.add_root_certificate(cert);
    }
    if let Ok(cert) = Certificate::from_pem(GOOGLE_CA_PEM) {
        builder = builder.add_root_certificate(cert);
    }
    builder.build().unwrap()
}

// ----------------------------------------------------------------------------
// Fail-Closed Credential Ingestion (No Hardcoded Secrets Allowed)
// ----------------------------------------------------------------------------
fn require_credentials(config: Config) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    fn is_missing(val: &str) -> bool {
        let t = val.trim();
        t.is_empty() || t.starts_with("MISSING_") || t.starts_with("YOUR_") || t.contains("***REMOVED***")
    }

    let mut missing_fields = Vec::new();
    if is_missing(&config.paypal_client_id) { missing_fields.push("paypal_client_id"); }
    if is_missing(&config.paypal_client_secret) { missing_fields.push("paypal_client_secret"); }

    if let Some(ref v_id) = config.paypal_verified_client_id {
        if is_missing(v_id) { missing_fields.push("paypal_verified_client_id"); }
    } else {
        missing_fields.push("paypal_verified_client_id");
    }

    if let Some(ref v_sec) = config.paypal_verified_client_secret {
        if is_missing(v_sec) { missing_fields.push("paypal_verified_client_secret"); }
    } else {
        missing_fields.push("paypal_verified_client_secret");
    }

    if !missing_fields.is_empty() {
        return Err(format!(
            "FAIL-CLOSED: Missing or placeholder PayPal credentials for: {}. \
            Hardcoded credentials have been completely removed. \
            Supply real credentials via environment variables or user_data metadata.",
            missing_fields.join(", ")
        ).into());
    }

    Ok(config)
}

async fn fetch_config() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    if let (Ok(p_id), Ok(p_sec), Ok(pv_id), Ok(pv_sec), Ok(dom)) = (
        std::env::var("PAYPAL_CLIENT_ID"),
        std::env::var("PAYPAL_CLIENT_SECRET"),
        std::env::var("PAYPAL_VERIFIED_CLIENT_ID"),
        std::env::var("PAYPAL_VERIFIED_CLIENT_SECRET"),
        std::env::var("DOMAIN"),
    ) {
        return require_credentials(Config {
            paypal_client_id: p_id,
            paypal_client_secret: p_sec,
            paypal_verified_client_id: Some(pv_id),
            paypal_verified_client_secret: Some(pv_sec),
            domain: dom,
            eab_key_id: std::env::var("EAB_KEY_ID").ok(),
            eab_hmac_key: std::env::var("EAB_HMAC_KEY").ok(),
            staging: std::env::var("STAGING").map(|s| s == "true").unwrap_or(false),
            dns_api_token: std::env::var("DNS_API_TOKEN").ok(),
            dns_zone: std::env::var("DNS_ZONE").ok(),
        });
    }

    if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        if let Ok(resp) = client.get("http://100.100.100.200/latest/user-data").send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let raw = text.trim();
                    let decoded_bytes = if raw.starts_with('{') {
                        raw.as_bytes().to_vec()
                    } else {
                        use base64::Engine as _;
                        base64::engine::general_purpose::STANDARD.decode(raw).unwrap_or_default()
                    };
                    if let Ok(cfg) = serde_json::from_slice::<Config>(&decoded_bytes) {
                        return require_credentials(cfg);
                    }
                }
            }
        }
    }

    Err("Configuration unavailable. Must provide credentials via environment or user_data.".into())
}

// ----------------------------------------------------------------------------
// In-RAM Ephemeral ACME Certificate Manager (Zero Disk Writes)
// ----------------------------------------------------------------------------
struct InRamAcmeManager {
    domain: String,
    eab_key_id: Option<String>,
    eab_hmac_key: Option<String>,
    dns_api_token: Option<String>,
    dns_zone: Option<String>,
}

impl InRamAcmeManager {
    fn new(config: &Config) -> Self {
        Self {
            domain: config.domain.clone(),
            eab_key_id: config.eab_key_id.clone(),
            eab_hmac_key: config.eab_hmac_key.clone(),
            dns_api_token: config.dns_api_token.clone(),
            dns_zone: config.dns_zone.clone(),
        }
    }

    fn dns01_zone(&self) -> String {
        if let Some(ref z) = self.dns_zone {
            if !z.is_empty() { return z.clone(); }
        }
        match self.domain.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => rest.to_string(),
            _ => self.domain.clone(),
        }
    }

    async fn dns01_publish(&self, fqdn: &str, value: &str) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        let token = self.dns_api_token.as_deref().ok_or("Missing DNS API Token")?;
        let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
        let base = "https://api.cloudflare.com/client/v4";
        let zone = self.dns01_zone();

        let zone_id = if zone.len() == 32 && zone.chars().all(|c| c.is_ascii_hexdigit()) {
            zone
        } else {
            let z_resp: serde_json::Value = client.get(format!("{}/zones?name={}", base, zone))
                .bearer_auth(token).send().await?.json().await?;
            z_resp["result"][0]["id"].as_str().ok_or("Cloudflare zone not found")?.to_string()
        };

        let body = serde_json::json!({ "type": "TXT", "name": fqdn, "content": value, "ttl": 60 });
        let create_resp: serde_json::Value = client.post(format!("{}/zones/{}/dns_records", base, zone_id))
            .bearer_auth(token).json(&body).send().await?.json().await?;
        let record_id = create_resp["result"]["id"].as_str().ok_or("Failed to create TXT record")?.to_string();

        tokio::time::sleep(Duration::from_secs(15)).await;
        Ok((zone_id, record_id))
    }

    async fn dns01_cleanup(&self, zone_id: &str, record_id: &str) {
        if let Some(ref token) = self.dns_api_token {
            let client = reqwest::Client::new();
            let _ = client.delete(format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone_id, record_id))
                .bearer_auth(token).send().await;
        }
    }

    /// Obtains an ACME certificate in RAM without saving private keys to disk
    async fn obtain_certificate_in_ram(
        &self,
        ephemeral_tls_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use acme2_eab::{AccountBuilder, AuthorizationStatus, Csr, DirectoryBuilder, OrderBuilder};
        use base64::Engine as _;
        use sha2::Digest as _;

        let acme_url = if self.eab_key_id.is_some() && self.eab_hmac_key.is_some() {
            ZEROSSL_CA_DIRECTORY
        } else {
            LETSENCRYPT_CA_DIRECTORY
        };

        let dir = DirectoryBuilder::new(acme_url.to_string()).build().await?;
        let mut builder = AccountBuilder::new(dir);
        builder.contact(vec![format!("mailto:admin@{}", self.domain)]);
        builder.terms_of_service_agreed(true);

        if let (Some(ref kid), Some(ref hmac)) = (&self.eab_key_id, &self.eab_hmac_key) {
            let hmac_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(hmac.trim())
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(hmac.trim()))?;
            builder.external_account_binding(kid.clone(), openssl::pkey::PKey::hmac(&hmac_bytes)?);
        }

        let account = builder.build().await?;
        let mut order_builder = OrderBuilder::new(account.clone());
        order_builder.add_dns_identifier(self.domain.clone());
        let mut order = order_builder.build().await?;

        for auth in order.authorizations().await? {
            if matches!(auth.status, AuthorizationStatus::Valid) { continue; }
            let challenge = auth.challenges.iter().find(|c| c.r#type == "dns-01")
                .ok_or("CA did not offer DNS-01 challenge")?.clone();
            let key_auth = challenge.key_authorization()?.ok_or("Missing key authorization")?;
            let txt_val = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(key_auth.as_bytes()));
            let fqdn = format!("_acme-challenge.{}", auth.identifier.value);

            let (zone_id, record_id) = self.dns01_publish(&fqdn, &txt_val).await?;
            let res = challenge.validate().await;
            if res.is_ok() {
                let _ = challenge.wait_done(Duration::from_secs(5), 60).await;
            }
            self.dns01_cleanup(&zone_id, &record_id).await;
        }

        order = order.wait_ready(Duration::from_secs(5), 60).await?;
        order = order.finalize(Csr::Automatic(ephemeral_tls_key.clone())).await?.wait_done(Duration::from_secs(5), 120).await?;

        let certs = order.certificate().await?.ok_or("No certificate returned from CA")?;
        let mut chain_pem = Vec::new();
        for c in certs {
            chain_pem.extend_from_slice(&c.to_pem()?);
            chain_pem.push(b'\n');
        }
        Ok(chain_pem)
    }
}

// Builds the OpenSSL SslAcceptor strictly in memory (Zero Disk Storage)
fn build_in_memory_ssl_acceptor(
    cert_chain_pem: &[u8],
    private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> Result<Arc<SslAcceptor>, Box<dyn std::error::Error + Send + Sync>> {
    let certs = openssl::x509::X509::stack_from_pem(cert_chain_pem)?;
    if certs.is_empty() {
        return Err("No certificates parsed from memory".into());
    }

    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    builder.set_certificate(&certs[0])?;
    for intermediate in certs.iter().skip(1) {
        builder.add_extra_chain_cert(intermediate.clone())?;
    }
    builder.set_private_key(private_key)?;
    builder.check_private_key()?;
    Ok(Arc::new(builder.build()))
}

// ----------------------------------------------------------------------------
// Pre-Flight Protocol & E2EE Endpoints
// ----------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct PreflightRequest {
    pub client_ecdh_pub_b64: String,
    pub client_nonce_hex: String,
    pub flow: Option<String>,
    pub custom_info: Option<String>,
}

async fn serve_verify_html() -> impl IntoResponse {
    // Served from the initramfs on disk, NOT embedded via include_str!. This
    // is deliberate: EXPECTED_ENCLAVE_SHA256 (the code-pin gate) lives in this
    // file and must equal the running binary's self-measure SHA256(/init).
    // Embedding the auditor would make that self-referential (pin ==
    // SHA256(binary containing pin)), an unsatisfiable fixed point. See
    // build-initramfs-tools.sh where verify.html is copied to /verify.html.
    match std::fs::read("/verify.html") {
        Ok(bytes) => ([(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], bytes).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "verify.html not present in initramfs",
        )
            .into_response(),
    }
}

async fn preflight_cors() -> impl IntoResponse {
    (
        [
            (axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (axum::http::header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS"),
            (axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
        ],
        StatusCode::NO_CONTENT,
    )
}

async fn attest_preflight(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(payload): Json<PreflightRequest>,
) -> Response {
    use base64::engine::general_purpose::STANDARD as B64STD;
    use base64::Engine as _;
    use sha2::Digest;

    if let Err(status) = state.record_egress(addr.ip(), 8192) {
        return status.into_response();
    }

    let client_pub = match B64STD.decode(payload.client_ecdh_pub_b64.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid client_ecdh_pub_b64").into_response(),
    };
    // Panic-safe validation: reject a non-DER/unsupported key NOW, so the
    // callback's ECDH cannot fail later (panic = abort would kill the enclave).
    if openssl::pkey::PKey::public_key_from_der(&client_pub).is_err() {
        return (StatusCode::BAD_REQUEST, "client_ecdh_pub_b64 is not a valid DER public key").into_response();
    }
    let nonce_vec = match hex::decode(payload.client_nonce_hex.trim()) {
        Ok(v) if v.len() == 32 => v,
        _ => return (StatusCode::BAD_REQUEST, "client_nonce_hex must be exactly 32 bytes").into_response(),
    };
    let mut client_nonce = [0u8; 32];
    client_nonce.copy_from_slice(&nonce_vec);

    let flow = payload.flow.as_deref().unwrap_or("verified");
    let (cid, _csec, scope, label) = state.get_flow_config(flow);

    let custom_info = payload.custom_info.as_deref().unwrap_or("NONE").trim();
    let custom_info_str = if custom_info.is_empty() { "NONE" } else { custom_info };

    let pkce = match PkceSession::new(client_pub.clone(), client_nonce, custom_info_str.to_string()) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("PKCE generation failed: {}", e)).into_response(),
    };
    let code_challenge = pkce.code_challenge.clone();

    // Hardware binding calculated strictly in RAM
    let report_data = compute_preflight_binding(
        &state.enclave_identity.pubkey_der,
        &code_challenge,
        &client_pub,
        &client_nonce,
        custom_info_str,
    );

    let quote_res = tpm::quote(&hex::encode(&report_data[..32]), Some(report_data));

    use rand::Rng;
    let state_token = hex::encode(rand::thread_rng().gen::<[u8; 32]>());
    let auth_base = if state.staging { PAYPAL_SANDBOX_AUTH } else { PAYPAL_PRODUCTION_AUTH };
    let ecdh_pub_der = pkce.enclave_ecdh.public_key_to_der().unwrap_or_default();

    let signed_fields = serde_json::json!({
        "binding": "v161",
        "code_challenge": code_challenge,
        "state": state_token,
        "flow": label,
        "paypal_client_id": cid,
        "redirect_uri": state.redirect_uri,
        "authorize_base": auth_base,
        "scope": scope,
        "enclave_ecdh_public_key_b64": B64STD.encode(&ecdh_pub_der),
        "custom_info": custom_info_str,
    });

    let signed_fields_str = serde_json::to_string(&signed_fields).unwrap();
    let signature = {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;
        let mut signer = Signer::new(MessageDigest::sha256(), &state.enclave_identity.pkey).unwrap();
        signer.update(signed_fields_str.as_bytes()).unwrap();
        B64STD.encode(signer.sign_to_vec().unwrap())
    };

    state.pending_oauth.write().insert(state_token.clone(), (label, pkce));

    let binary_sha256 = hex::encode(sha2::Sha256::digest(&std::fs::read("/init").unwrap_or_default()));
    // Pre-flight is pre-login: paypal_user_info_raw_hash carries the documented
    // placeholder (real user hash is bound only at the login/callback step).
    let attestation_report = serde_json::json!({
        "custom_info": custom_info_str,
        "paypal_user_info_raw_hash": prelogin_paypal_hash(),
        "enclave_config": {
            "boot_measurements": {
                "binary_sha256": binary_sha256,
                "disk_manifest": &state.boot_manifest,
            }
        },
        "session_context": {
            "preflight": {
                "binding": "v161",
                "code_challenge": code_challenge,
                "client_pub_b64": B64STD.encode(&client_pub),
                "client_nonce_hex": payload.client_nonce_hex,
                "custom_info": custom_info_str,
            }
        },
        "hardware_level_attestation": quote_res,
        "timestamp_ms": chrono::Utc::now().timestamp_millis() as u64,
    });
    let report_sig = sign_report(&state, &attestation_report);

    let body = serde_json::json!({
        "attestation_envelope": {
            "attestation_report": attestation_report,
            "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
            "enclave_signature_b64": report_sig,
        },
        "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
        "signed_fields": signed_fields,
        "preflight_signature_b64": signature,
    });

    let mut resp = ([(axum::http::header::CONTENT_TYPE, "application/json")], Json(body)).into_response();
    resp.headers_mut().insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
    resp
}

// ----------------------------------------------------------------------------
// Standalone Auditor Envelope (GET /debug/envelope)
// ----------------------------------------------------------------------------
// verify.html's pre-flight button (runPreflight) fetches this path and runs
// the full audit on a LIVE report before the user starts a login. The body
// mirrors attest_preflight's `attestation_envelope` exactly — the same shape
// executePreflightAndLogin audits — with an SEC-02 (v160)5-component nonce
// bound into the TDX quote's report_data and NO client session bound (session
// binding belongs to the login flow's POST). Pre-login there is no PayPal user,
// so paypal_user_info_raw_hash carries a documented placeholder and the nonce
// is self-consistent with it; the real user hash is bound only at login.
async fn debug_envelope(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    use sha2::Digest;
    if let Err(status) = state.record_egress(addr.ip(), 8192) {
        return status.into_response();
    }

    let binary_sha256 = hex::encode(sha2::Sha256::digest(&std::fs::read("/init").unwrap_or_default()));
    let custom_info = "NONE";
    let paypal_hash = prelogin_paypal_hash();

    // SEC-02 nonce = SHA-256(paypal_hash ∥ pubkey_hash ∥ custom_info_hash ∥
    // binary_sha256 ∥ manifest_hash). Bind the TDX quote's report_data[0..32]
    // to it ([32..64] zero) so the auditor's recomputed expectedNonce matches.
    let nonce = sec02_nonce(
        &paypal_hash,
        &state.enclave_identity.pubkey_der,
        custom_info,
        &binary_sha256,
        &state.boot_manifest,
    );
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&nonce);
    let quote_res = tpm::quote(&hex::encode(nonce), Some(report_data));

    let attestation_report = serde_json::json!({
        "custom_info": custom_info,
        "paypal_user_info_raw_hash": paypal_hash,
        "enclave_config": {
            "boot_measurements": {
                "binary_sha256": binary_sha256,
                "disk_manifest": &state.boot_manifest,
            }
        },
        "session_context": {},
        "hardware_level_attestation": quote_res,
        "timestamp_ms": chrono::Utc::now().timestamp_millis() as u64,
    });
    let signature = sign_report(&state, &attestation_report);

    let body = serde_json::json!({
        "attestation_report": attestation_report,
        "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
        "enclave_signature_b64": signature,
    });

    let mut resp = ([(axum::http::header::CONTENT_TYPE, "application/json")], Json(body)).into_response();
    resp.headers_mut().insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
    resp
}

// ----------------------------------------------------------------------------
// Local Auditor Out-of-Band Claim Route (Zero WebPKI MITM)
// ----------------------------------------------------------------------------
#[derive(Deserialize)]
struct ClaimQuery {
    state: Option<String>,
}

async fn get_e2ee_blob(
    Query(query): Query<ClaimQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let state_token = match query.state {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "Missing state").into_response(),
    };

    let blob = state.pending_e2ee_blobs.write().remove(&state_token);
    match blob {
        Some((payload, _)) => {
            let mut resp = Json(payload).into_response();
            resp.headers_mut().insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
            resp
        }
        None => (StatusCode::NOT_FOUND, "No E2EE payload for session or already claimed").into_response(),
    }
}

// ----------------------------------------------------------------------------
// Safe Callback Handler: E2EE Encrypted Output Only
// ----------------------------------------------------------------------------
async fn callback(
    Query(query): Query<CallbackQuery>,
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    use base64::engine::general_purpose::STANDARD as B64STD;
    use base64::Engine as _;
    use sha2::Digest;

    let code = query.code.clone().unwrap_or_default();
    let state_param = query.state.clone().unwrap_or_default();

    let pending_entry = state.pending_oauth.write().remove(&state_param);
    let (flow, pkce) = match pending_entry {
        Some((f, p)) if p.created_at.elapsed() < Duration::from_secs(600) => (f, p),
        _ => return (StatusCode::FORBIDDEN, "Invalid or expired session. Start from /verify.html").into_response(),
    };

    let (cid, csec, _, _) = state.get_flow_config(&flow);
    let api_base = if state.staging { PAYPAL_SANDBOX_API } else { PAYPAL_PRODUCTION_API };

    let token_resp = hardened_client().post(format!("{}/v1/oauth2/token", api_base))
        .basic_auth(&cid, Some(&csec))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &state.redirect_uri),
            ("code_verifier", &pkce.code_verifier),
        ])
        .send().await;

    let mut token_obj: TokenResponse = match token_resp {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(TokenResponse { access_token: String::new(), id_token: None }),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "Token exchange failed with PayPal").into_response(),
    };

    let mut userinfo: PayPalUserInfo = match hardened_client()
        .get(format!("{}/v1/identity/oauth2/userinfo?schema=paypalv1.1", api_base))
        .bearer_auth(&token_obj.access_token)
        .send()
        .await
    {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "PayPal userinfo fetch failed").into_response(),
    };

    // Zeroize sensitive token memory immediately
    zeroize_str(&mut token_obj.access_token);
    if let Some(ref mut idt) = token_obj.id_token { zeroize_str(idt); }

    let minimized = userinfo.verified_only();
    if minimized.verified_account.as_deref() != Some("true") {
        return (StatusCode::FORBIDDEN, "PayPal account must be verified").into_response();
    }

    // Build the final attestation report. The login report binds the REAL PayPal
    // user hash into the SEC-02 nonce and a fresh hardware quote, so the
    // post-login audit's recomputed expectedNonce matches the quote's report_data.
    let binary_sha256 = hex::encode(sha2::Sha256::digest(&std::fs::read("/init").unwrap_or_default()));
    let paypal_user_raw_hash = hex::encode(sha2::Sha256::digest(
        serde_json::to_string(&minimized).unwrap_or_default().as_bytes(),
    ));
    let custom_info = pkce.custom_info.clone();

    let nonce = sec02_nonce(
        &paypal_user_raw_hash,
        &state.enclave_identity.pubkey_der,
        &custom_info,
        &binary_sha256,
        &state.boot_manifest,
    );
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&nonce);
    let quote_res = tpm::quote(&hex::encode(nonce), Some(report_data));

    let report_payload = serde_json::json!({
        "paypal_user_info": minimized,
        "paypal_user_info_raw_hash": paypal_user_raw_hash,
        "custom_info": custom_info,
        "timestamp_ms": chrono::Utc::now().timestamp_millis() as u64,
        "enclave_config": {
            "boot_measurements": {
                "binary_sha256": binary_sha256,
                "disk_manifest": &state.boot_manifest,
            }
        },
        "session_context": {
            "tls_certificate_pem": state.tls_cert_pem.read().clone().unwrap_or_default(),
        },
        "hardware_level_attestation": quote_res,
    });
    let sig = sign_report(&state, &report_payload);

    let full_envelope = serde_json::json!({
        "attestation_report": report_payload,
        "enclave_signature_b64": sig,
        "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
    });

    // Derive session key in RAM and encrypt using AES-256-GCM (AAD: client_nonce)
    let mut session_key = match crypto_e2ee::derive_session_key(
        &pkce.enclave_ecdh,
        &pkce.client_ecdh_pub,
        &pkce.client_nonce,
    ) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "E2EE key derivation failed").into_response(),
    };
    let report_json = match serde_json::to_string(&full_envelope) {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Envelope serialization failed").into_response(),
    };
    let (iv, ct) = match crypto_e2ee::encrypt_envelope(&session_key, report_json.as_bytes(), &pkce.client_nonce) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "E2EE encryption failed").into_response(),
    };
    // Zeroize the derived session key immediately after use (plan requirement).
    session_key.iter_mut().for_each(|b| *b = 0);

    let ecdh_pub_der = pkce.enclave_ecdh.public_key_to_der().unwrap_or_default();
    let e2ee_blob = serde_json::json!({
        "alg": "AES-256-GCM+HKDF-SHA256+ECDH-P256",
        "aad": "client_nonce",
        "iv_b64": B64STD.encode(&iv),
        "ct_b64": B64STD.encode(&ct),
        "enclave_ecdh_public_key_b64": B64STD.encode(&ecdh_pub_der),
        "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
        "state": state_param,
        "flow": flow,
    });

    // Save for local claim
    state.pending_e2ee_blobs.write().insert(state_param.clone(), (e2ee_blob.clone(), Instant::now()));

    // Never render plaintext user info: only return the encrypted blob
    // container (v164: the page then stashes it into sessionStorage and
    // hands decryption/audit/download to verify.html in the user's tab).
    let content = CALLBACK_CONTENT
        .replace("__E2EE_BLOB__", &e2ee_blob.to_string().replace("</", "<\\/"));
    let html = HTML_TEMPLATE.replace("{{CONTENT}}", &content);

    let _ = state.record_egress(addr.ip(), html.len() as u64);
    Html(html).into_response()
}

// ----------------------------------------------------------------------------
// Runtime Main Loop
// ----------------------------------------------------------------------------
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    enclave_init::mount_filesystems();
    enclave_init::load_drivers();
    let boot_manifest = enclave_init::measure_boot_components();
    enclave_init::setup_firewall();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        // Initialize tracing to /dev/kmsg (O_NONBLOCK): the plan's info!/warn!
        // statements need a subscriber, and stderr (the serial console tty) can
        // wedge runtime workers on a stalled UART.
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(kmsg_log::KmsgMakeWriter)
            .with_ansi(false)
            .init();

        if let Err(_) = enclave_init::configure_network().await {
            enclave_init::poweroff();
        }

        let config = fetch_config().await.unwrap_or_else(|e| {
            error!("FATAL: {}", e);
            enclave_init::poweroff();
        });

        // 1. Generate Ephemeral Enclave Identity (RAM ONLY, Never Logged)
        let enclave_identity = EphemeralEnclaveIdentity::generate()?;
        info!("--- EPHEMERAL ENCLAVE RSA KEY GENERATED (RAM ONLY, {} bytes) ---", enclave_identity.pubkey_der.len());

        let state = Arc::new(AppState {
            paypal_client_id: config.paypal_client_id.clone(),
            paypal_client_secret: config.paypal_client_secret.clone(),
            paypal_verified_client_id: config.paypal_verified_client_id.clone().unwrap_or_default(),
            paypal_verified_client_secret: config.paypal_verified_client_secret.clone().unwrap_or_default(),
            redirect_uri: format!("https://{}/callback", config.domain),
            domain: config.domain.clone(),
            https_ready: Arc::new(AtomicBool::new(false)),
            staging: config.staging,
            tls_cert_pem: Arc::new(RwLock::new(None)),
            enclave_identity,
            ip_stats: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            global_egress_bytes: Arc::new(AtomicU64::new(0)),
            last_limit_reset: Arc::new(RwLock::new(Instant::now())),
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            boot_manifest,
            pending_oauth: Arc::new(RwLock::new(std::collections::HashMap::new())),
            pending_e2ee_blobs: Arc::new(RwLock::new(std::collections::HashMap::new())),
        });

        // Periodic cleanup of expired volatile sessions
        let cleanup_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_state.pending_oauth.write().retain(|_, (_, p)| p.created_at.elapsed() < Duration::from_secs(600));
                cleanup_state.pending_e2ee_blobs.write().retain(|_, (_, t)| t.elapsed() < Duration::from_secs(600));
            }
        });

        let app = Router::new()
            .route("/", get(serve_verify_html))
            .route("/verify.html", get(serve_verify_html))
            .route("/attest/preflight", axum::routing::options(preflight_cors).post(attest_preflight))
            .route("/debug/envelope", get(debug_envelope))
            .route("/callback", get(callback))
            .route("/e2ee-blob", get(get_e2ee_blob))
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let http_listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 80))).await?;
        let http_app = app.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, addr)) = http_listener.accept().await {
                    let svc_app = http_app.clone();
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let svc = hyper::service::service_fn(move |mut req| {
                            let a = svc_app.clone();
                            req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
                            async move { Ok::<_, std::convert::Infallible>(a.oneshot(req).await.unwrap_or_else(|n| match n {})) }
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(io, svc).await;
                    });
                }
            }
        });

        // 2. Ephemeral In-RAM TLS Key Generation (Every Boot, Never Written to Disk)
        info!("Generating fresh in-memory ephemeral TLS keypair (RAM ONLY)...");
        let ephemeral_tls_key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(4096)?)?;

        let acme_mgr = InRamAcmeManager::new(&config);
        let mut retry_delay = Duration::from_secs(15);
        let cert_chain_pem = loop {
            match acme_mgr.obtain_certificate_in_ram(&ephemeral_tls_key).await {
                Ok(chain) => {
                    info!("ACME certificate obtained in RAM successfully.");
                    break chain;
                }
                Err(e) => {
                    warn!("ACME certificate failed: {}. Retrying in {:?} (no self-signed fallback)...", e, retry_delay);
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(300));
                }
            }
        };

        *state.tls_cert_pem.write() = Some(String::from_utf8_lossy(&cert_chain_pem).to_string());
        let ssl_acceptor = build_in_memory_ssl_acceptor(&cert_chain_pem, &ephemeral_tls_key)?;
        state.https_ready.store(true, Ordering::Relaxed);

        let https_listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 443))).await?;
        info!("HTTPS server listening on port 443 with in-RAM TLS configuration.");

        loop {
            let (stream, addr) = https_listener.accept().await?;
            let acceptor = ssl_acceptor.clone();
            let app_clone = app.clone();
            let sem = state.connection_semaphore.clone();

            tokio::spawn(async move {
                let _permit = match sem.try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let ssl = match openssl::ssl::Ssl::new(acceptor.context()) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut tls_stream = match tokio_openssl::SslStream::new(ssl, stream) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if tokio::time::timeout(Duration::from_secs(10), std::pin::Pin::new(&mut tls_stream).accept()).await.is_err() {
                    return;
                }
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = hyper::service::service_fn(move |mut req| {
                    let a = app_clone.clone();
                    req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
                    async move { Ok::<_, std::convert::Infallible>(a.oneshot(req).await.unwrap_or_else(|n| match n {})) }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, svc).await;
            });
        }
    })
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn require_credentials_rejects_empty_or_placeholders() {
        let bad = Config {
            paypal_client_id: String::new(),
            paypal_client_secret: "secret".into(),
            paypal_verified_client_id: Some("id".into()),
            paypal_verified_client_secret: Some("sec".into()),
            domain: "example.com".into(),
            eab_key_id: None,
            eab_hmac_key: None,
            staging: false,
            dns_api_token: None,
            dns_zone: None,
        };
        assert!(require_credentials(bad).is_err());
    }

    #[test]
    fn test_in_memory_ssl_acceptor_creation() {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

        // A structurally complete self-signed certificate: without validity,
        // subject/issuer and a signature the DER encoding fails ("illegal zero
        // content"), which would test nothing about the acceptor path.
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "paypal-auth-vm-test").unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let cert_pem = cert.to_pem().unwrap();

        let acceptor = build_in_memory_ssl_acceptor(&cert_pem, &pkey);
        assert!(acceptor.is_ok());
    }
}
