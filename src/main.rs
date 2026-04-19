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
    pub fn load_drivers() {
        modprobe("gve");
        modprobe("virtio_net");
        modprobe("virtio_scsi");
        modprobe("virtio_blk");
        modprobe("sev_guest");
        modprobe("sev-guest");
        modprobe("vfat");
        modprobe("nls_cp437");
        modprobe("nls_ascii");
    }

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

        // 9. Mount EFI partition to measure the boot chain
        std::fs::create_dir_all("/boot/efi").ok();
        // GCP standard is sda1, VirtIO is vda1.
        mount_fs("/dev/sda1", "/boot/efi", "vfat");
        mount_fs("/dev/vda1", "/boot/efi", "vfat");

        kmsg("Filesystems mounted");
    }

    pub fn measure_boot_components() -> std::collections::HashMap<String, String> {
        use sha2::{Digest, Sha256};
        let mut manifest = std::collections::HashMap::new();
        
        let mount_point = "/tmp/esp";
        let _ = std::fs::create_dir_all(mount_point);
        
        fn mount_device(source: &str, target: &str) -> bool {
            let src = std::ffi::CString::new(source).unwrap();
            let tgt = std::ffi::CString::new(target).unwrap();
            let fst = std::ffi::CString::new("vfat").unwrap();
            let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), libc::MS_RDONLY, std::ptr::null()) };
            if ret == 0 {
                kmsg(&format!("Successfully mounted {} to {}", source, target));
                true
            } else {
                false
            }
        }

        // DYNAMIC DISCOVERY: Scan /sys/class/block for anything that looks like a partition
        let mut success = false;
        if let Ok(entries) = std::fs::read_dir("/sys/class/block") {
            let mut candidates: Vec<String> = entries.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.chars().any(|c| c.is_digit(10))) // Likely a partition
                .collect();
            candidates.sort(); // Try sda1 before sda2 etc.
            
            for dev_name in candidates {
                let dev_path = format!("/dev/{}", dev_name);
                if mount_device(&dev_path, mount_point) {
                    success = true;
                    break;
                }
            }
        }
        
        if !success {
            kmsg("CRITICAL: Failed to mount EFI System Partition after scanning all devices!");
        }

        fn hash_recursive(dir: &str, mount_point: &str, manifest: &mut std::collections::HashMap<String, String>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    let path_str = path.to_string_lossy();
                    if path.is_dir() {
                        hash_recursive(&path_str, mount_point, manifest);
                    } else if path.is_file() {
                        if let Ok(mut file) = std::fs::File::open(&path) {
                            let mut hasher = Sha256::new();
                            if std::io::copy(&mut file, &mut hasher).is_ok() {
                                let h = hex::encode(hasher.finalize());
                                // Key should be relative to the ESP root (e.g. EFI/BOOT/grub.cfg)
                                let key = path_str.strip_prefix(mount_point)
                                    .unwrap_or(&path_str)
                                    .trim_start_matches('/')
                                    .to_string();
                                manifest.insert(key, h);
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

    fn modprobe(module: &str) {
        let paths = ["/sbin/modprobe", "/usr/sbin/modprobe", "/bin/modprobe", "modprobe"];
        let mut success = false;
        for path in &paths {
            match std::process::Command::new(path).arg("-q").arg(module).status() {
                Ok(s) if s.success() => {
                    kmsg(&format!("modprobe {} (via {}): OK", module, path));
                    success = true;
                    break;
                },
                Ok(_) => {}, // Try next path if this one failed (maybe not found)
                Err(_) => {},
            }
        }
        if !success {
            kmsg(&format!("modprobe {}: ALL PATHS FAILED", module));
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
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use acme2_eab::{
    gen_rsa_private_key, AccountBuilder, AuthorizationStatus, DirectoryBuilder, OrderBuilder, Csr,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Semaphore;
use tokio::net::TcpListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use std::collections::HashMap;
use std::net::IpAddr;

// ============================================================================
// CONSTANTS
// ============================================================================

mod tpm {
    use tokio::process::Command;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Serialize};

    pub const PCR_SELECTION: &str = "0,4,8,9,15";

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
        pub pcr_values: std::collections::HashMap<String, String>,
        pub nonce_hex: String,
        pub snp_report_b64: Option<String>,
    }

    pub mod snp {
        use std::fs::File;
        use std::os::unix::io::AsRawFd;
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        #[repr(C, packed)]
        struct SnpReportReq {
            user_data: [u8; 64],
            vmpl: u32,
            _reserved: [u8; 28],
        }

        #[repr(C, packed)]
        struct SnpGuestRequestIoctl {
            msg_version: u8,
            req_ptr: u64,
            resp_ptr: u64,
            exit_info: u64,
        }

        pub fn get_report(nonce: &[u8; 64]) -> Option<String> {
            let file = File::open("/dev/sev-guest").ok()?;
            let mut req = SnpReportReq {
                user_data: *nonce,
                vmpl: 0,
                _reserved: [0u8; 28],
            };
            let mut resp = [0u8; 4000]; // SNP report is ~1.2KB
            let mut ioctl_data = SnpGuestRequestIoctl {
                msg_version: 1,
                req_ptr: &req as *const _ as u64,
                resp_ptr: resp.as_mut_ptr() as u64,
                exit_info: 0,
            };

            const SNP_GUEST_REQ: u64 = 0xC0205301; // Ioctl for SNP_GET_REPORT
            unsafe {
                if libc::ioctl(file.as_raw_fd(), SNP_GUEST_REQ as libc::c_ulong, &mut ioctl_data) == 0 {
                    return Some(STANDARD.encode(&resp[..1200])); // Report size is 1184 bytes
                }
            }
            None
        }
    }

    pub async fn run_cmd(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new(cmd)
            .args(args)
            .env("TCTI", "device:/dev/tpmrm0")
            .output().await?;
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
            "/tmp/dek.plain", "/tmp/primary_seal.ctx",
            "/tmp/dek.priv", "/tmp/dek.pub",
        ];
        let _ = cleanup(&cleanup_paths).await;

        tokio::fs::write("/tmp/dek.plain", dek).await?;
        // Use the well-known deterministic owner-hierarchy primary template.
        // This produces the SAME primary key on every boot of the same physical TPM.
        run_cmd("tpm2_createprimary", &[
            "-C", "o",
            "-g", "sha256",
            "-G", "rsa2048",
            "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt",
            "-c", "/tmp/primary_seal.ctx",
        ]).await?;
        run_cmd("tpm2_create", &[
            "-C", "/tmp/primary_seal.ctx",
            "-r", "/tmp/dek.priv",
            "-u", "/tmp/dek.pub",
            "-i", "/tmp/dek.plain",
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
            "/tmp/dek.pub", "/tmp/dek.priv", "/tmp/primary_seal.ctx",
            "/tmp/dek.ctx",
        ];
        let _ = cleanup(&cleanup_paths).await;

        let pub_b = STANDARD.decode(&sealed.pub_blob)?;
        let priv_b = STANDARD.decode(&sealed.priv_blob)?;
        tokio::fs::write("/tmp/dek.pub", pub_b).await?;
        tokio::fs::write("/tmp/dek.priv", priv_b).await?;

        // Recreate the SAME deterministic primary using the identical template as seal_dek
        run_cmd("tpm2_createprimary", &[
            "-C", "o",
            "-g", "sha256",
            "-G", "rsa2048",
            "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt",
            "-c", "/tmp/primary_seal.ctx",
        ]).await?;
        run_cmd("tpm2_load", &[
            "-C", "/tmp/primary_seal.ctx",
            "-u", "/tmp/dek.pub",
            "-r", "/tmp/dek.priv",
            "-c", "/tmp/dek.ctx",
        ]).await?;

        let dek = run_cmd("tpm2_unseal", &["-c", "/tmp/dek.ctx"]).await?;

        let _ = cleanup(&cleanup_paths).await;
        Ok(dek)
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

        // 1. Create primary key in Owner hierarchy explicitly
        run_cmd("tpm2_createprimary", &[
            "-C", "o", 
            "-g", "sha256", 
            "-G", "rsa2048", 
            "-c", &primary_ctx
        ]).await?;

        // 2. Create the AK with 'restricted|sign' - required for TPM2_Quote
        run_cmd("tpm2_create", &[
            "-C", &primary_ctx,
            "-g", "sha256",
            "-G", "rsa2048",
            "-a", "sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth",
            "-u", &ak_pub,
            "-r", &ak_priv
        ]).await?;
        
        // 3. Load it
        run_cmd("tpm2_load", &[
            "-C", &primary_ctx,
            "-u", &ak_pub,
            "-r", &ak_priv,
            "-c", &ak_ctx
        ]).await?;

        // Extract AK PEM for the report
        run_cmd("tpm2_readpublic", &["-c", &ak_ctx, "-f", "pem", "-o", &ak_pem]).await?;
        let ak_pem_str = tokio::fs::read_to_string(&ak_pem).await?;

        run_cmd("tpm2_quote", &[
            "-c", &ak_ctx,
            "-l", &format!("sha256:{}", PCR_SELECTION),
            "-q", nonce_hex,
            "-m", &quote_msg,
            "-s", &quote_sig,
        ]).await?;
        let msg = tokio::fs::read(&quote_msg).await?;
        let sig = tokio::fs::read(&quote_sig).await?;

        let pcr_out = run_cmd("tpm2_pcrread", &[&format!("sha256:{}", PCR_SELECTION)]).await.unwrap_or_default();
        let pcr_str = String::from_utf8_lossy(&pcr_out);
        let mut pcr_values = std::collections::HashMap::new();
        for line in pcr_str.lines() {
            if line.contains(':') && !line.trim().is_empty() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let idx = parts[0].trim_matches(|c: char| !c.is_numeric()).to_string();
                    let val = parts[1].trim().to_string();
                    if !idx.is_empty() && !val.is_empty() {
                        pcr_values.insert(idx, val);
                    }
                }
            }
        }

        let ek_cert = match run_cmd("tpm2_readpublic", &["-c", "0x81010001", "-f", "pem", "-o", &format!("{}/ek.pub", work_dir)]).await {
            Ok(_) => {
                match run_cmd("tpm2_getekcertificate", &["-X", "-o", &format!("{}/ek.cert", work_dir)]).await {
                    Ok(cert_der) => Some(STANDARD.encode(cert_der)),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        };

        // 5. Hardware SNP Report (Firmware / Launch Measurement)
        let mut snp_nonce = [0u8; 64];
        if let Ok(nh) = hex::decode(nonce_hex) {
            let len = nh.len().min(64);
            snp_nonce[..len].copy_from_slice(&nh[..len]);
        }
        let snp_report_b64 = snp::get_report(&snp_nonce);

        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        Ok(AttestationResult {
            tpm_quote_msg: STANDARD.encode(msg),
            tpm_quote_sig: STANDARD.encode(sig),
            ak_pub_pem: ak_pem_str,
            ek_cert,
            pcrs: PCR_SELECTION.to_string(),
            pcr_values,
            nonce_hex: nonce_hex.to_string(),
            snp_report_b64,
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


const MAX_TRACKED_IPS: usize = 1000;
const MAX_CONCURRENT_CONNECTIONS: usize = 50;
const GLOBAL_EGRESS_BYTES_PER_HOUR: u64 = 512 * 1024 * 1024; // 512 MB
const IP_EGRESS_BYTES_PER_HOUR: u64 = 25 * 1024 * 1024;     // 25 MB
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
        .footer { margin-top: 30px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #333; padding-top: 15px; }
        .footer a { color: #64b5f6; text-decoration: none; margin: 0 10px; }
        .document-content h2 { color: #64b5f6; margin-top: 25px; border-bottom: 1px solid #333; padding-bottom: 5px; }
        .document-content p { line-height: 1.6; }
    </style>
</head>
<body><div class="container">{{CONTENT}}</div></body></html>
"#;

const PRIVACY_POLICY: &str = r#"
    <div class="document-content">
        <h1 id="privacy-policy">Privacy Policy & Data Security</h1>
        <p>This service is an experimental, open-source project maintained by Leonardo Pedro.</p>
        
        <h2 id="security-assurance">1. Data Security & Integrity</h2>
        <p>I have performed amateur-level testing and amateur-level code audits to identify potential data leak vectors. As of the latest release, <strong>I have found no evidence of data leaks or vulnerabilities</strong>. However, given the experimental nature of this service, I cannot offer any absolute guarantee that the system is free of flaws or leaks.</p>
        
        <h2 id="shared-responsibility">2. Shared Responsibility Model</h2>
        <p>This service is offered for free with the understanding that security is a collective effort. By using this service, you agree to assume the responsibility of <strong>verifying the remote attestation</strong>. You are encouraged to inspect the hardware quotes and binary identity to confirm you are running the intended code.</p>
        
        <h2 id="reporting-vulnerabilities">3. Reporting Vulnerabilities</h2>
        <p>The risks and responsibilities are shared by all users. If you discover a security flaw or vulnerability, you are expected to alert me immediately by opening an issue at: <br>
        <a href="https://github.com/leonardopedro/verifiedUniqueAliases/issues" target="_blank" style="color:#64b5f6;">github.com/leonardopedro/verifiedUniqueAliases/issues</a>.<br>
        Your reports allow me to correct or minimize issues for the benefit of the entire community.</p>
        
        <h2 id="data-handling">4. Data Handling</h2>
        <p>All evidence so far suggests that this service operates in encrypted RAM (AMD SEV-SNP),  it does not utilize persistent databases for user profiles and your data exists only for the duration of the session required to perform the OAuth flow and generate your attestation report. But it is up to the user (you) to verify this is so in the remote attestation.</p>
        <div class="footer"><a href="/">Back to Home</a></div>
    </div>
"#;

const USER_AGREEMENT: &str = r#"
    <div class="document-content">
        <h1 id="user-agreement">User Agreement</h1>
        <p>By using this experimental service, you accept the following terms and conditions.</p>
        
        <h2 id="as-is">1. "AS IS" Provision</h2>
        <p>This service is a free, experimental demonstration of a bitwise-reproducible, self-attesting enclave built on Google Cloud Confidential VM. It is provided <strong>"AS IS", WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND</strong>, consistent with the Apache 2.0 License.</p>
        
        <h2 id="verification">2. User Responsibility & Verification</h2>
        <p>The core philosophy of this project is verifiable trust. Users are responsible for verifying the hardware attestation provided by the AMD SEV-SNP enclave. You acknowledge that you use this service at your own risk.</p>
        
        <h2 id="community-reporting">3. Community Security</h2>
        <p>You agree to report any potential security issues or flaws at <a href="https://github.com/leonardopedro/verifiedUniqueAliases/issues" target="_blank" style="color:#64b5f6;">github.com/leonardopedro/verifiedUniqueAliases/issues</a>. This collaborative approach allows us to minimize risks for everyone. You acknowledge that vulnerabilities may exist despite best efforts.</p>
        
        <h2 id="liability">4. Limitation of Liability</h2>
        <p>To the maximum extent permitted by applicable law, I (Leonardo Pedro) shall not be liable for any direct, indirect, incidental, or consequential damages resulting from the use of this service.</p>
        <div class="footer"><a href="/">Back to Home</a></div>
    </div>
"#;

// ============================================================================
// CONFIG (single JSON secret)
// ============================================================================

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
    acme_account_json: Option<String>,
    // v69: Asymmetric key for signing the attestation payload
    #[serde(default)]
    attestation_signing_key: Option<String>,
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
    // v69: For inclusion in remote attestation
    tls_cert_pem: Arc<RwLock<Option<String>>>,
    attestation_signing_key: Option<String>,
    // v70: DDoS Protection for IP tracking
    ip_stats: Arc<RwLock<HashMap<IpAddr, u64>>>,
    global_egress_bytes: Arc<AtomicU64>,
    last_limit_reset: Arc<RwLock<Instant>>,
    // v71: Concurrency Control
    connection_semaphore: Arc<Semaphore>,
    boot_manifest: std::collections::HashMap<String, String>,
}

struct PayPalFlowConfig {
    client_id: String,
    client_secret: String,
    scope: String,
    label: String,
}

impl AppState {
    fn get_flow_config(&self, flow_name: &str) -> PayPalFlowConfig {
        if flow_name == "verified" {
            PayPalFlowConfig {
                client_id: self.paypal_verified_client_id.clone(),
                client_secret: self.paypal_verified_client_secret.clone(),
                scope: "https%3A%2F%2Furi.paypal.com%2Fservices%2Fpaypalattributes".to_string(),
                label: "verified".to_string(),
            }
        } else {
            PayPalFlowConfig {
                client_id: self.paypal_client_id.clone(),
                client_secret: self.paypal_client_secret.clone(),
                scope: "openid%20profile%20email%20address%20profile%20email%20https%3A%2F%2Furi.paypal.com%2Fservices%2Fpaypalattributes".to_string(),
                label: "full".to_string(),
            }
        }
    }

    fn record_egress_data(&self, ip: IpAddr, bytes: u64) -> Result<(), StatusCode> {
        let now = Instant::now();
        
        let mut stats = self.ip_stats.write();
        let mut reset = self.last_limit_reset.write();
        
        // Reset counters if hour passed
        if now.duration_since(*reset) > Duration::from_secs(3600) {
            info!("Egress data counters reset (1 hour interval reached)");
            *reset = now;
            self.global_egress_bytes.store(0, Ordering::Relaxed);
            stats.clear();
        }
        drop(reset); 

        // 1. Global Data Limit Check
        let current_global = self.global_egress_bytes.fetch_add(bytes, Ordering::Relaxed);
        if current_global + bytes >= GLOBAL_EGRESS_BYTES_PER_HOUR {
            error!("Global data limit reached ({}/{} bytes)", current_global, GLOBAL_EGRESS_BYTES_PER_HOUR);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // 2. Per-IP Data Limit Check
        let ip_bytes = if let Some(count) = stats.get_mut(&ip) {
            *count += bytes;
            *count
        } else if stats.len() < MAX_TRACKED_IPS {
            stats.insert(ip, bytes);
            bytes
        } else {
            0
        };

        if ip_bytes > IP_EGRESS_BYTES_PER_HOUR && ip_bytes != 0 {
            error!("IP bandwidth limit reached for {}: ({}/{} bytes)", ip, ip_bytes, IP_EGRESS_BYTES_PER_HOUR);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        Ok(())
    }
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
struct PayPalAddress {
    street_address: Option<String>,
    locality: Option<String>,
    region: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PayPalEmail {
    value: String,
    primary: Option<bool>,
    confirmed: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PayPalUserInfo {
    user_id: String,
    sub: Option<String>,
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
    emails: Option<Vec<PayPalEmail>>,
    email_verified: Option<bool>,
    gender: Option<String>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    locale: Option<String>,
    phone_number: Option<String>,
    address: Option<PayPalAddress>,
    verified_account: Option<String>,
    verified: Option<String>,
    account_type: Option<String>,
    age_range: Option<String>,
    payer_id: Option<String>,
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
    String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok().map(|s| s.trim().trim_matches('\0').to_string())
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
            attestation_signing_key: std::env::var("ATTESTATION_SIGNING_KEY").ok(),
        });
    }

    // 1. Determine which secret to load by checking PAYPAL_AUTH_MODE
    let mode_secret = "projects/project-ae136ba1-3cc9-42cf-a48/secrets/PAYPAL_AUTH_MODE/versions/latest";
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

    // --- PHASE 0: Parse all metadata attributes into environment variables ---
    // This allows tee-env-TLS_CACHE_SECRET to be picked up by std::env::var later
    if let Ok(resp) = client.get("http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true")
        .header("Metadata-Flavor", "Google")
        .send().await {
        if let Ok(attrs) = resp.json::<serde_json::Value>().await {
            if let Some(obj) = attrs.as_object() {
                for (k, v) in obj {
                    if let Some(val) = v.as_str() {
                        if let Some(env_key) = k.strip_prefix("tee-env-") {
                            info!("Setting metadata env: {}={}", env_key, val);
                            std::env::set_var(env_key, val);
                        }
                    }
                }
            }
        }
    }

    // 1. Determine which secret to load by checking PAYPAL_AUTH_MODE
    let mode = if let Ok(resp) = client.get(format!("https://secretmanager.googleapis.com/v1/{}:access", mode_secret))
        .bearer_auth(access_token)
        .send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                if let Some(encoded) = json["payload"]["data"].as_str() {
                    if let Ok(decoded) = STANDARD.decode(encoded) {
                        if let Ok(mode_json) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                            mode_json["active_mode"].as_str().unwrap_or("production").to_string()
                        } else { "production".to_string() }
                    } else { "production".to_string() }
                } else { "production".to_string() }
            } else { "production".to_string() }
        } else {
            info!("PAYPAL_AUTH_MODE secret not found, defaulting to production");
            "production".to_string()
        };

    // v70: Store which mode we are in for later
    std::env::set_var("ACTIVE_MODE", &mode);

    info!("Active mode from Vault: {}", mode);

    let base_secret_name = if mode == "staging" {
        "PAYPAL_AUTH_STAGING"
    } else {
        "PAYPAL_AUTH_PRODUCTION"
    };

    // Priority 2: Fetch target secret
    let secret_name = std::env::var("SECRET_NAME").unwrap_or_else(|_| {
        format!("projects/project-ae136ba1-3cc9-42cf-a48/secrets/{}/versions/latest", base_secret_name)
    });

    info!("Fetching main config from: {}", secret_name);
    let secret_resp: serde_json::Value = client
        .get(format!("https://secretmanager.googleapis.com/v1/{}:access", secret_name))
        .bearer_auth(access_token)
        .send()
        .await?
        .json()
        .await?;

    let encoded = secret_resp["payload"]["data"]
        .as_str()
        .ok_or_else(|| format!("No payload in Secret Manager response for {}", secret_name))?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let decoded = STANDARD.decode(encoded.trim())?;
    let json_str = String::from_utf8(decoded)?;
    let clean_json = json_str.trim().trim_matches('\0');

    // v70: Save bootstrap config for later persistence
    let _ = std::fs::write("/tmp/bootstrap_config.json", clean_json);
    let _ = std::fs::write("/tmp/bootstrap_secret_id.txt", base_secret_name);

    let mut config: Config = serde_json::from_str(clean_json)?;

    // Override EAB keys from secrets if available (allows rotation without config update)
    let eab_key_id_secret = fetch_secret_direct("EAB_KEY_ID").await;
    let eab_hmac_secret = fetch_secret_direct("EAB_HMAC_KEY").await;
    if let (Some(kid), Some(hmac)) = (eab_key_id_secret, eab_hmac_secret) {
        config.eab_key_id = Some(kid);
        config.eab_hmac_key = Some(hmac);
    }

    // Override PayPal credentials from individual secrets if available
    if let Some(id) = fetch_secret_direct("PAYPAL_CLIENT_ID").await { config.paypal_client_id = id; }
    if let Some(sec) = fetch_secret_direct("PAYPAL_CLIENT_SECRET").await { config.paypal_client_secret = sec; }
    if let Some(id) = fetch_secret_direct("PAYPAL_VERIFIED_CLIENT_ID").await { config.paypal_verified_client_id = Some(id); }
    if let Some(sec) = fetch_secret_direct("PAYPAL_VERIFIED_CLIENT_SECRET").await { config.paypal_verified_client_secret = Some(sec); }
    
    if let Some(staging_env) = fetch_secret_direct("PAYPAL_STAGING").await {
        config.staging = staging_env == "true";
    }

    // Symmetrical Fallbacks: Ensure both flows have valid defaults if missing
    let config = Config {
        paypal_client_id: if config.paypal_client_id.is_empty() || config.paypal_client_id == "MISSING_CLIENT_ID" {
            "ARDDrFepkPcuh-bWdtKPLeMNptSHp2BvhahGiPNt3n317a-Uu68Xu4c9F_4N0hPI5YK60R3xRMNYr-B0".to_string()
        } else {
            config.paypal_client_id
        },
        paypal_client_secret: if config.paypal_client_secret.is_empty() || config.paypal_client_secret == "MISSING_CLIENT_SECRET" {
            "EFdUSE2qjgZy5Ok5f4Cy0SBuodWTj30TzO-7b8W8VAQOoNDwu-Feecb7va89C0jS5BZuclqiJSt4I20s".to_string()
        } else {
            config.paypal_client_secret
        },
        paypal_verified_client_id: Some(config.paypal_verified_client_id.unwrap_or_else(|| {
            "AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p".to_string()
        })),
        paypal_verified_client_secret: Some(config.paypal_verified_client_secret.unwrap_or_else(|| {
            "EHSSIjy5sUHPYrBA1tN-UqDLfuTe-FSSdxRVJ6CCvNcwK6QphDUExRPGurFvA4DibvFNA-LvnHFUY7vP".to_string()
        })),
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
        if let Some((cert, key, acme_key)) = Self::fetch_cached_tls().await {
            // Restore ACME account key to tmpfs for the current session
            if let Some(ak) = acme_key {
                let _ = tokio::fs::write("/tmp/acme-account.json", ak).await;
            }
            return Ok((cert, key));
        }

        info!("Obtaining TLS certificate from Google Public CA...");
        let acme_url = GOOGLE_PUBLIC_CA_DIRECTORY;
        let account_path = "/tmp/acme-account.json";
        
        // ... (rest of account logic)
        let account = if let Ok(data) = tokio::fs::read_to_string(account_path).await {
            info!("Restoring ACME account from tmpfs...");
            let dir = DirectoryBuilder::new(acme_url.to_string()).build().await?;
            let priv_key_pem = data.trim();
            let priv_pem = openssl::pkey::PKey::private_key_from_pem(priv_key_pem.as_bytes())?;
            let mut builder = AccountBuilder::new(dir);
            builder.private_key(priv_pem);
            builder.build().await?
        } else {
            let kid = self.eab_key_id.as_ref().ok_or("Missing EAB key ID")?;
            info!("Creating new ACME account with EAB Key ID: {}...", &kid[..8.min(kid.len())]);
            let hmac_str = self.eab_hmac_key.as_ref().ok_or("Missing EAB HMAC key")?;

            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            let hmac_bytes = URL_SAFE_NO_PAD.decode(hmac_str.trim()).map_err(|e| format!("EAB HMAC decode failed: {}", e))?;
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

        // ... (rest of certificate logic)
        info!("Creating ACME order for domain: {}", self.domain);
        let mut order_builder = OrderBuilder::new(account.clone());
        order_builder.add_dns_identifier(self.domain.clone());
        let mut order = order_builder.build().await?;

        // ... (authorizations)
        let authorizations = order.authorizations().await?;
        for auth in authorizations {
            if matches!(auth.status, AuthorizationStatus::Valid) { continue; }
            let mut challenge = auth.challenges.iter().find(|c| c.r#type == "http-01")
                .ok_or("No HTTP-01 challenge found")?.clone();

            let challenge_dir = "/tmp/acme-challenge";
            tokio::fs::create_dir_all(challenge_dir).await?;
            let token = challenge.token.as_ref().ok_or("Missing token")?;
            let key_auth = challenge.key_authorization()?.ok_or("Missing key authorization")?;
            tokio::fs::write(format!("{}/{}", challenge_dir, token.replace("/", "_")), key_auth.as_bytes()).await?;

            challenge.validate().await?;
            challenge.wait_done(Duration::from_secs(5), 72).await?;
        }

        order = order.wait_ready(Duration::from_secs(5), 72).await?;
        let pkey = gen_rsa_private_key(4096)?;
        let key_pem = pkey.private_key_to_pem_pkcs8()?;
        let order = order.finalize(Csr::Automatic(pkey)).await?;
        let order = order.wait_done(Duration::from_secs(5), 144).await?;

        match order.certificate().await? {
            Some(cert) => {
                let mut cert_chain_str = String::new();
                for c in cert {
                    if let Ok(pem) = c.to_pem() {
                        cert_chain_str.push_str(std::str::from_utf8(&pem).unwrap_or(""));
                        cert_chain_str.push('\n');
                    }
                }
                
                let acme_account_key = tokio::fs::read(account_path).await.ok();
                Self::store_cached_tls(cert_chain_str.as_bytes(), &key_pem, acme_account_key.as_deref()).await;
                Ok((cert_chain_str.into_bytes(), key_pem))
            }
            None => Err("Certificate not available".into()),
        }
    }

    async fn fetch_cached_tls() -> Option<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
        let secret_name = std::env::var("TLS_CACHE_SECRET").ok()?;
        info!("Attempting to restore TLS from cache: {}", secret_name);
        let client = reqwest::Client::new();
        // ... (fetch secret logic from standard metadata)
        let token_resp: serde_json::Value = client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
            .header("Metadata-Flavor", "Google")
            .send().await.ok()?.json().await.ok()?;
        let access_token = token_resp["access_token"].as_str()?;
        let url = format!("https://secretmanager.googleapis.com/v1/{}/versions/latest:access", secret_name);
        
        let secret_resp: serde_json::Value = client.get(&url).bearer_auth(access_token).send().await.ok()?.json().await.ok()?;
        let encoded = secret_resp["payload"]["data"].as_str()?;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let wrapper_bytes = STANDARD.decode(encoded).ok()?;
        let wrapper: serde_json::Value = serde_json::from_slice(&wrapper_bytes).ok()?;
        
        info!("Fetched cached envelope, attempting to unseal DEK...");
        let sealed_dek: tpm::SealedData = serde_json::from_value(wrapper["sealed_dek"].clone()).ok()?;
        let dek = match tpm::unseal_dek(&sealed_dek).await {
            Ok(d) => d,
            Err(e) => {
                error!("TPM Unseal failed for TLS cache DEK: {}", e);
                return None;
            }
        };

        info!("DEK unsealed, decrypting TLS payload...");

        let nonce = STANDARD.decode(wrapper["nonce"].as_str()?).ok()?;
        let ciphertext = STANDARD.decode(wrapper["ciphertext"].as_str()?).ok()?;
        let plaintext = crypto::decrypt(&dek, &nonce, &ciphertext).ok()?;

        let json: serde_json::Value = serde_json::from_slice(&plaintext).ok()?;
        let cert = STANDARD.decode(json["cert"].as_str()?).ok()?;
        let key = STANDARD.decode(json["key"].as_str()?).ok()?;
        let acme_key = json["acme_key"].as_str().and_then(|ak| STANDARD.decode(ak).ok());
        
        info!("Successfully restored and unsealed TLS cache (including ACME account)");
        Some((cert, key, acme_key))
    }

    async fn store_cached_tls(cert: &[u8], key: &[u8], acme_key: Option<&[u8]>) {
        if let Ok(secret_name) = std::env::var("TLS_CACHE_SECRET") {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let dek = crypto::generate_dek();
            let sealed_dek = match tpm::seal_dek(&dek).await {
                Ok(s) => s,
                Err(e) => { error!("Failed to seal DEK: {}", e); return; }
            };

            let mut json_map = serde_json::Map::new();
            json_map.insert("cert".to_string(), serde_json::Value::String(STANDARD.encode(cert)));
            json_map.insert("key".to_string(), serde_json::Value::String(STANDARD.encode(key)));
            if let Some(ak) = acme_key {
                json_map.insert("acme_key".to_string(), serde_json::Value::String(STANDARD.encode(ak)));
            }
            let payload_json = serde_json::Value::Object(json_map).to_string();

            let (nonce, ciphertext) = match crypto::encrypt(&dek, payload_json.as_bytes()) {
                Ok(c) => c,
                Err(e) => { error!("Failed to encrypt: {}", e); return; }
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
                .header("Metadata-Flavor", "Google").send().await {
                if let Ok(json) = token_resp.json::<serde_json::Value>().await {
                    if let Some(access_token) = json["access_token"].as_str() {
                        let url = format!("https://secretmanager.googleapis.com/v1/{}:addVersion", secret_name);
                        let _ = client.post(&url).bearer_auth(access_token).json(&serde_json::json!({ "payload": { "data": payload_b64 } })).send().await;
                    }
                }
            }
        }
    }
}

// ============================================================================
// ATTESTATION
// ============================================================================

fn sign_payload(payload: &str, private_key_pem: &str) -> String {
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use openssl::hash::MessageDigest;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).expect("Invalid private key");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("Failed to create signer");
    signer.update(payload.as_bytes()).expect("Failed to update signer");
    let signature = signer.sign_to_vec().expect("Failed to sign");
    STANDARD.encode(signature)
}

fn extract_pub_key(private_key_pem: &str) -> String {
    use openssl::pkey::PKey;
    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).ok();
    pkey.and_then(|k| k.public_key_to_pem().ok())
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "N/A".to_string())
}

async fn generate_attestation(
    state: &AppState,
    clicked_button_label: String,
    userinfo: PayPalUserInfo,
) -> String {
    use sha2::{Digest, Sha256};
    
    // 1. Get current time with ms precision
    let now = chrono::Utc::now();
    let timestamp_ms = now.timestamp_millis() as u64;

    // 2. Convert userinfo to a sorted Value and hash its alphabetical representation
    let userinfo_val = serde_json::to_value(&userinfo).expect("Failed to value-ize userinfo");
    let paypal_json = serde_json::to_string(&userinfo_val).expect("Failed to serialize userinfo");
    let mut hasher = Sha256::new();
    hasher.update(paypal_json.as_bytes());
    let paypal_hash = hex::encode(hasher.finalize());

    // 2.5 Software Hash Check (Self-measure)
    let bin_path = "/init"; 
    let mut bin_hasher = Sha256::new();
    if let Ok(data) = std::fs::read(bin_path) {
        bin_hasher.update(&data);
    }
    let binary_self_hash = hex::encode(bin_hasher.finalize());

    // 3. Obtain hardware attestation quote (PCR 15 base)
    // Nonce is the hash of the user data to ensure 1-to-1 binding
    let tpm_report = tpm::quote(&paypal_hash).await.expect("TPM quote failed");
    let tpm_val = serde_json::to_value(&tpm_report).expect("Failed to value-ize tpm_report");

    // 4. Resolve current TLS certificate
    let cert_pem = state.tls_cert_pem.read().clone().unwrap_or_else(|| "UNSET_DURING_STARTUP".to_string());
    
    // 5. Construct the full signed payload
    // All components are converted to Values (which use BTreeMap/sorted order)
    let payload = serde_json::json!({
        "paypal_user_info": userinfo_val,
        "paypal_user_info_raw_hash": paypal_hash,
        "timestamp_ms": timestamp_ms,
        "enclave_config": {
            "version": "v82-master",
            "paypal_client_id_full": &state.paypal_client_id,
            "paypal_client_id_verified": &state.paypal_verified_client_id,
            "staging_mode": if state.staging { "sandbox" } else { "production" },
            "domain": &state.domain,
            "boot_measurements": {
                "binary_sha256": &binary_self_hash,
                "disk_manifest": &state.boot_manifest,
            },
            "enclave_debug": {
                "manifest_size": state.boot_manifest.len(),
                "kernel_log_tail": if let Ok(log) = std::fs::read_to_string("/dev/kmsg") { log.chars().rev().take(1000).collect::<String>().chars().rev().collect::<String>() } else { "LOG_UNREADABLE".to_string() }
            }
        },
        "session_context": {
            "clicked_button_label": clicked_button_label,
            "tls_certificate_pem": &cert_pem,
        },
        "hardware_level_attestation": tpm_val,
    });

    // v70: We use Compact JSON for the signature to ensure deterministic verification (Canonical-lite)
    let payload_compact = serde_json::to_string(&payload).expect("Failed to serialize compact payload");
    
    // 6. Sign everything using the enclave-bound asymmetric key
    let signature = if let Some(key) = &state.attestation_signing_key {
        sign_payload(&payload_compact, key)
    } else {
        "UNSIGNED_KEY_MISSING".to_string()
    };

    let full_report = serde_json::json!({
        "attestation_report": payload,
        "enclave_signature_b64": signature,
        "enclave_signing_public_key": if let Some(key) = &state.attestation_signing_key {
            extract_pub_key(key)
        } else {
            "N/A".to_string()
        }
    });

    serde_json::to_string_pretty(&full_report).unwrap()
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
        return Err(format!("Userinfo API returned {}: {}", resp.status(), resp.text().await?).into());
    }
    
    let body = resp.text().await?;
    match serde_json::from_str::<PayPalUserInfo>(&body) {
        Ok(u) => Ok(u),
        Err(e) => {
            error!("FAIL: Userinfo JSON decoding error: {}. Raw body: {}", e, body);
            Err(format!("Decoding error: {}. See serial logs for body.", e).into())
        }
    }
}



// ============================================================================
// HTTP HANDLERS
// ============================================================================

async fn index(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    let content = format!(
        r#"
        <h1>Confidential PayPal Authentication</h1>
        <div class="info">
            <p><strong>Domain:</strong> {}</p>
            <p><strong>Status:</strong> <span class="cert-status">v71 Hardened (AMD SEV-SNP)</span></p>
            <p><strong>Certificate:</strong> RAM ONLY (Google Public CA)</p>
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
        <div class="footer">
            <a href="/privacy#privacy-policy">Privacy Policy</a> |
            <a href="/terms#user-agreement">User Agreement</a>
        </div>
        "#,
        state.domain
    );
    let html = HTML_TEMPLATE.replace("{{CONTENT}}", &content);
    if let Err(status) = state.record_egress_data(addr.ip(), html.len() as u64) {
        return status.into_response();
    }
    Html(html).into_response()
}

async fn privacy(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = state.record_egress_data(addr.ip(), PRIVACY_POLICY.len() as u64) {
        return status.into_response();
    }
    Html(HTML_TEMPLATE.replace("{{CONTENT}}", PRIVACY_POLICY)).into_response()
}

async fn terms(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = state.record_egress_data(addr.ip(), USER_AGREEMENT.len() as u64) {
        return status.into_response();
    }
    Html(HTML_TEMPLATE.replace("{{CONTENT}}", USER_AGREEMENT)).into_response()
}

#[derive(Deserialize)]
struct LoginParams {
    flow: Option<String>,
}

async fn login(
    Query(params): Query<LoginParams>,
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = state.record_egress_data(addr.ip(), 500 /* Estimated redir size */) {
        return status.into_response();
    }
    let flow = params.flow.as_deref().unwrap_or("full");
    let config = state.get_flow_config(flow);
    
    let auth_base = if state.staging { PAYPAL_SANDBOX_AUTH } else { PAYPAL_PRODUCTION_AUTH };

    let url = format!(
        "{}?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}",
        auth_base,
        config.client_id,
        urlencoding::encode(&config.scope),
        urlencoding::encode(&state.redirect_uri),
        config.label
    );
    Redirect::temporary(&url).into_response()
}

async fn callback(
    Query(query): Query<CallbackQuery>,
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    if let Some(_error) = query.error {
        return (StatusCode::BAD_REQUEST, "Error from PayPal").into_response();
    }
    let code = query.code.clone().unwrap_or_default();
    let flow = query.state.as_deref().unwrap_or("full");
    let config = state.get_flow_config(flow);
    
    let redirect_uri = state.redirect_uri.clone();

    let api_base = if state.staging { PAYPAL_SANDBOX_API } else { PAYPAL_PRODUCTION_API };

    let token = match exchange_code_for_token(&code, &config.client_id, &config.client_secret, &redirect_uri, api_base).await {
        Ok(t) => t,
        Err(e) => {
            error!("Token exchange failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Token exchange failed: {}", e)).into_response();
        }
    };

    let userinfo = match get_userinfo(&token.access_token, api_base).await {
        Ok(u) => u,
        Err(e) => {
            error!("Userinfo failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Userinfo failed: {}", e)).into_response();
        }
    };

    let attestation = generate_attestation(&state, config.label.clone(), userinfo.clone()).await;

    // Show all userinfo data as formatted JSON
    let userinfo_full_json = serde_json::to_string_pretty(&userinfo).unwrap();

    let html = HTML_TEMPLATE.replace(
        "{{CONTENT}}",
        &format!(
            r#"
        <h1>Authentication Successful</h1>
        <div class="info">
            <h3>Verified PayPal User Profile</h3>
            <pre>{}</pre>
        </div>
        <div class="attestation">
            <h3>Hardware-Attested Enclave Report</h3>
            <p><strong>Certificate Authority:</strong> Google Public CA</p>
            <p><strong>Enclave Mode:</strong> {}</p>
            <p><strong>Hashed & Signed Evidence:</strong></p>
            <pre id="raw_report">{}</pre>
        </div>
        <button onclick="downloadReport()" class="btn" style="background:#4caf50; margin-right: 10px;">Download Attestation Report (.json)</button>
        <a href="/" class="btn" style="background: #333;">Back</a>

        <script>
            function downloadReport() {{
                const data = document.getElementById('raw_report').innerText;
                const blob = new Blob([data], {{ type: 'application/json' }});
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = 'attestation_report.json';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
            }}
        </script>
        "#,
            html_escape::encode_text(&userinfo_full_json),
            if state.staging { "Confidential Sandbox" } else { "Confidential Production" },
            html_escape::encode_text(&attestation),
        ),
    );
    
    if let Err(status) = state.record_egress_data(addr.ip(), html.len() as u64) {
        return status.into_response();
    }

    Html(html).into_response()
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
    
    // 1. PID 1 RESPONSIBILITIES: Mount filesystems FIRST!
    enclave_init::mount_filesystems();
    // 2. Now load drivers (requires /sys, /proc)
    enclave_init::load_drivers();
    // 3. Finally measure boot components
    let boot_manifest = enclave_init::measure_boot_components();

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

        async_main(boot_manifest).await
    })
}

async fn async_main(boot_manifest: std::collections::HashMap<String, String>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    
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
    info!("Starting PayPal Auth on GCP Confidential VM (v71 Hardened)");
    info!("SECRET_NAME={:?}", std::env::var("SECRET_NAME"));

    eprintln!("[DEBUG] about to fetch config");
    
    // --- MEASURED BOOT ---
    // Measure the running binary into PCR 15 as defined in AGENTS.md
    if let Ok(exe) = std::env::current_exe() {
        if let Ok(data) = std::fs::read(&exe) {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();
            let hash_hex = hex::encode(hash);
            info!("Measured Boot: Extending PCR 15 with BIN_HASH={}", hash_hex);
            let _ = tpm::run_cmd("tpm2_pcrextend", &["15:sha256", &hash_hex]).await;
        }
    }
    // Log current PCR 15 state for diagnostics
    if let Ok(pcr_out) = tpm::run_cmd("tpm2_pcrread", &["sha256:15"]).await {
        info!("Current PCR 15 State:\n{}", String::from_utf8_lossy(&pcr_out).trim());
    }

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

    // v69: Attestation Signing Key handling (cloned to avoid partial move of config)
    let attestation_signing_key = if let Some(key) = config.attestation_signing_key.clone() {
        info!("Attestation signing key loaded from Vault");
        Some(key)
    } else {
        info!("Attestation signing key missing in Vault, generating ephemeral RAM-ONLY RSA 4096 key...");
        acme2_eab::gen_rsa_private_key(4096).ok().map(|k| {
            let pem = String::from_utf8(k.private_key_to_pem_pkcs8().expect("Failed to convert key to PEM")).unwrap();
            info!("--- EPHEMERAL RSA KEY GENERATED (RAM ONLY) ---");
            info!("{}", pem);
            info!("----------------------------------------------");
            pem
        })
    };

    // Initialize app state
    eprintln!("[DEBUG] building app state");
    let state = Arc::new(AppState {
        paypal_client_id: config.paypal_client_id.clone(),
        paypal_client_secret: config.paypal_client_secret.clone(),
        paypal_verified_client_id: config.paypal_verified_client_id.clone().unwrap_or_default(),
        paypal_verified_client_secret: config.paypal_verified_client_secret.clone().unwrap_or_default(),
        redirect_uri,
        used_paypal_ids: Arc::new(RwLock::new(HashSet::new())),
        domain: config.domain.clone(),
        https_ready: https_ready_clone,
        staging: config.staging,
        tls_cert_pem: Arc::new(RwLock::new(None)),
        attestation_signing_key,
        ip_stats: Arc::new(RwLock::new(HashMap::new())),
        global_egress_bytes: Arc::new(AtomicU64::new(0)),
        last_limit_reset: Arc::new(RwLock::new(Instant::now())),
        connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        boot_manifest,
    });

    // Build the main app router
    eprintln!("[DEBUG] building router");
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/privacy", get(privacy))
        .route("/terms", get(terms))
        .route("/report", get(|| async { Redirect::to("/") }))
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

    let state_for_http = state.clone();
    let http_handle = tokio::spawn(async move {
        loop {
            let (stream, addr) = match http_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to accept HTTP connection: {}", e);
                    continue;
                }
            };
            let router = http_router.clone();
            let semaphore = state_for_http.connection_semaphore.clone();

            tokio::spawn(async move {
                let _permit = match semaphore.try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        error!("Concurrency limit reached (HTTP)");
                        return;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |mut req| {
                    let router = router.clone();
                    req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
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
            *state.tls_cert_pem.write() = Some(String::from_utf8_lossy(&r.0).to_string());
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

    let state_for_https = state.clone();
    let https_handle = tokio::spawn(async move {
        loop {
            let (stream, addr) = match https_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to accept HTTPS connection: {}", e);
                    continue;
                }
            };
            let ssl_config = https_tls_config.clone();
            let app = app.clone();
            let semaphore = state_for_https.connection_semaphore.clone();

            tokio::spawn(async move {
                let _permit = match semaphore.try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        error!("Concurrency limit reached (HTTPS)");
                        return;
                    }
                };
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
                let svc = hyper::service::service_fn(move |mut req| {
                    let app = app.clone();
                    req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
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
