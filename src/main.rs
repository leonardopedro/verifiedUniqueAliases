//! PaynePal OAuth Confidential VM
//!
//! Configuration: Single JSON secret in GCP Secret Manager  
//! TLS: Google Public CA via ACME
//! Runtime: GCP Confidential VM (AMD SEV-SNP) or Oracle Cloud OCI SEV-SNP depending on build target

mod oci_snp;  // AMD SEV-SNP attestation adapter for OCI E5/E6 confidential instances
#[cfg(feature = "oci")]
mod oci_principal;  // Instance-principal auth + Secret Management fetch (Option A / Vuln 2)

const GOOGLE_CA_PEM: &[u8] = include_bytes!("google_ca.pem");
const PAYPAL_CA_PEM: &[u8] = include_bytes!("paypal.pem");

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
        // v128: Final boss mode module loading
        let _ = std::process::Command::new("/bin/mount").args(["-t", "proc", "none", "/proc"]).status();
        let _ = std::process::Command::new("/bin/mount").args(["-t", "sysfs", "none", "/sys"]).status();
        let _ = std::process::Command::new("/bin/mount").args(["-t", "configfs", "none", "/sys/kernel/config"]).status();
        
        insmod_all();
        
        // Try to clear existing (possibly broken) attestation state (AMD paths — GCP & OCI)
        let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "amd_tsm"]).status();
        let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "amd-tsm"]).status();
        let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "tsm"]).status();
        let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "tsm_report"]).status();
        let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "sev_guest"]).status();
        let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "sev-guest"]).status();

        modprobe("configfs");
        let _ = std::process::Command::new("/bin/mount").args(["-t", "configfs", "none", "/sys/kernel/config"]).status();
        
        modprobe("virt_anchor");
        modprobe("coco");
        
        modprobe("tsm");
        modprobe("amd_tsm");
        modprobe("amd-tsm");
        // v148: crypto prerequisites for the sev_guest probe — probe calls
        // crypto_alloc_aead("gcm(aes)"); if gcm/ghash are absent the probe
        // fails with -EIO and /dev/sev-guest never appears (both SNP paths
        // depend on it: PATH 0 ioctl and PATH 3 ConfigFS TSM provider).
        // gf128mul is pulled in as ghash_generic's modules.dep dependency.
        modprobe("gcm");
        modprobe("ghash_generic");
        modprobe("sev-guest");
        modprobe("sev_guest");
        modprobe("coco_guest");
        
        // v134: Aggressive probe retry (AMD platforms — GCP & OCI)
        let _ = std::process::Command::new("/bin/sh").args(["-c", "echo sev-guest > /sys/bus/platform/drivers/sev-guest/bind"]).status();
        
        if !std::path::Path::new("/sys/kernel/config/tsm").exists()
        {
             let _ = std::process::Command::new("/bin/mkdir").args(["-p", "/sys/kernel/config/tsm"]).status();
        }
  
        modprobe("gve");
        modprobe("virtio_net");
        modprobe("virtio_scsi");
        modprobe("virtio_blk");
        modprobe("virtio_pci");
        modprobe("nvme");
        modprobe("nvme_core");
        // v153b (real-OCI E5 bring-up, 2026-10-13): the boot volume on OCI
        // confidential E5 is a paravirtualized SCSI device ("ORACLE
        // BlockVolume" behind virtio_scsi) — without sd_mod no /dev/sda*
        // node ever appears, the ESP can never be mounted, and every report
        // ships `disk_manifest: {}` (❌ Image Atomicity). sd_mod/sr_mod are
        // staged in the OL10 initramfs but were never modprobe'd (qemu
        // attaches the disk as virtio-blk/vda, which masked the bug).
        modprobe("sd_mod");
        modprobe("sr_mod");
        
        // v91: Recursive module hunter for attestation drivers
        kmsg("Scanning for attestation modules...");
        let _ = std::process::Command::new("find").args(["/lib/modules", "-name", "*sev*", "-o", "-name", "*tsm*", "-o", "-name", "*coco*"]).status();
        
        modprobe("tpm_tis");
        modprobe("tpm_crb");
        
        modprobe("vfat");
        modprobe("nls_cp437");
        modprobe("nls_ascii");

        // v116: Strict Kernel Egress Filtering via nftables
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
            "add rule inet filter output tcp dport 443 accept",
        ];

        // v152 SECURITY: FAIL-CLOSED firewall. The old code only logged
        // spawn errors AND ignored non-zero exit statuses — a missing or
        // broken `nft` (e.g. glibc mismatch in the OL10 initramfs) left the
        // enclave running with NO egress filtering at all. Any failure now
        // aborts the boot: operating without the firewall violates the
        // threat model, so halting beats serving an unfiltered enclave.
        for cmd in commands {
            match std::process::Command::new("/usr/sbin/nft").arg(cmd).status() {
                Ok(st) if st.success() => {}
                Ok(st) => {
                    kmsg(&format!("FATAL: nft command '{}' exited with {} — fail-closed", cmd, st));
                    poweroff();
                }
                Err(e) => {
                    kmsg(&format!("FATAL: failed to execute nft command '{}': {} — fail-closed", cmd, e));
                    poweroff();
                }
            }
        }
        kmsg("Egress firewall active: default DROP, only DNS/80/443/metadata/loopback permitted");
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
        
        // CRITICAL FIX: load configfs module BEFORE trying to mount it
        modprobe("configfs");
        mount_fs("configfs", "/sys/kernel/config", "configfs");
        std::fs::create_dir_all("/dev/pts").ok();

        // 9. Mount EFI partition to measure the boot chain.
        //    vfat's default iocharset (utf8) needs the nls_utf8 module, which
        //    is NOT staged in the OL10 initramfs — a plain vfat mount then
        //    fails on OCI. Retry with the NLS charsets that are kernel
        //    builtins (nls_ascii / nls_cp437). GCP standard is sda1, VirtIO
        //    is vda1; OCI E5 is vda1 (virtio-blk) or nvme0n1p1 (PV-NVMe).
        std::fs::create_dir_all("/boot/efi").ok();
        for efi_dev in ["/dev/sda1", "/dev/vda1", "/dev/nvme0n1p1"] {
            let mounted = [None, Some("iocharset=ascii"), Some("iocharset=cp437")].into_iter().any(|opts| {
                let src = std::ffi::CString::new(efi_dev).unwrap();
                let tgt = std::ffi::CString::new("/boot/efi").unwrap();
                let fst = std::ffi::CString::new("vfat").unwrap();
                let data_c = opts.map(std::ffi::CString::new).transpose().ok().flatten();
                let data_ptr = data_c.as_ref().map(|c| c.as_ptr().cast::<std::ffi::c_void>()).unwrap_or(std::ptr::null());
                let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), libc::MS_RDONLY, data_ptr) };
                if ret == 0 {
                    kmsg(&format!("Mounted EFI partition {} at /boot/efi{}", efi_dev, opts.map(|o| format!(" ({o})")).unwrap_or_default()));
                }
                ret == 0
            });
            if mounted { break; }
        }

        kmsg("Filesystems mounted");
    }

    pub fn measure_boot_components() -> std::collections::BTreeMap<String, String> {
        use sha2::{Digest, Sha256};
        let mut manifest = std::collections::BTreeMap::new();
        
        let mount_point = "/tmp/esp";
        let _ = std::fs::create_dir_all(mount_point);

        // v153 (audit follow-up: empty `disk_manifest` on OCI): this manifest
        // is what verify.html's GitHub-provenance half audits on TPM-less
        // reports — an empty manifest renders as "❌ Image Atomicity". On the
        // live OCI E5 instance it was empty because UEK8's vfat defaults to
        // iocharset=utf8 and nls_utf8 is NOT staged in the OL10 initramfs,
        // so every plain vfat mount failed with EIO. Fix: explicit iocharset
        // fallbacks using NLS charsets that are kernel builtins on both UEK8
        // and Debian (nls_ascii / nls_cp437), plus broader discovery.
        modprobe("vfat");
        modprobe("nls_cp437");
        modprobe("nls_ascii");

        fn mount_device_logged(source: &str, target: &str, data: Option<&str>, log_fail: bool) -> bool {
            let src = std::ffi::CString::new(source).unwrap();
            let tgt = std::ffi::CString::new(target).unwrap();
            let fst = std::ffi::CString::new("vfat").unwrap();
            let data_c = match data { Some(d) => std::ffi::CString::new(d).ok(), None => None };
            let data_ptr = match &data_c {
                Some(c) => c.as_ptr().cast::<std::ffi::c_void>(),
                None => std::ptr::null(),
            };
            let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), libc::MS_RDONLY, data_ptr) };
            if ret == 0 {
                kmsg(&format!("Successfully mounted {}{} -> {}", source, data.map(|d| format!(" ({d})")).unwrap_or_default(), target));
                true
            } else {
                if log_fail {
                    kmsg(&format!("vfat mount of {} failed: {}", source, std::io::Error::last_os_error()));
                }
                false
            }
        }

        // 1. Prefer the ESP that mount_filesystems() already mounted at
        //    /boot/efi — same volume, and it proves the mount path worked.
        if std::fs::read_dir("/boot/efi").map(|mut e| e.next().is_some()).unwrap_or(false) {
            kmsg("Measuring boot components from already-mounted /boot/efi");
            hash_recursive("/boot/efi", "/boot/efi", &mut manifest);
            if !manifest.is_empty() {
                kmsg(&format!("Disk manifest: {} files measured (pre-mounted ESP)", manifest.len()));
                return manifest;
            }
        }

        // 2. DYNAMIC DISCOVERY: try EVERY block device (partitions AND
        //    whole-disk images — the old digit-only filter skipped bare
        //    `vda`/`sda`, which is how an unpartitioned ESP would appear),
        //    each across the iocharset fallbacks. loop/ram/zram devices are
        //    skipped: never the ESP, and a stray loop mount could shadow it.
        //
        //    v153b: RETRY with patience. On real OCI E5 the PV disk attaches
        //    as a virtio-scsi LUN whose async SCSI scan + sd probe completes
        //    a few hundred ms AFTER the drivers load (measured on hardware:
        //    scan at ~2.18s, single-shot measurement at ~2.31s saw ZERO
        //    block devices → empty manifest). Scan for up to ~10s.
        let mut success = false;
        'rounds: for round in 0..20u32 {
            let mut candidates: Vec<String> = std::fs::read_dir("/sys/class/block")
                .map(|entries| {
                    let mut v: Vec<String> = entries.filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .filter(|n| !n.starts_with("loop") && !n.starts_with("ram") && !n.starts_with("zram"))
                        .collect();
                    v.sort();
                    v
                })
                .unwrap_or_default();
            if round == 0 || round == 4 || round == 12 {
                kmsg(&format!("block devices (round {}): {:?}", round, candidates));
            }
            let log_fail = round < 3;
            for dev_name in &candidates {
                let dev_path = format!("/dev/{}", dev_name);
                for opts in [None, Some("iocharset=ascii"), Some("iocharset=cp437")] {
                    if mount_device_logged(&dev_path, mount_point, opts, log_fail) {
                        success = true;
                        break 'rounds;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        if !success {
            kmsg("CRITICAL: Failed to mount EFI System Partition after scanning all devices!");
        }

        fn hash_recursive(dir: &str, mount_point: &str, manifest: &mut std::collections::BTreeMap<String, String>) {
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
        if success {
            hash_recursive(mount_point, mount_point, &mut manifest);
            let tgt = std::ffi::CString::new(mount_point).unwrap();
            unsafe { libc::umount(tgt.as_ptr()); }
        }
        kmsg(&format!("Disk manifest: {} files measured", manifest.len()));
        manifest
    }

    fn insmod_all() {
        kmsg("Aggressively loading all discovered modules via insmod...");
        let paths = ["/sbin/find", "/usr/bin/find", "/bin/find", "find"];
        for path in &paths {
            if let Ok(output) = std::process::Command::new(path).args(["/lib/modules", "-name", "*.ko"]).output() {
                let s = String::from_utf8_lossy(&output.stdout);
                for line in s.lines() {
                    if line.contains("tsm") || line.contains("sev") || line.contains("coco") || line.contains("anchor") || line.contains("virtio") || line.contains("gve") || line.contains("configfs") {
                        kmsg(&format!("insmod {}", line));
                        let _ = std::process::Command::new("/sbin/insmod").arg(line).status();
                    }
                }
                break;
            }
        }
    }

    fn modprobe(module: &str) {
        let paths = ["/sbin/modprobe", "/usr/sbin/modprobe", "/bin/modprobe", "modprobe"];
        let mut success = false;
        let mut last_err = String::from("no path ran");
        for path in &paths {
            match std::process::Command::new(path).arg(module).output() {
                Ok(out) if out.status.success() => {
                    kmsg(&format!("modprobe {} (via {}): OK", module, path));
                    success = true;
                    break;
                },
                Ok(out) => {
                    if last_err == "no path ran" {
                        let err = String::from_utf8_lossy(&out.stderr);
                        let sout = String::from_utf8_lossy(&out.stdout);
                        last_err = format!(
                            "rc={} out='{}' err='{}'",
                            out.status.code().unwrap_or(-1),
                            sout.trim(),
                            err.trim()
                        );
                    }
                },
                Err(e) => {
                    if last_err == "no path ran" {
                        last_err = format!("spawn {}: {}", path, e);
                    }
                },
            }
        }
        if !success {
            kmsg(&format!("modprobe {}: ALL PATHS FAILED ({})", module, last_err));
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
        
        // CRITICAL GCP FIX: Set MTU to 1460 to avoid fragmentation on ACME/TLS packets
        let _ = Command::new("/sbin/ip").args(["link", "set", "dev", iface, "mtu", "1460"]).status();
        
        kmsg(&format!("Network up: {} gw={:?} mtu=1460", cidr, lease.gw));
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

        // CRITICAL FIX: Prevent Time-Rollback TLS breakage.
        // Seed the system clock to a realistic 2026 epoch.
        let _ = std::process::Command::new("/bin/date")
            .args(["-s", "@1777000000"])
            .status();

        // SYNC TIME from trusted source over PINNED TLS
        // Because clock is >= 2026, the TLS handshake will succeed.
        {
            // GCP & OCI: Use Google as time source
            if let Ok(resp) = crate::hardened_client().get("https://www.google.com").send().await {
                if let Some(date_str) = resp.headers().get("Date") {
                    if let Ok(date) = date_str.to_str() {
                        let _ = std::process::Command::new("/bin/date").args(["-s", date]).status();
                        kmsg(&format!("System time cryptographically synced to: {}", date));
                    }
                }
            }
        }

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
    Json, Router,
};
use acme2_eab::{
    gen_rsa_private_key, AccountBuilder, AuthorizationStatus, DirectoryBuilder, OrderBuilder, Csr,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Semaphore;
use tokio::net::TcpListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use std::collections::BTreeMap;
use std::net::IpAddr;

// ============================================================================
// CONSTANTS
// ============================================================================

mod tpm {
    use tokio::process::Command;
    use tracing::error;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Serialize};

    pub const PCR_SELECTION: &str = "0,4,8,9,15";

    #[derive(Serialize, Deserialize, Clone)]
    pub struct SealedData {
        pub pub_blob: String,
        pub priv_blob: String,
    }

    #[derive(Serialize, Deserialize, Clone)]
    #[allow(dead_code)]  // GCP-specific helper, used selectively in code paths
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
        // v153: VLEK (Versioned Loaded Endorsement Key) when the PSP cert
        // table offers one — some multi-tenant confidential hosts sign
        // reports with a vendor-loaded key instead of the chip VCEK.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub vlek_der_b64: Option<String>,
        // v154: Where the published endorsement leaf came from, so auditors
        // can see the provenance of the key that (should) verify the report:
        // "psp-table:VCEK" / "psp-table:VLEK" (silicon-provisioned, authoritative),
        // "psp-table+kds-chain:…" (leaf from PSP, chain completed from KDS),
        // "kds" (AMD KDS — only published when it actually verifies).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub vcek_source: Option<String>,
        // Legacy TDX schema fields — always None after the OCI migration,
        // kept so older reports remain deserializable.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pck_cert_pem: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tdx_policy: Option<String>,
        pub platform_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub td_info: Option<serde_json::Value>,
    }

    pub mod snp {
        use std::fs;
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        pub fn get_report(nonce: &[u8; 64]) -> Option<(Vec<u8>, Option<String>)> {
            // v124: Use the modern unified TSM (Trusted Security Module) ConfigFS interface
            let tsm_base = "/sys/kernel/config/tsm/report";
            // v125: Ensure the TSM ConfigFS hierarchy is present
            if !fs::metadata(tsm_base).is_ok() {
                let _ = std::process::Command::new("mkdir").args(["-p", tsm_base]).status();
            }

            // v124: Use a unique directory name per request to avoid race conditions or stale reports
            let unique_id = hex::encode(&nonce[..16]);
            let report_dir = format!("{}/paypal_audit_{}", tsm_base, unique_id);
            
            // Clean up any stale directory if it exists
            let _ = fs::remove_dir_all(&report_dir);
            
            if let Err(e) = fs::create_dir(&report_dir) {
                tracing::error!("Failed to create TSM report directory {}: {}", report_dir, e);
                return None;
            }

            // 1. Set the nonce/inblob
            if let Err(e) = fs::write(format!("{}/inblob", report_dir), nonce) {
                tracing::error!("Failed to write inblob to ConfigFS: {}", e);
                let _ = fs::remove_dir_all(&report_dir);
                return None;
            }

            // 2. Wait for hardware report generation (ConfigFS is asynchronous)
            // Some vTPMs/CPUs are slow to generate the silicon signature.
            std::thread::sleep(std::time::Duration::from_millis(1000));

            // 3. Read the report
            let report_path = format!("{}/outblob", report_dir);
            let report = match fs::read(&report_path) {
                Ok(data) => {
                    tracing::info!("Successfully read SNP report from ConfigFS outblob ({} bytes)", data.len());
                    Some(data)
                },
                Err(e) => {
                    tracing::error!("Failed to read outblob from ConfigFS at {}: {}", report_path, e);
                    None
                }
            };

            let auxblob = match fs::read(format!("{}/auxblob", report_dir)) {
                Ok(data) if !data.is_empty() => {
                    tracing::info!("Successfully read SNP auxblob from ConfigFS ({} bytes)", data.len());
                    Some(STANDARD.encode(&data))
                },
                _ => None,
            };

            // Cleanup
            let _ = fs::remove_dir_all(&report_dir);
            report.map(|r| (r, auxblob))
        }
    }

    pub async fn run_cmd(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new(cmd)
            .args(args)
            .env("TCTI", "device:/dev/tpmrm0")
            .env("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")
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
        // v117: Enforce PCR policy (0,4,8,9,15) to prevent unsealing on a modified image
        let policy_file = "/tmp/policy.bin";
        // v118: Explicitly specify --policy-pcr
        run_cmd("tpm2_createpolicy", &[
            "--policy-pcr",
            "-l", &format!("sha256:{}", PCR_SELECTION),
            "-L", policy_file,
        ]).await?;

        run_cmd("tpm2_create", &[
            "-C", "/tmp/primary_seal.ctx",
            "-r", "/tmp/dek.priv",
            "-u", "/tmp/dek.pub",
            "-i", "/tmp/dek.plain",
            "-L", policy_file,
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

    // =========================================================================
    // v152: AMD KDS material cache — VCEK + ASK/ARK cert chain
    // ---------------------------------------------------------------------------
    // The enclave may boot from a read-only root or a volatile initramfs, so KDS
    // material is fetched ONCE and persisted. Directory resolution order:
    //   1. $AMD_VCEK_CACHE_DIR           explicit override (bring-up / tests)
    //   2. /persistent/.enclave/amd-kds  writable persistent mount (survives reboot)
    //   3. /tmp/amd-kds-cache            tmpfs fallback when /persistent is absent
    // A cache miss (or an expired / partial entry) is the ONLY reason to hit
    // kdsintf.amd.com again. The VCEK cache name embeds chip_id + reported TCB
    // SPLs, so a TCB update changes the key and triggers exactly one fresh
    // download — every other boot reuses the persisted cert.
    // =========================================================================

    /// Writable cache directory, chosen once per process.
    fn kds_cache_dir() -> Option<std::path::PathBuf> {
        static DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
        DIR.get_or_init(|| {
            let mut candidates: Vec<std::path::PathBuf> = Vec::new();
            if let Ok(d) = std::env::var("AMD_VCEK_CACHE_DIR") {
                if !d.is_empty() { candidates.push(std::path::PathBuf::from(d)); }
            }
            candidates.push(std::path::PathBuf::from("/persistent/.enclave/amd-kds"));
            candidates.push(std::path::PathBuf::from("/tmp/amd-kds-cache"));
            for dir in &candidates {
                if std::fs::create_dir_all(dir).is_ok() {
                    let probe = dir.join(".probe");
                    if std::fs::write(&probe, b"1").is_ok() {
                        let _ = std::fs::remove_file(&probe);
                        tracing::info!("v152: AMD KDS cache directory: {}", dir.display());
                        return Some(dir.clone());
                    }
                }
            }
            tracing::warn!("v152: no writable AMD KDS cache directory — every attestation will hit kdsintf.amd.com");
            None
        }).clone()
    }

    /// Cache name for a VCEK: family + chip + reported TCB SPLs. Any TCB
    /// component changing produces a new key → forced re-download for that TCB.
    fn kds_vcek_cache_name(family: &str, chip_id: &str, bl: u8, tee: u8, snp: u8, ucode: u8) -> String {
        format!("vcek-{}-{}-{:02}{:02}{:02}{:02}.der", family, chip_id, bl, tee, snp, ucode)
    }

    /// Re-download certs that expire within this window (an expired VCEK would
    /// fail the auditor's chain check anyway — expiry outranks TCB stability).
    const KDS_CERT_MARGIN_SECS: i64 = 7 * 24 * 3600;

    fn kds_cert_not_expired(cert: &openssl::x509::X509) -> bool {
        let margin = match openssl::asn1::Asn1Time::from_unix(chrono::Utc::now().timestamp() + KDS_CERT_MARGIN_SECS) {
            Ok(m) => m,
            Err(_) => return false,
        };
        match margin.diff(cert.not_after()) {
            // not_after − margin > 0 → cert still valid past the margin.
            Ok(d) => d.days > 0 || (d.days == 0 && d.secs > 0),
            Err(_) => false,
        }
    }

    /// A cached VCEK is usable iff it parses (PEM or raw DER — KDS serves DER)
    /// and its validity window comfortably outlives the next attestation.
    fn kds_vcek_is_fresh(bytes: &[u8]) -> bool {
        match openssl::x509::X509::from_pem(bytes).or_else(|_| openssl::x509::X509::from_der(bytes)) {
            Ok(c) => kds_cert_not_expired(&c),
            Err(_) => false,
        }
    }

    /// Number of `-----BEGIN CERTIFICATE-----` markers in a PEM blob.
    fn kds_chain_cert_count(pem: &[u8]) -> usize {
        pem.windows(27).filter(|w| *w == b"-----BEGIN CERTIFICATE-----").count()
    }

    /// Split a PEM bundle into parsed X.509 certificates (order preserved).
    fn kds_pem_certs(pem: &[u8]) -> Vec<openssl::x509::X509> {
        let text = String::from_utf8_lossy(pem);
        let mut out = Vec::new();
        for chunk in text.split("-----END CERTIFICATE-----") {
            let begin = match chunk.find("-----BEGIN CERTIFICATE-----") { Some(i) => i, None => continue };
            let block = format!("{}-----END CERTIFICATE-----", &chunk[begin..]);
            if let Ok(c) = openssl::x509::X509::from_pem(block.as_bytes()) { out.push(c); }
        }
        out
    }

    /// The published chain must be the FULL issuer path — ASK (signs the VCEK)
    /// → ARK (root). verify.html anchors silicon trust ONLY on the ARK (SHA-256
    /// of its raw DER) and walks VCEK→ASK→ARK itself, so a blob shorter than
    /// ASK+ARK can never validate: it is neither cached nor published.
    fn kds_chain_is_fresh(pem: &[u8]) -> bool {
        if kds_chain_cert_count(pem) < 2 { return false; }
        let certs = kds_pem_certs(pem);
        certs.len() >= 2 && certs.iter().all(kds_cert_not_expired)
    }

    async fn fetch_vcek(chip_id: &str, bl: u8, tee: u8, snp: u8, ucode: u8) -> Option<String> {
        // Family-aware KDS endpoint (Milan / Genoa / Turin) derived from CPUID
        let family = crate::oci_snp::amd_kds_family();
        let cache_name = kds_vcek_cache_name(&family, chip_id, bl, tee, snp, ucode);

        // 1. Cache first — reused across boots until the TCB (key) changes.
        if let Some(dir) = kds_cache_dir() {
            let path = dir.join(&cache_name);
            match tokio::fs::read(&path).await {
                Ok(bytes) if !bytes.is_empty() && kds_vcek_is_fresh(&bytes) => {
                    tracing::info!("v152: VCEK cache hit {} ({} bytes)", path.display(), bytes.len());
                    return Some(STANDARD.encode(&bytes));
                }
                Ok(_) => tracing::warn!("v152: cached VCEK expired/unparsable — re-downloading {}", path.display()),
                Err(_) => {} // miss (incl. TCB change → new cache name)
            }
        }

        // 2. Fetch from the public AMD KDS (standard client: no pinning).
        let client = reqwest::Client::new();
        let url = format!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}", family, chip_id, bl, tee, snp, ucode);
        tracing::info!("v136: Fetching VCEK from {}", url);
        let bytes = match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    match resp.bytes().await {
                        Ok(b) => { tracing::info!("v136: VCEK fetch succeeded ({} bytes)", b.len()); Some(b) },
                        Err(e) => { tracing::warn!("v136: VCEK body read failed: {}", e); None },
                    }
                } else {
                    tracing::warn!("v136: VCEK fetch failed with status {}. Response: {:?}", status, resp.text().await.unwrap_or_default());
                    None
                }
            },
            Err(e) => { tracing::warn!("v136: VCEK fetch HTTP error: {}", e); None }
        }?;

        // 3. Persist (best effort) and prune superseded TCBs for this chip so
        //    the cache directory holds exactly one VCEK per chip.
        if let Some(dir) = kds_cache_dir() {
            let path = dir.join(&cache_name);
            match tokio::fs::write(&path, &bytes).await {
                Ok(()) => {
                    tracing::info!("v152: VCEK persisted to {}", path.display());
                    let prefix = format!("vcek-{}-{}-", family, chip_id);
                    if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
                        while let Ok(Some(entry)) = rd.next_entry().await {
                            let name = entry.file_name();
                            let name = name.to_string_lossy();
                            if name.starts_with(&prefix) && name != cache_name.as_str() {
                                let _ = tokio::fs::remove_file(entry.path()).await;
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!("v152: VCEK cache write to {} failed: {}", path.display(), e),
            }
        }

        Some(STANDARD.encode(&bytes))
    }

    async fn fetch_amd_chain() -> Option<String> {
        let family = crate::oci_snp::amd_kds_family();
        let cache_name = format!("chain-{}.pem", family);

        // 1. Cache first — family-scoped and TCB-independent.
        if let Some(dir) = kds_cache_dir() {
            let path = dir.join(&cache_name);
            if let Ok(text) = tokio::fs::read(&path).await {
                if kds_chain_is_fresh(&text) {
                    tracing::info!("v152: AMD cert chain cache hit {} ({} certs)", path.display(), kds_chain_cert_count(&text));
                    return Some(STANDARD.encode(&text));
                }
                tracing::warn!("v152: cached AMD chain incomplete/stale — re-downloading {}", path.display());
            }
        }

        let client = reqwest::Client::new();
        match client.get(format!("https://kdsintf.amd.com/vcek/v1/{}/cert_chain", family)).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        if !kds_chain_is_fresh(text.as_bytes()) {
                            // Fail closed: a partial chain can never satisfy the
                            // auditor's ARK pin, so refuse to cache/publish it.
                            tracing::error!("v152: AMD chain fetch returned an incomplete chain ({} certs, need ASK+ARK) — refusing to publish", kds_chain_cert_count(text.as_bytes()));
                            return None;
                        }
                        tracing::info!("v136: AMD chain fetch succeeded ({} certs)", kds_chain_cert_count(text.as_bytes()));
                        // 2. Persist (best effort).
                        if let Some(dir) = kds_cache_dir() {
                            let path = dir.join(&cache_name);
                            if let Err(e) = tokio::fs::write(&path, &text).await {
                                tracing::warn!("v152: AMD chain cache write to {} failed: {}", path.display(), e);
                            }
                        }
                        return Some(STANDARD.encode(text.as_bytes()));
                    }
                } else {
                    tracing::warn!("v136: AMD chain fetch failed with status {}", resp.status());
                }
            },
            Err(e) => tracing::warn!("v136: AMD chain fetch HTTP error: {}", e),
        }
        None
    }

    // v152: Warm the KDS cache up front — fetch the VCEK + cert chain once and
    // persist them BEFORE the first attestation request. Uses a zero-nonce SNP
    // report only to read chip_id + TCB SPLs for the cache key; that report is
    // never presented as evidence. No-op when valid cache entries exist.
    #[cfg(feature = "oci")]
    pub async fn warm_kds_cache() {
        if !std::path::Path::new("/dev/sev-guest").exists() {
            tracing::info!("v152: KDS warm-up skipped (/dev/sev-guest absent)");
            return;
        }
        let report = match crate::oci_snp::snp_get_report(&[0u8; 64]) {
            Some(r) => r,
            None => { tracing::warn!("v152: KDS warm-up skipped (zero-nonce SNP report unavailable)"); return; }
        };
        let info = match crate::oci_snp::parse_report(&report) {
            Some(i) => i,
            None => { tracing::warn!("v152: KDS warm-up skipped (SNP report unparsable)"); return; }
        };
        tracing::info!("v152: warming AMD KDS cache — chip {} TCB {:02}{:02}{:02}{:02}", &info.chip_id_hex[..16], info.bl, info.tee, info.snp, info.ucode);
        let vcek = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await;
        let chain = fetch_amd_chain().await;
        tracing::info!("v152: KDS warm-up complete (vcek={}, chain={})", vcek.is_some(), chain.is_some());
    }

    // v154: Boot-time diagnostics for the AMD endorsement path. On OCI E5
    // hosts with VLEK-style provisioning the PSP's signing key is NOT in
    // kdsintf.amd.com, so the ONLY authoritative endorsement leaf comes from
    // the PSP's own certificate table (SNP_GET_EXT_REPORT). This probe runs
    // with a zero-nonce report (never presented as evidence) and logs, to the
    // serial console, exactly which certs this host offers and which of them
    // verifies a live report — so a host-level key mismatch is visible from
    // the boot log without needing a full attestation run.
    #[cfg(feature = "oci")]
    pub async fn diagnostic_psp_probe() {
        use base64::Engine as _;
        if !std::path::Path::new("/dev/sev-guest").exists() {
            tracing::info!("v154: PSP diag skipped (/dev/sev-guest absent)");
            return;
        }
        let ext = crate::oci_snp::snp_get_ext_report(&[0u8; 64]);
        // The plain report works even when the extended request doesn't — the
        // KDS verdict below must still run: it is the per-host oracle that
        // decides whether reports from this host are third-party verifiable.
        let (report, certs) = match &ext {
            Some(e) => (e.report.clone(), Some(e.certs.clone())),
            None => {
                tracing::warn!("v154: PSP diag: SNP_GET_EXT_REPORT failed — hypervisor provides no cert table on this host (SNP_SET_EXT_CONFIG not provisioned); KDS is the only cert source");
                match crate::oci_snp::snp_get_report(&[0u8; 64]) {
                    Some(r) => (r, None),
                    None => { tracing::warn!("v154: PSP diag: zero-nonce SNP report unavailable"); return; }
                }
            }
        };
        let Some(info) = crate::oci_snp::parse_report(&report) else {
            tracing::warn!("v154: PSP diag: zero-nonce report unparsable");
            return;
        };
        if let Some(certs) = certs.as_ref() {
            let table = crate::oci_snp::parse_snp_cert_table(certs);
            tracing::info!("v154: PSP diag: certs blob {} bytes — vcek={} vlek={} ask={} ark={}",
                certs.len(),
                table.vcek.as_ref().map(|c| crate::oci_snp::hash_cert(c)).unwrap_or_default(),
                table.vlek.as_ref().map(|c| crate::oci_snp::hash_cert(c)).unwrap_or_default(),
                table.ask.is_some(), table.ark.is_some());
            for (label, leaf) in [("VCEK", &table.vcek), ("VLEK", &table.vlek)] {
                if let Some(l) = leaf {
                    let sig_ok = crate::oci_snp::verify_report_signature(&report, l);
                    let chain_ok = match (&table.ask, &table.ark) {
                        (Some(a), Some(k)) => crate::oci_snp::validate_amd_chain(l, a, k),
                        _ => false,
                    };
                    tracing::info!("v154: PSP diag: {} leaf sig_ok={} chain_ok(table)={}", label, sig_ok, chain_ok);
                }
            }
        }
        if let Some(b64) = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await {
            if let Ok(der) = STANDARD.decode(&b64) {
                tracing::info!("v154: PSP diag: KDS VCEK sig_ok={} (chip {} TCB {:02}{:02}{:02}{:02})",
                    crate::oci_snp::verify_report_signature(&report, &der),
                    &info.chip_id_hex[..16], info.bl, info.tee, info.snp, info.ucode);
            }
        } else {
            tracing::warn!("v154: PSP diag: no KDS VCEK for this chip/TCB (404?)");
        }
    }

    #[cfg(test)]
    mod kds_cache_tests {
        fn self_signed(days: u32) -> openssl::x509::X509 {
            use openssl::asn1::Asn1Time;
            use openssl::hash::MessageDigest;
            use openssl::pkey::PKey;
            use openssl::rsa::Rsa;
            use openssl::x509::X509Builder;
            let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
            let mut b = X509Builder::new().unwrap();
            b.set_version(2).unwrap();
            let mut name = openssl::x509::X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "kds-cache-test").unwrap();
            let name = name.build();
            b.set_subject_name(&name).unwrap();
            b.set_issuer_name(&name).unwrap();
            b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
            b.set_not_after(&Asn1Time::days_from_now(days).unwrap()).unwrap();
            b.set_pubkey(&pkey).unwrap();
            b.sign(&pkey, MessageDigest::sha256()).unwrap();
            b.build()
        }

        #[test]
        fn vcek_cache_key_is_tcb_scoped() {
            let base = super::kds_vcek_cache_name("Genoa", "cafe", 1, 0, 8, 113);
            assert_eq!(base, "vcek-Genoa-cafe-010008113.der");
            // TCB change (any SPL) → new key → exactly one forced re-download.
            assert_ne!(base, super::kds_vcek_cache_name("Genoa", "cafe", 1, 0, 9, 113));
            assert_ne!(base, super::kds_vcek_cache_name("Genoa", "cafe", 2, 0, 8, 113));
            // Different chip or family never collides.
            assert_ne!(base, super::kds_vcek_cache_name("Genoa", "dead", 1, 0, 8, 113));
            assert_ne!(base, super::kds_vcek_cache_name("Milan", "cafe", 1, 0, 8, 113));
        }

        #[test]
        fn vcek_freshness_tracks_expiry() {
            let fresh = self_signed(365).to_pem().unwrap();
            let stale = self_signed(3).to_pem().unwrap(); // inside the 7-day margin
            assert!(super::kds_vcek_is_fresh(&fresh));
            assert!(!super::kds_vcek_is_fresh(&stale));
            assert!(!super::kds_vcek_is_fresh(b"not a certificate"));
            // Raw DER form (what KDS actually serves) is accepted too.
            let der = self_signed(365).to_der().unwrap();
            assert!(super::kds_vcek_is_fresh(&der));
        }

        #[test]
        fn chain_requires_full_ask_to_ark_path() {
            let pem = self_signed(365).to_pem().unwrap();
            let full = [pem.as_slice(), pem.as_slice()].concat();
            assert_eq!(super::kds_chain_cert_count(&full), 2);
            assert!(super::kds_pem_certs(&full).len() == 2);
            assert!(super::kds_chain_is_fresh(&full));
            // ASK without ARK (or a single cert) is never accepted/published.
            assert!(!super::kds_chain_is_fresh(&pem));
            assert_eq!(super::kds_chain_cert_count(&pem), 1);
        }
    }


    /// v160 (Pillar 2): SNP report_data (64 bytes) =
    /// bytes 0..32: SHA-256( P_enc SPKI DER ∥ session-nonce raw bytes )
    /// bytes 32..64: zero
    ///
    /// The hardware quote commits DIRECTLY to the ephemeral enclave key
    /// (P_enc) on top of everything the session nonce already covers (paypal
    /// ∥ pubkey hash ∥ custom_info ∥ binary ∥ manifest). The auditor
    /// recomputes expectedBinding = SHA-256(pemToBuffer(
    /// enclave_signing_public_key) ∥ expectedNonce) and requires
    /// report_data[0..32] === expectedBinding — pinned by
    /// `security_tests::snp_report_data_binding_parity_v160` ↔ node harness
    /// Test 8 (update all three together). The GCP TPM-quote extraData path
    /// is untouched: it still carries the raw session nonce.
    pub(crate) fn snp_report_data_binding(pubkey_der: &[u8], nonce_hex: &str) -> [u8; 64] {
        use sha2::{Digest, Sha256};
        let mut out = [0u8; 64];
        let nonce_raw = hex::decode(nonce_hex).unwrap_or_default();
        let mut binding_hasher = Sha256::new();
        binding_hasher.update(pubkey_der);
        binding_hasher.update(&nonce_raw);
        out[..32].copy_from_slice(&binding_hasher.finalize());
        out
    }

    /// v161 (plan Pillars 2–5): CLIENT-BOUND SNP report_data —
    /// bytes 0..32: SHA-256( P_enc SPKI DER ∥ code_challenge ∥
    ///                       P_client SPKI DER ∥ client_nonce[32] )
    /// bytes 32..64: zero
    ///
    /// The hardware quote commits to the exact browser session that requested
    /// the pre-flight: the ephemeral enclave signing key, the PKCE challenge
    /// the enclave will present to PayPal, the browser's ephemeral ECDH key,
    /// and the browser's nonce. Only a report carrying ALL four inputs in its
    /// report_data satisfies the auditor (verify.html `preflightBindingHex`,
    /// pinned by `security_tests::preflight_binding_parity_v161` ↔ node
    /// harness Test 9 — update all three together). The v160 session binding
    /// (snp_report_data_binding) stays for the legacy /debug/envelope path.
    pub(crate) fn preflight_report_data_binding(
        pubkey_der: &[u8],
        code_challenge: &str,
        client_pub_der: &[u8],
        client_nonce: &[u8; 32],
    ) -> [u8; 64] {
        use sha2::{Digest, Sha256};
        let mut out = [0u8; 64];
        let mut h = Sha256::new();
        h.update(pubkey_der);
        h.update(code_challenge.as_bytes());
        h.update(client_pub_der);
        h.update(client_nonce);
        out[..32].copy_from_slice(&h.finalize());
        out
    }

    /// v160 (Pillar 2): `pubkey_der` is P_enc's SubjectPublicKeyInfo DER —
    /// bound into the SNP report_data as SHA-256(P_enc ∥ session_nonce) so the
    /// hardware quote commits directly to the ephemeral enclave key. The GCP
    /// TPM-quote extraData keeps carrying the raw session nonce (unchanged).
    pub async fn quote(nonce_hex: &str, pubkey_der: &[u8], report_data_override: Option<[u8; 64]>) -> Result<AttestationResult, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(feature = "oci")]
        if crate::oci_snp::is_sev_snp_available() {
            tracing::info!("AMD SEV-SNP hardware attestation path active (OCI)");
        }

        // TPM presence probe: OCI confidential instances expose NO vTPM — the SNP
        // report is the sole hardware evidence there. GCP always has the vTPM.
        let tpm_available = std::path::Path::new("/dev/tpmrm0").exists()
            || std::path::Path::new("/dev/tpm0").exists();
        if !tpm_available {
            tracing::warn!("No TPM device present — TPM quote skipped, AMD SEV-SNP report carries hardware attestation");
        }
        
        let work_dir = format!("/tmp/tpm_{}", hex::encode(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_be_bytes()));
        let _ = std::fs::create_dir_all(&work_dir);

        let _primary_ctx = format!("{}/primary.ctx", work_dir);
        let _ak_ctx = format!("{}/ak.ctx", work_dir);
        let _ak_pub = format!("{}/ak.pub", work_dir);
        let _ak_priv = format!("{}/ak.priv", work_dir);
        let ak_pem = format!("{}/ak.pem", work_dir);
        let _ak_der = format!("{}/ak.der", work_dir);
        let quote_msg = format!("{}/quote.msg", work_dir);
        let quote_sig = format!("{}/quote.sig", work_dir);
        // v135: GCP delivers the AMD SEV-SNP report in the TPM quote's auxblob
        // This is the ONLY way to get AMD hardware-signed data on GCP.
        let auxblob_path = format!("{}/auxblob.bin", work_dir);

        // 1. Find the persistent AK handle dynamically from the GCP vTPM
        //    (skipped entirely when no TPM device exists — OCI confidential VMs)
        let mut ak_ctx = String::new();
        
        // v143: Aggressive 'Shotgun' AK Discovery with explicit error logging
        let standard_handles = ["0x81010002", "0x81010001", "0x81000001", "0x81000002"];
        if tpm_available {
        for h in &standard_handles {
            // Try both tpm2_readpublic and tpm2 readpublic
            for cmd in ["tpm2_readpublic", "tpm2"] {
                let args = if cmd == "tpm2" { vec!["readpublic", "-c", h] } else { vec!["-c", h] };
                match run_cmd(cmd, &args).await {
                    Ok(pub_out) => {
                        let pub_str = String::from_utf8_lossy(&pub_out).to_lowercase();
                        if pub_str.contains("sign") {
                            tracing::info!("DEBUG: Successfully anchored to hardware AK handle: {} (via {})", h, cmd);
                            ak_ctx = h.to_string();
                            break;
                        }
                    },
                    Err(e) => {
                        tracing::warn!("DEBUG: Failed to read handle {} via {}: {}", h, cmd, e);
                    }
                }
            }
            if !ak_ctx.is_empty() { break; }
        }
        }

        if ak_ctx.is_empty() && tpm_available {
            tracing::error!("Standard handles failed. SYSTEMATIC SEARCH of persistent handles...");
            // Try systemically searching a wider range if the cap list fails
            for i in 0..10 {
                let h = format!("0x8101000{:x}", i);
                if let Ok(pub_out) = run_cmd("tpm2_readpublic", &["-c", &h]).await {
                    if String::from_utf8_lossy(&pub_out).to_lowercase().contains("sign") {
                        ak_ctx = h;
                        break;
                    }
                }
            }
        }

        if ak_ctx.is_empty() && tpm_available {
            tracing::warn!("Systematic search failed. Attempting capability discovery...");
            for cmd in ["tpm2_getcap", "tpm2"] {
                let args = if cmd == "tpm2" { vec!["getcap", "handles-persistent"] } else { vec!["handles-persistent"] };
                match run_cmd(cmd, &args).await {
                    Ok(handles_out) => {
                        let str_out = String::from_utf8_lossy(&handles_out);
                        tracing::info!("Discovered persistent handles via {}: {}", cmd, str_out);
                        for part in str_out.split(|c: char| !c.is_alphanumeric() && c != 'x') {
                            if part.starts_with("0x81") {
                                let h_str = part.to_string();
                                if let Ok(pub_out) = run_cmd("tpm2_readpublic", &["-c", &h_str]).await {
                                    if String::from_utf8_lossy(&pub_out).to_lowercase().contains("sign") {
                                        ak_ctx = h_str;
                                        break;
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => tracing::error!("Capability discovery failed via {}: {}", cmd, e),
                }
                if !ak_ctx.is_empty() { break; }
            }
        }
        
        // v145: GCP vTPM Architecture — Session AK for Signing
        // The Google EK Cert (NVRAM) proves hardware identity. The TPM Quote is signed
        // by a fresh session signing key (session AK), created via tpm2_createprimary.
        // These are intentionally different keys — EK = silicon proof, session AK = quote signer.
        if ak_ctx.is_empty() && tpm_available {
            tracing::info!("Creating session signing AK via tpm2_createprimary...");
            let ak_ctx_file = format!("{}/ak.ctx", work_dir);
            for cmd in ["tpm2_createprimary", "tpm2"] {
                let args = if cmd == "tpm2" {
                    vec!["createprimary", "-C", "e", "-g", "sha256", "-G", "rsa2048", "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign", "-c", &ak_ctx_file]
                } else {
                    vec!["-C", "e", "-g", "sha256", "-G", "rsa2048", "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign", "-c", &ak_ctx_file]
                };
                match run_cmd(cmd, &args).await {
                    Ok(_) => {
                        tracing::info!("Session signing AK created via {}", cmd);
                        ak_ctx = ak_ctx_file;
                        break;
                    },
                    Err(e) => tracing::error!("createprimary failed via {}: {}", cmd, e),
                }
            }
        }

        
        // Final fallback: Failure (only fatal when a TPM exists but no AK could be
        // derived — i.e. the GCP path. TPM-less OCI instances continue with the
        // SEV-SNP report as sole hardware evidence.)
        if ak_ctx.is_empty() && tpm_available {
            return Err("CRITICAL: Could not find or derive a hardware-bound AK. Identity cannot be verified.".into());
        }

        // TPM-derived evidence: AK PEM, signed quote, PCRs, EK cert.
        // Only populated when a TPM device exists (GCP vTPM). OCI confidential
        // instances have no vTPM — these fields stay empty and the AMD SEV-SNP
        // report (PATH 0) carries the hardware attestation instead.
        let (ak_pem_str, msg, sig, pcr_values, ek_cert, ak_der_bytes) =
            if tpm_available && !ak_ctx.is_empty() {
        // Extract AK PEM for the report
        run_cmd("tpm2_readpublic", &["-c", &ak_ctx, "-f", "pem", "-o", &ak_pem]).await?;
        let ak_pem_str = tokio::fs::read_to_string(&ak_pem).await?;

        tracing::info!("DEBUG: TPM Quote starting with nonce 0x{}...", nonce_hex);
        run_cmd("tpm2_quote", &[
            "-c", &ak_ctx,
            "-l", &format!("sha256:{}", PCR_SELECTION),
            "-q", &nonce_hex,
            "-m", &quote_msg,
            "-s", &quote_sig,
            // v135: Request the GCP SNP auxblob — this contains the AMD hardware-signed report
            "-o", &auxblob_path,
        ]).await?;
        tracing::info!("DEBUG: TPM Quote done.");

        // v117: Capture the public key hash that was bound to this nonce (if any)
        // Note: The nonce_hex passed here is already the combined hash.
        let msg = tokio::fs::read(&quote_msg).await?;
        let sig = tokio::fs::read(&quote_sig).await?;

        let pcr_out = match run_cmd("tpm2_pcrread", &[&format!("sha256:{}", PCR_SELECTION)]).await {
            Ok(out) => out,
            Err(e) => {
                error!("TPM tpm2 pcrread FAILED: {}", e);
                vec![]
            }
        };
        let pcr_str = String::from_utf8_lossy(&pcr_out);
        tracing::info!("TPM PCRREAD OUT: {}", pcr_str);
        tracing::info!("TPM PCR SELECTION WAS: {}", PCR_SELECTION);
        let mut pcr_values = std::collections::BTreeMap::new();
        for line in pcr_str.lines() {
            if line.contains(':') && !line.trim().is_empty() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let idx = parts[0].trim_matches(|c: char| !c.is_numeric()).to_string();
                    let val = parts[1].trim().to_string();
                    if !idx.is_empty() && !val.is_empty() {
                        pcr_values.insert(format!("pcr_{}", idx), val);
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

        // 🔴 FIX: Cryptographically bind using raw DER bytes instead of the PEM string.
        // PEM strings can have varying newlines which silently break the hash.
        use base64::{engine::general_purpose::STANDARD as _STANDARD2, Engine as _};
        let ak_b64 = ak_pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
            .replace(|c: char| c.is_whitespace(), "");
        let ak_der_bytes = _STANDARD2.decode(ak_b64).unwrap_or_default();

                (ak_pem_str, msg, sig, pcr_values, ek_cert, ak_der_bytes)
            } else {
                tracing::warn!("No TPM evidence available — proceeding with empty TPM fields (SNP report is the hardware root)");
                (String::new(), Vec::new(), Vec::new(), std::collections::BTreeMap::new(), None, Vec::new())
            };

        // Hardware SNP Report & AMD Certificates
        use sha2::Digest;
        let ak_der_sha256 = hex::encode(sha2::Sha256::digest(&ak_der_bytes));

        // v160 (Pillar 2): SNP report_data = SHA-256(P_enc ∥ nonce), rest zero
        // — see snp_report_data_binding() for the full contract.
        // v161 (Pillars 2–5): pre-flight sessions override this with the
        // client-bound binding (P_enc ∥ code_challenge ∥ P_client ∥ nonce_c).
        let nonce_bytes = report_data_override.unwrap_or_else(|| snp_report_data_binding(pubkey_der, nonce_hex));

        tracing::info!("DEBUG: SNP report_data binding prepared ({})", if report_data_override.is_some() { "v161 client-bound" } else { "SHA-256(P_enc ∥ nonce)" });
        // 1. Fetch Google AK Certificate (Mandatory Identity Root)
        // v137: Directly fetch from TPM NVRAM (primary path) with enlarged buffer (2048 bytes)
        // to prevent truncation of the hardware-bound AMD SNP extensions.
        let mut google_ak_cert_pem = None;
        tracing::info!("Retrieving Google AK Certificate from hardware NVRAM...");
        let indices = [("0x01c00002", "2048"), ("0x01c00001", "2048")];
        for (idx, _size_hint) in &indices {
            if let Ok(data) = run_cmd("tpm2", &["nvread", idx, "-C", "o"]).await {
                if !data.is_empty() {
                    tracing::info!("Obtained Google AK Cert from NVRAM index {} ({} bytes)", idx, data.len());
                    // v125: Manually wrap Base64 in PEM headers to avoid dependency on openssl in initramfs
                    let b64 = STANDARD.encode(&data);
                    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
                    for chunk in b64.as_bytes().chunks(64) {
                        pem.push_str(std::str::from_utf8(chunk).unwrap());
                        pem.push('\n');
                    }
                    pem.push_str("-----END CERTIFICATE-----\n");
                    google_ak_cert_pem = Some(pem);
                    break;
                }
            }
        }

        // v136: AMD SEV-SNP Hardware Report — Three-Path Acquisition Strategy
        // The AMD hardware root of trust: report signed by VCEK (fused AMD silicon key).
        // Independently verifiable against AMD's KDS without trusting Google.
        let mut auxblob_b64 = None;
        let mut vcek_der_b64 = None;
        let mut vlek_der_b64 = None;
        let mut amd_chain_b64 = None;
        let mut snp_report_b64 = None;
        // v154: provenance of the published endorsement leaf (auditor-visible).
        let mut vcek_source: Option<String> = None;

        // Helper closure to try parsing SNP report from a byte slice.
        // Delegates to oci_snp::parse_report — correct offsets:
        // chip_id @ 0x1A0, reported_tcb @ 0x180 (family-aware TCB byte layout).
        let try_parse_snp = |data: &[u8]| -> Option<crate::oci_snp::SnpReportInfo> {
            for &offset in &[0usize, 4, 8, 16, 32, 64] {
                if data.len() > offset {
                    if let Some(info) = crate::oci_snp::parse_report(&data[offset..]) {
                        tracing::info!("AMD TCB Info - ChipID: {}, BL: {}, TEE: {}, SNP: {}, UCode: {}",
                            &info.chip_id_hex[..16], info.bl, info.tee, info.snp, info.ucode);
                        return Some(info);
                    }
                }
            }
            None
        };

        // PATH 0: OCI /dev/sev-guest — SNP_GET_EXT_REPORT (extended guest request,
        // GHCB v2): the PSP returns the session-bound attestation report AND its
        // own VCEK/VLEK + ASK + ARK certificate table in one call. The
        // silicon-provisioned certs are authoritative — on some OCI E5 hosts the
        // PSP's signing key does NOT match the kdsintf.amd.com entry for the
        // same chip_id/TCB, so KDS-fetched certs fail to verify the live
        // report's signature. KDS remains the fallback (legacy kernels, or an
        // incomplete PSP table).
        #[cfg(feature = "oci")]
        if snp_report_b64.is_none() {
            tracing::info!("v153: PATH 0 — /dev/sev-guest SNP_GET_EXT_REPORT (report + PSP cert table)");
            let mut got_ext = false;
            if let Some(ext) = crate::oci_snp::snp_get_ext_report(&nonce_bytes) {
                if let Some(info) = crate::oci_snp::parse_report(&ext.report) {
                    tracing::info!("v153: PATH 0 ext report {} bytes, AMD chip {}", info.report.len(), &info.chip_id_hex[..16]);
                    let table = crate::oci_snp::parse_snp_cert_table(&ext.certs);
                    tracing::info!("v153: PSP cert table — vcek={} vlek={} ask={} ark={}",
                        table.vcek.as_ref().map(|c| crate::oci_snp::hash_cert(c)).unwrap_or_default(),
                        table.vlek.as_ref().map(|c| crate::oci_snp::hash_cert(c)).unwrap_or_default(),
                        table.ask.is_some(), table.ark.is_some());
                    // vlek_der_b64: publish the vendor-loaded key when present so
                    // auditors can see which key the PSP actually offers.
                    if let Some(vlek) = table.vlek.as_ref() {
                        vlek_der_b64 = Some(STANDARD.encode(vlek));
                    }
                    // Try EVERY endorsement leaf the PSP offers (VCEK first,
                    // then VLEK). Ground truth is the SIGNATURE: on some
                    // multi-tenant confidential hosts the report is signed by
                    // a vendor-loaded key (VLEK-style provisioning) whose
                    // entry is NOT in AMD KDS — only the PSP knows the real
                    // signer. The chain is completed from the table when
                    // present, else from the KDS ASK/ARK (issuer keys are
                    // not chip-specific). A leaf is published iff it verifies
                    // this report's signature; a valid chain alone proves
                    // nothing about who signed THIS report.
                    let table_chain = match (table.ask.clone(), table.ark.clone()) {
                        (Some(ask), Some(ark)) => Some((ask, ark, "psp-table".to_string())),
                        _ => {
                            if table.vcek.is_some() || table.vlek.is_some() {
                                tracing::warn!("v154: PSP table has a leaf but no ASK/ARK — completing chain from KDS");
                                match fetch_amd_chain().await {
                                    Some(pem) => {
                                        let ders = crate::oci_snp::pem_certs_to_der(&pem);
                                        match (ders.first(), ders.get(1)) {
                                            (Some(ask), Some(ark)) => Some((ask.clone(), ark.clone(), "psp-table+kds-chain".to_string())),
                                            _ => { tracing::warn!("v154: KDS chain unusable ({} certs) — probing leaves without chain", ders.len()); None }
                                        }
                                    }
                                    None => None,
                                }
                            } else {
                                None
                            }
                        }
                    };
                    let mut published = false;
                    for (label, leaf) in [("VCEK", table.vcek.clone()), ("VLEK", table.vlek.clone())] {
                        let leaf = match leaf { Some(l) => l, None => continue };
                        let sig_ok = crate::oci_snp::verify_report_signature(&info.report, &leaf);
                        let chain_ok = table_chain.as_ref().map(|(ask, ark, _)| crate::oci_snp::validate_amd_chain(&leaf, ask, ark)).unwrap_or(false);
                        tracing::info!("v154: {} leaf: sig_ok={} chain_ok={} sha256={}", label, sig_ok, chain_ok, &crate::oci_snp::hash_cert(&leaf)[..16]);
                        if sig_ok {
                            let source = match (table_chain.as_ref(), chain_ok) {
                                (Some((_, _, how)), true) => format!("{}:{}", how, label),
                                (Some((_, _, how)), false) => format!("{}:{}(chain-unverified)", how, label),
                                (None, _) => format!("psp-table:{}(chain-unverified)", label),
                            };
                            tracing::info!("v154: PSP cert table VERIFIED with {} (report signed by this key, source={})", label, source);
                            vcek_der_b64 = Some(STANDARD.encode(&leaf));
                            vcek_source = Some(source);
                            if let Some((ask, ark, _)) = table_chain.as_ref() {
                                let chain_pem = format!("{}{}",
                                    crate::oci_snp::der_to_pem("CERTIFICATE", ask),
                                    crate::oci_snp::der_to_pem("CERTIFICATE", ark));
                                amd_chain_b64 = Some(STANDARD.encode(chain_pem.as_bytes()));
                            }
                            published = true;
                            break;
                        }
                    }
                    if !published {
                        tracing::error!("v154: NO PSP leaf (VCEK/VLEK) verifies this report — trying KDS");
                    }
                    snp_report_b64 = Some(STANDARD.encode(&info.report));
                    got_ext = true;
                    // KDS fallback — verify BEFORE publishing. On OCI E5 hosts
                    // whose PSP key is not in KDS (VLEK-style provisioning) the
                    // KDS VCEK chains fine to the ARK but does NOT sign this
                    // report; publishing it would give auditors a cert that
                    // fails the signature check (sig=false). Fail closed:
                    // publish nothing rather than a wrong key.
                    if vcek_der_b64.is_none() {
                        if let Some(b64) = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await {
                            match STANDARD.decode(&b64) {
                                Ok(der) if crate::oci_snp::verify_report_signature(&info.report, &der) => {
                                    tracing::info!("v154: KDS VCEK verifies the live report — publishing (source=kds)");
                                    vcek_der_b64 = Some(b64);
                                    vcek_source = Some("kds".to_string());
                                }
                                Ok(_) => tracing::error!("v154: KDS VCEK does NOT verify the live report signature (OCI PSP/KDS key mismatch) — NOT publishing it; report ships without an endorsement leaf and auditors must fail closed"),
                                Err(e) => tracing::error!("v154: KDS VCEK undecodable: {}", e),
                            }
                        }
                    }
                    if amd_chain_b64.is_none() {
                        amd_chain_b64 = fetch_amd_chain().await;
                    }
                } else {
                    tracing::error!("v153: PATH 0 ext report unparseable");
                }
            }
            if !got_ext {
                // Legacy path: plain SNP_GET_REPORT (older kernels without the
                // extended request) — certs from AMD KDS as before, but with
                // the SAME verify-before-publish rule as the ext path (SEC-02/
                // v154): on hosts whose PSP signs with a key KDS does not
                // hold, the KDS cert chains to the ARK yet does NOT sign this
                // report — publishing it would give auditors a cert that
                // fails the signature check. Fail closed instead.
                tracing::info!("v136: PATH 0 — /dev/sev-guest SNP_GET_REPORT");
                if let Some(report) = crate::oci_snp::snp_get_report(&nonce_bytes) {
                    if let Some(info) = crate::oci_snp::parse_report(&report) {
                        tracing::info!("v136: PATH 0 report {} bytes, AMD chip {}", info.report.len(), &info.chip_id_hex[..16]);
                        if let Some(b64) = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await {
                            match STANDARD.decode(&b64) {
                                Ok(der) if crate::oci_snp::verify_report_signature(&info.report, &der) => {
                                    tracing::info!("v155: plain-report KDS VCEK verifies the live report — publishing (source=kds)");
                                    vcek_der_b64 = Some(b64);
                                    vcek_source = Some("kds".to_string());
                                }
                                Ok(_) => tracing::error!("v155: plain-report KDS VCEK does NOT verify the live report signature (OCI PSP/KDS key mismatch) — NOT publishing; report ships without an endorsement leaf"),
                                Err(e) => tracing::error!("v155: plain-report KDS VCEK undecodable: {}", e),
                            }
                        }
                        amd_chain_b64 = fetch_amd_chain().await;
                        snp_report_b64 = Some(STANDARD.encode(&info.report));
                    } else {
                        tracing::error!("v136: PATH 0 produced an unparseable SNP report");
                    }
                }
            }
        }

        // PATH 1: GCP vTPM NVRAM — AMD SNP report provisioned by hypervisor at boot
        // Index 0x01400001 is the well-known GCP location for the hardware SNP report.
        tracing::info!("v136: PATH 1 — NVRAM discovery and systematic scan");
        let mut discovered_handles = vec!["0x01400001".to_string(), "0x01400002".to_string(), "0x01c00003".to_string()];
        if let Ok(output) = run_cmd("tpm2", &["getcap", "handles-nv-indices"]).await {
             let s = String::from_utf8_lossy(&output);
             for line in s.lines() {
                 if let Some(h) = line.split_whitespace().find(|s| s.starts_with("0x")) {
                     discovered_handles.push(h.to_string());
                 }
             }
        }
        discovered_handles.sort();
        discovered_handles.dedup();
        tracing::info!("v136: Scanning discovered NV handles: {:?}", discovered_handles);

        if snp_report_b64.is_none() {
        'nvram: for idx in &discovered_handles {
            let data = if let Ok(d) = run_cmd("tpm2_nvread", &["-C", "o", idx]).await { d }
                       else if let Ok(d) = run_cmd("tpm2_nvread", &["-C", "p", idx]).await { d }
                       else if let Ok(d) = run_cmd("tpm2_nvread", &["-C", "e", idx]).await { d }
                       else if let Ok(d) = run_cmd("tpm2", &["nvread", idx]).await { d }
                       else { continue; };

            if data.len() < 32 { continue; }
            tracing::info!("v136: NVRAM {} returned {} bytes", idx, data.len());
            
            // v147: Chip ID Hunter — scan for SNP report header at any offset
            for offset in (0..data.len().saturating_sub(1088)).step_by(8) {
                if let Some(info) = try_parse_snp(&data[offset..]) {
                    tracing::info!("v147: Found SNP report at NVRAM {} offset {}", idx, offset);
                    tracing::info!("v147: AMD Chip ID: {}", &info.chip_id_hex[..16]);
                    vcek_der_b64 = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await;
                    amd_chain_b64 = fetch_amd_chain().await;
                    snp_report_b64 = Some(STANDARD.encode(&info.report));
                    break 'nvram;
                }
            }
            
            // Fallback for smaller/truncated reports in auxblob
            if let Some(info) = try_parse_snp(&data) {
                tracing::info!("v136: Parsed SNP report ({} bytes) from NVRAM {}", info.report.len(), idx);
                vcek_der_b64 = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await;
                amd_chain_b64 = fetch_amd_chain().await;
                snp_report_b64 = Some(STANDARD.encode(&info.report));
                break 'nvram;
            }
        }
        }

        // PATH 2: TPM quote auxblob (PCR qualification data — may contain SNP embedding)
        if snp_report_b64.is_none() {
            tracing::info!("v136: PATH 2 — TPM quote auxblob");
            if let Ok(raw) = tokio::fs::read(&auxblob_path).await {
                if !raw.is_empty() {
                    tracing::info!("v136: auxblob {} bytes", raw.len());
                    if auxblob_b64.is_none() { auxblob_b64 = Some(STANDARD.encode(&raw)); }
                    
                    // v147: Chip ID Hunter in auxblob
                    for offset in (0..raw.len().saturating_sub(1088)).step_by(8) {
                        if let Some(info) = try_parse_snp(&raw[offset..]) {
                            tracing::info!("v147: Found SNP report in auxblob at offset {}", offset);
                            vcek_der_b64 = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await;
                            amd_chain_b64 = fetch_amd_chain().await;
                            snp_report_b64 = Some(STANDARD.encode(&info.report));
                            break;
                        }
                    }

                    if snp_report_b64.is_none() {
                        if let Some(info) = try_parse_snp(&raw) {
                            vcek_der_b64 = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await;
                            amd_chain_b64 = fetch_amd_chain().await;
                            snp_report_b64 = Some(STANDARD.encode(&info.report));
                            tracing::info!("v136: Found SNP report in auxblob");
                        }
                    }
                }
            }
        }

        // PATH 3: ConfigFS TSM interface (requires sev-guest.ko)
        if snp_report_b64.is_none() {
            tracing::info!("v136: PATH 3 — ConfigFS TSM");
            if let Some((report, aux)) = snp::get_report(&nonce_bytes) {
                if aux.is_some() { auxblob_b64 = aux; }
                if let Some(info) = crate::oci_snp::parse_report(&report) {
                    vcek_der_b64 = fetch_vcek(&info.chip_id_hex, info.bl, info.tee, info.snp, info.ucode).await;
                    amd_chain_b64 = fetch_amd_chain().await;
                    snp_report_b64 = Some(STANDARD.encode(&info.report));
                    tracing::info!("v136: Got SNP report via ConfigFS ({} bytes)", info.report.len());
                } else {
                    snp_report_b64 = Some(STANDARD.encode(&report));
                    tracing::warn!("v136: ConfigFS report ({} bytes) failed strict parse — stored unparsed", report.len());
                }
            }
        }

        if snp_report_b64.is_some() {
            tracing::info!("v136: AMD hardware root established!");
        } else {
            tracing::error!("v136: ALL SNP paths failed — AMD hardware root unavailable");
        }

        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        // Platform identity: both build targets are AMD SEV-SNP.
        // (Legacy Intel TDX / PCK collection removed — OCI migration.)
        let (pck_cert_pem, tdx_policy, platform_type, td_info_json) =
            (None, None, "AMD SEV-SNP".to_string(), None);

        // v154: any leaf that arrived via the KDS-fetching legacy paths
        // (NVRAM / auxblob / ConfigFS) without an explicit provenance label.
        let vcek_source = vcek_source.or_else(|| vcek_der_b64.as_ref().map(|_| "kds".to_string()));

        Ok(AttestationResult {
            tpm_quote_msg: STANDARD.encode(msg),
            tpm_quote_sig: STANDARD.encode(sig),
            ak_pub_pem: ak_pem_str,
            ek_cert,
            pcrs: PCR_SELECTION.to_string(),
            pcr_values,
            nonce_hex: nonce_hex.to_string(),
            snp_report_b64,
            auxblob_b64,
            signature_binding_pubkey_hash: "".to_string(), // Filled by caller
            vcek_der_b64,
            vlek_der_b64,
            vcek_source,
            amd_chain_b64,
            google_ak_cert_pem,
            ak_der_sha256,
            pck_cert_pem,
            tdx_policy,
            platform_type,
            td_info: td_info_json,
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

    /// v161: AES-256-GCM with associated data. The client nonce is
    /// the AAD, so a ciphertext captured in one session cannot be replayed or
    /// spliced into another — decryption fails without the exact session's
    /// nonce (which is itself bound into the hardware quote).
    pub fn encrypt_aad(dek: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        use aes_gcm::aead::Payload;
        let key = Key::<Aes256Gcm>::from_slice(dek);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|e| format!("AesGcm encrypt failed: {:?}", e))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    /// v161: decrypt an AAD-bound ciphertext (mirror of encrypt_aad).
    pub fn decrypt_aad(dek: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use aes_gcm::aead::Payload;
        let key = Key::<Aes256Gcm>::from_slice(dek);
        let cipher = Aes256Gcm::new(key);
        let nonce_arr = Nonce::from_slice(nonce);
        let plaintext = cipher
            .decrypt(nonce_arr, Payload { msg: ciphertext, aad })
            .map_err(|e| format!("AesGcm decrypt failed: {:?}", e))?;
        Ok(plaintext)
    }

    /// v161 (Pillar 5): HKDF-SHA256 (RFC 5869) built on openssl's HMAC — the
    /// same extract-then-expand primitive WebCrypto exposes, so the browser
    /// and the enclave derive byte-identical keys from the ECDH shared secret.
    pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
        use openssl::pkey::PKey;
        use openssl::sign::Signer;
        fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
            let k = PKey::hmac(key).expect("HMAC key");
            // HMAC keys carry the digest in the Signer (not
            // new_without_digest, which is for raw-signature schemes).
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

    /// v161 (Pillars 3+5): ECDH(P-256) → HKDF-SHA256 → 32-byte AES key.
    /// salt = the client's 32-byte nonce (key is useless outside the exact
    /// browser session that requested the pre-flight), info = protocol label
    /// (domain separation from any other HKDF use in this binary).
    pub fn derive_e2ee_session_key(
        enclave_ecdh: &openssl::pkey::PKey<openssl::pkey::Private>,
        client_pub_der: &[u8],
        client_nonce: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        use openssl::derive::Deriver;
        use openssl::pkey::PKey;
        let peer = PKey::public_key_from_der(client_pub_der)
            .map_err(|e| format!("client ECDH public key is not valid SPKI DER: {}", e))?;
        let mut deriver = Deriver::new(enclave_ecdh)?;
        deriver.set_peer(&peer)?;
        let mut ikm = deriver.derive_to_vec()?;
        let mut key = [0u8; 32];
        hkdf_sha256(&ikm, client_nonce, b"paypal-auth-vm/e2ee/v1", &mut key);
        ikm.iter_mut().for_each(|b| *b = 0); // best-effort wipe of the raw secret
        Ok(key)
    }

    /// v161: generate the enclave's per-session ECDH keypair (P_enc_ecdh).
    /// RAM-only, one per pre-flight session, never serialized to disk.
    pub fn generate_ecdh_keypair() -> Result<openssl::pkey::PKey<openssl::pkey::Private>, Box<dyn std::error::Error + Send + Sync>> {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec = EcKey::generate(&group)?;
        Ok(openssl::pkey::PKey::from_ec_key(ec)?)
    }
}


const MAX_TRACKED_IPS: usize = 1000;
const MAX_CONCURRENT_CONNECTIONS: usize = 50;
// v153 SECURITY (audit SEC-05): the GLOBAL_EGRESS_BYTES_PER_HOUR cap (512
// MB/hour shared across all clients) was removed. The homepage is ~3 KB, so
// ~170k cheap requests — or one fat /callback download loop — exhausted the
// shared counter and record_egress_data() returned 429 to EVERY client until
// the hour rolled over: a self-inflicted service-wide DoS with no attacker
// cost. Abuse containment stays per-IP; bulk-volume protection belongs at the
// infrastructure firewall (nftables), not in the request path.
const IP_EGRESS_BYTES_PER_HOUR: u64 = 25 * 1024 * 1024;     // 25 MB
const GOOGLE_PUBLIC_CA_DIRECTORY: &str = "https://dv.acme-v02.api.pki.goog/directory";
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
        .links-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 40px; }
        .card { background: rgba(255,255,255,0.02); padding: 24px; border-radius: 8px; border: 1px solid #30363d; text-decoration: none; color: #c9d1d9; display: block; font-family: system-ui, -apple-system, sans-serif; }
        .card:hover { border-color: #58a6ff; }
        .card h3 { margin: 0 0 10px 0; color: #58a6ff; }
        .card p { margin: 0; font-size: 0.9rem; }
    </style>
</head>
<body><div class="container">{{CONTENT}}</div></body></html>
"#;

// Legal policies migrated to GitHub Pages

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
    #[allow(dead_code)]  // Used in GCP builds for ACME account persistence
    acme_account_json: Option<String>,
    // v69: Asymmetric key for signing the attestation payload
    #[serde(default)]
    attestation_signing_key: Option<String>,
    // v153 Option A (audit Vuln 2): OCID of the OCI Secret Management bundle
    // holding the real configuration. When set on the (non-secret) user_data
    // template, the enclave resolves credentials via instance principals
    // instead of trusting plaintext metadata. Empty credential strings in the
    // template are placeholders — they fail `require_credentials` if the
    // secret cannot be fetched (fail-closed).
    #[serde(default)]
    secret_ocid: Option<String>,
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
    #[allow(dead_code)]  // Used for rate limiting / dedup logic in future versions
    used_paypal_ids: Arc<RwLock<HashSet<String>>>,
    domain: String,
    https_ready: Arc<AtomicBool>,
    staging: bool,
    // v69: For inclusion in remote attestation
    tls_cert_pem: Arc<RwLock<Option<String>>>,
    // v160 (Pillar 2): the ephemeral enclave identity (P_enc / S_enc) —
    // private key PEM stays RAM-only; public material is precomputed for the
    // session nonce and the SNP report_data binding.
    enclave_identity: Option<EphemeralEnclaveIdentity>,
        ip_stats: Arc<RwLock<std::collections::BTreeMap<IpAddr, u64>>>,
        last_limit_reset: Arc<RwLock<Instant>>,
    connection_semaphore: Arc<Semaphore>,
    boot_manifest: BTreeMap<String, String>,
    pending_attestations: Arc<RwLock<std::collections::HashMap<String, (String, PayPalUserInfo, Instant)>>>,
    // v152 SECURITY: OAuth CSRF state. Maps the random `state` token sent to
    // PayPal (also mirrored in the browser's HttpOnly cookie) to the flow
    // label + the PKCE session. Verified strictly on /callback: token must
    // exist server-side, match the cookie, and is single-use.
    // v160 (Pillar 3): value gains the PKCE session — the code_verifier
    // lives ONLY in this in-RAM map (single-use, 10 min TTL).
    pending_oauth_states: Arc<RwLock<std::collections::HashMap<String, (String, PkceSession)>>> ,
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
            stats.clear();
        }
        drop(reset); 

        // Per-IP Data Limit Check (see IP_EGRESS_BYTES_PER_HOUR for why the
        // old global cap was removed — audit SEC-05).
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

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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

impl PayPalUserInfo {
    /// Data minimization for the `verified` flow: keep ONLY the verification
    /// facts PayPal is entitled to return for the `paypalattributes` scope —
    /// the account alias (`user_id`/`payer_id`) and the verified flag.
    ///
    /// Everything else (name, email, address, birthdate, picture, …) is
    /// dropped *immediately after the fetch*, before it can reach: the
    /// verified_account gate, the session store, the completion page, the
    /// nonce hash, or the signed attestation report. Even if the token were
    /// ever over-scoped or PayPal returned extra fields, no profile data can
    /// cross the enclave boundary on this flow.
    fn into_verification_only(self) -> PayPalUserInfo {
        PayPalUserInfo {
            user_id: self.user_id,
            payer_id: self.payer_id,
            verified_account: self.verified_account,
            ..Default::default()
        }
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

// ============================================================================
// GCP SECRET MANAGER (GCP-only; no-op on OCI builds)
// ============================================================================

#[cfg(not(feature = "oci"))]
#[allow(dead_code)]  // Only used in GCP builds, but required for shared code paths
async fn fetch_secret_direct(secret_id: &str) -> Option<String> {
    let client = crate::hardened_client();
    let token_resp: serde_json::Value = client
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform")
        .header("Metadata-Flavor", "Google")
        .send().await.ok()?.json().await.ok()?;
    let access_token = token_resp["access_token"].as_str()?;

    // Audit SEC-07: the operator's GCP project id is no longer hard-coded in
    // this public repo — bake it in at compile time for GCP builds:
    //   GCP_PROJECT_ID=... cargo build --release
    let project_id = gcp_project_id()?;
    let url = format!("https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access", project_id, secret_id);
    let secret_resp: serde_json::Value = client
        .get(&url).bearer_auth(access_token).send().await.ok()?.json().await.ok()?;
    let encoded = secret_resp["payload"]["data"].as_str()?;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok().map(|s| s.trim().trim_matches('\0').to_string())
}

#[cfg(feature = "oci")]
async fn fetch_secret_direct(_secret_id: &str) -> Option<String> {
    None
}

/// Load config from a local JSON file (OCI / general fallback)
async fn load_config_from_file(path: &str) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(content.trim())?;
    Ok(config)
}

async fn fetch_config() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    // Priority 1: Check for environment variables (KeePassXC / Local / OCI)
    if let (Ok(p_id), Ok(p_sec), Ok(pv_id), Ok(pv_sec), Ok(dom)) = (
        std::env::var("PAYPAL_CLIENT_ID"),
        std::env::var("PAYPAL_CLIENT_SECRET"),
        std::env::var("PAYPAL_VERIFIED_CLIENT_ID"),
        std::env::var("PAYPAL_VERIFIED_CLIENT_SECRET"),
        std::env::var("DOMAIN"),
    ) {
        info!("Using configuration from Environment Variables");
        return require_credentials(Config {
            paypal_client_id: p_id,
            paypal_client_secret: p_sec,
            paypal_verified_client_id: Some(pv_id),
            paypal_verified_client_secret: Some(pv_sec),
            domain: dom,
            secret_ocid: None,
            eab_key_id: std::env::var("EAB_KEY_ID").ok(),
            eab_hmac_key: std::env::var("EAB_HMAC_KEY").ok(),
            staging: std::env::var("STAGING").map(|s| s == "true").unwrap_or(false),
            acme_account_json: std::env::var("ACME_ACCOUNT_JSON").ok(),
            attestation_signing_key: std::env::var("ATTESTATION_SIGNING_KEY").ok(),
        });
    }

    // Priority 2: Try local config file (OCI or fallback)
    let config_file_env = std::env::var("CONFIG_FILE").unwrap_or_else(|_| "/etc/paypal-auth/config.json".to_string());
    if let Ok(config) = load_config_from_file(&config_file_env).await {
        info!("Loaded configuration from {}", config_file_env);
        return require_credentials(config);
    }

    // Priority 3: GCP Secret Manager (only on GCP builds)
    #[cfg(not(feature = "oci"))]
    {
        info!("Attempting to fetch configuration from GCP Secret Manager...");
        let gcp_config = fetch_config_from_gcp().await;
        match gcp_config {
            Ok(c) => return require_credentials(c),
            Err(e) => {
                warn!("GCP Secret Manager unavailable: {}. Falling back to file config.", e);
            }
        }
    }

    // Priority 3: OCI instance user_data (JSON config delivered by deploy-oci.sh)
    #[cfg(feature = "oci")]
    {
        info!("Attempting to fetch configuration from OCI instance user_data...");
        match crate::oci_snp::oci_user_data().await {
            Some(raw) => {
                match serde_json::from_str::<Config>(raw.trim()) {
                    Ok(c) => {
                        // Option A: resolve the real config from Secret
                        // Management when the template names a secret OCID.
                        // On fetch/parse failure keep the template — its empty
                        // credential fields then fail `require_credentials`
                        // (fail-closed; no silent plaintext fallback exists
                        // because the migrated template carries no secrets).
                        let c = match c.secret_ocid.clone() {
                            Some(ocid) => {
                                info!("secret_ocid present — resolving configuration via instance principal...");
                                match crate::oci_principal::get_secret_bundle(&ocid).await {
                                    Ok(inner) => match resolve_secret_config(inner.trim()) {
                                        Ok(resolved) => {
                                            info!("Loaded configuration from OCI Secret Management bundle");
                                            resolved
                                        }
                                        Err(e) => {
                                            warn!("Secret bundle is not valid config JSON: {}", e);
                                            c
                                        }
                                    },
                                    Err(e) => {
                                        warn!("Secret bundle fetch failed: {}", e);
                                        c
                                    }
                                }
                            }
                            None => c,
                        };
                        info!("Loaded configuration from OCI instance user_data");
                        return require_credentials(c);
                    }
                    Err(e) => warn!("OCI user_data is not valid config JSON: {}", e),
                }
            }
            None => info!("OCI user_data not available"),
        }
    }

    #[cfg(feature = "oci")]
    {
        info!("OCI build: config provided via environment variables, CONFIG_FILE, or instance user_data");
    }

    Err("Configuration not available. Set PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_VERIFIED_CLIENT_ID, PAYPAL_VERIFIED_CLIENT_SECRET, DOMAIN environment variables, or provide CONFIG_FILE path.".into())
}

/// Parse a secret-bundle payload as the real configuration (Option A).
/// The bundle's own `secret_ocid` field (if any) is cleared so the resolved
/// config can never re-trigger a fetch.
#[cfg(feature = "oci")]
fn resolve_secret_config(secret_json: &str) -> Result<Config, String> {
    let mut cfg: Config = serde_json::from_str(secret_json).map_err(|e| e.to_string())?;
    cfg.secret_ocid = None;
    Ok(cfg)
}

/// GCP project id for the Secret Manager path (GCP build only).
/// Audit SEC-07: not hard-coded anymore — provide it at compile time:
///   GCP_PROJECT_ID=... cargo build --release
#[cfg(not(feature = "oci"))]
fn gcp_project_id() -> Option<&'static str> {
    option_env!("GCP_PROJECT_ID").filter(|s| !s.is_empty())
}

/// Fetch configuration from GCP Secret Manager
#[cfg(not(feature = "oci"))]
async fn fetch_config_from_gcp() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    let project_id = gcp_project_id()
        .ok_or("GCP_PROJECT_ID not baked into this build — GCP Secret Manager path disabled (set the env at compile time)")?;
    let mode_secret = format!("projects/{}/secrets/PAYPAL_AUTH_MODE/versions/latest", project_id);
    let client = hardened_client();

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

    std::env::set_var("ACTIVE_MODE", &mode);
    info!("Active mode from Vault: {}", mode);

    let base_secret_name = if mode == "staging" { "PAYPAL_AUTH_STAGING" } else { "PAYPAL_AUTH_PRODUCTION" };

    let secret_name = std::env::var("SECRET_NAME").unwrap_or_else(|_| {
        format!("projects/{}/secrets/{}/versions/latest", project_id, base_secret_name)
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
    let clean_json = String::from_utf8(decoded)?.trim().trim_matches('\0').to_string();

    let _ = std::fs::write("/tmp/bootstrap_config.json", &clean_json);
    let _ = std::fs::write("/tmp/bootstrap_secret_id.txt", base_secret_name);

    let mut config: Config = serde_json::from_str(&clean_json)?;

    let eab_key_id_secret = fetch_secret_direct("EAB_KEY_ID").await;
    let eab_hmac_secret = fetch_secret_direct("EAB_HMAC_KEY").await;
    if let (Some(kid), Some(hmac)) = (eab_key_id_secret, eab_hmac_secret) {
        config.eab_key_id = Some(kid);
        config.eab_hmac_key = Some(hmac);
    }
    if let Some(id) = fetch_secret_direct("PAYPAL_CLIENT_ID").await { config.paypal_client_id = id; }
    if let Some(sec) = fetch_secret_direct("PAYPAL_CLIENT_SECRET").await { config.paypal_client_secret = sec; }
    if let Some(id) = fetch_secret_direct("PAYPAL_VERIFIED_CLIENT_ID").await { config.paypal_verified_client_id = Some(id); }
    if let Some(sec) = fetch_secret_direct("PAYPAL_VERIFIED_CLIENT_SECRET").await { config.paypal_verified_client_secret = Some(sec); }
    if let Some(staging_env) = fetch_secret_direct("PAYPAL_STAGING").await {
        config.staging = staging_env == "true";
    }

    Ok(config)
}

/// v152 SECURITY: validate credentials instead of substituting hardcoded
/// fallbacks. Live PayPal client secrets must never be compiled into the
/// binary — the OCI image is public-repo-derived and reproducible, so every
/// embedded secret is world-readable. Startup now ABORTS when credentials
/// are missing so a misconfigured deployment fails loudly instead of
/// silently operating on leaked credentials.
fn require_credentials(config: Config) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    fn missing(v: Option<&str>) -> bool {
        match v {
            None => true,
            Some(s) => {
                let s = s.trim();
                s.is_empty() || s == "MISSING_CLIENT_ID" || s == "MISSING_CLIENT_SECRET"
            }
        }
    }
    let mut problems = Vec::new();
    if config.paypal_client_id.trim().is_empty() || config.paypal_client_id.trim() == "MISSING_CLIENT_ID" {
        problems.push("paypal_client_id");
    }
    if config.paypal_client_secret.trim().is_empty() || config.paypal_client_secret.trim() == "MISSING_CLIENT_SECRET" {
        problems.push("paypal_client_secret");
    }
    if missing(config.paypal_verified_client_id.as_deref()) {
        problems.push("paypal_verified_client_id");
    }
    if missing(config.paypal_verified_client_secret.as_deref()) {
        problems.push("paypal_verified_client_secret");
    }
    if !problems.is_empty() {
        return Err(format!(
            "Missing/placeholder PayPal credentials: {}. Provide them via environment variables, CONFIG_FILE, or instance user_data — hardcoded fallbacks were removed in v152.",
            problems.join(", ")
        ).into());
    }
    Ok(config)
}

// ============================================================================
// ACME CERTIFICATE MANAGER (Google Public CA on GCP; Google Public CA on OCI
// when EAB credentials are provisioned, Let's Encrypt fallback without them)
// ============================================================================

struct GooglePublicCaManager {
    domain: String,
    eab_key_id: Option<String>,
    eab_hmac_key: Option<String>,
    // NOTE: `staging` is intentionally absent here.
    // The `staging` flag in the Vault secret controls PayPal Sandbox mode only.
    // ACME/TLS certificates always use the production CA endpoint.
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

    /// Whether External Account Binding credentials are present and usable
    #[cfg(feature = "oci")]
    fn has_eab(&self) -> bool {
        self.eab_key_id.as_deref().map(str::trim).is_some_and(|s| !s.is_empty())
            && self.eab_hmac_key.as_deref().map(str::trim).is_some_and(|s| !s.is_empty())
    }

    /// Select the appropriate ACME directory based on platform and EAB availability
    fn acme_directory(&self) -> &str {
        #[cfg(feature = "oci")]
        {
            // OCI: Google Public CA when EAB credentials are provisioned in the
            // instance config (same CA as GCP — avoids Let's Encrypt's per-week
            // rate limits, which the boot-time re-issuance cycle burns through);
            // fall back to Let's Encrypt (no EAB required) when they are absent.
            if self.has_eab() { GOOGLE_PUBLIC_CA_DIRECTORY } else { LETSENCRYPT_CA_DIRECTORY }
        }
        #[cfg(not(feature = "oci"))]
        {
            // GCP: Use Google Public CA (requires EAB)
            GOOGLE_PUBLIC_CA_DIRECTORY
        }
    }

    /// Whether this CA requires External Account Binding (EAB) credentials
    fn requires_eab(&self) -> bool {
        #[cfg(feature = "oci")]
        { self.has_eab() }
        #[cfg(not(feature = "oci"))]
        { true }
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

        info!("Obtaining TLS certificate via ACME...");
        let acme_url = self.acme_directory();
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
        } else if let Some(account_pem) = self
            .acme_account_json
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            // Cross-boot account persistence: the config carries the ACME
            // account private key, so the SAME account is reused on every boot.
            // No new account — and therefore no still-valid EAB — is needed
            // after the first issuance (Google Public CA EAB keys expire 7
            // days after creation, which would otherwise break every boot).
            // For Google Public CA the key MUST already have an account
            // registered at acme_url (pre-created once with a fresh EAB);
            // CAs that allow account creation without EAB (Let's Encrypt)
            // accept a fresh key here directly.
            info!("Restoring ACME account from config-provided account key...");
            let dir = DirectoryBuilder::new(acme_url.to_string()).build().await?;
            let priv_pem = openssl::pkey::PKey::private_key_from_pem(account_pem.as_bytes())?;
            let mut builder = AccountBuilder::new(dir);
            builder.contact(vec![format!("mailto:admin@{}", self.domain)]);
            builder.terms_of_service_agreed(true);
            builder.private_key(priv_pem);
            let account = builder.build().await?;
            if let Ok(priv_key_pem) = account.private_key().private_key_to_pem_pkcs8() {
                let _ = tokio::fs::write(account_path, priv_key_pem).await;
            }
            account
        } else if self.requires_eab() {
            let kid = self.eab_key_id.as_ref().ok_or("Missing EAB key ID")?;
            info!("Creating new ACME account with EAB Key ID: {}...", &kid[..8.min(kid.len())]);
            let hmac_str = self.eab_hmac_key.as_ref().ok_or("Missing EAB HMAC key")?;

            use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            let hmac_bytes = if hmac_str.contains('-') || hmac_str.contains('_') {
                URL_SAFE_NO_PAD.decode(hmac_str.trim()).map_err(|e| format!("EAB HMAC URL-Safe decode failed: {}", e))?
            } else {
                STANDARD.decode(hmac_str.trim()).map_err(|e| format!("EAB HMAC Standard decode failed: {}", e))?
            };
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
        } else {
            // No EAB required (Let's Encrypt / OCI)
            info!("Creating new ACME account (no EAB)...");
            let dir = DirectoryBuilder::new(acme_url.to_string()).build().await?;
            let mut builder = AccountBuilder::new(dir);
            builder.contact(vec![format!("mailto:admin@{}", self.domain)]);
            builder.terms_of_service_agreed(true);
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
            let challenge = auth.challenges.iter().find(|c| c.r#type == "http-01")
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
        // TLS caching relies on cloud KMS — only available on GCP builds
        #[cfg(feature = "oci")]
        {
            info!("TLS cache via GCP Secret Manager not available on OCI builds");
            return None;
        }
        #[cfg(not(feature = "oci"))]
        {
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

        info!("DEK unsealed, decrypting TLS private key...");

        let nonce = STANDARD.decode(wrapper["nonce"].as_str()?).ok()?;
        let ciphertext = STANDARD.decode(wrapper["ciphertext"].as_str()?).ok()?;
        let plaintext = crypto::decrypt(&dek, &nonce, &ciphertext).ok()?;

        let inner_json: serde_json::Value = serde_json::from_slice(&plaintext).ok()?;
        let key = STANDARD.decode(inner_json["key"].as_str()?).ok()?;
        
        // v118: cert and acme_key are now in the outer wrapper (clear base64)
        let cert = STANDARD.decode(wrapper["cert"].as_str()?).ok()?;
        let acme_key = wrapper["acme_key"].as_str().and_then(|ak| STANDARD.decode(ak).ok());
        
        info!("Successfully restored and unsealed TLS private key from cache (cert and ACME account unsealed)");
        Some((cert, key, acme_key))
        } // end cfg(not(oci))
    }

    async fn store_cached_tls(cert: &[u8], key: &[u8], acme_key: Option<&[u8]>) {
        // TLS cache store only works on GCP builds (uses GCP Secret Manager)
        #[cfg(feature = "oci")]
        {
            let _ = (cert, key, acme_key);
            info!("TLS cache storage skipped on OCI build");
            return;
        }
        #[cfg(not(feature = "oci"))]
        {
        if let Ok(secret_name) = std::env::var("TLS_CACHE_SECRET") {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let dek = crypto::generate_dek();
            let sealed_dek = match tpm::seal_dek(&dek).await {
                Ok(s) => s,
                Err(e) => { error!("Failed to seal DEK: {}", e); return; }
            };

            // v118: Only protect the TLS private key with TPM/measurement
            // cert and acme_key are stored in the clear (base64) in the envelope
            let mut inner_map = serde_json::Map::new();
            inner_map.insert("key".to_string(), serde_json::Value::String(STANDARD.encode(key)));
            let inner_json = serde_json::Value::Object(inner_map).to_string();

            let (nonce, ciphertext) = match crypto::encrypt(&dek, inner_json.as_bytes()) {
                Ok(c) => c,
                Err(e) => { error!("Failed to encrypt: {}", e); return; }
            };
            
            let mut payload_map = serde_json::Map::new();
            payload_map.insert("sealed_dek".to_string(), serde_json::to_value(sealed_dek).unwrap());
            payload_map.insert("nonce".to_string(), serde_json::Value::String(STANDARD.encode(nonce)));
            payload_map.insert("ciphertext".to_string(), serde_json::Value::String(STANDARD.encode(ciphertext)));
            payload_map.insert("cert".to_string(), serde_json::Value::String(STANDARD.encode(cert)));
            if let Some(ak) = acme_key {
                payload_map.insert("acme_key".to_string(), serde_json::Value::String(STANDARD.encode(ak)));
            }
            let payload = serde_json::Value::Object(payload_map);
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
        } // end cfg(not(oci))
    }
}

// ============================================================================
// ATTESTATION
// ============================================================================

// ============================================================================
// v160 (Pillar 2): EPHEMERAL ENCLAVE IDENTITY — P_enc / S_enc
//
// The RSA keypair that signs attestation reports is generated in encrypted
// RAM at boot (SEV-SNP memory encryption keeps S_enc from the hypervisor),
// never written to disk, never logged. Public material is computed once and
// cached for the two bindings:
//   * pubkey_sha256 → element 2 of the 160-byte session-nonce pre-image;
//   * pubkey_der    → first element of the SNP report_data pre-image:
//     report_data[0..32] = SHA-256(P_enc_SPKI_DER ∥ session_nonce).
// Private key stays a PEM string (what sign_payload consumes) rather than a
// stored openssl PKey so AppState stays trivially Send+Sync. Key size:
// RSA-4096 — the size deployed since v69; the plan's prose allows RSA-4096
// or ECDSA P-384, and the 3072 in its illustrative snippet would be a
// downgrade of the deployed size.
#[derive(Clone)]
pub struct EphemeralEnclaveIdentity {
    /// S_enc — private key PEM (PKCS#8). RAM-only; never logged, never persisted.
    pem: String,
    /// P_enc — SubjectPublicKeyInfo DER bytes (hashed into report_data).
    pub pubkey_der: Vec<u8>,
    /// SHA-256(P_enc SPKI DER) — the pubkey element of the session nonce.
    pub pubkey_sha256: [u8; 32],
    /// P_enc PEM — published in the report as `enclave_signing_public_key`.
    pubkey_pem: String,
}

impl EphemeralEnclaveIdentity {
    /// Generate a fresh per-boot RAM-only RSA-4096 keypair.
    pub fn generate() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        let rsa = Rsa::generate(4096)?;
        let pkey = PKey::from_rsa(rsa)?;
        let pem = String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?;
        Self::from_pem_owned(pem)
    }

    /// Wrap an operator-supplied key (Vault/config) with cached public material.
    pub fn from_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::from_pem_owned(pem.to_string())
    }

    fn from_pem_owned(pem: String) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use openssl::pkey::PKey;
        use sha2::{Digest, Sha256};
        let pkey = PKey::private_key_from_pem(pem.as_bytes())?;
        let pubkey_der = pkey.public_key_to_der()?;
        let pubkey_sha256 = Sha256::digest(&pubkey_der).into();
        // public_key_to_pem() — byte-identical to the pre-v160 helper that
        // derived this field on the fly, so published report fields are
        // unchanged by the move to cached identity material.
        let pubkey_pem = String::from_utf8(pkey.public_key_to_pem()?)?;
        Ok(Self { pem, pubkey_der, pubkey_sha256, pubkey_pem })
    }
}

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

/// v152: session nonce = SHA-256(paypal_hash ∥ pubkey_hash ∥ SHA-256(custom_info)).
/// Canonical JSON for the disk manifest: `[[path, sha256], …]`, sorted by
/// path, compact (no whitespace). Hashed into the hardware-bound session
/// nonce (SEC-02) and mirrored byte-for-byte by the auditor's
/// `JSON.stringify(sorted.map(k => [k, m[k]]))` in verify.html — the two
/// MUST produce identical bytes or every attestation fails its binding check.
/// (BTreeMap iteration is already key-sorted; the explicit sort documents
/// the contract and keeps us safe if the type ever changes.)
fn canonical_manifest_json(manifest: &std::collections::BTreeMap<String, String>) -> String {
    let mut pairs: Vec<(&String, &String)> = manifest.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    serde_json::to_string(&pairs).unwrap_or_default()
}

/// SEC-02 (code-to-silicon binding): the session nonce bound into the AMD
/// SNP report_data / TPM quote extraData commits to the EXACT code identity
/// of the running enclave, not only the user's PayPal profile:
///
///   nonce = SHA-256( paypal_hash ∥ pubkey_hash ∥ SHA-256(custom_info)
///                    ∥ binary_sha256 ∥ SHA-256(canonical_manifest_json) )
///
/// v160 (Pillar 2): the TPM extraData still carries this nonce verbatim;
/// the SNP report_data[0..32] now carries SHA-256(P_enc_DER ∥ nonce) — the
/// quote binds the ephemeral enclave key directly, on top of the key hash
/// that element 2 of this nonce already covers.
///
/// On OCI the SEV-SNP launch digest covers only the fleet-constant OVMF
/// firmware, so without this fusion a tampered disk would still produce a
/// "valid" hardware quote. With it, the silicon quote itself commits to the
/// measured binary + disk manifest, and the auditor's independent Sigstore
/// lookup of those same hashes closes the loop (Layer 2 + Layer 3 of the
/// defense-in-depth model). MUST stay in lockstep with `expectedNonce` in
/// verify.html.
fn compute_session_nonce(
    paypal_hash_hex: &str,
    pub_key_hash: &[u8],
    custom_info: &str,
    binary_sha256_hex: &str,
    manifest_canonical_json: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut custom_hasher = Sha256::new();
    custom_hasher.update(custom_info.as_bytes());
    let custom_info_hash = custom_hasher.finalize();

    let mut manifest_hasher = Sha256::new();
    manifest_hasher.update(manifest_canonical_json.as_bytes());
    let manifest_hash = manifest_hasher.finalize();

    let mut combined_hasher = Sha256::new();
    combined_hasher.update(hex::decode(paypal_hash_hex).expect("Internal Error: Invalid PayPal Hex"));
    combined_hasher.update(pub_key_hash);
    combined_hasher.update(custom_info_hash);
    combined_hasher.update(hex::decode(binary_sha256_hex).expect("Internal Error: Invalid binary hash hex"));
    combined_hasher.update(manifest_hash);
    hex::encode(combined_hasher.finalize())
}

async fn generate_attestation(
    state: &AppState,
    clicked_button_label: String,
    userinfo: PayPalUserInfo,
    custom_info: Option<String>,
    // v161 (Pillars 2–5): Some(pkce) ⇒ client-bound pre-flight session —
    // the SNP report_data uses the v161 four-element binding and the report
    // carries the client inputs so the auditor can recompute the binding.
    preflight: Option<&PkceSession>,
) -> String {
    use sha2::{Digest, Sha256};
    
    // 1. Get current time with ms precision
    let now = chrono::Utc::now();
    let timestamp_ms = now.timestamp_millis() as u64;

    // 2. Convert userinfo to a sorted Value and hash its alphabetical representation
    let userinfo_val = serde_json::to_value(&userinfo).expect("Failed to value-ize userinfo");
    let userinfo_compact = serde_json::to_string(&userinfo_val).expect("Failed to serialize userinfo");
    let mut hasher = Sha256::new();
    hasher.update(userinfo_compact.as_bytes());
    let paypal_hash = hex::encode(hasher.finalize());

    // v161 (threat model: colluding owner reads the serial console): the old
    // DEBUG println!s dumped the plaintext identity + full report payload to
    // kmsg/console. Identity material now leaves this function only inside
    // the signed report (and, for pre-flight sessions, its E2EE ciphertext).

    // 2.5 Software Hash Check (Self-measure)
    let bin_path = "/init"; 
    let mut bin_hasher = Sha256::new();
    if let Ok(data) = std::fs::read(bin_path) {
        bin_hasher.update(&data);
    }
    let binary_self_hash = hex::encode(bin_hasher.finalize());

    // 3. Obtain hardware attestation quote (PCR 15 base)
    // v117 Hardening: Bind the Enclave Signing Public Key to the Hardware Attestation
    // This prevents "Key Substitution" attacks where an attacker replaces the public key
    // in the JSON report with their own.
    let pub_key_pem = if let Some(id) = &state.enclave_identity {
        id.pubkey_pem.clone()
    } else {
        "N/A".to_string()
    };
    
    // CRITICAL: the nonce hashes the raw DER bytes of the public key, NOT
    // the PEM string (verify.html: strip PEM headers → atob() → SHA-256 of
    // raw DER bytes). Both values are precomputed on the identity — same
    // bytes, no re-parse. The v160 SNP report_data binding also needs the
    // full DER (report_data[0..32] = SHA-256(P_enc ∥ session nonce)).
    // No identity (key-less diagnostic path) keeps the legacy bytes: hash of
    // the empty pre-image.
    let (pub_key_der, pub_key_hash_bytes): (Vec<u8>, [u8; 32]) = if let Some(id) = &state.enclave_identity {
        (id.pubkey_der.clone(), id.pubkey_sha256)
    } else {
        (Vec::new(), Sha256::digest(b"").into())
    };
    let pub_key_hash_hex = hex::encode(pub_key_hash_bytes);

    // v152: Bind custom_info into the hardware-attested nonce (see
    // compute_session_nonce). Previously custom_info was only covered by the
    // enclave's software signature, so a leaked signing key allowed
    // substitution without invalidating the hardware quote.
    // v155 (SEC-02): the nonce additionally commits to the measured binary
    // hash + canonical disk-manifest composite, so the silicon quote binds
    // the exact code identity (the OCI launch digest alone is fleet-constant
    // and cannot distinguish disks).
    let custom_info_str = custom_info.clone().unwrap_or_else(|| "NONE".to_string());
    let manifest_canonical = canonical_manifest_json(&state.boot_manifest);
    let final_combined_nonce = compute_session_nonce(
        &paypal_hash,
        &pub_key_hash_bytes,
        &custom_info_str,
        &binary_self_hash,
        &manifest_canonical,
    );

    info!("Generating hardware attestation with bound public key hash: {}", pub_key_hash_hex);
    // v161 (Pillars 2–5): pre-flight sessions bind the CLIENT's inputs into
    // the silicon quote instead of the v160 session-nonce binding:
    // report_data[0..32] = SHA-256(P_enc ∥ code_challenge ∥ P_client ∥ nonce_c)
    let report_data_override = preflight.map(|pk| {
        tpm::preflight_report_data_binding(&pub_key_der, &pk.code_challenge, &pk.client_ecdh_pub, &pk.client_nonce)
    });
    let mut tpm_report = match tpm::quote(&final_combined_nonce, &pub_key_der, report_data_override).await {
        Ok(r) => r,
        Err(e) => return format!("ERROR: Failed to generate TPM Quote: {}", e),
    };
    tpm_report.signature_binding_pubkey_hash = pub_key_hash_hex;
    
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
            "version": "v119-STABLE",
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
            }
        },
        "session_context": {
            "clicked_button_label": clicked_button_label,
            "tls_certificate_pem": &cert_pem,
            // v161: the auditor recomputes the four-element hardware binding
            // from these values; executePreflightAndLogin additionally
            // asserts them against the inputs this browser generated.
            "preflight": match preflight {
                Some(pk) => {
                    use base64::Engine as _;
                    serde_json::json!({
                        "binding": "v161",
                        "code_challenge": pk.code_challenge,
                        "client_pub_b64": base64::engine::general_purpose::STANDARD.encode(&pk.client_ecdh_pub),
                        "client_nonce_hex": hex::encode(pk.client_nonce),
                    })
                }
                None => serde_json::Value::Null,
            },
        },
        "custom_info": custom_info_str,
        "hardware_level_attestation": tpm_val,
    });

    // v70: We use Compact JSON for the signature to ensure deterministic verification (Canonical-lite)
    // v161: no /tmp/last_payload.json dump and no DEBUG println — under the
    // collusion threat model the plaintext report must exist only in RAM and
    // (for pre-flight sessions) inside the client-bound ciphertext.
    let payload_compact = serde_json::to_string(&payload).expect("Failed to serialize compact payload");
    
    // 6. Sign everything using the enclave-bound asymmetric key
    let signature = if let Some(id) = &state.enclave_identity {
        sign_payload(&payload_compact, &id.pem)
    } else {
        "UNSIGNED_KEY_MISSING".to_string()
    };

    let full_report = serde_json::json!({
        "attestation_report": payload,
        "enclave_signature_b64": signature,
        "enclave_signing_public_key": if state.enclave_identity.is_some() {
            pub_key_pem
        } else {
            "N/A".to_string()
        }
    });

    serde_json::to_string_pretty(&full_report).unwrap()
}

// ============================================================================
// OAUTH
// ============================================================================

// ============================================================================
// HARDENED HTTP CLIENT
// ============================================================================

fn hardened_client() -> reqwest::Client {
    use reqwest::Certificate;
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .use_rustls_tls()
        // v151: DNS Egress Hardening (Prevent DNS Hijacking)
        // v153 (audit SEC-06): pin MULTIPLE Cloudflare/Fastly edge addresses
        // per PayPal host instead of a single Anycast IP. A single pinned IP
        // is a single point of failure — PayPal/Cloudflare reroute edges
        // routinely (the v151 pin 104.16.124.74 stopped appearing in live
        // DNS answers by 2026-10), and when that edge goes dark every token
        // exchange dies until a new disk image is built. reqwest tries the
        // pinned addrs in order, so this degrades gracefully. IP takeover
        // cannot forge identity here: TLS still validates the hostname
        // against the embedded PayPal/Google roots — the pins only defeat
        // resolver hijack and keep availability. Refresh this list if
        // PayPal's edges rotate again (dig api-m.paypal.com).
        .resolve_to_addrs("api-m.paypal.com", &[
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 16, 125, 58)), 443),
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 16, 126, 58)), 443),
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 16, 124, 74)), 443),
        ])
        .resolve_to_addrs("api-m.sandbox.paypal.com", &[
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(146, 75, 123, 1)), 443),
        ]);
    
    // Pin PayPal Root CA (Embedded)
    if let Ok(cert) = Certificate::from_pem(PAYPAL_CA_PEM) {
        builder = builder.add_root_certificate(cert);
        info!("Pinned PayPal Root CA (Embedded)");
    }
    
    // Pin Google Public CA Root (Embedded)
    if let Ok(cert) = Certificate::from_pem(GOOGLE_CA_PEM) {
        builder = builder.add_root_certificate(cert);
        info!("Pinned Google Root CA (Embedded)");
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// v160 (Pillar 3): authorization-code exchange, STRICT PKCE (RFC 7636).
/// `code_verifier` is generated in enclave RAM at /login and presented only
/// here. If a malicious owner/provider intercepts `code` at the callback
/// endpoint, redemption fails at PayPal: the server requires
/// SHA-256(code_verifier) === code_challenge, and the verifier never left
/// the enclave.
async fn exchange_code_for_token(
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    api_base: &str,
    code_verifier: &str,
) -> Result<TokenResponse, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/v1/oauth2/token", api_base);
    let resp = hardened_client()
        .post(&url)
        .basic_auth(client_id, Some(client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier), // Strict RFC 7636 proof
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
    let resp = hardened_client()
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

#[cfg(not(feature = "oci"))]
const PLATFORM_LABEL: &str = "AMD SEV-SNP / Google Cloud";
#[cfg(feature = "oci")]
const PLATFORM_LABEL: &str = "AMD SEV-SNP / Oracle Cloud";

async fn index(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    let content = format!(
        r#"
        <h1>Confidential PayPal Authentication</h1>
        <div class="info">
            <p><strong>Domain:</strong> {}</p>
            <p><strong>Platform:</strong> <span class="cert-status">Hardened ({})</span></p>
            <p><strong>Certificate:</strong> RAM ONLY (Google Public CA)</p>
        </div>
        <div class="info">
            <p><strong>Verified Candidate Login (Recommended First):</strong></p>
            <p>This button uses a restricted PayPal App to only verify your "PayPal Verified" status and perform hardware attestation. No profile or email data is shared yet.</p>
            <a href="/verify.html#login-verified" class="btn" style="background:#4caf50;">Check Attestation & PayPal Verification</a>
        </div>
        <div class="info">
            <p><strong>Full Data Login:</strong></p>
            <p>Asks for standard profile and email data for full application functionality.</p>
            <a href="/verify.html#login-full" class="btn">Login with PayPal (Full Data)</a>
        </div>
        <div class="footer">
            <a href="https://leonardopedro.github.io/verifiedUniqueAliases/privacy.html">Privacy Policy</a> |
            <a href="https://leonardopedro.github.io/verifiedUniqueAliases/terms.html">User Agreement</a> |
            <a href="/verify.html">Official Auditor</a>
        </div>
        "#,
        state.domain, PLATFORM_LABEL
    );
    let html = HTML_TEMPLATE.replace("{{CONTENT}}", &content);
    if let Err(status) = state.record_egress_data(addr.ip(), html.len() as u64) {
        return status.into_response();
    }
    Html(html).into_response()
}

async fn privacy() -> Response {
    Redirect::to("https://leonardopedro.github.io/verifiedUniqueAliases/privacy.html").into_response()
}

async fn terms() -> Response {
    Redirect::to("https://leonardopedro.github.io/verifiedUniqueAliases/terms.html").into_response()
}

#[derive(Deserialize)]
struct LoginParams {
    flow: Option<String>,
}

// v160 (Pillar 3): OAuth 2.0 PKCE (RFC 7636) session.
//
// code_verifier: 32 random bytes, base64url — exists ONLY in enclave RAM
// (inside pending_oauth_states, single-use, 10 min TTL) for the lifetime of
// one authorization request. code_challenge = BASE64URL(SHA256(verifier))
// goes to PayPal on the authorize request; the verifier is presented only
// by this enclave on the token exchange. Security invariant: a colluding
// owner/provider who intercepts the callback URL (code + state) CANNOT
// redeem the code at PayPal — the authorization server requires
// SHA-256(code_verifier) === code_challenge and no other party has it.
//
// The plan's `session_id` field is deliberately not duplicated here: the
// random `state` token that keys pending_oauth_states IS the session id.
struct PkceSession {
    code_verifier: String,
    code_challenge: String,
    // v161 (Pillars 2–5): client-bound pre-flight session.
    // client_ecdh_pub empty ⇒ legacy /login session (v160 session binding).
    client_ecdh_pub: Vec<u8>,
    client_nonce: [u8; 32],
    // Enclave's per-session ECDH keypair (P_enc_ecdh / S_enc_ecdh). RAM-only,
    // never serialized — like S_enc, it exists only inside encrypted memory.
    enclave_ecdh: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    created_at: Instant,
}

impl PkceSession {
    fn mint() -> (String, String) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use base64::Engine as _;
        use rand::Rng;
        use sha2::{Digest, Sha256};

        let mut verifier_bytes = [0u8; 64];
        rand::thread_rng().fill(&mut verifier_bytes);
        let code_verifier = B64URL.encode(verifier_bytes);

        // Code challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
        let challenge_hash = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = B64URL.encode(challenge_hash);
        (code_verifier, code_challenge)
    }

    fn new() -> Self {
        let (code_verifier, code_challenge) = Self::mint();
        Self {
            code_verifier,
            code_challenge,
            client_ecdh_pub: Vec::new(),
            client_nonce: [0u8; 32],
            enclave_ecdh: None,
            created_at: Instant::now(),
        }
    }

    /// v161: pre-flight session — the quote will bind (P_enc ∥ code_challenge
    /// ∥ P_client ∥ client_nonce), and the callback response is E2EE-sealed
    /// to P_client via the per-session enclave ECDH key.
    fn new_preflight(client_ecdh_pub: Vec<u8>, client_nonce: [u8; 32]) -> Self {
        let (code_verifier, code_challenge) = Self::mint();
        let enclave_ecdh = crate::crypto::generate_ecdh_keypair().ok();
        Self {
            code_verifier,
            code_challenge,
            client_ecdh_pub,
            client_nonce,
            enclave_ecdh,
            created_at: Instant::now(),
        }
    }

    fn is_preflight(&self) -> bool {
        !self.client_ecdh_pub.is_empty() && self.enclave_ecdh.is_some()
    }
}

// ============================================================================
// v161 (plan Pillar 4): PRE-FLIGHT ATTESTATION PROTOCOL
// ============================================================================
//
// POST /attest/preflight — the browser (verify.html, same origin) generates an
// ephemeral ECDH keypair + 32-byte nonce, and the enclave returns a
// SYNTHETIC-identity attestation envelope whose AMD SEV-SNP report_data binds:
//
//     SHA-256( P_enc_SPKI ∥ code_challenge ∥ P_client_SPKI ∥ client_nonce )
//
// together with the PKCE material the client needs to construct the PayPal
// authorize URL ITSELF (plan §6 step 7) — the enclave never redirects. The
// non-report fields are signed by S_enc (whose P_enc the hardware quote
// commits to), so the client can authenticate the challenge/state/client_id
// triple before ever sending the user to PayPal. The code_verifier stays in
// encrypted RAM; a colluding owner/hypervisor who later intercepts the
// authorization code cannot redeem it (Pillar 2).

#[derive(Deserialize)]
pub struct PreflightRequest {
    /// SPKI DER (base64 STANDARD) of the browser's ephemeral ECDH P-256 key.
    pub client_ecdh_pub_b64: String,
    /// 32-byte browser nonce, hex-encoded.
    pub client_nonce_hex: String,
    /// "verified" (default) or "full" — selects the PayPal app/scope.
    pub flow: Option<String>,
}

async fn serve_verify_html() -> impl IntoResponse {
    // Same-origin hosting of the auditor is REQUIRED by the v161 flow: the
    // pre-flight stores S_client in sessionStorage and the /callback page
    // reads it back — sessionStorage is per-origin, so the auditor MUST be
    // served by the enclave itself. The github.io copy remains for offline
    // audits of downloaded reports.
    Html(include_str!("../verify.html")).into_response()
}

async fn preflight_cors() -> impl IntoResponse {
    // OPTIONS preflight for the cross-auditor POST (verify.html may be opened
    // from file:// or github.io for the hardware check itself; the login
    // completion always returns to this origin).
    (
        [
            (axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (axum::http::header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS"),
            (axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
        ],
        axum::http::StatusCode::NO_CONTENT,
    )
}

async fn attest_preflight(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(payload): Json<PreflightRequest>,
) -> Response {
    if let Err(status) = state.record_egress_data(addr.ip(), 24 * 1024 /* envelope estimate */) {
        return status.into_response();
    }
    use base64::engine::general_purpose::STANDARD as B64STD;
    use base64::Engine as _;

    // Strict input validation: the client key MUST be a parsable SPKI DER of
    // an EC P-256 key (WebCrypto ECDH export), the nonce exactly 32 bytes.
    let client_pub = match B64STD.decode(payload.client_ecdh_pub_b64.trim()) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid client_ecdh_pub_b64: {}", e)).into_response(),
    };
    match openssl::pkey::PKey::public_key_from_der(&client_pub)
        .and_then(|k| {
            k.ec_key()
                .map(|ec| ec.group().curve_name())
                .map_err(|_| openssl::error::ErrorStack::get())
        }) {
        Ok(Some(nid)) if nid == openssl::nid::Nid::X9_62_PRIME256V1 => {}
        _ => return (StatusCode::BAD_REQUEST, "client_ecdh_pub_b64 must be an ECDH P-256 SPKI DER public key").into_response(),
    }
    let nonce_vec = match hex::decode(payload.client_nonce_hex.trim()) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid client_nonce_hex: {}", e)).into_response(),
    };
    if nonce_vec.len() != 32 {
        return (StatusCode::BAD_REQUEST, "client_nonce_hex must decode to exactly 32 bytes").into_response();
    }
    let mut client_nonce = [0u8; 32];
    client_nonce.copy_from_slice(&nonce_vec);

    let flow = match payload.flow.as_deref().unwrap_or("verified") {
        "verified" => "verified",
        "full" => "full",
        _ => return (StatusCode::BAD_REQUEST, "flow must be 'verified' or 'full'").into_response(),
    };
    let config = state.get_flow_config(flow);

    if state.enclave_identity.is_none() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Enclave identity uninitialized").into_response();
    }

    // Mint the single-use PKCE session (verifier stays in encrypted RAM).
    let pkce = PkceSession::new_preflight(client_pub.clone(), client_nonce);
    if pkce.enclave_ecdh.is_none() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Enclave ECDH key generation failed").into_response();
    }
    use rand::Rng;
    let mut state_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut state_bytes);
    let oauth_state = hex::encode(state_bytes);

    // Synthetic-identity envelope with the REAL hardware evidence + the v161
    // client-bound report_data (identity is explicitly fake — same discipline
    // as /debug/envelope; this is hardware+binding proof, never identity).
    let synthetic: PayPalUserInfo = serde_json::from_str(
        r#"{"user_id":"PREFLIGHT-ONLY-NOT-A-REAL-PAYPAL-USER","sub":"PREFLIGHT-ONLY","payer_id":"PREFLIGHT","verified_account":"true","verified":"true"}"#,
    ).expect("static synthetic preflight identity");
    let envelope_str = generate_attestation(
        &state,
        "preflight (synthetic identity — NOT a real PayPal login)".to_string(),
        synthetic,
        Some("PREFLIGHT ENVELOPE — synthetic identity, binds this browser session".to_string()),
        Some(&pkce),
    ).await;
    if envelope_str.starts_with("ERROR:") {
        error!("preflight quote failed: {}", envelope_str);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Hardware quote failed — see enclave log").into_response();
    }
    let envelope: serde_json::Value = match serde_json::from_str(&envelope_str) {
        Ok(v) => v,
        Err(e) => {
            error!("preflight envelope serialization failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Envelope construction failed").into_response();
        }
    };

    let id = state.enclave_identity.as_ref().unwrap();
    let auth_base = if state.staging { PAYPAL_SANDBOX_AUTH } else { PAYPAL_PRODUCTION_AUTH };
    let ecdh_pub_b64 = match pkce.enclave_ecdh.as_ref().unwrap().public_key_to_der() {
        Ok(der) => B64STD.encode(der),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "ECDH public export failed").into_response(),
    };

    // The fields that pin THIS login attempt. Signed by S_enc so the client
    // can authenticate them against the hardware-committed P_enc BEFORE the
    // user is sent to PayPal.
    let signed_fields = serde_json::json!({
        "binding": "v161",
        "code_challenge": pkce.code_challenge,
        "state": oauth_state,
        "flow": config.label,
        "paypal_client_id": config.client_id,
        "redirect_uri": state.redirect_uri,
        "authorize_base": auth_base,
        "scope": config.scope,
        "enclave_ecdh_public_key_b64": ecdh_pub_b64,
    });
    let signed_fields_compact = serde_json::to_string(&signed_fields).expect("serialize signed fields");
    let signature = sign_payload(&signed_fields_compact, &id.pem);

    // Single-use server-side session (10 min TTL, swept with the /login set).
    state.pending_oauth_states.write().insert(oauth_state.clone(), (config.label.clone(), pkce));

    let body = serde_json::json!({
        "attestation_envelope": envelope,
        "enclave_signing_public_key": id.pubkey_pem,
        "signed_fields": signed_fields,
        "preflight_signature_b64": signature,
    });

    let mut resp = ([(axum::http::header::CONTENT_TYPE, "application/json")], Json(body)).into_response();
    // Same-origin CORS: the auditor may live on file:// or github.io for the
    // hardware check; no credentials ride this endpoint (the envelope is
    // synthetic-identity diagnostics + key material for THIS session).
    resp.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        axum::http::HeaderValue::from_static("*"),
    );
    // Cookie binds the browser that started the flow (Login CSRF defense,
    // RFC 6749 §10.12) — verified strictly on /callback.
    let cookie = format!(
        "paypal_oauth_state={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600",
        oauth_state
    );
    if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, hv);
    }
    resp
}

async fn login(
    Query(_params): Query<LoginParams>,
    State(_state): State<Arc<AppState>>,
) -> Response {
    // v161 (plan §6): the enclave no longer redirects to PayPal itself. The
    // client must audit the hardware binding FIRST (pre-flight), then build
    // the authorize URL from the S_enc-signed fields. /login stays as a
    // compatibility shim pointing at the auditor.
    Redirect::temporary("/verify.html").into_response()
}

async fn debug_attestation() -> impl IntoResponse {
    let mut results = serde_json::Map::new();
    
    // Check TPM Quote
    let nonce = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";        match tpm::quote(nonce, &[], None).await {
        Ok(r) => { 
            results.insert("tpm_quote_status".to_string(), serde_json::Value::String("SUCCESS".to_string())); 
            results.insert("report".to_string(), serde_json::to_value(r).unwrap()); 
        },
        Err(e) => { 
            results.insert("tpm_quote_status".to_string(), serde_json::Value::String(format!("FAILED: {}", e))); 
        }
    }
    
    // Check ConfigFS status
    let _configfs_path = "/sys/kernel/config/tsm/report";
    results.insert("tsm_loaded".to_string(), serde_json::Value::Bool(std::path::Path::new("/sys/kernel/config/tsm").exists()));
    results.insert("amd_tsm_loaded".to_string(), serde_json::Value::Bool(std::path::Path::new("/sys/bus/platform/drivers/amd_tsm").exists() || std::path::Path::new("/sys/bus/platform/drivers/amd-tsm").exists()));
    results.insert("sev_guest_device".to_string(), serde_json::Value::Bool(std::path::Path::new("/dev/sev-guest").exists()));

    // v147: TPM-less (OCI) runtime diagnostics — the only observability channel
    // on the enclave (no shell, no dmesg binary in the initramfs).
    results.insert(
        "cmdline".to_string(),
        serde_json::Value::String(
            std::fs::read_to_string("/proc/cmdline").unwrap_or_default().trim().to_string(),
        ),
    );

    // CPU flags relevant to AMD confidential compute (sev / sev_es / sev_snp)
    let mut cpu_sev_flags: Vec<String> = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("flags"))
        .flat_map(|l| l.split_whitespace().skip(1).map(|s| s.to_string()).collect::<Vec<_>>())
        .filter(|f| f.contains("sev") || f == "snp")
        .collect();
    cpu_sev_flags.sort();
    cpu_sev_flags.dedup();
    results.insert("cpu_sev_flags".to_string(), serde_json::to_value(&cpu_sev_flags).unwrap());

    // Loaded kernel modules (names only)
    let modules: Vec<String> = std::fs::read_to_string("/proc/modules")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
        .collect();
    results.insert("loaded_modules".to_string(), serde_json::to_value(&modules).unwrap());

    results.insert(
        "sev_guest_driver_dir".to_string(),
        serde_json::Value::Bool(std::path::Path::new("/sys/bus/platform/drivers/sev-guest").exists()),
    );
    results.insert(
        "tsm_report_dir".to_string(),
        serde_json::Value::Bool(std::path::Path::new("/sys/kernel/config/tsm/report").exists()),
    );

    // Fresh modprobe attempt with captured kmod diagnostics — kmod prints the
    // probe result (e.g. "ERROR: could not insert 'sev_guest': No such device")
    match std::process::Command::new("/sbin/modprobe").args(["sev-guest"]).output() {
        Ok(o) => {
            results.insert(
                "modprobe_sev_guest_rc".to_string(),
                serde_json::Value::from(o.status.code().unwrap_or(-1)),
            );
            results.insert(
                "modprobe_sev_guest_out".to_string(),
                serde_json::Value::String(
                    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
                        .trim()
                        .to_string(),
                ),
            );
        }
        Err(e) => {
            results.insert(
                "modprobe_sev_guest_out".to_string(),
                serde_json::Value::String(format!("spawn error: {}", e)),
            );
        }
    }

    // Bounded non-blocking /dev/kmsg scan (O_NONBLOCK → stop at buffer end)
    let mut klog: Vec<String> = Vec::new();
    #[allow(unused_imports)]
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o4000) // O_NONBLOCK
        .open("/dev/kmsg")
    {
        use std::io::Read;
        let mut buf = [0u8; 8192];
        for _ in 0..600 {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let line = String::from_utf8_lossy(&buf[..n]).to_string();
                    let lower = line.to_lowercase();
                    if lower.contains("sev") || lower.contains("tsm") || lower.contains("snp")
                        || lower.contains("coco") || lower.contains("encrypt")
                    {
                        klog.push(line.trim().to_string());
                    }
                }
                Err(_) => break, // EAGAIN — no more buffered records
            }
        }
    }
    let klog_len = klog.len();
    klog.drain(..klog_len.saturating_sub(40));
    results.insert("kmsg_sev".to_string(), serde_json::to_value(&klog).unwrap());

    if let Ok(output) = std::process::Command::new("dmesg").output() {
        let s = String::from_utf8_lossy(&output.stdout);
        let sev_logs: Vec<String> = s.lines()
            .filter(|l| l.contains("SEV") || l.contains("SNP") || l.contains("tsm") || l.contains("coco") || l.contains("guest"))
            .map(|s| s.to_string())
            .collect();
        results.insert("dmesg_sev".to_string(), serde_json::Value::from(sev_logs));
    }

    Json(results)
}

// v156 (audit): full signed attestation envelope with a SYNTHETIC identity.
// /debug/attestation only exposes the raw hardware quote (diagnostic nonce),
// so before this route an operator could not run verify.html against the LIVE
// enclave without completing a real PayPal login. This handler feeds
// generate_attestation a fabricated profile (sub=DEBUG-ONLY): the enclave
// signature, the SEC-02 nonce binding and the SNP evidence are the real
// enclave's, the identity is explicitly fake. Useful to prove the deployed
// enclave end-to-end; NEVER usable as identity proof — the report says so in
// every identity field.
async fn debug_envelope(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let synthetic: PayPalUserInfo = serde_json::from_str(
        r#"{"user_id":"DEBUG-ONLY-NOT-A-REAL-PAYPAL-USER","sub":"DEBUG-ONLY","payer_id":"DEBUG","verified_account":"true","verified":"true"}"#,
    )
    .expect("static synthetic debug identity");
    let envelope = generate_attestation(
        &state,
        "debug-envelope (synthetic identity — NOT a real PayPal login)".to_string(),
        synthetic,
        Some("DEBUG ENVELOPE — synthetic identity, no real user attached".to_string()),
        None, // v161: /debug/envelope keeps the v160 session binding; the
              // client-bound (v161) binding is minted by /attest/preflight
    )
    .await;
    (
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            // v160 (Pillar 4): pre-flight. verify.html (local auditor, file://
            // origin) fetches this endpoint BEFORE the user starts the PayPal
            // login to pin the live enclave's P_enc and hardware evidence.
            // The endpoint is public, synthetic-identity diagnostics — CORS
            // grants browsers read access only, no credentials ride along.
            (axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        envelope,
    )
}

// v156 (audit): security headers on every HTTPS response. The enclave renders
// an OAuth callback carrying user identity + a signed attestation report:
//   - frame-ancestors 'none' / X-Frame-Options DENY  → clickjacking
//   - X-Content-Type-Options: nosniff                → MIME sniffing
//   - Referrer-Policy: no-referrer                   → the callback URL (with
//     PayPal `code`) must never leak via Referer to external links
//   - HSTS                                            → pin HTTPS
//   - Cache-Control: no-store                        → identity/report pages
//     must not be written to browser or proxy caches
// Deliberately NOT a full resource CSP: the pages use inline styles/scripts
// and a strict policy would break them without nonces; frame-ancestors gets
// the clickjacking defense without that cost.
async fn security_headers(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    h.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("frame-ancestors 'none'"),
    );
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    h.insert(
        axum::http::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=(), usb=()"),
    );
    resp
}

// v161: best-effort in-place wipe of a sensitive string (tokens, secrets).
// The allocator may have copied old pages; this closes the window inside our
// own process image (the plan's "zeroize immediately after userinfo fetch").
fn zeroize_str(s: &mut String) {
    unsafe {
        let bytes = s.as_bytes_mut();
        for b in bytes.iter_mut() { *b = 0; }
    }
    s.clear();
}

// v161 (Pillar 5): the post-login page. It carries ONLY the ciphertext; the
// decryption key material never left the browser (S_client in sessionStorage)
// and the hardware-committed P_enc pin is re-checked after decryption. The
// page then hands the decrypted report to the same-origin /verify.html
// auditor via sessionStorage for the full multi-check audit.
fn render_e2ee_page(blob: &serde_json::Value) -> String {
    let content = format!(
        r#"
        <h1>Authentication Successful</h1>
        <div class="info">
            <h3>Hardware-Attested, Client-Encrypted Delivery</h3>
            <p>Your PayPal identity was fetched inside the SEV-SNP enclave, minimized, encrypted to the
               session key YOU generated (ECDH → HKDF → AES-256-GCM), and signed by the enclave's
               hardware-committed signing key. Only this browser can open it.</p>
            <p id="st" style="color:#e0e0e0;">⏳ Decrypting and verifying…</p>
            <a id="openAuditor" class="btn" style="display:none; background:#4caf50; margin-top:10px;" href="/verify.html">Open Full Auditor →</a>
        </div>
        <script type="application/json" id="e2ee-blob">{}</script>
        <script>
        (async () => {{
            const b64d = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
            const pemDer = pem => b64d(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
            const reorder = o => {{ if (o === null || typeof o !== 'object' || Array.isArray(o)) return o; const out = {{}}; Object.keys(o).sort().forEach(k => out[k] = reorder(o[k])); return out; }};
            const st = document.getElementById('st');
            const fail = m => {{ st.innerHTML = '❌ ' + m; }};
            try {{
                const blob = JSON.parse(document.getElementById('e2ee-blob').textContent);
                const jwk = JSON.parse(sessionStorage.getItem('pav_client_jwk') || 'null');
                const nonceHex = sessionStorage.getItem('pav_client_nonce') || '';
                const pinned = sessionStorage.getItem('pav_p_enc') || '';
                if (!jwk || !nonceHex) throw new Error('no pre-flight session in this browser — restart the login from /verify.html');
                const nonceBytes = Uint8Array.from(nonceHex.match(/.{{2}}/g) || [], h => parseInt(h, 16));
                if (nonceBytes.length !== 32) throw new Error('stored client nonce is malformed');
                // 1. ECDH(P-256): deriveBits(S_client, P_enc_ecdh)
                const priv = await crypto.subtle.importKey('jwk', jwk, {{ name: 'ECDH' }}, false, ['deriveBits']);
                const peer = await crypto.subtle.importKey('spki', b64d(blob.enclave_ecdh_public_key_b64), {{ name: 'ECDH' }}, false, []);
                const bits = await crypto.subtle.deriveBits({{ name: 'ECDH', public: peer }}, priv, 256);
                // 2. HKDF-SHA256(salt=client_nonce, info=protocol label) → AES-256 key
                const base = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
                const key = await crypto.subtle.deriveKey(
                    {{ name: 'HKDF', hash: 'SHA-256', salt: nonceBytes, info: new TextEncoder().encode('paypal-auth-vm/e2ee/v1') }},
                    base, {{ name: 'AES-GCM', length: 256 }}, false, ['decrypt']);
                // 3. AES-256-GCM decrypt (AAD = client_nonce → session-bound)
                const pt = await crypto.subtle.decrypt(
                    {{ name: 'AES-GCM', iv: b64d(blob.iv_b64), additionalData: nonceBytes }},
                    key, b64d(blob.ct_b64));
                const envelope = JSON.parse(new TextDecoder().decode(pt));
                // 4. PRE-FLIGHT PIN: the report MUST be signed by the P_enc the
                //    hardware quote committed to at pre-flight time.
                const reportPem = envelope.enclave_signing_public_key;
                if (pinned && reportPem !== pinned) throw new Error('PRE-FLIGHT VIOLATION: report key ≠ pinned P_enc — the enclave was swapped. Do NOT trust this payload.');
                // 5. S_enc signature over the canonical (sorted-key) report
                const k = await crypto.subtle.importKey('spki', pemDer(reportPem), {{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }}, false, ['verify']);
                const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', k, b64d(envelope.enclave_signature_b64),
                    new TextEncoder().encode(JSON.stringify(reorder(envelope.attestation_report))));
                if (!ok) throw new Error('S_enc report signature INVALID — forged or corrupted payload');
                // 6. Hand the verified report to the same-origin auditor.
                sessionStorage.setItem('pav_e2ee_report', JSON.stringify(envelope, null, 2));
                const sub = (envelope.attestation_report.paypal_user_info || {{}}).sub || '(unknown)';
                st.innerHTML = '✅ Decrypted + signature verified + P_enc pin matched.<br>PayPal identity <b>' + sub + '</b> was delivered inside a client-bound, hardware-attested ciphertext.<br>Open the full auditor for the complete multi-check report.';
                document.getElementById('openAuditor').style.display = 'inline-block';
            }} catch (e) {{ fail(e.message); }}
        }})();
        </script>
        "#,
        // Safe embedding in a raw-text <script> block: neutralize any
        // `</…` sequence (the only way JSON text can close the tag early).
        blob.to_string().replace("</", "<\\/")
    );
    HTML_TEMPLATE.replace("{{CONTENT}}", &content)
}

async fn callback(
    Query(query): Query<CallbackQuery>,
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    if let Some(_error) = query.error {
        return (StatusCode::BAD_REQUEST, "Error from PayPal").into_response();
    }
    let code = query.code.clone().unwrap_or_default();

    // v152 SECURITY: strict OAuth state verification (Login CSRF defense).
    // 1. The `state` must be a token WE issued (server-side map, single-use).
    // 2. It must match the HttpOnly cookie set on /login — proving the
    //    callback hits the same browser that initiated the flow, so an
    //    attacker's captured code+state pair cannot be replayed on a victim.
    let oauth_state = match query.state.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (StatusCode::BAD_REQUEST, "Missing OAuth state").into_response(),
    };
    let cookie_state = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| {
            c.split(';')
                .map(str::trim)
                .find_map(|kv| kv.strip_prefix("paypal_oauth_state="))
        });
    if cookie_state != Some(oauth_state.as_str()) {
        warn!("OAuth state cookie mismatch — possible Login CSRF attempt");
        return (StatusCode::FORBIDDEN, "Invalid OAuth state (session mismatch). Please restart the login from the homepage.").into_response();
    }
    let (flow, pkce) = {
        let mut states = state.pending_oauth_states.write();
        match states.remove(&oauth_state) {
            Some((flow, pkce)) if pkce.created_at.elapsed() < Duration::from_secs(600) => (flow, pkce),
            _ => {
                warn!("OAuth state unknown or expired — possible replay attempt");
                return (StatusCode::FORBIDDEN, "Invalid or expired OAuth state. Please restart the login from the homepage.").into_response();
            }
        }
    };
    let config = state.get_flow_config(&flow);
    
    let redirect_uri = state.redirect_uri.clone();

    let api_base = if state.staging { PAYPAL_SANDBOX_API } else { PAYPAL_PRODUCTION_API };

    let token = match exchange_code_for_token(&code, &config.client_id, &config.client_secret, &redirect_uri, api_base, &pkce.code_verifier).await {
        Ok(t) => t,
        Err(e) => {
            // v156 (audit): the detailed error (reqwest chain, PayPal response
            // body) goes to the enclave log ONLY — echoing it to the browser
            // discloses internal endpoints / upstream replies on a public
            // OAuth surface.
            error!("Token exchange failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Token exchange failed — the enclave logged the details.").into_response();
        }
    };

    let userinfo = match get_userinfo(&token.access_token, api_base).await {
        Ok(u) => u,
        Err(e) => {
            error!("Userinfo failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Userinfo fetch failed — the enclave logged the details.").into_response();
        }
    };

    // Data minimization (verified flow): project down to the verification
    // facts BEFORE anything else happens — the gate below, the session
    // store, the page, the nonce, and the signed report all only ever see
    // {user_id, payer_id, verified_account}. The `full` flow keeps the
    // complete profile (its scope explicitly grants it).
    let userinfo = if config.label == "verified" {
        userinfo.into_verification_only()
    } else {
        userinfo
    };

    // v74-PROD: Strict verified_account check to prevent resource spend on unverified profiles
    if userinfo.verified_account.as_deref() != Some("true") {
        warn!("Blocked attestation for unverified PayPal account: {:?}", userinfo.payer_id);
        return (
            StatusCode::FORBIDDEN,
            "Verification Failed: Your PayPal account must be fully verified to obtain a hardware-attested report."
        ).into_response();
    }

    // ========================================================================
    // v161 (plan Pillars 3+5): CLIENT-BOUND E2EE DELIVERY
    // ========================================================================
    // A pre-flight session delivers its report encrypted to P_client via
    // ECDH(P-256) + HKDF-SHA256 + AES-256-GCM, signed by S_enc. Neither the
    // domain owner (who can terminate TLS with a genuine cert) nor the cloud
    // provider (who sees plaintext RAM-exit traffic) can read the payload —
    // it exists in plaintext only inside SEV-SNP-encrypted memory and inside
    // the ciphertext only the browser holding S_client can open.
    if pkce.is_preflight() {
        let report_json = generate_attestation(
            &state,
            config.label.clone(),
            userinfo,
            None,
            Some(&pkce),
        ).await;
        if report_json.starts_with("ERROR:") {
            error!("E2EE report quote failed: {}", report_json);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Attestation quote failed — the enclave logged the details.").into_response();
        }
        let id = match &state.enclave_identity {
            Some(id) => id,
            None => return (StatusCode::INTERNAL_SERVER_ERROR, "Enclave identity uninitialized").into_response(),
        };
        let ecdh = pkce.enclave_ecdh.as_ref().unwrap();
        let session_key = match crypto::derive_e2ee_session_key(ecdh, &pkce.client_ecdh_pub, &pkce.client_nonce) {
            Ok(k) => k,
            Err(e) => {
                error!("E2EE key derivation failed: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Client key agreement failed — the enclave logged the details.").into_response();
            }
        };
        let (iv, ct) = match crypto::encrypt_aad(&session_key, report_json.as_bytes(), &pkce.client_nonce) {
            Ok(v) => v,
            Err(e) => {
                error!("E2EE encryption failed: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Payload encryption failed — the enclave logged the details.").into_response();
            }
        };
        // Zeroize the session key and the PayPal token before rendering.
        let mut key_wipe = session_key;
        key_wipe.iter_mut().for_each(|b| *b = 0);
        let mut token_wipe = token.access_token.clone();
        zeroize_str(&mut token_wipe);
        if let Some(mut idt) = token.id_token.clone() { zeroize_str(&mut idt); }

        use base64::engine::general_purpose::STANDARD as B64STD;
        use base64::Engine as _;
        let ecdh_pub_b64 = ecdh.public_key_to_der().map(|d| B64STD.encode(d)).unwrap_or_default();
        let e2ee_blob = serde_json::json!({
            "alg": "AES-256-GCM+HKDF-SHA256+ECDH-P256",
            "aad": "client_nonce",
            "iv_b64": B64STD.encode(&iv),
            "ct_b64": B64STD.encode(&ct),
            "enclave_ecdh_public_key_b64": ecdh_pub_b64,
            "enclave_signing_public_key": &id.pubkey_pem,
            "state": oauth_state,
            "flow": config.label,
        });
        let html = render_e2ee_page(&e2ee_blob);
        if let Err(status) = state.record_egress_data(addr.ip(), html.len() as u64) {
            return status.into_response();
        }
        return Html(html).into_response();
    }

    // v116-PROD: Multi-step attestation feature mapping PayPal profile to custom nonce before generation.
    use rand::Rng;
    let session_id: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    state.pending_attestations.write().insert(session_id.clone(), (config.label.clone(), userinfo.clone(), Instant::now()));

    let html = HTML_TEMPLATE.replace(
        "{{CONTENT}}",
        &format!(
            r#"
        <h1>Authentication Successful</h1>
        <div class="info">
            <h3>Verified PayPal Profile Linked</h3>
            <p>Your PayPal identity has been successfully secured in RAM. You may now generate your one-time Hardware Attestation Certificate.</p>
        </div>
        <div class="info" style="border-color: #2196f3;">
            <h3>Optional: Attach Custom Data</h3>
            <p>You may optionally attach a custom string (e.g. a Wallet Address, a nonce, or a public key) strictly bound to this attestation report.</p>
            <form action="/generate" method="POST">
                <input type="hidden" name="session_id" value="{}">
                <input type="text" name="custom_info" placeholder="Enter custom data here..." style="width: 100%; padding: 12px; margin-bottom: 20px; border-radius: 4px; border: 1px solid #30363d; background: #0d1117; color: white;" maxlength="512">
                <button type="submit" class="btn" style="background:#4caf50; width: 100%;">Generate Certificate (One-Time)</button>
            </form>
        </div>
        "#,
            session_id
        ),
    );
    
    if let Err(status) = state.record_egress_data(addr.ip(), html.len() as u64) {
        return status.into_response();
    }

    Html(html).into_response()
}

#[derive(serde::Deserialize)]
struct GenerateCertForm {
    session_id: String,
    custom_info: String,
}

async fn generate_cert(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    axum::extract::Form(form): axum::extract::Form<GenerateCertForm>,
) -> Response {
    let pending = state.pending_attestations.write().remove(&form.session_id);
    let (label, userinfo, _timestamp) = match pending {
        Some(p) => p,
        None => {
            return (
                StatusCode::FORBIDDEN,
                "Invalid Session ID or Certificate already generated. You may only generate the certificate once per PayPal authentication.",
            ).into_response();
        }
    };

    let custom_info = if form.custom_info.trim().is_empty() {
        None
    } else {
        Some(form.custom_info.clone())
    };

    let attestation = generate_attestation(&state, label, userinfo.clone(), custom_info, None).await;
    let userinfo_full_json = serde_json::to_string_pretty(&userinfo).unwrap();

    let html = HTML_TEMPLATE.replace(
        "{{CONTENT}}",
        &format!(
            r#"
        <h1>Attestation Complete</h1>
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
        <div class="links-grid">
            <div class="card" style="grid-column: 1 / -1; border-color: #4caf50;">
                <h3 style="color: #4caf50;">✅ Download Attestation & Auditor (Recommended)</h3>
                <p>For maximum security, download both your generated report and the auditor file, then verify locally.</p>
                <div style="margin-top: 15px;">
                    <button onclick="downloadReport()" class="btn" style="background:#4caf50; margin-right: 10px; font-family: inherit;">Download Report (.json)</button>
                    <a href="https://raw.githubusercontent.com/leonardopedro/verifiedUniqueAliases/refs/heads/main/verify.html" class="btn" target="_blank" style="background:#238636; margin-right: 10px; font-family: inherit;">Download Auditor (.html)</a>
                    <span style="font-size: 0.85rem; color: #888;">(Right-click the second link and choose "Save Link As...")</span>
                </div>
            </div>

            <a href="https://leonardopedro.github.io/verifiedUniqueAliases/verify.html" target="_blank" class="card" style="border-color: #d29922;">
                <h3 style="color: #d29922;">⚠️ Web Auditor (Less Safe)</h3>
                <p>Verify your generated JSON directly on the hosted GitHub Pages domain.</p>
            </a>
            
            <a href="/" class="card" style="border-color: #30363d; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;">
                <h3 style="color: #c9d1d9;">Return Home</h3>
            </a>
        </div>

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
    // SECURITY: an unvalidated path segment joined onto a directory is a
    // traversal primitive — `..%2F..%2Fproc%2F1%2Fenviron` arrives as one
    // Path segment and is percent-decoded AFTER routing, escaping
    // /tmp/acme-challenge while this route is live on port 80 during the
    // pre-TLS boot window (PID 1 = root). RFC 8555 §8.3 http-01 tokens are
    // unpadded base64url — reject everything outside that alphabet.
    if !acme_token_valid(&token) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read_to_string(format!("/tmp/acme-challenge/{}", token)).await {
        Ok(c) => c.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// RFC 8555 http-01 token alphabet check: unpadded base64url
/// (`[A-Za-z0-9_-]+`), bounded length. Rejects `..`, `/` (raw or
/// percent-decoded), NUL, and everything else outside the alphabet.
fn acme_token_valid(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 128
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
    // SECURITY: /tmp is world-writable tmpfs — the private key must not be
    // world-readable (tokio::fs::write creates 0644 under umask 022).
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions("/tmp/tls-key.pem", std::fs::Permissions::from_mode(0o600))?;
    }

    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    // Load the FULL chain (leaf + intermediates): set_certificate_file() maps to
    // SSL_CTX_use_certificate_file, which reads only the FIRST certificate —
    // with a Let's Encrypt leaf that drops the YR2 intermediate and every
    // non-browser client fails verification with "unable to get local issuer".
    builder.set_certificate_chain_file("/tmp/tls-cert.pem")?;
    builder.set_private_key_file("/tmp/tls-key.pem", SslFiletype::PEM)?;
    builder.check_private_key()?;

    Ok(Arc::new(builder.build()))
}

// v152 SECURITY: the self-signed TLS fallback (rcgen) was REMOVED. Serving
// an untrusted certificate when ACME is rate-limited breaks production and
// conditions users to click through warnings (MITM prompt-fatigue). ACME is
// now retried with capped backoff instead — see async_main.

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
    
    // 4. Anchor manifest in PCR 15 for the auditor
    {
        use sha2::{Digest, Sha256};
        let manifest_json = canonical_manifest_json(&boot_manifest);
        let manifest_hash = Sha256::digest(manifest_json.as_bytes());
        let hash_hex = hex::encode(manifest_hash);
        
        enclave_init::kmsg(&format!("Anchoring manifest ({} files) in PCR 15: {}", boot_manifest.len(), hash_hex));
        
        let _ = std::process::Command::new("tpm2")
            .args(["pcrextend", &format!("15:sha256={}", hash_hex)])
            .status();
    }

    // Platform-specific hardware interface check
    if std::path::Path::new("/dev/sev-guest").exists() {
        enclave_init::kmsg("Hardware interface /dev/sev-guest is PRESENT");
    } else {
        enclave_init::kmsg("Hardware interface /dev/sev-guest is MISSING");
    }
    #[cfg(feature = "oci")]
    {
        if std::path::Path::new("/dev/tpmrm0").exists() {
            enclave_init::kmsg("TPM device /dev/tpmrm0 present (unexpected on OCI confidential VM)");
        } else {
            enclave_init::kmsg("No TPM device — expected on OCI; AMD SEV-SNP report is the hardware root");
        }
        match std::fs::read_to_string("/sys/module/kvm_amd/parameters/sev_snp") {
            Ok(v) => enclave_init::kmsg(&format!("kvm_amd sev_snp = {}", v.trim())),
            Err(_) => enclave_init::kmsg("kvm_amd sev_snp parameter not exposed"),
        }
    }

    // 2. Initialize the Tokio runtime now that the environment is sane
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // 3. Configure network (DHCP) from within the async runtime
    enclave_init::setup_firewall();
    rt.block_on(async {
        if let Err(e) = enclave_init::configure_network().await {
            eprintln!("[FATAL] Network config failed: {}", e);
            enclave_init::poweroff();
        }

        async_main(boot_manifest).await
    })
}

#[allow(dead_code)]  // Debug endpoint, not used in production
async fn test_quote(axum::extract::State(_state): axum::extract::State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    match tpm::quote("1234", &[], None).await {
        Ok(tpm_data) => axum::response::Json(tpm_data).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("TPM Quote Failed: {}", e)).into_response(),
    }
}

async fn async_main(boot_manifest: BTreeMap<String, String>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    
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
    info!("Starting PayPal Auth on {} (v151 Hardened)", PLATFORM_LABEL);

    #[cfg(feature = "oci")]
    {
        // v152: fetch the AMD VCEK + ASK/ARK cert chain once, up front, and
        // persist them (read-only root → /persistent when available, /tmp
        // tmpfs otherwise). Later quote() calls reuse the cache and only
        // re-download when the TCB changes.
        tokio::spawn(async { tpm::warm_kds_cache().await });
        // v154: probe the PSP's own endorsement table at boot and log the
        // host-level key provenance (VCEK vs VLEK vs KDS mismatch) to the
        // serial console — diagnostics only, zero-nonce report.
        tokio::spawn(async { tpm::diagnostic_psp_probe().await });
    }
    info!("SECRET_NAME={:?}", std::env::var("SECRET_NAME"));

    eprintln!("[DEBUG] about to fetch config");
    
    // --- MEASURED BOOT ---
    // Note: PCR 15 was anchored with the disk manifest in PID 1 phase.
    // BIN_HASH is included in the report JSON and verified via SLSA.
    
    // DIAGNOSTIC: Check TPM device presence
    let tpm_exists = std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists();
    info!("TPM Device present: {}", tpm_exists);

    // Log current PCR 15 state for diagnostics (TPM builds only)
    if tpm_exists {
        if let Ok(pcr_out) = tpm::run_cmd("tpm2", &["pcrread", "sha256:15"]).await {
            info!("Current PCR 15 State:\n{}", String::from_utf8_lossy(&pcr_out).trim());
        }

        // DIAGNOSTIC: Dump all NV indices to find the SEV-SNP report
        match tpm::run_cmd("/usr/bin/tpm2_getcap", &["handles-nv-index"]).await {
            Ok(nv_out) => info!("Available TPM NV Indices:\n{}", String::from_utf8_lossy(&nv_out).trim()),
            Err(e) => warn!("Failed to get TPM NV indices (full path): {}", e),
        }
    }

    #[cfg(not(feature = "oci"))]
    {
        let _client = hardened_client();
        // Try the instance-level identity token (GCP Attestation Token)
        match _client.get("http://metadata.google.internal/computeMetadata/v1/instance/identity?audience=paypal-auditor&format=full")
            .header("Metadata-Flavor", "Google")
            .send().await {
            Ok(resp) => {
                match resp.text().await {
                    Ok(jwt) => info!("ATTESTATION TOKEN: {}", jwt),
                    Err(e) => warn!("Failed to read attestation token text: {}", e),
                }
            },
            Err(e) => warn!("Failed to fetch attestation token: {}", e),
        }
    }

    #[cfg(feature = "oci")]
    {
        // OCI: Fetch instance identity from the Instance Metadata Service (opc/v2)
        match crate::oci_snp::oci_metadata("instance/").await {
            Some(identity_doc) => {
                let preview: String = identity_doc.chars().take(200).collect();
                info!("OCI Instance Identity: {}", preview);
            }
            None => warn!("OCI metadata service unavailable"),
        }
        // Check AMD SEV-SNP availability
        if crate::oci_snp::is_sev_snp_available() {
            info!("AMD SEV-SNP hardware attestation available on this OCI instance");
        } else {
            warn!("AMD SEV-SNP interface not detected — SNP report acquisition may fail");
        }
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

    // v69/v160: Attestation signing key → EphemeralEnclaveIdentity (P_enc/S_enc).
    // A Vault/config key is parsed eagerly (an unparseable one fails LOUDLY and
    // falls back to a fresh ephemeral key rather than shipping a key that can
    // never sign); otherwise a per-boot RAM-only RSA-4096 key is generated.
    // v152 SECURITY: never log private key material. On OCI the GRUB cmdline
    // carries `console=ttyS0`, so every info!() line lands in the Instance
    // Console History (readable by anyone with console access) — log only the
    // key's existence and size of its public material.
    let enclave_identity = if let Some(key) = config.attestation_signing_key.clone() {
        match EphemeralEnclaveIdentity::from_pem(&key) {
            Ok(id) => {
                info!("Attestation signing key loaded from Vault");
                Some(id)
            }
            Err(e) => {
                error!("Vault attestation key unparseable ({}) — falling back to a fresh ephemeral RAM-only key", e);
                EphemeralEnclaveIdentity::generate().ok()
            }
        }
    } else {
        info!("Attestation signing key missing in Vault, generating ephemeral RAM-ONLY RSA 4096 key...");
        match EphemeralEnclaveIdentity::generate() {
            Ok(id) => {
                info!("--- EPHEMERAL RSA KEY GENERATED (RAM ONLY, {} pubkey-DER bytes, material never logged) ---", id.pubkey_der.len());
                Some(id)
            }
            Err(e) => {
                error!("Ephemeral enclave key generation failed: {}", e);
                None
            }
        }
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
        enclave_identity,
        ip_stats: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        last_limit_reset: Arc::new(RwLock::new(Instant::now())),
        connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        boot_manifest,
        pending_attestations: Arc::new(RwLock::new(std::collections::HashMap::new())),
        pending_oauth_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
    });

    // v117: Background task for cleaning up expired pending attestations (DoS mitigation)
    let state_for_cleanup = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = Instant::now();
            let mut pending = state_for_cleanup.pending_attestations.write();
            let before = pending.len();
            pending.retain(|_, (_, _, timestamp)| {
                now.duration_since(*timestamp) < Duration::from_secs(600) // 10 minute TTL
            });
            let after = pending.len();
            if before != after {
                info!("Cleaned up {} expired pending attestations ({} remaining)", before - after, after);
            }
            drop(pending);

            // v152: same TTL sweep for OAuth CSRF state tokens (v160: the
            // PKCE session rides in the same entry — its created_at is the TTL clock)
            let mut oauth = state_for_cleanup.pending_oauth_states.write();
            oauth.retain(|_, (_, pkce)| now.duration_since(pkce.created_at) < Duration::from_secs(600));
        }
    });

    // Build the main app router
    eprintln!("[DEBUG] building router");
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/generate", axum::routing::post(generate_cert))
        .route("/debug/attestation", get(debug_attestation))
        .route("/debug/envelope", get(debug_envelope))
        // v161 (plan Pillars 4+5): pre-flight protocol + same-origin auditor.
        .route("/attest/preflight", axum::routing::options(preflight_cors).post(attest_preflight))
        .route("/verify.html", get(serve_verify_html))
        .route("/privacy", get(privacy))
        .route("/terms", get(terms))
        .route("/report", get(|| async { Redirect::to("/") }))
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .layer(axum::middleware::from_fn(security_headers))
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
    info!("Obtaining TLS certificate via ACME...");
    let ca = GooglePublicCaManager::new(&config);
    let (cert_pem, key_pem) = match ca.ensure_certificate().await {
        Ok(r) => {
            info!("Certificate obtained via ACME");
            https_ready.store(true, Ordering::Relaxed);
            *state.tls_cert_pem.write() = Some(String::from_utf8_lossy(&r.0).to_string());
            r
        }
        Err(e) => {
            // v152 SECURITY: never fall back to a self-signed certificate.
            // When Google Public CA / Let's Encrypt rate-limits us, a
            // self-signed cert would break production AND train users to
            // click through browser warnings (MITM prompt-fatigue). Instead
            // retry ACME with capped backoff — rate-limit windows expire;
            // serving an untrusted cert does not become safer over time.
            error!("ACME certificate failed: {}. Retrying with backoff (no self-signed fallback).", e);
            let mut backoff = Duration::from_secs(120);
            let max_backoff = Duration::from_secs(3600);
            let (cert_pem, key_pem) = loop {
                tokio::time::sleep(backoff).await;
                match ca.ensure_certificate().await {
                    Ok(r) => {
                        info!("Certificate obtained via ACME after retry");
                        break r;
                    }
                    Err(e2) => {
                        warn!("ACME retry failed: {} — backing off {:?}", e2, backoff);
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
            };
            https_ready.store(true, Ordering::Relaxed);
            *state.tls_cert_pem.write() = Some(String::from_utf8_lossy(&cert_pem).to_string());
            (cert_pem, key_pem)
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

// PROD: Debug handlers removed

// ============================================================================
// v152 SECURITY REGRESSION TESTS
// ============================================================================
#[cfg(test)]
mod security_tests {
    use super::*;

    fn base_config() -> Config {
        Config {
            paypal_client_id: "id".to_string(),
            paypal_client_secret: "secret".to_string(),
            paypal_verified_client_id: Some("vid".to_string()),
            paypal_verified_client_secret: Some("vsecret".to_string()),
            domain: "example.com".to_string(),
            eab_key_id: None,
            eab_hmac_key: None,
            staging: false,
            acme_account_json: None,
            attestation_signing_key: None,
            secret_ocid: None,
        }
    }

    #[cfg(feature = "oci")]
    #[test]
    fn option_a_secret_resolution_and_fail_closed() {
        // 1. The migrated (non-secret) user_data template parses: empty
        //    credential fields + secret_ocid.
        let template: Config = serde_json::from_str(
            r#"{"paypal_client_id":"","paypal_client_secret":"","domain":"x.example.com","secret_ocid":"ocid1.secret.oc1..abc"}"#,
        )
        .expect("template must parse");
        assert_eq!(template.secret_ocid.as_deref(), Some("ocid1.secret.oc1..abc"));

        // 2. An unfetched template FAILS credential validation (fail-closed:
        //    no silent acceptance of an empty secret).
        assert!(require_credentials(template).is_err());

        // 3. The secret bundle payload resolves to full credentials and its
        //    own secret_ocid is cleared (no re-fetch loops).
        let resolved = resolve_secret_config(
            r#"{"paypal_client_id":"id","paypal_client_secret":"sec","domain":"x.example.com","secret_ocid":"ocid1.secret.oc1..abc"}"#,
        )
        .expect("bundle must resolve");
        assert_eq!(resolved.paypal_client_secret, "sec");
        assert!(resolved.secret_ocid.is_none());

        // 4. A malformed bundle is rejected loudly.
        assert!(resolve_secret_config("not json").is_err());
    }

    #[test]
    fn require_credentials_accepts_real_credentials() {
        assert!(require_credentials(base_config()).is_ok());
    }

    // v160 (Pillar 2) cross-implementation parity pin: the SNP report_data
    // binding = SHA-256(P_enc_SPKI_DER ∥ session_nonce). Mirrored by
    // scripts/test-verify-security.mjs Test 8 and verify.html's
    // snpBindingHex() — update all three together (same discipline as the
    // session-nonce pin below).
    #[test]
    fn snp_report_data_binding_parity_v160() {
        let der = b"fake-der-bytes";
        let nonce = "398c2c1b18583ac9c3935ffdea04f0b2a3dfdd927140072bd50511e9f77db8f7";
        let binding = tpm::snp_report_data_binding(der, nonce);
        // [32..64] must be zero; [0..32] the pinned digest.
        assert_eq!(binding[32..], [0u8; 32]);
        assert_eq!(
            hex::encode(&binding[..32]),
            "22a092286d97a00032a2c8b1a24b3c4691ff9fad6d1759c18d17b7a5354c248f"
        );
        // Determinism + nonce sensitivity (a different session cannot reuse
        // another session's binding).
        assert_ne!(
            hex::encode(&tpm::snp_report_data_binding(der, nonce)[..32]),
            hex::encode(&tpm::snp_report_data_binding(der, &"00".repeat(32))[..32])
        );
    }

    // v161 (plan Pillars 2–5) cross-implementation parity pin: the
    // CLIENT-BOUND SNP report_data binding =
    //   SHA-256(P_enc_SPKI_DER ∥ code_challenge ∥ P_client_SPKI_DER ∥ client_nonce).
    // Mirrored by scripts/test-verify-security.mjs Test 9 and verify.html's
    // preflightBindingHex() — update all three together.
    #[test]
    fn preflight_binding_parity_v161() {
        let pubkey_der = b"fake-der-bytes";
        let code_challenge = "TEST_CHALLENGE_v161_parity";
        let client_pub = b"fake-client-ecdh-der";
        let client_nonce: [u8; 32] =
            hex::decode("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
                .unwrap()
                .try_into()
                .unwrap();

        let binding = tpm::preflight_report_data_binding(pubkey_der, code_challenge, client_pub, &client_nonce);
        // [32..64] must be zero; [0..32] the pinned digest.
        assert_eq!(binding[32..], [0u8; 32]);
        assert_eq!(
            hex::encode(&binding[..32]),
            "eb25571bb08d245e4a89f8903c5d348e193e70fe5c2926e2ab033bdcc6beeba8"
        );
        // Every element is live: changing any one input changes the binding
        // (a replayed/spliced session cannot reuse another's report_data).
        let base = hex::encode(&binding[..32]);
        assert_ne!(base, hex::encode(&tpm::preflight_report_data_binding(b"other-der", code_challenge, client_pub, &client_nonce)[..32]));
        assert_ne!(base, hex::encode(&tpm::preflight_report_data_binding(pubkey_der, "OTHER_CHALLENGE", client_pub, &client_nonce)[..32]));
        assert_ne!(base, hex::encode(&tpm::preflight_report_data_binding(pubkey_der, code_challenge, b"other-client", &client_nonce)[..32]));
        let mut other_nonce = client_nonce;
        other_nonce[0] ^= 0xff;
        assert_ne!(base, hex::encode(&tpm::preflight_report_data_binding(pubkey_der, code_challenge, client_pub, &other_nonce)[..32]));
        // …and it differs from the v160 session binding by construction.
        assert_ne!(base, hex::encode(&tpm::snp_report_data_binding(pubkey_der, &hex::encode(client_nonce))[..32]));
    }

    // v161: pre-flight sessions are client-bound and carry their own ECDH
    // key; legacy /login sessions are not (v160 path).
    #[test]
    fn preflight_session_is_client_bound() {
        let mut nonce = [7u8; 32];
        nonce[0] = 1;
        let pk = PkceSession::new_preflight(b"client-der".to_vec(), nonce);
        assert!(pk.is_preflight());
        assert_eq!(pk.client_ecdh_pub, b"client-der");
        assert_eq!(pk.client_nonce, nonce);
        assert!(pk.enclave_ecdh.is_some());
        // RFC 7636 derivation still holds for pre-flight sessions.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        assert_eq!(
            pk.code_challenge,
            B64URL.encode(Sha256::digest(pk.code_verifier.as_bytes()))
        );
        // The verifier never appears in the challenge and vice versa.
        assert_ne!(pk.code_verifier, pk.code_challenge);
        // Two sessions never share verifier/challenge/nonce-derived material.
        let other = PkceSession::new_preflight(b"client-der".to_vec(), nonce);
        assert_ne!(other.code_verifier, pk.code_verifier);
        // Legacy sessions are NOT client-bound.
        assert!(!PkceSession::new().is_preflight());
        // ECDH key agreement round-trip: two sessions derive DIFFERENT keys
        // for the same client key+nonce (per-session enclave ECDH key).
        let client = crypto::generate_ecdh_keypair().expect("test ECDH key");
        let client_der = client.public_key_to_der().unwrap();
        let k1 = crypto::derive_e2ee_session_key(pk.enclave_ecdh.as_ref().unwrap(), &client_der, &nonce).unwrap();
        let k2 = crypto::derive_e2ee_session_key(other.enclave_ecdh.as_ref().unwrap(), &client_der, &nonce).unwrap();
        assert_ne!(k1, k2, "per-session enclave ECDH key must yield distinct session keys");
        // Encrypt/decrypt round-trip with AAD binding.
        let (iv, ct) = crypto::encrypt_aad(&k1, b"payload", &nonce).unwrap();
        assert_eq!(crypto::decrypt_aad(&k1, &iv, &ct, &nonce).unwrap(), b"payload");
        // AAD-less decryption of an AAD-bound ciphertext fails (GCM
        // authentication covers the associated data) — replaying the
        // ciphertext with a stripped/other AAD is rejected by the primitive.
        assert!(crypto::decrypt(&k1, &iv, &ct).is_err());
        // RFC 5869 Test Case 1 (HKDF-SHA256): pins the Rust implementation to
        // the standard WebCrypto implements, so the browser's deriveKey and
        // the enclave's derive_e2ee_session_key agree byte-for-byte.
        let tc1_ikm = vec![0x0bu8; 22];
        let tc1_salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let tc1_info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let mut tc1_okm = [0u8; 42];
        crypto::hkdf_sha256(&tc1_ikm, &tc1_salt, &tc1_info, &mut tc1_okm);
        assert_eq!(
            hex::encode(tc1_okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        // Wrong AAD (another session's nonce) must fail closed.
        let mut other_nonce = nonce;
        other_nonce[31] ^= 0xff;
        assert!(crypto::decrypt_aad(&k1, &iv, &ct, &other_nonce).is_err());
    }

    // v160 (Pillar 3): PKCE (RFC 7636 §4.2) invariants — the challenge is
    // exactly BASE64URL(SHA256(ASCII(verifier))), the verifier is 64 random
    // bytes in the base64url alphabet (no padding — it rides URL/query
    // encoding on the token request), and no two sessions repeat.
    #[test]
    fn pkce_session_matches_rfc7636() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use base64::Engine as _;
        use sha2::{Digest, Sha256};

        let a = PkceSession::new();
        let b = PkceSession::new();

        assert_eq!(
            a.code_challenge,
            B64URL.encode(Sha256::digest(a.code_verifier.as_bytes()))
        );
        assert_eq!(a.code_verifier.len(), 86); // 64 bytes → 86 base64url chars, unpadded
        assert!(a
            .code_verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(a.code_verifier, b.code_verifier);
        assert_ne!(a.code_challenge, b.code_challenge);
    }

    #[test]
    fn require_credentials_rejects_missing_secret() {
        let mut c = base_config();
        c.paypal_client_secret = String::new();
        assert!(require_credentials(c).is_err());
    }

    /// SECURITY: /\.well-known/acme-challenge/{token} must never traverse out
    /// of /tmp/acme-challenge. The token is a single axum Path segment but
    /// percent-decoding happens AFTER routing, so `..%2F..%2Fetc%2Fpasswd`
    /// arrives as one segment and would escape the directory if joined
    /// unvalidated.
    #[test]
    fn acme_token_rejects_traversal() {
        // traversal primitives — all must be rejected
        for tok in [
            "..",
            "../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd", // not decoded here; '%' is outside the alphabet
            "../../proc/1/environ",
            ".",
            "",
            "a/b",
            "token\0.txt",
            "token.with.dots",
            "tok en",
        ] {
            assert!(!acme_token_valid(tok), "accepted traversal token {tok:?}");
        }
        // RFC 8555 §8.3: unpadded base64url — realistic http-01 tokens pass
        for tok in [
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
            "LT-7Mn7l0Dh7l0Dh7l0Dh7l0Dh7l0Dh7l0Dh7l0Dh7",
            "_abc-XYZ_0123456789",
        ] {
            assert!(acme_token_valid(tok), "rejected valid token {tok:?}");
        }
        // bounded length (DoS: unbounded join/read)
        assert!(!acme_token_valid(&"a".repeat(129)));
    }

    #[test]
    fn require_credentials_rejects_legacy_placeholder() {
        let mut c = base_config();
        c.paypal_client_secret = "MISSING_CLIENT_SECRET".to_string();
        assert!(require_credentials(c).is_err());
        let mut c2 = base_config();
        c2.paypal_verified_client_id = Some("MISSING_CLIENT_ID".to_string());
        assert!(require_credentials(c2).is_err());
    }

    #[test]
    fn no_hardcoded_fallback_secrets_in_source() {
        // The old hardcoded PayPal credentials must never come back.
        // Fragments are assembled from parts so this test's own source
        // cannot match itself under include_str!("main.rs").
        let src = include_str!("main.rs");
        let leaked = [
            format!("{}{}", "EFdUSE2qjgZy5Ok5f4Cy0", "SBuodWTj30TzO"),
            format!("{}{}", "EHSSIjy5sUHPYrBA1tN-U", "qDLfuTe-FSSdx"),
            format!("{}{}", "ARDDrFepkPcuh-bWdtKPLe", "MNptSHp2Bvha"),
            format!("{}{}", "AZXkzMWMioIQ-lYG1lrKrg", "iDAwtx2rWtig"),
        ];
        for frag in &leaked {
            assert!(!src.contains(frag.as_str()), "hardcoded credential fragment found in source: {}", &frag[..12]);
        }
    }

    #[test]
    fn session_nonce_binds_custom_info() {
        use sha2::{Digest, Sha256};
        let paypal_hash = hex::encode(Sha256::digest(b"{\"sub\":\"user\"}"));
        let pubkey = Sha256::digest(b"fake-der-bytes");
        // SEC-02: the nonce also binds the binary hash + canonical manifest.
        let binary = "ab".repeat(32);
        let mut manifest = std::collections::BTreeMap::new();
        // Inserted deliberately "unsorted"; canonical_manifest_json must sort.
        manifest.insert("EFI/BOOT/vmlinuz".to_string(), "cc".repeat(32));
        manifest.insert("EFI/BOOT/initrd.img".to_string(), "dd".repeat(32));
        let canonical = canonical_manifest_json(&manifest);
        // Canonical form is the sorted [path, sha] pair array, compact JSON —
        // byte-identical to verify.html's JSON.stringify of the sorted pairs.
        assert_eq!(
            canonical,
            format!("[[\"EFI/BOOT/initrd.img\",\"{}\"],[\"EFI/BOOT/vmlinuz\",\"{}\"]]", "dd".repeat(32), "cc".repeat(32))
        );

        let n1 = compute_session_nonce(&paypal_hash, &pubkey, "walletA", &binary, &canonical);
        let n2 = compute_session_nonce(&paypal_hash, &pubkey, "walletB", &binary, &canonical);
        assert_ne!(n1, n2, "custom_info must be bound into the nonce");

        // The code identity is bound too: different binary or manifest →
        // different nonce (a tampered disk cannot reuse a valid quote).
        let other_binary = format!("{}ac", "ab".repeat(31)); // 32 bytes, last byte flipped
        let n_bin = compute_session_nonce(&paypal_hash, &pubkey, "walletA", &other_binary, &canonical);
        assert_ne!(n1, n_bin, "binary_sha256 must be bound into the nonce");
        let mut manifest2 = manifest.clone();
        manifest2.insert("EFI/BOOT/evil.efi".to_string(), "ee".repeat(32));
        let n_man = compute_session_nonce(&paypal_hash, &pubkey, "walletA", &binary, &canonical_manifest_json(&manifest2));
        assert_ne!(n1, n_man, "disk manifest must be bound into the nonce");

        // Absent custom_info is canonicalized to "NONE" by the caller; the
        // auditor hashes report.custom_info (or "NONE") identically.
        let n_none = compute_session_nonce(&paypal_hash, &pubkey, "NONE", &binary, &canonical);
        assert_ne!(n1, n_none);

        // Deterministic for the same inputs
        assert_eq!(n1, compute_session_nonce(&paypal_hash, &pubkey, "walletA", &binary, &canonical));

        // Cross-check against an independent SHA-256(5-element pre-image) impl —
        // this exact vector is mirrored in the node test for verify.html.
        let mut h = Sha256::new();
        h.update(hex::decode(&paypal_hash).unwrap());
        h.update(&pubkey);
        h.update(Sha256::digest(b"walletA"));
        h.update(hex::decode(&binary).unwrap());
        h.update(Sha256::digest(canonical.as_bytes()));
        assert_eq!(n1, hex::encode(h.finalize()));

        // Cross-implementation parity pin: this vector was computed
        // independently in node (crypto.createHash) and by verify.html's
        // WebCrypto expectedNonce code. If enclave and auditor ever drift
        // apart again, this assertion fails at CI time.
        assert_eq!(
            n1,
            "398c2c1b18583ac9c3935ffdea04f0b2a3dfdd927140072bd50511e9f77db8f7",
            "nonce formula drifted from the auditor's expectedNonce — update verify.html and this vector together"
        );
    }

    #[test]
    fn verified_flow_projection_drops_all_profile_data() {
        // Even if the token were over-scoped or PayPal returned extra
        // fields, the verified flow must never let profile data past the
        // fetch: no name/email/address/birthdate can reach the session
        // store, the nonce, or the signed report.
        let full = PayPalUserInfo {
            user_id: "https://uri.paypal.com/services/paypalaccount/XYZ".to_string(),
            sub: Some("sub-1".to_string()),
            name: Some("Alice Example".to_string()),
            given_name: Some("Alice".to_string()),
            family_name: Some("Example".to_string()),
            email: Some("alice@example.com".to_string()),
            emails: Some(vec![PayPalEmail { value: "alice@example.com".to_string(), primary: Some(true), confirmed: Some(true) }]),
            email_verified: Some(true),
            birthdate: Some("1990-01-01".to_string()),
            picture: Some("https://example.com/a.png".to_string()),
            phone_number: Some("+15551234567".to_string()),
            address: Some(PayPalAddress { street_address: Some("1 Main St".to_string()), locality: Some("Berlin".to_string()), region: None, postal_code: Some("10115".to_string()), country: Some("DE".to_string()) }),
            verified_account: Some("true".to_string()),
            payer_id: Some("XYZ".to_string()),
            ..Default::default()
        };

        let projected = full.clone().into_verification_only();

        // Verification facts survive (the gate + report binding need them).
        assert_eq!(projected.user_id, full.user_id);
        assert_eq!(projected.payer_id.as_deref(), Some("XYZ"));
        assert_eq!(projected.verified_account.as_deref(), Some("true"));

        // Everything else is gone — check the serialized form, which is
        // what actually reaches the nonce hash and the report.
        let v = serde_json::to_value(&projected).unwrap();
        for pii in ["sub", "name", "given_name", "family_name", "middle_name", "nickname",
                    "preferred_username", "profile", "picture", "website", "email", "emails",
                    "email_verified", "gender", "birthdate", "zoneinfo", "locale", "phone_number",
                    "address", "verified", "account_type", "age_range"] {
            assert!(v.get(pii).is_none() || v[pii].is_null(), "field {} survived projection: {}", pii, v);
        }

        // Deterministic, and distinct from the unprojected payload.
        assert_eq!(serde_json::to_value(projected.clone()).unwrap(), serde_json::to_value(projected).unwrap());
        assert_ne!(serde_json::to_value(&full).unwrap(), serde_json::to_value(&full.clone().into_verification_only()).unwrap());
    }
}
