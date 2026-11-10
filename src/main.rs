//! PayPal OAuth Confidential Enclave (Intel TDX / Alibaba Cloud)
//!
//! Hardened Zero-Trust Implementation against Colluding Owner & Cloud Provider

mod intel_tdx;
mod selfreport;

const PAYPAL_CA_PEM: &[u8] = include_bytes!("paypal.pem");

mod enclave_init {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::Ipv4Addr;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

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

        {
            let _ = std::process::Command::new("/sbin/modprobe").args(["-r", "intelpsfw"]).status();
            modprobe("configfs");
            let _ = std::process::Command::new("/bin/mount").args(["-t", "configfs", "none", "/sys/kernel/config"]).status();
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
        // Shutdown path: the hypervisor's graceful stop is an ACPI power-button
        // press, which only reaches userspace through the button driver and the
        // evdev input interface. Neither is built into Debian's cloud kernel
        // (`CONFIG_ACPI_BUTTON=m`, `CONFIG_INPUT_EVDEV=m`) and neither was in
        // the initramfs, so a stop request used to reach nothing at all.
        modprobe("button");
        modprobe("evdev");
    }

    /// Set by the SIGTERM handler: the handler itself may do nothing else.
    static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
    /// Why the shutdown started, recorded for the log line the operator reads.
    /// Never written from signal context.
    static SHUTDOWN_REASON: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

    /// How long a graceful stop waits for sessions already in flight.
    ///
    /// Equal to the proxy's default idle budget for one session
    /// (`TLS_PROXY_SESSION_TIMEOUT`, 120 s): a notarisation that outlives its
    /// own timeout is already dead, so waiting longer cannot save it. It also
    /// stays well inside the platform's stop window — the pre-fix instance sat
    /// in `Stopping` for 260 s before the platform force-stopped it.
    pub const DRAIN_BUDGET: Duration = Duration::from_secs(120);

    /// What the drain loop should do next, kept pure so it can be tested
    /// without an HTTP client, a proxy child, or a clock.
    #[derive(Debug, PartialEq, Eq)]
    pub enum DrainStep {
        /// Nothing in flight: the machine can power off.
        Done,
        /// Sessions still running, budget left: keep waiting.
        Wait,
        /// Budget spent with this many sessions still running: power off anyway
        /// and say so, rather than hold the instance open forever.
        GiveUp(u64),
    }

    pub fn drain_step(active: u64, waited: Duration, budget: Duration) -> DrainStep {
        if active == 0 {
            DrainStep::Done
        } else if waited >= budget {
            DrainStep::GiveUp(active)
        } else {
            DrainStep::Wait
        }
    }

    /// Watch for the hypervisor's shutdown request and honour it.
    ///
    /// Nothing here existed before: this process is PID 1, `poweroff()` in this
    /// module parks instead of powering off (it is the fail-closed halt), and no
    /// handler was ever installed for a signal or for ACPI. A graceful
    /// `StopInstance` therefore sat in `Stopping` until the platform gave up and
    /// force-stopped it.
    pub fn arm_shutdown_handling() {
        unsafe {
            // SIGTERM is what a container runtime or an init-style stop sends;
            // PID 1 ignores it by default, so a stop request that used this
            // signal was silently discarded.
            libc::signal(libc::SIGTERM, shutdown_on_signal as libc::sighandler_t);
        }
        std::thread::spawn(watch_power_button);
        std::thread::spawn(shutdown_worker);
        std::thread::spawn(shutdown_watchdog);
        kmsg("shutdown handling armed (ACPI power button + SIGTERM, drains sessions)");
    }

    /// Ask for a shutdown from a context that may allocate and log.
    ///
    /// Idempotent: the second and later requests are ignored, so a power-button
    /// press arriving while a drain is already running cannot restart it or
    /// reset the budget.
    pub fn request_shutdown(reason: &str) {
        if SHUTDOWN_REQUESTED.swap(true, Ordering::SeqCst) {
            return;
        }
        *SHUTDOWN_REASON.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason.to_string());
        kmsg(&format!("shutdown requested: {reason}"));
    }

    extern "C" fn shutdown_on_signal(_sig: libc::c_int) {
        // Async-signal-safe by construction: one store, no allocation, no
        // logging through stdio on a console that may have stopped draining.
        // The worker does the drain and the syscall.
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }

    /// The single path from "shutdown requested" to the machine being off.
    ///
    /// Both the power button and SIGTERM set the flag; this thread is what
    /// drains, logs, and powers off, so there is exactly one place where a
    /// shutdown can go wrong.
    fn shutdown_worker() {
        loop {
            std::thread::sleep(Duration::from_millis(200));
            if !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                continue;
            }
            let reason = SHUTDOWN_REASON
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .unwrap_or_else(|| "SIGTERM".to_string());
            drain_then_power_off(&reason);
        }
    }

    /// The runtime the drain runs on.
    ///
    /// **`enable_all()`, not `enable_time()`**: the drain calls the proxy's
    /// loopback API, and with the IO driver disabled the connect never
    /// completes — the worker parks forever and the hypervisor sits in
    /// `Stopping` with no console to say why. That is not hypothetical: it is
    /// exactly what v219 did on its first graceful stop, which then needed a
    /// force-stop. Pinned by `the_drain_runtime_can_reach_the_loopback_api`.
    pub(crate) fn drain_runtime() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }

    /// Last line of defence: if the drain worker itself wedges or panics, the
    /// machine still must not sit in `Stopping` forever.
    ///
    /// The budget is the drain budget plus a grace period, so this only fires
    /// when the normal path has already failed — the process exiting without
    /// releasing the instance is the failure mode that costs an operator a
    /// force-stop and tells them nothing.
    fn shutdown_watchdog() {
        let deadline = Duration::from_secs(DRAIN_BUDGET.as_secs() + 15);
        loop {
            std::thread::sleep(Duration::from_millis(500));
            if !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                continue;
            }
            let started = Instant::now();
            while started.elapsed() < deadline {
                std::thread::sleep(Duration::from_millis(500));
            }
            kmsg("shutdown watchdog: the drain did not finish, powering off anyway");
            power_off_now();
        }
    }

    /// Let in-flight notarised sessions finish, then power off.
    ///
    /// A notarisation in flight holds the prover's transcript and the proof of
    /// which host it came from; cutting it at power-off discards work the prover
    /// cannot recover, and the prover gets no answer that explains why. So the
    /// proxy is told to take no new sessions and this waits for the count to
    /// reach zero, bounded by [`DRAIN_BUDGET`] so a wedged session cannot pin the
    /// instance open.
    fn drain_then_power_off(reason: &str) -> ! {
        let api_port = crate::PROXY_SUPERVISOR.get().map(|sup| sup.api_port);
        let Some(api_port) = api_port else {
            kmsg(&format!("shutdown ({reason}): no proxy child yet, powering off"));
            power_off_now();
        };

        let rt = match drain_runtime() {
            Ok(rt) => rt,
            Err(e) => {
                kmsg(&format!("shutdown ({reason}): no drain runtime ({e}), powering off"));
                power_off_now();
            }
        };

        let started = Instant::now();
        let active = match rt.block_on(crate::proxy_loopback_call(
            "drain",
            api_port,
            reqwest::Method::POST,
            "/drain",
        )) {
            Ok(value) => {
                kmsg(&format!(
                    "drain ({reason}): proxy accepts no new sessions, {} in flight",
                    value
                        .get("active_sessions")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                ));
                value
                    .get("active_sessions")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            }
            Err((_, detail)) => {
                // No proxy to drain: nothing can be in flight through it.
                kmsg(&format!("drain ({reason}): proxy unreachable ({detail}), powering off"));
                power_off_now();
            }
        };

        let mut remaining = active;
        loop {
            match drain_step(remaining, started.elapsed(), DRAIN_BUDGET) {
                DrainStep::Done => {
                    kmsg(&format!(
                        "drain ({reason}): no sessions in flight, powering off after {}s",
                        started.elapsed().as_secs()
                    ));
                    power_off_now();
                }
                DrainStep::GiveUp(stuck) => {
                    kmsg(&format!(
                        "drain ({reason}): budget of {}s spent with {stuck} still in flight, \
                         powering off (those sessions are lost)",
                        DRAIN_BUDGET.as_secs()
                    ));
                    power_off_now();
                }
                DrainStep::Wait => {}
            }
            std::thread::sleep(Duration::from_millis(250));
            // The health answer is authoritative: a session that finished
            // between polls shows up as a lower count, and an unreachable API
            // means the child is gone and nothing is in flight.
            remaining = match rt.block_on(crate::proxy_loopback_call(
                "drain",
                api_port,
                reqwest::Method::GET,
                "/health",
            )) {
                Ok(value) => value
                    .get("active_sessions")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                Err(_) => 0,
            };
        }
    }

    /// Power the machine off for real. Deliberately distinct from `poweroff()`,
    /// which is the fail-closed halt-and-park: a shutdown request must release
    /// the instance, not preserve evidence indefinitely.
    fn power_off_now() -> ! {
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_POWER_OFF);
        }
        // The kernel refused (it can, e.g. when not privileged inside a
        // namespace). Park rather than spin; the platform will force-stop.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    /// One `struct input_event` frame: `timeval` (16 bytes on x86_64), then the
    /// type, code and value.
    const INPUT_EVENT_LEN: usize = 24;
    pub const EV_KEY: u16 = 0x01;
    pub const KEY_POWER: u16 = 116;

    /// True only for a power button being *pressed*: a release, a repeat, or any
    /// other key on the device must not power the machine off.
    pub fn is_power_press(frame: &[u8]) -> bool {
        frame.len() == INPUT_EVENT_LEN
            && u16::from_ne_bytes([frame[16], frame[17]]) == EV_KEY
            && u16::from_ne_bytes([frame[18], frame[19]]) == KEY_POWER
            && i32::from_ne_bytes([frame[20], frame[21], frame[22], frame[23]]) == 1
    }

    fn watch_power_button() {
        use std::collections::HashSet;
        let mut armed: HashSet<std::path::PathBuf> = HashSet::new();
        loop {
            if let Ok(dir) = std::fs::read_dir("/dev/input") {
                for entry in dir.flatten() {
                    let path = entry.path();
                    let is_event = path
                        .file_name()
                        .map(|n| n.to_string_lossy().starts_with("event"))
                        .unwrap_or(false);
                    // A node is watched once; `insert` is the de-duplication.
                    if is_event && armed.insert(path.clone()) {
                        std::thread::spawn(move || watch_input_node(path));
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    fn watch_input_node(path: std::path::PathBuf) {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(f) => f,
            Err(_) => return,
        };
        // Only the ACPI power button is allowed to power this machine off. An
        // event node that happens to report KEY_POWER for another reason (a
        // vendor HID quirk, a test device) is ignored by name.
        let name = evdev_name(&file);
        if !name.contains("Power Button") {
            return;
        }
        kmsg(&format!("watching {} ({}) for a power button press", path.display(), name));
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match (&file).read(&mut chunk) {
                Ok(0) => std::thread::sleep(std::time::Duration::from_millis(250)),
                Ok(n) => {
                    pending.extend_from_slice(&chunk[..n]);
                    let mut frames = 0;
                    while pending.len() >= INPUT_EVENT_LEN {
                        let frame: Vec<u8> = pending.drain(..INPUT_EVENT_LEN).collect();
                        if is_power_press(&frame) {
                            request_shutdown("ACPI power button pressed");
                        }
                        frames += 1;
                        if frames > 256 {
                            break;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(250))
                }
                Err(_) => return,
            }
        }
    }

    /// `EVIOCGNAME`: the answering device's name, empty when it cannot be read.
    fn evdev_name(file: &std::fs::File) -> String {
        use std::os::unix::io::AsRawFd;
        const IOC_READ: libc::c_ulong = 2;
        const EVIOCGNAME_NR: libc::c_ulong = 0x06;
        let mut buf = [0u8; 256];
        let request = (IOC_READ << 30)
            | ((buf.len() as libc::c_ulong) << 16)
            | ((b'E' as libc::c_ulong) << 8)
            | EVIOCGNAME_NR;
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), request, buf.as_mut_ptr()) };
        if rc < 0 {
            return String::new();
        }
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).to_string()
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

    /// Open exactly ONE inbound TCP port for an optional service (the
    /// TLSNotary proxy). The boot ruleset admits only 80/443 — right for the
    /// PayPal flow — so a service that must be reachable elsewhere asks for that
    /// port here, instead of the ruleset being loosened for everyone.
    pub fn open_service_port(port: u16) {
        let rule = format!("insert rule inet filter input tcp dport {} accept", port);
        match std::process::Command::new("/usr/sbin/nft").arg(&rule).status() {
            Ok(s) if s.success() => kmsg(&format!("nft: opened inbound tcp/{}", port)),
            _ => {
                kmsg(&format!(
                    "FATAL: could not open inbound tcp/{} — halting (the service would be unreachable)",
                    port
                ));
                poweroff();
            }
        }
    }

    // =========================================================================
    // v168 (independent security audit — plan Phases 1.1 / 4.1 / 4.2): boot
    // artifact + kernel hardening and post-boot egress lockdown.
    // Threat model: the cloud host controls the virtual disk (grub.cfg, and
    // with it the kernel command line), the virtual network, and the
    // metadata service. The EXPECTED_RTMR* pins in verify.html decide code
    // identity REMOTELY; these gates close the in-guest half.
    // =========================================================================

    /// The EXACT kernel command line built by build-alibaba-image.sh (the
    /// grub.cfg `linux` line after the kernel path). Drift guard:
    /// security_tests::cmdline_pin_matches_build_script asserts this constant
    /// stays byte-identical to the build script. Deliberate deviations from
    /// plan.md's example text, all justified: `quiet` is omitted because the
    /// TDX probe transcript must stay visible on the serial console (the
    /// project's primary diagnosis channel); `selinux=0` would disable a MAC
    /// policy if one is ever enabled (the initramfs ships none); `panic=1`
    /// reboots out of a panicked kernel, trading diagnosability for no
    /// security gain (a panicked kernel serves nothing). The actual defense
    /// against hypervisor argument injection is (a) determinism — this exact
    /// pinned string — plus (b) verify_cmdline() below and (c) the auditor's
    /// RTMR pins over the measured boot chain.
    ///
    /// Console note: the TDX firmware this platform ships today stops the
    /// console-capture stream at its own TD-stage lines, so nothing the guest
    /// writes reaches `GetInstanceConsoleOutput`. `earlyprintk=serial,...` was
    /// built and booted to test that (v215 probe) and it made no difference, so
    /// the cmdline stays at the audited baseline rather than carrying an entry
    /// that would force an RTMR pin rotation for no captured output.
    pub const EXPECTED_CMDLINE: &str =
        "console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0 swiotlb=524288";

    /// Fail closed on any kernel command line other than the audited one —
    /// the in-guest half of "hypervisor argument injection" defense (the
    /// remote half is the RTMR pin over the measured cmdline event).
    /// GRUB may legitimately prefix BOOT_IMAGE=<path>; everything else must
    /// match EXPECTED_CMDLINE exactly.
    pub fn verify_cmdline() {
        let observed = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let observed = observed.trim_matches('\0').trim();
        kmsg(&format!("Kernel cmdline: {:?}", observed));
        let stripped = observed
            .strip_prefix("BOOT_IMAGE=")
            .and_then(|s| s.find(' ').map(|i| &s[i + 1..]))
            .unwrap_or(observed);
        if stripped != EXPECTED_CMDLINE {
            kmsg(&format!(
                "FATAL: kernel cmdline mismatch — hypervisor/GRUB argument injection suspected. expected {:?} got {:?}. Halting.",
                EXPECTED_CMDLINE, stripped
            ));
            poweroff();
        }
        kmsg("Kernel cmdline matches the audited pin.");
    }

    /// v168 (plan Phase 4.2): kernel defense-in-depth for the secret-bearing
    /// runtime. TDX memory encryption covers DRAM ONLY — a swapped-out page
    /// would reach the host-controlled virtual disk in plaintext; kexec
    /// could later load an UNMEASURED kernel past the RTMR pins; suid-
    /// dumpable core dumps can carry key material to disk. Fail closed.
    pub fn harden_kernel() {
        kmsg("Hardening kernel (swapoff / kexec_load_disabled / suid_dumpable=0)...");
        // 1. swap must never be active while secrets are in RAM.
        if let Ok(swaps) = std::fs::read_to_string("/proc/swaps") {
            for line in swaps.lines().skip(1) {
                let dev = line.split_whitespace().next().unwrap_or("");
                if dev.is_empty() {
                    continue;
                }
                if let Ok(c) = std::ffi::CString::new(dev) {
                    let rc = unsafe { libc::swapoff(c.as_ptr()) };
                    kmsg(&format!("  swapoff({}) -> {}", dev, rc));
                }
            }
        }
        let remaining = std::fs::read_to_string("/proc/swaps")
            .map(|s| s.lines().skip(1).filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        if remaining != 0 {
            kmsg("FATAL: swap still active after swapoff — secrets could page to the host-controlled disk. Halting.");
            poweroff();
        }
        // 2. sysctl hardening. A kernel built without the knob is acceptable
        // (nothing to disable); a knob that REFUSES the hardened value is not.
        // 3. core dumps (plan Phase 4: "ulimit -c 0") — a core of the enclave
        //    process would carry key material to a filesystem the host reads.
        //    RLIMIT_CORE=0 kills them at the syscall layer (suid_dumpable=0
        //    covers the setuid case; this covers the process itself).
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
        kmsg(&format!("  setrlimit(RLIMIT_CORE, 0) -> {}", rc));
        for (path, val, name) in [
            ("/proc/sys/kernel/kexec_load_disabled", "1", "kexec_load_disabled"),
            ("/proc/sys/fs/suid_dumpable", "0", "suid_dumpable"),
        ] {
            if !std::path::Path::new(path).exists() {
                kmsg(&format!("  {} absent in this kernel — nothing to disable", name));
                continue;
            }
            if std::fs::write(path, val).is_err() {
                kmsg(&format!("FATAL: cannot set {} = {} — halting.", name, val));
                poweroff();
            }
            let rb = std::fs::read_to_string(path).unwrap_or_default();
            if rb.trim() != val {
                kmsg(&format!("FATAL: {} did not stick (read back {:?}) — halting.", name, rb.trim()));
                poweroff();
            }
        }
        kmsg("Kernel hardening applied.");
    }

    /// v168 (plan Phase 4.1): POST-BOOT EGRESS LOCKDOWN. The boot-time rules
    /// keep IMDS (100.100.100.200), DNS and
    /// port 80 open — necessary for user_data + ACME DNS-01 + HTTPS time
    /// sync, but afterwards they are pure exfiltration surface (DNS queries
    /// alone can leak secrets to a colluding resolver). Once the TLS cert is
    /// in RAM, the ONLY runtime egress is the PayPal API on 443 to the
    /// pinned IPs — hardened_client() resolves those names to these same
    /// addresses, so no DNS lookup is ever needed again. (DHCP is a one-shot
    /// BOOTP exchange at boot — there is no lease renewal daemon to starve.)
    pub fn egress_lockdown() {
        kmsg("POST-BOOT EGRESS LOCKDOWN: dropping IMDS/metadata, DNS, port 80; 443 only to pinned PayPal endpoints...");
        // v186 (self-report heartbeat fix): capture the sink's addresses while
        // DNS is STILL open, then allow EXACTLY those on 443. The boot-stage
        // documents already landed pre-lockdown, but `selfreport::serving()`
        // (and any later halt/failure) publishes after this flush — previously
        // dropped by the output policy, so a healthy box was indistinguishable
        // from a dark one. The sink payload is secret-free and signed per
        // request (write-only RAM key), so this reopens no exfil channel: no
        // DNS, no port 80, no wildcard — just 443 to the one pinned endpoint.
        let sink_addrs = crate::selfreport::pin_sink_network();
        let mut commands: Vec<String> = vec![
            "flush chain inet filter output".into(),
            "add rule inet filter output oif lo accept".into(),
            "add rule inet filter output ct state established,related accept".into(),
            // == hardened_client() pin set (api-m.paypal.com / api-m.sandbox) ==
            "add rule inet filter output ip daddr { 104.16.124.74, 146.75.123.1 } tcp dport 443 accept".into(),
        ];
        // The relay targets the proxy may serve, at the addresses boot-time DNS
        // gave them. Without this the proxy's SYN to a rotated CDN address is
        // dropped by the policy and the session stalls until its timeout.
        if let Some(relay_ips) = RELAY_TARGET_IPS.get().filter(|v| !v.is_empty()) {
            commands.push(format!(
                "add rule inet filter output ip daddr {{ {} }} tcp dport 443 accept",
                relay_ips.join(", ")
            ));
            kmsg(&format!(
                "Relay targets reachable after lockdown: 443 to {}",
                relay_ips.join(", ")
            ));
        }
        if !sink_addrs.is_empty() {
            let set = sink_addrs
                .iter()
                .map(|a| a.ip().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            commands.push(format!(
                "add rule inet filter output ip daddr {{ {} }} tcp dport 443 accept",
                set
            ));
            kmsg(&format!(
                "Self-report sink survives lockdown: 443 pinned to {}",
                set
            ));
        } else if crate::selfreport::sink_configured() {
            kmsg("WARNING: self-report sink configured but its hostname did not resolve pre-lockdown — post-lockdown reports will be dropped.");
        }
        for cmd in commands {
            match std::process::Command::new("/usr/sbin/nft").arg(&cmd).status() {
                Ok(s) if s.success() => {}
                _ => {
                    kmsg(&format!("FATAL: egress lockdown command '{}' failed — halting (fail closed).", cmd));
                    poweroff();
                }
            }
        }
        kmsg("Egress locked down: output policy drop except loopback + PayPal pinned 443 + self-report sink 443.");
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
        // v175 (live debug 2026-10-23): the ESP is NOT always /dev/sda1 or
        // /dev/vda1 — an NVMe system disk (imported images are flagged
        // NvmeSupport=supported) exposes it as /dev/nvme0n1p1. The hardcoded
        // pair silently mounted NOTHING, so /verify.html 500'd with
        // "not present on ESP or initramfs" while the file sat right there on
        // the ESP (the measurement path's dynamic scan found it — see
        // measure_boot_components). Mount whichever partition actually
        // carries a FAT filesystem with content.
        let esp_has_content = |target: &str| -> bool {
            // The real ESP always carries the boot chain under EFI/ and the
            // auditor at its root — require one of them so a random FAT
            // partition can never be mistaken for the measured ESP.
            std::path::Path::new(target).join("EFI").is_dir()
                || std::path::Path::new(target).join("verify.html").is_file()
        };
        if !esp_has_content("/boot/efi") {
            if let Ok(entries) = std::fs::read_dir("/sys/class/block") {
                let mut candidates: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.chars().any(|c| c.is_ascii_digit()))
                    .collect();
                candidates.sort();
                for dev_name in candidates {
                    let dev_path = format!("/dev/{}", dev_name);
                    let src = std::ffi::CString::new(dev_path).unwrap();
                    let tgt = std::ffi::CString::new("/boot/efi").unwrap();
                    let fst = std::ffi::CString::new("vfat").unwrap();
                    let rc = unsafe {
                        libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, std::ptr::null())
                    };
                    if rc == 0 && esp_has_content("/boot/efi") {
                        kmsg("ESP mounted at /boot/efi via block-device scan (NVMe or non-sda/vda layout)");
                        break;
                    }
                }
            }
        }
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
            // v176 (live debug 2026-10-23): when the SAME partition is already
            // mounted RW at /boot/efi (mount_filesystems' block scan), a
            // second MS_RDONLY mount fails with "Can't mount, would change RO
            // state" and the manifest came back EMPTY. Try RO first, fall back
            // to RW — this mount is read-only in spirit either way.
            let ro = unsafe {
                libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), libc::MS_RDONLY, std::ptr::null())
            };
            ro == 0
                || unsafe {
                    libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, std::ptr::null()) == 0
                }
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
        // Loopback already carries 127.0.0.1/8 (the kernel initialises it) but
        // starts DOWN, and binding an address of a down interface fails with
        // EADDRNOTAVAIL. The PayPal listener binds 0.0.0.0 so it never noticed;
        // the TLS proxy's attestation API binds 127.0.0.1 and crash-looped with
        // "cannot bind the attestation API on 127.0.0.1:8081: Cannot assign
        // requested address" (exit 1, supervisor backoff) until this ran.
        let _ = std::process::Command::new("/sbin/ip").args(["link", "set", "lo", "up"]).status();
        kmsg("Loopback raised (127.0.0.1 up)");

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

        // Relay targets are pinned once the config says which they are — see
        // main() after fetch_config(). They cannot be pinned here: at this
        // point the config has not been read yet, and the list is configurable.
        // DNS is still open then (egress_lockdown is later), which is all the
        // pinning needs.
        Ok(())
    }

    /// Boot-resolved addresses of the relay targets, kept so `egress_lockdown`
    /// can allow exactly the addresses /etc/hosts hands the proxy. Empty when
    /// DNS answered nothing, in which case no extra rule is added.
    static RELAY_TARGET_IPS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

    /// A relay target that is already an address, so nothing has to resolve it.
    /// IPv4 only: the egress rule is `ip daddr`, and TLS verifies against the
    /// committed name, so an IPv6 literal would be allowed by neither.
    pub(crate) fn relay_target_is_literal(name: &str) -> bool {
        name.parse::<std::net::Ipv4Addr>().is_ok()
    }

    /// Write the IPv4 addresses the configured relay targets had at boot into
    /// /etc/hosts, so the proxy can still resolve them after DNS is locked down,
    /// and remember them for the firewall allowlist.
    ///
    /// Names come from `services.tls_proxy.relay_targets` and are already
    /// validated (see `validate_relay_targets`); this lower-cases and
    /// de-duplicates them anyway, because a hosts file matches case-sensitively
    /// while DNS does not.
    pub fn pin_relay_targets(names: &[String]) {
        use std::net::ToSocketAddrs;
        let mut granted: Vec<String> = Vec::new();
        let mut lines = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
        if !lines.is_empty() && !lines.ends_with('\n') {
            lines.push('\n');
        }
        let mut already: Vec<String> = Vec::new();
        for raw in names {
            let entry = raw.trim().to_ascii_lowercase();
            if entry.is_empty() || already.contains(&entry) {
                continue;
            }
            already.push(entry.clone());
            // `host@address`: the operator already knows the address, so it is
            // pinned as given rather than resolved — this is how a host whose
            // DNS rotates (or does not answer at boot) stays reachable.
            if let Some((host, address)) = entry.split_once('@') {
                lines.push_str(&format!("{address} {host}\n"));
                if !granted.contains(&address.to_string()) {
                    granted.push(address.to_string());
                }
                kmsg(&format!(
                    "relay target {host} pinned in /etc/hosts to {address} (configured address, not resolved)"
                ));
                continue;
            }
            // A bare literal needs no resolution and no hosts entry:
            // getaddrinfo answers it without DNS, so it survives the lockdown
            // on its own. It opens 443 only: the prover cannot commit an
            // address, so nothing can actually be relayed to it.
            if relay_target_is_literal(&entry) {
                if !granted.contains(&entry) {
                    granted.push(entry.clone());
                }
                kmsg(&format!(
                    "relay target {entry} is a literal address: allowed on 443, but a prover cannot commit to it (use host@address)"
                ));
                continue;
            }
            let name = entry;
            match (name.as_str(), 443u16).to_socket_addrs() {
                Ok(addrs) => {
                    let ips: Vec<String> = addrs
                        .filter(|a| a.is_ipv4())
                        .map(|a| a.ip().to_string())
                        .collect();
                    if ips.is_empty() {
                        kmsg(&format!(
                            "relay target {name}: no IPv4 address at boot — sessions to it cannot resolve after lockdown"
                        ));
                        continue;
                    }
                    lines.push_str(&format!("{} {}\n", ips.join(" "), name));
                    for ip in &ips {
                        if !granted.contains(ip) {
                            granted.push(ip.clone());
                        }
                    }
                    kmsg(&format!(
                        "relay target {name} pinned in /etc/hosts to {}",
                        ips.join(", ")
                    ));
                }
                Err(e) => kmsg(&format!("relay target {name}: resolution failed: {e}")),
            }
        }
        if let Err(e) = std::fs::write("/etc/hosts", lines) {
            kmsg(&format!("cannot write /etc/hosts: {e}"));
        }
        let _ = RELAY_TARGET_IPS.set(granted);
    }

    /// Fail closed: publish the recorded reason to the out-of-mainland report
    /// sink FIRST (best effort, detached), then park forever. Parking — not
    /// rebooting — preserves the evidence and never hides the failure behind a
    /// boot loop.
    pub fn poweroff() -> ! {
        crate::selfreport::halt();
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
    extract::{Path as AxumPath, Query, State},
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
// Ephemeral In-RAM Enclave ECDH Session (per login callback)
// ----------------------------------------------------------------------------
// v180 (user directive — NO pre-login attestation): the pre-login PKCE
// handshake is gone, so the enclave no longer keeps a server-side pending
// session. The client session (P_client ∥ nonce ∥ flow ∥ custom_info) travels
// inside the OAuth `state` parameter, is validated at /callback, and is bound
// into the hardware quote's report_data[32..64] — a forged state therefore
// only produces a report that fails the local audit, never a usable blob.
// This helper mints the fresh per-callback enclave ECDH keypair the E2EE
// layer needs (the client's counterpart key arrives in the state token).
fn new_enclave_ecdh() -> Result<openssl::pkey::PKey<openssl::pkey::Private>, Box<dyn std::error::Error + Send + Sync>> {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    Ok(openssl::pkey::PKey::from_ec_key(ec_key)?)
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
// yet when the standalone /debug/envelope is generated.
// The auditor recomputes expectedNonce from whatever value we publish here, so
// any deterministic placeholder keeps the binding self-consistent; the real
// user hash is bound only at the login (callback) step. Self-documenting marker.
fn prelogin_paypal_hash() -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b"PRELOGIN_NO_USER"))
}

// v179 (plan Phase 1 — session-substitution defense): the callback quote's
// report_data[32..64] binds the CLIENT session that initiated the login:
//
//   SHA-256(P_client SPKI-DER ∥ Nonce_client)
//
// P_client/Nonce_client are generated in the user's browser and arrive with
// the login session (v180: carried inside the OAuth `state` token, parsed by
// /callback — no server-side pending session). The
// auditor holds ITS OWN copy of these values (localStorage/sessionStorage
// written when the key was created) and recomputes this digest — a report
// minted for a different browser's session carries the wrong bytes in the
// hardware quote and fails closed. Byte-identical to verify.html's
// `clientSessionBindingHex()`.
fn client_session_binding(client_pub_der: &[u8], client_nonce: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(client_pub_der);
    hasher.update(client_nonce);
    hasher.finalize().into()
}

/// v186 (audit round 5): canonicalize `custom_info` (trim; empty → "NONE")
/// and enforce the SAME 512-byte bound the auditor has always applied
/// client-side. The enclave previously accepted any size: `custom_info` is
/// copied TWICE into the signed login-session response (state token +
/// signed_fields) yet charged as 4 KiB of egress, so a direct caller could
/// inflate a single response ~256x past its budget charge — and, via a
/// forged `/callback` state token, park an unbounded blob in the E2EE vault
/// (charged 32 KiB). `None` = reject (fail closed). Shared by
/// `/attest/login-session` and `/callback` so both ends enforce one rule.
fn canonical_custom_info(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let s = if trimmed.is_empty() {
        "NONE".to_string()
    } else {
        trimmed.to_string()
    };
    if s.len() > 512 {
        None
    } else {
        Some(s)
    }
}

/// The HTTPS listener's public key, in the two forms a report publishes: the
/// SPKI PEM itself, and the SHA-256 of its DER for display and pinning.
///
/// v223 (user directive): a report must name the key a prover can seal the
/// PayPal code to. Publishing the fingerprint here is what lets the user check
/// the first (data-free) attestation and then hand the code to exactly that
/// instance — the private half never leaves TDX-protected RAM and is regenerated
/// on every boot.
fn attested_tls_key(state: &AppState) -> (String, String) {
    use sha2::Digest;
    let pem = state.tls_pubkey_pem.read().clone().unwrap_or_default();
    let sha256 = pubkey_fingerprint(&pem);
    (pem, sha256)
}

/// SHA-256 of a public key's DER as published in `tls_public_key_sha256`.
fn pubkey_fingerprint(pem: &str) -> String {
    use sha2::Digest;
    openssl::pkey::PKey::public_key_from_pem(pem.as_bytes())
        .ok()
        .and_then(|k| k.public_key_to_der().ok())
        .map(|der| hex::encode(sha2::Sha256::digest(&der)))
        .unwrap_or_default()
}

/// The notary's attestation-signing key, named in this report so a signed
/// TLSNotary record can be tied to this hardware quote.
///
/// v231 (the caveat v230 shipped with): a proxy record authenticates itself with
/// a per-boot RSA key that the record also carries, which on its own says only
/// "whoever wrote this record had that key". The proxy now publishes the key and
/// its SPKI-DER fingerprint on its loopback API, and every report minted here
/// names them — so the quote's report_data (which binds this enclave's identity
/// key, /init, and the disk manifest) transitively covers the notary key, and a
/// record verifier can compare instead of trust.
///
/// The fingerprint is recomputed here from the PEM rather than copied from the
/// child's answer: a wrong or missing PEM yields an empty field, never a value
/// this process did not calculate.
async fn attested_proxy_key() -> serde_json::Value {
    let sup = match PROXY_SUPERVISOR.get() {
        Some(sup) if sup.alive.load(Ordering::Relaxed) => sup,
        _ => {
            return serde_json::json!({
                "available": false,
                "reason": "services.tls_proxy is not enabled or its process is not running"
            })
        }
    };
    let body = match proxy_loopback_json("pubkey", sup.api_port, "/pubkey").await {
        Ok(v) => v,
        Err(_) => {
            return serde_json::json!({
                "available": false,
                "reason": "the notary did not answer GET /pubkey on its loopback API"
            })
        }
    };
    let pem = body
        .get("pubkey_pem")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let sha256 = pubkey_fingerprint(&pem);
    if pem.is_empty() || sha256.is_empty() {
        return serde_json::json!({
            "available": false,
            "reason": "the notary answered /pubkey without a usable public key"
        });
    }
    serde_json::json!({
        "available": true,
        "algorithm": body.get("algorithm").cloned().unwrap_or(serde_json::Value::Null),
        "signature_alg": body.get("signature_alg").cloned().unwrap_or(serde_json::Value::Null),
        "pubkey_pem": pem,
        "pubkey_sha256": sha256,
        // The child's own claim, kept for cross-checking: a mismatch here means
        // the PEM and its advertised fingerprint disagree, which is worth seeing
        // rather than silently fixing.
        "reported_sha256": body.get("pubkey_sha256").cloned().unwrap_or(serde_json::Value::Null),
    })
}

/// The `nonce` seal slot's public key, in the same two forms as the TLS slot.
///
/// v225 (user directive — two seals, one boot): a user may want to bind BOTH a
/// PayPal code and a nonce of their own choosing to the same instance. A second
/// boot key gives that a slot of its own, so a single data-free report names
/// both targets and the callback can prove both seals arrived in this boot.
fn attested_seal_key(state: &AppState) -> (String, String) {
    let pem = state.seal_pubkey_pem.read().clone().unwrap_or_default();
    let sha256 = pubkey_fingerprint(&pem);
    (pem, sha256)
}

/// Validate a caller-supplied `redirect_uri` before it can reach an authorize
/// URL: https only, no credentials, no query string, no fragment, no spaces.
///
/// Deliberately does NOT rewrite the value (no trailing-slash or case
/// normalisation): PayPal compares `redirect_uri` byte-for-byte, and the
/// allowlist below compares it the same way, so a "helpful" normalisation here
/// would silently turn one registered URI into a different, unregistered one.
fn normalize_redirect_uri(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.len() > 512 {
        return None;
    }
    let rest = t.strip_prefix("https://")?;
    if rest.is_empty() || rest.starts_with('/') {
        return None;
    }
    // `?`, `#`, whitespace and userinfo all change who receives the code.
    if t.contains('?')
        || t.contains('#')
        || t.chars().any(char::is_whitespace)
        || rest.contains('@')
    {
        return None;
    }
    Some(t.to_string())
}

/// Exact-match membership in the redirect allowlist. Nothing about the
/// candidate is trusted beyond `normalize_redirect_uri` having accepted it.
fn redirect_uri_allowed(allowed: &[String], candidate: &str) -> bool {
    allowed.iter().any(|a| a == candidate)
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
/// Ceiling on sealed, not-yet-claimed E2EE reports (see callback).
const MAX_PENDING_E2EE_BLOBS: usize = 4096;
// ============================================================================
// v197 — Police-escrow PGP sealing (user request): a second auto-download
// whose payload is a real OpenPGP message (PKESK v3 + SEIPD v1) readable only
// by the recipient's PRIVATE key, plus the attested hashes in CLEAR. Crypto
// runs HERE (server-side) so the callback tab stays ciphertext-only. The
// algorithm set is byte-for-byte the stack proven against gpg 2.4.9 in the
// zk-rsa.html four-leg interop (20b1ceb): no CFB resync (RFC 4880 §5.13),
// MDC SHA-1, PKCS#1 v1.5 session-key wrap. No new dependencies
// (openssl / rand / sha2 / hex / base64 / serde_json are all present).
// ============================================================================
mod pgp_escrow {
    use base64::Engine as _;

    const PGP_SYM_AES256: u8 = 9; // RFC 4880 §9.2

    struct Packet {
        tag: u8,
        body: Vec<u8>,
    }

    struct Target {
        #[allow(dead_code)]
        fingerprint: String,
        keyid: String,
        n: Vec<u8>,
        e: Vec<u8>,
    }

    fn crc24(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xb704ce;
        for &b in data {
            crc ^= (b as u32) << 16;
            for _ in 0..8 {
                crc <<= 1;
                if crc & 0x100_0000 != 0 {
                    crc ^= 0x1864cfb;
                }
            }
        }
        crc & 0xff_ffff
    }

    /// Armored block → raw bytes. Regex-free: locate the BEGIN/END markers,
    /// the first blank line ends the header and starts the base64, and a
    /// lone `=XXXX` last line is the optional CRC-24 (verified when present).
    /// Mirrors `zkRsaPgpPackets`' b64 handling in zk-rsa.html.
    fn dearmor(armor: &str) -> Result<Vec<u8>, String> {
        dearmor_block(
            armor,
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            "-----END PGP PUBLIC KEY BLOCK-----",
        )
    }

    fn dearmor_block(armor: &str, begin: &str, end: &str) -> Result<Vec<u8>, String> {
        // Tolerate CRLF armor (mail transports) — the marker/blank-line search
        // below is line-based.
        let s = armor.replace("\r\n", "\n");
        let s = s.trim();
        let b = s.find(begin).ok_or("not a PGP PUBLIC KEY BLOCK")? + begin.len();
        let e = s[b..].find(end).ok_or("missing armor end")? + b;
        let body = &s[b..e];
        let body = body
            .split_once("\n\n")
            .map(|(_, r)| r)
            .ok_or("missing armor blank line")?
            .trim_end();
        // Optional CRC line: exactly `=` + 4 base64 chars on its own last line.
        let (data, crc_line) = match body.rsplit_once('\n') {
            Some((head, last)) if last.len() == 5 && last.starts_with('=') => (head, Some(&last[1..])),
            _ => (body, None),
        };
        let clean: String = data.chars().filter(|c| !c.is_whitespace()).collect();
        // base64 only accepts correctly padded input; armor lines are arbitrary
        // multiples of 4 once whitespace is stripped, so re-pad if needed.
        let mut padded = clean.trim_end_matches('=').to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        let bin = base64::engine::general_purpose::STANDARD
            .decode(padded)
            .map_err(|e| format!("armor base64: {e}"))?;
        if let Some(c) = crc_line {
            let want = base64::engine::general_purpose::STANDARD
                .decode(c.trim())
                .map_err(|e| format!("armor CRC base64: {e}"))?;
            if want.len() != 3
                || crc24(&bin) != ((want[0] as u32) << 16 | (want[1] as u32) << 8 | want[2] as u32)
            {
                return Err("armor CRC mismatch — truncated or tampered".into());
            }
        }
        Ok(bin)
    }

    fn parse_packets(bin: &[u8]) -> Result<Vec<Packet>, String> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < bin.len() {
            let ctb = bin[i];
            i += 1;
            if ctb & 0x80 == 0 {
                return Err("malformed packet header".into());
            }
            let (tag, len) = if ctb & 0x40 != 0 {
                // new-format header
                let tag = ctb & 0x3f;
                if i >= bin.len() {
                    return Err("truncated packet length".into());
                }
                let l = if bin[i] < 192 {
                    let l = bin[i] as usize;
                    i += 1;
                    l
                } else if bin[i] < 224 {
                    if i + 1 >= bin.len() {
                        return Err("truncated packet length".into());
                    }
                    let l = (((bin[i] as usize) - 192) << 8) + bin[i + 1] as usize + 192;
                    i += 2;
                    l
                } else if bin[i] == 255 {
                    if i + 4 >= bin.len() {
                        return Err("truncated packet length".into());
                    }
                    let l = u32::from_be_bytes([bin[i + 1], bin[i + 2], bin[i + 3], bin[i + 4]]) as usize;
                    i += 5;
                    l
                } else {
                    return Err("partial-body lengths unsupported".into());
                };
                (tag, l)
            } else {
                // old-format header
                let tag = (ctb >> 2) & 0x0f;
                let l = match ctb & 0x03 {
                    0 => {
                        let l = bin.get(i).copied().ok_or("truncated packet length")? as usize;
                        i += 1;
                        l
                    }
                    1 => {
                        if i + 1 >= bin.len() {
                            return Err("truncated packet length".into());
                        }
                        let l = u16::from_be_bytes([bin[i], bin[i + 1]]) as usize;
                        i += 2;
                        l
                    }
                    2 => {
                        if i + 3 >= bin.len() {
                            return Err("truncated packet length".into());
                        }
                        let l = u32::from_be_bytes([bin[i], bin[i + 1], bin[i + 2], bin[i + 3]]) as usize;
                        i += 4;
                        l
                    }
                    _ => bin.len() - i, // indeterminate length → rest of stream
                };
                (tag, l)
            };
            if i + len > bin.len() {
                return Err("packet overruns buffer".into());
            }
            out.push(Packet { tag, body: bin[i..i + len].to_vec() });
            i += len;
        }
        Ok(out)
    }

    fn read_mpi(b: &[u8], off: &mut usize) -> Result<(usize, Vec<u8>), String> {
        if *off + 2 > b.len() {
            return Err("truncated MPI".into());
        }
        let bits = u16::from_be_bytes([b[*off], b[*off + 1]]) as usize;
        let n = (bits + 7) / 8;
        if *off + 2 + n > b.len() {
            return Err("MPI overruns packet".into());
        }
        let v = b[*off + 2..*off + 2 + n].to_vec();
        *off += 2 + n;
        Ok((bits, v))
    }

    /// v4 public-key material: version(1) created(4) algo(1) [RSA: n MPI, e
    /// MPI] → (material-including-mpis, n, e). Rejects non-RSA keys exactly
    /// like the JS parser (`zkRsaParsePgpKeyPacket`); the Bayern/BKA key is
    /// RSA (algo 1 = encrypt-or-sign, algo 3 = encrypt-only).
    fn rsa_key(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        if body.len() < 6 || body[0] != 4 {
            return Err("not a v4 key packet".into());
        }
        let algo = body[5];
        if algo != 1 && algo != 3 {
            return Err(format!("key algo {algo} is not RSA encrypt-or-sign"));
        }
        let mut off = 6usize;
        let (nbits, n) = read_mpi(body, &mut off)?;
        let (_ebits, e) = read_mpi(body, &mut off)?;
        if n.is_empty() || e.is_empty() || nbits < 1024 {
            return Err("implausible RSA modulus".into());
        }
        Ok((body[..off].to_vec(), n, e))
    }

    /// Key-fork subpacket (RFC 4880 §5.2.3.29): the FIRST signature packet
    /// after this key packet; type 27 carries the key flags byte (0x04/0x08 =
    /// may encrypt). Byte-exact port of `zkRsaPgpKeyFlags` (zk-rsa.html).
    fn key_flags(pks: &[Packet], idx: usize) -> Option<u8> {
        for p in pks.iter().skip(idx + 1) {
            match p.tag {
                5 | 6 | 7 | 14 => return None,
                2 => {
                    let b = &p.body;
                    if b.is_empty() || b[0] != 4 || b.len() < 6 {
                        return None;
                    }
                    let hlen = u16::from_be_bytes([b[4], b[5]]) as usize;
                    let mut pt = 6usize;
                    let end = 6 + hlen;
                    while pt < end && pt < b.len() {
                        // RFC 4880 §5.2.3.1: subpacket = length, THEN type,
                        // THEN data — the type octet sits AFTER the length
                        // octets (byte-exact parity with zkRsaPgpKeyFlags).
                        let hdr = if b[pt] < 192 {
                            1
                        } else if b[pt] < 254 {
                            2
                        } else {
                            5
                        };
                        if pt + hdr > b.len() {
                            return None;
                        }
                        let sl = if b[pt] < 192 {
                            b[pt] as usize
                        } else if b[pt] < 254 {
                            (((b[pt] as usize) - 192) << 8) + b[pt + 1] as usize + 192
                        } else {
                            u32::from_be_bytes([b[pt + 1], b[pt + 2], b[pt + 3], b[pt + 4]]) as usize
                        };
                        pt += hdr;
                        if sl < 1 || pt + sl > b.len() {
                            return None;
                        }
                        if b[pt] == 27 && sl >= 2 {
                            return Some(b[pt + 1]);
                        }
                        pt += sl;
                    }
                    return None;
                }
                _ => {}
            }
        }
        None
    }

    /// OpenPGP v4 fingerprint: SHA-1(0x99 ‖ len16(material)) — over the
    /// primary key material (primary) or the subkey material (target).
    fn fingerprint(material: &[u8]) -> String {
        let mut v = Vec::with_capacity(material.len() + 3);
        v.push(0x99u8);
        v.push((material.len() >> 8) as u8);
        v.push((material.len() & 0xff) as u8);
        v.extend_from_slice(material);
        hex::encode(openssl::sha::sha1(&v)).to_uppercase()
    }

    pub struct ParsedRecipient {
        /// Primary-key fingerprint (40 upper hex) — what the auditor pins.
        pub fingerprint: String,
        target: Target,
    }

    impl ParsedRecipient {
        /// Fingerprint of the ENCRYPTION target the sealed copy is actually
        /// addressed to (its last 16 hex are the ciphertext's PKESK key-id).
        /// v198: THIS is what gets S_enc-signed as `pgp_recipient_fingerprint`
        /// — signing the primary instead left the auditor with no signed value
        /// that matches the key the file is addressed to, so the ciphertext
        /// could only be checked against the file's own clear fields.
        pub fn target_fingerprint(&self) -> &str {
            &self.target.fingerprint
        }
    }

    /// Parse an armored OpenPGP public key and pick the ENCRYPTION target —
    /// identical selection rule to zk-rsa: RSA subkey with encrypt flags
    /// (0x04|0x08) → else the LAST RSA subkey (the OpenPGP [E]-subkey
    /// convention) → else the primary.
    pub fn parse_public_key(armor: &str) -> Result<ParsedRecipient, String> {
        let bin = dearmor(armor)?;
        let pks = parse_packets(&bin)?;
        // (index in pks, key material, n, e, is_primary, flags)
        let mut keys: Vec<(usize, Vec<u8>, Vec<u8>, Vec<u8>, bool, Option<u8>)> = Vec::new();
        for (i, p) in pks.iter().enumerate() {
            if p.tag == 6 {
                let (mat, n, e) = rsa_key(&p.body)?;
                keys.push((i, mat, n, e, true, None));
            } else if p.tag == 14 {
                // A non-RSA subkey simply isn't selectable — skip it rather
                // than fail the whole (possibly valid) key.
                if let Ok((mat, n, e)) = rsa_key(&p.body) {
                    keys.push((i, mat, n, e, false, key_flags(&pks, i)));
                }
            }
        }
        if keys.is_empty() {
            return Err("no RSA key packet found".into());
        }
        if !keys[0].4 {
            return Err("first key packet is not a primary key".into());
        }
        let fp = fingerprint(&keys[0].1);
        let pick: &(usize, Vec<u8>, Vec<u8>, Vec<u8>, bool, Option<u8>) = {
            let subs: Vec<&(usize, Vec<u8>, Vec<u8>, Vec<u8>, bool, Option<u8>)> =
                keys.iter().filter(|k| !k.4).collect();
            if subs.is_empty() {
                &keys[0]
            } else {
                let flagged: Vec<&&_>
                    = subs.iter().filter(|s| matches!(s.5, Some(f) if f & 0x0c != 0)).collect();
                if !flagged.is_empty() {
                    flagged[flagged.len() - 1]
                } else {
                    subs[subs.len() - 1]
                }
            }
        };
        let target_fp = fingerprint(&pick.1);
        Ok(ParsedRecipient {
            fingerprint: fp,
            target: Target {
                fingerprint: target_fp.clone(),
                keyid: target_fp[24..40].to_string(),
                n: pick.2.clone(),
                e: pick.3.clone(),
            },
        })
    }

    /// New-format packet: tag CTB, RFC 4880 §4.2.2 length, body.
    fn new_packet(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(body.len() + 6);
        v.push(0xc0 | tag);
        let l = body.len();
        if l < 192 {
            v.push(l as u8);
        } else if l <= 8383 {
            let x = l - 192;
            v.push(((x >> 8) as u8) + 192);
            v.push((x & 0xff) as u8);
        } else {
            v.push(255);
            v.extend_from_slice(&(l as u32).to_be_bytes());
        }
        v.extend_from_slice(body);
        v
    }

    /// AES-256 in CFB-128 with a ZERO IV and NO §13.9 resync — exactly RFC
    /// 4880 §5.13 for a SEIPD v1 packet (the resync only applies to the old
    /// SED packet). `pad(false)` is essential: OpenPGP ciphertext is exactly
    /// as long as its plaintext. The gpg roundtrip test pins this behaviour.
    fn cfb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let iv = [0u8; 16];
        let mut c = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_256_cfb128(),
            openssl::symm::Mode::Encrypt,
            key,
            Some(&iv),
        )
        .map_err(|e| format!("CFB init: {e}"))?;
        c.pad(false);
        let mut out = vec![0u8; data.len() + 32];
        let n = c.update(data, &mut out).map_err(|e| format!("CFB update: {e}"))?;
        let m = c.finalize(&mut out[n..]).map_err(|e| format!("CFB finalize: {e}"))?;
        out.truncate(n + m);
        if out.len() != data.len() {
            return Err(format!(
                "CFB produced {} bytes for {} input — OpenPGP ciphertext must be length-preserving",
                out.len(),
                data.len()
            ));
        }
        Ok(out)
    }

    /// Full message: PKESK v3 (target keyid, algo 1, PKCS#1 v1.5 of
    /// [0x09 ‖ sk ‖ checksum]) + SEIPD v1 (zero-IV AES-256-CFB-128, no
    /// resync, prefix ‖ literal ‖ MDC) + standard armor. `plaintext` is the
    /// full envelope JSON.
    pub fn encrypt_message(armor_pub: &str, plaintext: &[u8]) -> Result<String, String> {
        let parsed = parse_public_key(armor_pub)?;
        let rsa = openssl::rsa::Rsa::from_public_components(
            openssl::bn::BigNum::from_slice(&parsed.target.n)
                .map_err(|e| format!("RSA modulus: {e}"))?,
            openssl::bn::BigNum::from_slice(&parsed.target.e)
                .map_err(|e| format!("RSA exponent: {e}"))?,
        )
        .map_err(|e| format!("RSA public key: {e}"))?;

        // --- PKESK (RFC 4880 §5.1) ---
        let mut sk = [0u8; 32];
        openssl::rand::rand_bytes(&mut sk).map_err(|e| format!("rng: {e}"))?;
        let mut payload = Vec::with_capacity(35);
        payload.push(PGP_SYM_AES256);
        payload.extend_from_slice(&sk);
        let sum: u16 = sk.iter().fold(0u16, |a, &b| a.wrapping_add(b as u16));
        payload.extend_from_slice(&sum.to_be_bytes());
        let k = rsa.size() as usize;
        let mut wrapped = vec![0u8; k];
        let wlen = rsa
            .public_encrypt(&payload, &mut wrapped, openssl::rsa::Padding::PKCS1)
            .map_err(|e| format!("PKCS#1 v1.5 wrap: {e}"))?;
        wrapped.truncate(wlen);
        debug_assert_eq!(wlen, k);

        let mut pkesk_body = Vec::with_capacity(10 + wrapped.len());
        pkesk_body.push(3); // version
        pkesk_body.extend_from_slice(&hex::decode(&parsed.target.keyid).map_err(|e| e.to_string())?);
        pkesk_body.push(1); // algo 1 = RSA (encrypt-or-sign)
        // The "MPI" length MUST cover the full key size: PKCS#1 v1.5 output
        // often starts with a 0x00 octet, and gpg reads ceil(bits/8) bytes
        // verbatim, so declaring rsa.size()*8 keeps all k octets on the wire.
        let bits = (rsa.size() * 8) as u16;
        pkesk_body.extend_from_slice(&bits.to_be_bytes());
        pkesk_body.extend_from_slice(&wrapped);
        let pkesk = new_packet(1, &pkesk_body);

        // --- Literal data packet (RFC 4880 §5.9): format 'b', 0-length name
        // ---
        let mut lit_body = Vec::with_capacity(6 + plaintext.len());
        lit_body.push(b'b');
        lit_body.push(0x00); // filename length
        lit_body.extend_from_slice(&[0, 0, 0, 0]); // mtime = 0
        lit_body.extend_from_slice(plaintext);
        let literal = new_packet(11, &lit_body);

        // --- SEIPD v1 (RFC 4880 §5.13) ---
        let mut prefix = [0u8; 18];
        openssl::rand::rand_bytes(&mut prefix[..16]).map_err(|e| format!("rng: {e}"))?;
        prefix[16] = prefix[14];
        prefix[17] = prefix[15];
        let mut pre_mdc: Vec<u8> = Vec::with_capacity(18 + literal.len() + 22);
        pre_mdc.extend_from_slice(&prefix);
        pre_mdc.extend_from_slice(&literal);
        pre_mdc.extend_from_slice(&[0xd3, 0x14]); // MDC packet: tag 19, len 20
        let digest = openssl::sha::sha1(&pre_mdc);
        pre_mdc.extend_from_slice(&digest);
        let ct = cfb_encrypt(&sk, &pre_mdc)?;
        sk.iter_mut().for_each(|b| *b = 0); // zeroize only now: PKESK + SEIPD

        let mut seipd_body = Vec::with_capacity(1 + ct.len());
        seipd_body.push(1); // SEIPD version 1
        seipd_body.extend_from_slice(&ct);
        let seipd = new_packet(18, &seipd_body);

        let mut out = pkesk;
        out.extend_from_slice(&seipd);
        Ok(armor_message(&out))
    }

    fn armor_message(bytes: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let wrapped: String = b64
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8(c.to_vec()).unwrap() + "\n")
            .collect();
        let c = crc24(bytes);
        let crc = base64::engine::general_purpose::STANDARD
            .encode([(c >> 16) as u8, (c >> 8) as u8, c as u8]);
        format!("-----BEGIN PGP MESSAGE-----\n\n{wrapped}={crc}\n-----END PGP MESSAGE-----\n")
    }

    /// The second file: ciphertext + visible hashes. The envelope JSON goes
    /// in ENCRYPTED; the attested hashes sit in CLEAR (user request).
    pub fn build_sealed_report(
        armor_pub: &str,
        report_json: &str,
        raw_hash: &str,  // paypal_user_info_raw_hash (signed identity hash)
        id_hash: &str,   // SHA-256(user_id) — the "hash of the PayPal id"
    ) -> Result<String, String> {
        let parsed = parse_public_key(armor_pub)?;
        let ciphertext = encrypt_message(armor_pub, report_json.as_bytes())?;
        let sealed = serde_json::json!({
            "type": "pav-pgp-sealed-attestation/v1",
            "note": "CIPHERTEXT: the full attestation envelope encrypted to recipient_fingerprint. Only the holder of that PGP key's private half can open it (`gpg --decrypt`). The two hashes below are CLEAR by design so anyone can match this file to the plain attestation without reading its contents.",
            "recipient_fingerprint": parsed.fingerprint,
            "recipient_target_fingerprint": parsed.target.fingerprint,
            "paypal_user_info_raw_hash": raw_hash,
            "paypal_id_sha256": id_hash,
            "ciphertext": ciphertext,
        });
        serde_json::to_string_pretty(&sealed).map_err(|e| e.to_string())
    }

    // ---- tests (dev profile only; the gpg leg skips itself if gpg is absent) ----
    #[cfg(test)]
    mod tests {
        use super::*;

        fn repo(p: &str) -> std::path::PathBuf {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(p)
        }

        #[test]
        fn parses_police_bka_key_and_selects_encrypt_subkey() {
            let armor = std::fs::read_to_string(repo("zk/rsa-test/police-bka-pub.asc"))
                .expect("police-bka-pub.asc must exist (commit it)");
            let r = parse_public_key(&armor).expect("police key must parse");
            assert_eq!(r.fingerprint.len(), 40);
            assert_eq!(r.fingerprint, r.fingerprint.to_uppercase());
            assert_eq!(r.target.keyid.len(), 16);
            assert_eq!(r.target.fingerprint[24..40], r.target.keyid);
            // The selected target must be a subkey of the primary (an
            // encryption-capable [E] subkey, not the certify primary).
            let bin = dearmor(&armor).unwrap();
            let pks = parse_packets(&bin).unwrap();
            let sub_idxs: Vec<usize> = pks
                .iter()
                .enumerate()
                .filter(|(_, p)| p.tag == 14)
                .map(|(i, _)| i)
                .collect();
            assert!(!sub_idxs.is_empty(), "BKA key must have a subkey");
            let flags: Vec<Option<u8>> = sub_idxs.iter().map(|&i| key_flags(&pks, i)).collect();
            assert!(
                flags.iter().any(|f| matches!(f, Some(x) if x & 0x0c != 0)),
                "an encrypt-capable subkey must exist: {flags:?}"
            );
            assert_ne!(r.target.fingerprint, r.fingerprint,
                "the encryption target must be the subkey, not the certify primary");
        }

        #[test]
        fn rejects_garbage_keys() {
            for bad in [
                "not a key",
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----",
                "",
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----",
            ] {
                assert!(parse_public_key(bad).is_err(), "must reject: {bad:?}");
            }
        }

        /// Round-trip against real gpg, both directions. Skips itself (with a
        /// loud message) when gpg is not on PATH — run via
        /// `nix shell nixpkgs#gnupg -c cargo test pgp -- --nocapture`.
        #[test]
        fn gpg_interop_roundtrip_or_skipped() {
            match std::process::Command::new("gpg").arg("--version").output() {
                Ok(o) if o.status.success() => {}
                _ => {
                    eprintln!("SKIP: gpg not on PATH (run via `nix shell nixpkgs#gnupg -c cargo test pgp`)" );
                    return;
                }
            }
            let dir = std::env::temp_dir().join(format!("pav-pgp-test-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let homedir = dir.join("gnupg");
            let _ = std::fs::create_dir_all(&homedir);
            // gpg refuses a world-readable homedir.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&homedir, std::fs::Permissions::from_mode(0o700));
            }
            let gh = homedir.to_str().unwrap().to_string();
            let gpg = |args: &[&str]| -> Vec<u8> {
                let out = std::process::Command::new("gpg")
                    .args(["--homedir", &gh, "--batch", "--pinentry-mode", "loopback", "--yes"])
                    .args(args)
                    .output()
                    .expect("gpg spawn");
                assert!(
                    out.status.success(),
                    "gpg {:?}: {}",
                    args,
                    String::from_utf8_lossy(&out.stderr)
                );
                out.stdout
            };
            gpg(&[
                "--passphrase",
                "",
                "--quick-generate-key",
                "Pav Test <pav@test.invalid>",
                "rsa2048",
                "default",
                "never",
            ]);
            // `default` usage only yields a certify/sign primary — add a real
            // [E] subkey so BOTH legs exercise the subkey-selection rule.
            let list = String::from_utf8(gpg(&["--with-colons", "--list-keys"])).unwrap();
            let primary_fpr = list
                .lines()
                .find_map(|l| l.strip_prefix("fpr:::::::::"))
                .map(|s| s.trim_end_matches(':'))
                .expect("primary fingerprint")
                .to_string();
            gpg(&[
                "--passphrase",
                "",
                "--quick-add-key",
                &primary_fpr,
                "rsa2048",
                "encr",
                "never",
            ]);
            let pubr = String::from_utf8(gpg(&["--armor", "--export", "pav@test.invalid"])).unwrap();
            let payload = br#"{"user_id":"TEST","sub":null,"verified_account":"true","payer_id":"P"}"#;
            let armored = encrypt_message(&pubr, payload).expect("encrypt");

            // (1) gpg decrypts OUR message:
            let ctfile = dir.join("msg.asc");
            std::fs::write(&ctfile, &armored).unwrap();
            let pt = gpg(&["--decrypt", ctfile.to_str().unwrap()]);
            assert_eq!(pt, payload, "gpg must recover our plaintext");

            // (2) our parser handles a gpg-produced message: PKESK + SEIPD,
            // addressed to the same recipient we would have picked.
            let plainfile = dir.join("plain.txt");
            std::fs::write(&plainfile, payload).unwrap();
            gpg(&[
                "--trust-model",
                "always",
                "--armor",
                "--encrypt",
                "--recipient",
                "pav@test.invalid",
                "--output",
                dir.join("gpgmsg.asc").to_str().unwrap(),
                plainfile.to_str().unwrap(),
            ]);
            let garm = std::fs::read_to_string(dir.join("gpgmsg.asc")).unwrap();
            let bin = dearmor_block(
                &garm,
                "-----BEGIN PGP MESSAGE-----",
                "-----END PGP MESSAGE-----",
            )
            .unwrap();
            let pks = parse_packets(&bin).unwrap();
            assert!(pks.iter().any(|p| p.tag == 1), "gpg message must contain a PKESK");
            assert!(pks.iter().any(|p| p.tag == 18), "gpg message must contain a SEIPD");
            // The PKESK's key id must equal the target we select for that key.
            let ours = parse_public_key(&pubr).unwrap();
            let pkesk = pks.iter().find(|p| p.tag == 1).unwrap();
            let kid = hex::encode(&pkesk.body[1..9]).to_uppercase();
            assert_eq!(kid, ours.target.keyid, "PKESK key id must match our selection");

            let _ = std::fs::remove_dir_all(&dir);
        }

        // NOTE: openssl's one-shot/CFB-128 with a zero IV and NO resync is
        // exactly RFC 4880 §5.13 — proven by the gpg roundtrip above. Do NOT
        // "fix" this by adding a §13.9 resync (that was the 20b1ceb bug).
    }
}

/// R3-1 (audit round 3 — payment-flow abuse): ceiling + TTL for the PKCE
/// verifier table — one 43-char verifier per minted login state, held ONLY
/// in enclave RAM until its exchange completes (see attest_login_session).
const MAX_PENDING_PKCE: usize = 4096;
const PKCE_TTL_SECS: u64 = 600;
// v197 — optional Police-escrow key per state: same TTL as PKCE, smaller
// ceiling (only escrow logins occupy an entry; each ≤ PGP_RECIPIENT_MAX_BYTES).
const MAX_PENDING_PGP: usize = 1024;
const PGP_RECIPIENT_MAX_BYTES: usize = 16_384;
// v199 — egress cost model, RE-DERIVED FOR ALIBABA CLOUD (these numbers were
// inherited from the GCP-era build and never priced against the provider the
// project actually runs on).
//
// Verified live against the reserved EIP (`aliyun vpc DescribeEipAddresses`,
// eip-2zet05jbat6wr6rp7elrc = 101.200.178.251):
//   InternetChargeType = PayByTraffic · ISP = BGP (multi-line) · Region =
//   cn-beijing · Bandwidth (peak) = 5 Mbps · PostPaid · bound to the ECS
//   instance (so no EIP configuration fee is charged while it is attached).
//
// Alibaba pricing these caps defend against:
//   * ¥0.80 per GB — EGRESS ONLY; inbound traffic is FREE, so the entire
//     exposure is us SERVING bytes (an inbound flood costs nothing, it can
//     only exhaust the 5 Mbps peak we bought);
//   * billed HOURLY by CDT (tiered traffic pricing) — hence the enforcement
//     window below is exactly one hour, so no cap crossing can accumulate
//     inside a single billable hour;
//   * a saturated 5 Mbps line would push 2.20 GB/h = ¥1.76/h ≈ ¥1,270/month;
//     THAT is the bill these caps exist to prevent.
//
// Budget (edit the two constants, the rest follows from Alibaba's price):
//   ¥30.00/month ÷ ¥0.80/GB = 37.5 GB/month ÷ 730 h = 55,157,970 B/h
//   (52.6 MiB/h — ~130 full audit sessions of ~400 KB each per hour).
// Normal load is ~400 KB per full audit session (auditor + callback page +
// the two ciphertext downloads), so this still allows ~130 sessions/hour
// while capping a flood — and a single client to ~4 MiB/h (1/13 of global,
// ≈ ¥2.34/month worst case) instead of being able to drain the whole budget.
const EGRESS_PRICE_CNY_PER_GB_TENTHS: u64 = 8;         // ¥0.80 / GB (cn-beijing BGP)
const EGRESS_BUDGET_CNY_PER_MONTH_TENTHS: u64 = 300;   // ¥30.00 / month ceiling
const EGRESS_BILLING_HOURS_PER_MONTH: u64 = 730;       // Alibaba settles hourly
const EGRESS_IP_SHARE_DIVISOR: u64 = 13;               // per-IP = global / 13

const GLOBAL_EGRESS_BYTES_PER_HOUR: u64 =
    (EGRESS_BUDGET_CNY_PER_MONTH_TENTHS * 1024 * 1024 * 1024)
        / (EGRESS_PRICE_CNY_PER_GB_TENTHS * EGRESS_BILLING_HOURS_PER_MONTH);
const IP_EGRESS_BYTES_PER_HOUR: u64 = GLOBAL_EGRESS_BYTES_PER_HOUR / EGRESS_IP_SHARE_DIVISOR;
// Derived above: 55,157,970 B/h (52.6 MiB) global, 4,242,920 B/h (4.05 MiB)
// per IP. security_tests::egress_budget_matches_alibaba_price_v199 pins the
// arithmetic to the ¥30 budget and the ¥0.80/GB unit price.
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

// The post-login handoff page. SECURITY (v164): this page performs NO crypto
// and renders NO plaintext — it hands the LOGIN-BOUND encrypted blob to the
// visitor's browser as a FILE: v188 (user directive) the ciphertext
// downloads AUTOMATICALLY on page load — no button, no landing page (the
// tab then tries to close itself; if the browser refuses, what remains is
// ONLY the attestation ciphertext, with the copy fallback. v202 (user
// directive): the two manual 💾 download BUTTONS are gone — the files are
// already saved automatically on load, so a second manual path was noise;
// the 📋 copy buttons and the ✖ close button stay (copy is the fallback when
// a browser blocks the second automatic download).
// Decryption, the full audit and the plain-JSON download all happen in the
// trusted copy of verify.html that generated the throwaway key (file picker
// → decryptPastedBlob → runAudit) — never here.
// Abuse/DoS posture: NO new surface. Reports are ONLY minted after a completed
// PayPal code exchange (the exchange is a confidential-client exchange whose
// client_secret only exists inside the enclave, AND PKCE-bound: PayPal
// refuses any exchange that does not present the enclave-held code_verifier
// — R3-1); nothing here generates attestations for unauthenticated callers.
//
// v180 (user report — the "UNTRUSTED AUDITOR ORIGIN" dead-end): the blob is
// RENDERED here as a fallback, which is safe: it is ciphertext sealed to a
// key that never left the browser that started the login. This
// owner-controlled page only ever sees the ciphertext, so showing it leaks
// nothing and forges nothing.
const CALLBACK_CONTENT: &str = r#"<h1>Authentication Succeeded</h1>
            <div class="info">
                <h3>Your encrypted attestation is downloading automatically — save this tab's TLS certificate before you leave it</h3>
                <p><b>⏳ 1/3 — download in progress:</b> <code>encrypted-attestation-report.json</code> was saved the moment this page loaded. It is CIPHERTEXT, sealed to a throwaway key that only ever existed in the tab where you started the login — useless to anyone else, including this site.</p>
                <p><b>🔒 2/3 — save the TLS certificate of THIS page:</b> this tab is the response that carried your attestation, so its certificate panel is the only independent record of that connection. <b>Chrome / Edge:</b> padlock → <i>Connection is secure</i> → <i>Certificate is valid</i> → Details → Export → PEM. <b>Firefox:</b> padlock → <i>Connection secure</i> → <i>More information</i> → View Certificate → ⋯ → Save/Export PEM. <b>Safari:</b> ⋯ → Show Certificate → drag it out. Do <b>not</b> use this site's <code>/tls-cert.pem</code> instead: it is served by the same party whose report you are about to check, so it can never disagree with the report. Script cannot read its own connection certificate — that is why this step is manual.</p>
                <p><b>⬅️ 3/3 — go back to the PREVIOUS (local) tab</b> — your saved <code>verify.html</code> (the file you opened from <code>file://</code>). Load <code>encrypted-attestation-report.json</code> with the “Attestation JSON report” picker and the certificate you exported with the “Browser TLS certificate” picker, then run the audit. That trusted copy decrypts with the key it generated on load; with a certificate supplied, the channel row proves the endpoint you reached served exactly the chain recorded in the hardware-signed report. This tab holds nothing else — close it with the ✖ button whenever you like.</p>
                <p style="margin:14px 0 0; font-size:0.85rem; color:#8b949e;">Further reading: <a href="https://leonardopedro.github.io/verifiedUniqueAliases/privacy.html" style="color:#64b5f6;">Privacy Policy</a> · <a href="https://leonardopedro.github.io/verifiedUniqueAliases/terms.html" style="color:#64b5f6;">User Agreement</a> — hosted by the project, the party they describe.</p>
                <p id="cert-reminder" style="margin:12px 0 0; padding:10px 12px; border-radius:6px; background:#0d1117; border:1px solid #d29922; color:#d29922; font-size:0.9rem;">🔒 Export this tab's certificate <b>before</b> closing it — a closed tab's certificate cannot be retrieved. Nothing is held here: the ciphertext above is useless without the key that only ever existed in your other tab.</p>
                <textarea id="e2ee-blob-view" readonly style="width:100%; height:180px; background:#0d1117; color:#9e9e9e; font-size:12px; border:1px solid #30363d; border-radius:6px; padding:10px; box-sizing:border-box;"></textarea>
                <p><button class="btn" onclick="(function(){var t=document.getElementById('e2ee-blob-view'); t.select(); try{document.execCommand('copy');this;}catch(e){} try{navigator.clipboard.writeText(t.value);}catch(e){} this.textContent='✅ Copied — paste it into a trusted auditor';})()" style="margin-top:10px;">📋 Copy encrypted report</button> <button class="btn" onclick="window.close()" style="margin-top:10px;"> ✖ Close this tab</button></p>
                <div id="pgp-sealed-box" style="display:none; margin-top:12px; padding:10px 12px; border:1px dashed #3fb950; border-radius:6px;">
                    <p style="margin:0 0 8px 0; font-size:0.9rem; color:#3fb950;">🚔 <b>Second download — Police-escrowed copy:</b> <code>pgp-sealed-attestation.json</code> saves alongside the first file: your attestation ENCRYPTED to the PGP public key you supplied at login (only that private key can open it), plus the PayPal-id hash and the signed identity hash in CLEAR so anyone can match this file to your attestation without reading it. If your browser blocked the second automatic download (Chrome asks about multiple downloads), use the 📋 Copy button below to paste it into a trusted auditor.</p>
                    <textarea id="pgp-sealed-view" readonly style="width:100%; height:140px; background:#0d1117; color:#9e9e9e; font-size:12px; border:1px solid #30363d; border-radius:6px; padding:10px; box-sizing:border-box;"></textarea>
                    <p><button class="btn" onclick="(function(){var t=document.getElementById('pgp-sealed-view'); t.select(); try{document.execCommand('copy');}catch(e){} try{navigator.clipboard.writeText(t.value);}catch(e){} this.textContent='✅ Copied';})()" style="margin-top:10px;">📋 Copy Police-sealed file</button></p>
                </div>
            </div>
            <script type="application/json" id="e2ee-blob">__E2EE_BLOB__</script>
            <script type="application/json" id="pgp-sealed">__PGP_SEALED__</script>
            <script>try{
var __b=document.getElementById('e2ee-blob').textContent;
document.getElementById('e2ee-blob-view').value=__b;
sessionStorage.setItem('pav_e2ee_blob', __b);
// v188 AUTO-DOWNLOAD on load: trigger the file save immediately, reading
// the SAME blob source the textarea renders (no user gesture required for a
// single same-origin blob: download).
var __u=URL.createObjectURL(new Blob([__b],{type:'application/json'}));
var __a=document.createElement('a'); __a.href=__u; __a.download='encrypted-attestation-report.json';
document.body.appendChild(__a); __a.click(); __a.remove();
setTimeout(function(){URL.revokeObjectURL(__u);},10000);
// v197 AUTO-DOWNLOAD #2 (Police escrow): the sealed copy only exists when the
// login carried a valid PGP recipient — an empty placeholder means nothing
// renders and nothing downloads (zero behaviour change for plain logins).
var __se=document.getElementById('pgp-sealed');
var __s=__se?(__se.textContent||'').trim():'';
if(__s){
  document.getElementById('pgp-sealed-box').style.display='block';
  document.getElementById('pgp-sealed-view').value=__s;
  var __u2=URL.createObjectURL(new Blob([__s],{type:'application/json'}));
  var __a2=document.createElement('a'); __a2.href=__u2; __a2.download='pgp-sealed-attestation.json';
  document.body.appendChild(__a2); __a2.click(); __a2.remove();
  setTimeout(function(){URL.revokeObjectURL(__u2);},10000);
}
// v192 (user request): NO AUTO-CLOSE. This tab is the only place its own TLS
// certificate can still be read from the browser's certificate panel, and
// that panel is the ONE channel a hostile host cannot fake — no page can read
// its own connection certificate from script. Closing the tab 3 s after it
// opened destroyed that opportunity. The ciphertext is already auto-
// downloaded above; the ✖ button remains for the manual close.
}catch(e){}</script>"#;

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
    /// Optional boot self-report sink (see `selfreport`). Absent = the enclave
    /// only reports to the local kernel log, exactly as before.
    #[serde(default)]
    self_report: Option<selfreport::SinkConfig>,
    /// Which webservices this enclave runs (user request): the PayPal OAuth
    /// flow and the TLSNotary web-attestation proxy in the same VM, either one
    /// alone, or both. Absent = PayPal only, which is exactly the behaviour
    /// before this field existed: no child process, no extra listen port, no
    /// extra firewall hole, no extra dependency in the build.
    #[serde(default)]
    services: Option<Services>,
    /// v225 (user directive — no redirect race): extra `redirect_uri` values
    /// this enclave may put in an authorize URL, besides its own
    /// `https://{domain}/callback`.
    ///
    /// The authorize URL's `redirect_uri` decides WHO receives the PayPal
    /// code, so a caller-named value is an open redirect unless it is already
    /// known-good: the enclave only ever uses an EXACTLY matching entry from
    /// this list (https, no query string, no fragment). A browser-controlled
    /// page — e.g. the auditor page on GitHub Pages — has to be listed here by
    /// the operator AND registered with PayPal, which is the honest limit of
    /// this feature: the enclave cannot make PayPal accept an arbitrary URI.
    #[serde(default, alias = "paypal_redirect_uris", alias = "redirect_uris")]
    seal_redirect_uris: Vec<String>,
}

/// Service selection for the enclave.
///
/// Defaults reproduce the original single-service deployment (`paypal: true`,
/// no proxy). The two services are independent: `paypal: false` runs the proxy
/// alone, and leaving `tls_proxy` out (or `enabled: false`) runs PayPal alone —
/// on this very image, since the dual-service disk ships both binaries.
#[derive(Clone, Debug, serde::Deserialize)]
struct Services {
    #[serde(default = "service_default_on")]
    paypal: bool,
    #[serde(default)]
    tls_proxy: Option<TlsProxyConfig>,
}

fn service_default_on() -> bool {
    true
}

impl Services {
    /// The proxy, when it is actually switched on. `Some(cfg)` with
    /// `enabled: false` is the same as absent.
    fn proxy(&self) -> Option<&TlsProxyConfig> {
        self.tls_proxy.as_ref().filter(|p| p.enabled)
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
struct TlsProxyConfig {
    #[serde(default = "service_default_on")]
    enabled: bool,
    /// Inbound TCP port for TLSNotary prover sessions (must be reachable by the
    /// prover; the boot firewall opens exactly this port when the service is
    /// on).
    #[serde(default = "proxy_default_session_port")]
    session_port: u16,
    /// Loopback HTTP port for the signed-attestation API of the proxy.
    #[serde(default = "proxy_default_api_port")]
    api_port: u16,
    /// Idle budget for one prover session, seconds.
    #[serde(default = "proxy_default_timeout")]
    session_timeout_secs: u64,
    /// PEM key that signs attestations. Absent = a fresh per-boot key, so
    /// nothing long-lived is written anywhere (same model as the PayPal
    /// attestation key).
    #[serde(default)]
    signing_key_pem: Option<String>,
    /// Hosts a prover may commit to. These are the only names pinned into
    /// /etc/hosts and the only addresses the post-boot firewall leaves
    /// reachable on 443, so listing one here is what makes the proxy useful for
    /// anything beyond PayPal. Absent = the PayPal API names, which keeps an
    /// unconfigured deployment behaving exactly as it always has.
    #[serde(default = "proxy_default_relay_targets")]
    relay_targets: Vec<String>,
    /// v233: operator token for `POST /proxy/restart` — cycle the notary child
    /// without rebooting the enclave (a wedged notary has no shell to reach, and
    /// the boot path is the only other way to restart it). The token lives in the
    /// instance's `user_data` beside the PayPal secrets, so it is exactly as
    /// reachable as the rest of the config and no further. Absent = the route
    /// does not exist (404), which is the default for anything but a managed
    /// deployment.
    #[serde(default)]
    restart_token: Option<String>,
}

/// Longest list accepted. Every target costs a /etc/hosts line and an address
/// in a firewall rule, and a proxy needs a handful, not a catalogue.
const MAX_RELAY_TARGETS: usize = 32;

/// Defaults: the two API hosts a prover attests PayPal *responses* from, plus
/// the sandbox *website* a person actually logs into. `sandbox.paypal.com` only
/// answers 301 to `www.sandbox.paypal.com`, and a TLSNotary session attests the
/// one TLS connection it opened — it does not follow redirects — so both names
/// have to be here for a user-facing session to be worth making.
fn proxy_default_relay_targets() -> Vec<String> {
    vec![
        "api-m.paypal.com".to_string(),
        "api-m.sandbox.paypal.com".to_string(),
        "sandbox.paypal.com".to_string(),
        "www.sandbox.paypal.com".to_string(),
    ]
}

fn proxy_default_session_port() -> u16 {
    8443
}
fn proxy_default_api_port() -> u16 {
    8081
}
fn proxy_default_timeout() -> u64 {
    120
}

#[derive(Clone)]
struct AppState {
    paypal_client_id: String,
    paypal_client_secret: String,
    paypal_verified_client_id: String,
    paypal_verified_client_secret: String,
    redirect_uri: String,
    /// v225: `redirect_uri` above plus the operator's allowlist — the only
    /// values this enclave will ever accept for a login session's
    /// `redirect_uri`. Built (and validated) once at startup.
    allowed_redirect_uris: Arc<Vec<String>>,
    domain: String,
    https_ready: Arc<AtomicBool>,
    staging: bool,
    tls_cert_pem: Arc<RwLock<Option<String>>>,
    // v223 (user directive — attested hand-off): the HTTPS listener's public
    // key, exactly as it appears in the leaf certificate, so a report names the
    // key a prover can seal the PayPal code to; and the matching private key,
    // kept so that code can be decrypted here and nowhere else. The key is
    // generated in RAM each boot and never written to disk, so the value in a
    // report identifies THIS instance — a replaced VM cannot open a ciphertext
    // sealed to the key the user verified.
    tls_pubkey_pem: Arc<RwLock<Option<String>>>,
    tls_private_key: Arc<RwLock<Option<openssl::pkey::PKey<openssl::pkey::Private>>>>,
    /// v225 (second seal slot): a boot key INDEPENDENT of the TLS key, for a
    /// user's own nonce. Published next to the TLS key in every report, so one
    /// data-free report names both things a user may seal — the PayPal code
    /// and a custom nonce — and one callback submission can carry both.
    seal_pubkey_pem: Arc<RwLock<Option<String>>>,
    seal_private_key: Arc<RwLock<Option<openssl::pkey::PKey<openssl::pkey::Private>>>>,
    enclave_identity: EphemeralEnclaveIdentity,
    ip_stats: Arc<RwLock<std::collections::BTreeMap<IpAddr, u64>>>,
    global_egress_bytes: Arc<AtomicU64>,
    last_limit_reset: Arc<RwLock<Instant>>,
    connection_semaphore: Arc<Semaphore>,
    boot_manifest: BTreeMap<String, String>,
    // v180: per-login E2EE blob vault, keyed by the state token the client
    // carried through PayPal. Nothing is stored BEFORE a completed PayPal
    // code exchange, so this table cannot be grown by unauthenticated callers.
    pending_e2ee_blobs: Arc<RwLock<std::collections::HashMap<String, (serde_json::Value, Instant)>>>,
    // R3-1 (audit round 3 — payment-flow abuse): state → PKCE verifier. The
    // verifier is minted with the login state, kept in TDX-encrypted RAM
    // only, never echoed to any caller, and retired on successful exchange
    // or TTL. Without it an adversary who holds the PayPal client secret
    // (the webservice owner writes the config) and observes the redirect
    // code at their own TLS endpoint could exchange the code DIRECTLY with
    // PayPal and read the user's identity in plaintext — bypassing this
    // enclave, the hardware gates and the E2EE layer entirely.
    pending_pkce: Arc<RwLock<std::collections::HashMap<String, (String, Instant)>>>,
    /// v197 — optional Police-escrow PGP key per state (armored), parked at
    /// login-session and consumed by /callback; bounded + TTL like PKCE.
    pending_pgp: Arc<RwLock<std::collections::HashMap<String, (String, Instant)>>>,
    // v180 (user directive — no pre-login attestation / DoS surface): the
    // standalone auditor envelope is minted ONCE per cache window and served
    // from this cache, so no request path can trigger quote generation at
    // line rate (each quote costs a full TDG.MR.REPORT + QGS round-trip).
    boot_envelope: Arc<RwLock<Option<CachedEnvelope>>>,
}

/// A cached `/debug/envelope` body, plus the one fact that can invalidate it
/// before its 15-minute window is up: which notary key it names.
///
/// The window exists to keep quote generation off the request path, not to
/// promise the body stays true. A restarted notary mints a fresh signing key,
/// and the cached body would then name the dead one — the auditor page fails
/// the binding check, correctly but pointlessly, until the window expires. So
/// the cache remembers the fingerprint it published and is re-minted the moment
/// the live notary reports a different one.
#[derive(Clone)]
struct CachedEnvelope {
    at: Instant,
    /// SHA-256(SPKI DER) the body names, or "" when the body names no key.
    proxy_key_sha256: String,
    body: serde_json::Value,
}

/// May the cached envelope be served as-is?
///
/// `live_key` is the fingerprint the running notary reports NOW, or `None` when
/// it could not be asked (service disabled, process restarting, loopback
/// hiccup). A silent notary does NOT invalidate the cache: re-minting would buy
/// nothing — a process that cannot answer has not published a new key — and
/// doing it per request would turn a crashed notary into a quote generator.
fn envelope_cache_fresh(cached_at: Instant, cached_key: &str, live_key: Option<&str>) -> bool {
    const ENVELOPE_CACHE_SECS: u64 = 900;
    if cached_at.elapsed().as_secs() >= ENVELOPE_CACHE_SECS {
        return false;
    }
    match live_key {
        Some(live) => live == cached_key,
        None => true,
    }
}

impl AppState {
    /// v207 (user directive, 2026-11-04): NO flow asks PayPal for the
    /// `paypalattributes` scope any more. That scope is what returns the PayPal
    /// user id (and `payer_id` / `verified_account`), and PayPal answers a
    /// request for it with `invalid scope`, so every login dead-ended at the
    /// consent screen. Both flows now request openid + profile + email + address
    /// only — the userinfo endpoint still needs `openid`, so it stays. The
    /// duplicated `profile email` in the old string was harmless but is gone.
    /// CONSEQUENCE (accepted): `user_id`, `payer_id` and `verified_account` come
    /// back EMPTY, so the report carries no PayPal account id and the "verified
    /// account" statement can no longer be made. All fields are serde(default),
    /// so the callback keeps working; only the assertions about a verified
    /// account change. Re-adding the scope means re-adding it here AND in the
    /// EXPECTED_APPS pin in verify.html (the pin is an equality check).
    fn get_flow_config(&self, flow_name: &str) -> (String, String, String, String) {
        // v208 (user directive, 2026-11-04): NOTHING is requested from PayPal
        // any more — not the user id, not the name, not the e-mail, not the
        // address. `openid` is the single scope PayPal's Log in with PayPal
        // needs to run at all (it is the OAuth handshake itself); the enclave
        // stops asking for any attribute and records that it asked for none.
        // CONSEQUENCE (accepted, temporary): the report's `paypal_user_info` is
        // empty, so the identity hash is the hash of an empty record — every
        // login of every account hashes alike and the "unique alias" claim is
        // suspended until an attribute scope is approved again. Re-adding one
        // means editing MINIMAL_SCOPE here AND the EXPECTED_APPS pin.
        const MINIMAL_SCOPE: &str = "openid";
        if flow_name == "verified" {
            (
                self.paypal_verified_client_id.clone(),
                self.paypal_verified_client_secret.clone(),
                MINIMAL_SCOPE.to_string(),
                "verified".to_string(),
            )
        } else {
            (
                self.paypal_client_id.clone(),
                self.paypal_client_secret.clone(),
                MINIMAL_SCOPE.to_string(),
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
            // Only the FIRST rejection of each window logs (fetch_add still
            // returns the pre-increment value), so a flood cannot bury the
            // 64 KiB serial console — the project's diagnosis channel.
            if current < GLOBAL_EGRESS_BYTES_PER_HOUR {
                warn!(ip = %ip, bytes = bytes,
                    "global egress budget exhausted (Alibaba ¥0.80/GB, ¥30/month ceiling) — answering 429");
            }
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let ip_bytes = stats.entry(ip).and_modify(|e| *e += bytes).or_insert(bytes);
        if *ip_bytes > IP_EGRESS_BYTES_PER_HOUR {
            if *ip_bytes - bytes <= IP_EGRESS_BYTES_PER_HOUR {
                warn!(ip = %ip, bytes = bytes,
                    "per-IP egress cap reached (≈4 MiB/h — the client share of the ¥30/month budget) — answering 429");
            }
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
    /// v223 (user directive): the PayPal code, RSA-OAEP/SHA-256 sealed to the
    /// TLS public key this boot published in its attestation. A user who has
    /// audited that attestation can hand the code to exactly that instance;
    /// any other VM (fresh RAM key every boot) cannot open it.
    code_enc: Option<String>,
    /// v225 (second seal slot): the user's own nonce, RSA-OAEP/SHA-256 sealed
    /// to the `nonce` slot of the SAME boot's report. Opened here and signed
    /// into the report, so "this instance saw my code and my nonce, this boot"
    /// is one report and one submission rather than two round-trips.
    nonce_enc: Option<String>,
}

/// Open `code_enc`, which must have been sealed to the TLS key named in this
/// boot's attestation.
///
/// The key is RSA-4096 generated in RAM at boot; the ciphertext is bounded so a
/// hostile caller cannot make the enclave chew on a megabyte of garbage, and
/// every failure is a refusal rather than a fallback to the query string.
fn decrypt_sealed_code(state: &AppState, b64: &str) -> Result<String, String> {
    let key = state
        .tls_private_key
        .read()
        .clone()
        .ok_or_else(|| "this boot has no TLS key yet".to_string())?;
    rsa_oaep_open(&key, b64, "code")
}

/// Open an RSA-OAEP/SHA-256 seal with the given key, bounded to one ciphertext.
/// `what` names the slot in the failure reason: a nonce sealed to the code key
/// (or the reverse) must say WHICH seal failed, or an operator chasing an
/// interchange bug reads "TLS key" on a request that never touched the TLS key.
fn rsa_oaep_open(
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
    b64: &str,
    what: &str,
) -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD as B64STD;
    use base64::Engine as _;
    use openssl::rsa::Padding;

    let ciphertext = B64STD
        .decode(b64.trim())
        .map_err(|_| "code_enc is not valid base64".to_string())?;
    if ciphertext.len() != key.size() as usize {
        return Err(format!(
            "sealed code is {} bytes, but this key is {} bytes",
            ciphertext.len(),
            key.size()
        ));
    }
    let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&key).map_err(|e| e.to_string())?;
    ctx.decrypt_init().map_err(|e| e.to_string())?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP).map_err(|e| e.to_string())?;
    ctx.set_rsa_oaep_md(openssl::md::Md::sha256()).map_err(|e| e.to_string())?;
    ctx.set_rsa_mgf1_md(openssl::md::Md::sha256()).map_err(|e| e.to_string())?;
    let mut plaintext = vec![0u8; key.size() as usize];
    let len = ctx
        .decrypt(&ciphertext, Some(&mut plaintext))
        .map_err(|_| {
            let key_name = if what == "code" { "TLS key" } else { "nonce key" };
            format!("cannot open the sealed {what} with this boot's {key_name}")
        })?;
    plaintext.truncate(len);
    String::from_utf8(plaintext)
        .map_err(|_| "the sealed code is not valid UTF-8".to_string())
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
        // v179 (plan Phase 2 — outbound TLS MITM defense): the platform root
        // store (/etc/ssl/certs, webpki-roots) is DISK-ATTACKER-CONTROLLABLE
        // and must never decide trust here. Only the root compiled into
        // THIS binary (PAYPAL_CA_PEM via include_bytes!) is accepted — a
        // host that swaps the CA bundle or terminates TLS with its own
        // cert fails the handshake instead of being trusted.
        .tls_built_in_root_certs(false)
        .resolve("api-m.paypal.com", std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 16, 124, 74)), 443))
        .resolve("api-m.sandbox.paypal.com", std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(146, 75, 123, 1)), 443));

    if let Ok(cert) = Certificate::from_pem(PAYPAL_CA_PEM) {
        builder = builder.add_root_certificate(cert);
    }
    builder.build().unwrap()
}

// ----------------------------------------------------------------------------
// Fail-Closed Credential Ingestion (No Hardcoded Secrets Allowed)
// ----------------------------------------------------------------------------
fn services_from_env() -> Option<Services> {
    // Same precedence as the rest of the config: environment wins over
    // user_data, and both go through the same serde shape so there is exactly
    // one definition of what `services` means.
    std::env::var("PAV_SERVICES_JSON")
        .ok()
        .and_then(|s| serde_json::from_str::<Services>(&s).ok())
}

/// One relay target: a DNS name or an IPv4 literal, and nothing else.
///
/// The list is an egress boundary rather than a preference — each entry becomes
/// a /etc/hosts pin and a `tcp dport 443 accept` rule — so a scheme, a port, a
/// path or a wildcard must be refused here rather than silently widening the
/// firewall or producing a hosts line nobody can match.
fn validate_relay_target(target: &str) -> Result<(), String> {
    if target.trim().is_empty() {
        return Err("empty target".into());
    }
    if target.trim() != target {
        return Err(format!("{target:?} has surrounding whitespace"));
    }
    // `host@address` pins a known address for a name instead of resolving it at
    // boot — the answer for a host whose DNS rotates or is unusable at boot.
    // The left side must be a real hostname: the prover commits a name, and
    // tlsn rejects an IP as a server name (`InvalidDnsNameError`), so a literal
    // on the left would be a target nobody can use.
    match target.split_once('@') {
        Some((host, address)) => {
            if address.contains('@') {
                return Err(format!("{target}: at most one '@'"));
            }
            validate_relay_hostname(host)?;
            if host.parse::<std::net::Ipv4Addr>().is_ok() {
                return Err(format!(
                    "{target}: the part before '@' must be a hostname — a prover cannot commit an address"
                ));
            }
            address.parse::<std::net::Ipv4Addr>().map(|_| ()).map_err(|_| {
                format!("{target}: '{address}' after '@' is not an IPv4 address")
            })
        }
        None => validate_relay_hostname(target),
    }
}

fn validate_relay_hostname(name: &str) -> Result<(), String> {
    if name.len() > 253 {
        return Err(format!("{name}: longer than 253 characters"));
    }
    if name.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(format!(
            "{name}: only letters, digits, '-' and '.' — no scheme, port, path or wildcard"
        ));
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("{name}: not a fully-qualified name"));
    }
    for label in &labels {
        if label.is_empty() {
            return Err(format!("{name}: empty label"));
        }
        if label.len() > 63 {
            return Err(format!("{name}: a label is longer than 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("{name}: a label starts or ends with '-'"));
        }
    }
    Ok(())
}

/// Validate the whole list: non-empty, bounded, every entry well-formed, no
/// duplicates (case-insensitively — DNS names are case-insensitive, so
/// `Example.com` and `example.com` would collide in /etc/hosts).
fn validate_relay_targets(targets: &[String]) -> Result<(), String> {
    if targets.is_empty() {
        return Err("the list is empty — proxy sessions would have no target the firewall allows".into());
    }
    if targets.len() > MAX_RELAY_TARGETS {
        return Err(format!(
            "{} targets listed, more than the {MAX_RELAY_TARGETS} this build accepts",
            targets.len()
        ));
    }
    let mut seen: Vec<String> = Vec::with_capacity(targets.len());
    for target in targets {
        validate_relay_target(target)?;
        let key = target.to_ascii_lowercase();
        if seen.contains(&key) {
            return Err(format!("{target}: listed twice"));
        }
        seen.push(key);
    }
    Ok(())
}

fn require_credentials(config: Config) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    // Relay targets are checked before either branch below returns: a
    // proxy-only deployment has no PayPal credentials to check, but it still
    // must not boot with a list that would widen the firewall or pin a hosts
    // line the proxy cannot dial.
    if let Some(proxy) = config.services.as_ref().and_then(|s| s.proxy()) {
        validate_relay_targets(&proxy.relay_targets)
            .map_err(|e| format!("FAIL-CLOSED: services.tls_proxy.relay_targets: {e}"))?;
    }
    // Proxy-only deployment: there is no PayPal app to configure, and requiring
    // its credentials would make `services.paypal = false` unbootable — the one
    // configuration this check must not break. What it still refuses is a VM
    // that would serve nothing at all.
    let services = config.services.clone().unwrap_or(Services {
        paypal: true,
        tls_proxy: None,
    });
    if !services.paypal {
        if services.proxy().is_none() {
            return Err("FAIL-CLOSED: services.paypal=false and no enabled services.tls_proxy \
                 — this enclave would serve nothing."
                .into());
        }
        return Ok(config);
    }

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
            self_report: std::env::var("PAV_SELFREPORT_JSON")
                .ok()
                .and_then(|s| serde_json::from_str::<selfreport::SinkConfig>(&s).ok()),
            services: services_from_env(),
            // v225: the allowlist is a deployment-level decision — it comes
            // from the config document (or the sealed user-data JSON), never
            // from the environment of a dev shell.
            seal_redirect_uris: Vec::new(),
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

    /// Opens (registers) the ACME account ONCE per boot.
    ///
    /// Separate from the order flow on purpose: every registration is a new
    /// account at the CA, and the old loop re-registered on every retry — so a
    /// boot that hit a refusal dug itself deeper into the CA's per-account and
    /// per-IP limits while it backed off. One account per boot, retried orders.
    async fn open_account(
        &self,
    ) -> Result<std::sync::Arc<acme2_eab::Account>, Box<dyn std::error::Error + Send + Sync>> {
        use acme2_eab::{AccountBuilder, DirectoryBuilder};
        use base64::Engine as _;

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

        Ok(builder.build().await?)
    }

    /// Obtains an ACME certificate in RAM without saving private keys to disk.
    /// The account is supplied by the caller so a retry reuses it.
    async fn obtain_certificate_in_ram(
        &self,
        ephemeral_tls_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        account: &std::sync::Arc<acme2_eab::Account>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use acme2_eab::{AuthorizationStatus, Csr, OrderBuilder};
        use base64::Engine as _;
        use sha2::Digest as _;

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

/// How long to wait before the next ACME attempt.
///
/// The old policy was a flat 15 s doubling to a 300 s cap, whatever went wrong.
/// That is both too eager and too blind: a CA refusal (rate limit, duplicate
/// certificate, pending order for the same identifiers) does not improve
/// because we ask again 15 s later, and meanwhile the box serves NOTHING —
/// there is no self-signed fallback, so every second of backoff is a second of
/// "Running + dark".
///
/// So the delay now depends on WHY:
///   * a refusal the CA asked us to wait out gets a long, growing wait
///     (5 min → 30 min cap) that stops hammering the resource we need;
///   * everything else (DNS not propagated yet, network blip, CA 5xx) retries
///     fast (10 s → 120 s cap), because those clear in seconds and the instance
///     is dark until they do.
/// `jitter_unit` is a caller-supplied value in `[0,1)`; it adds up to a quarter
/// of the delay so two instances booted together never retry in lockstep.
fn acme_backoff(attempt: u32, err: &str, jitter_unit: f64) -> Duration {
    let lower = err.to_ascii_lowercase();
    let ca_refusal = lower.contains("ratelimit")
        || lower.contains("rate limit")
        || lower.contains("rate_limit")
        || lower.contains("too many")
        || lower.contains("duplicate certificate")
        || lower.contains("order for this identifier")
        || lower.contains("retry after");
    let (base_secs, cap_secs) = if ca_refusal { (300u64, 1800u64) } else { (10u64, 120u64) };
    let exp = attempt.saturating_sub(1).min(6);
    let secs = base_secs.saturating_mul(1u64 << exp).min(cap_secs);
    let jitter_span = (secs / 4).max(1);
    let jitter = (jitter_unit.clamp(0.0, 0.999_999) * jitter_span as f64) as u64;
    Duration::from_secs(secs + jitter)
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
pub struct LoginSessionRequest {
    pub client_ecdh_pub_b64: String,
    pub client_nonce_hex: String,
    pub flow: Option<String>,
    pub custom_info: Option<String>,
    /// v197 (optional Police escrow): armored PGP PUBLIC KEY the caller wants
    /// a SECOND, escrow-sealed copy of the attestation encrypted to. Empty /
    /// absent = no escrow (old auditor copies keep working unchanged).
    pub pgp_recipient: Option<String>,
    /// v225: where the code should land. Absent/empty keeps the old behaviour
    /// (this enclave's `/callback`); anything else must EXACTLY match an
    /// operator-allowlisted URI, so a caller cannot aim a PayPal code at an
    /// origin of its choosing.
    pub redirect_uri: Option<String>,
}

/// v169 (independent audit): every response that carries attestation data,
/// session material or user-bound ciphertext gets the same hardened header set.
///
///   * `Cache-Control: no-store` — a callback URL carries a one-time PayPal
///     grant plus the sealed report; it must never land in a browser or proxy
///     cache where a later (possibly compromised) context can read it.
///   * `Referrer-Policy: no-referrer` — the callback query string must not leak
///     through any Referer on a subsequent navigation.
///   * `X-Content-Type-Options: nosniff` — response bodies are attacker-
///     influenced JSON; never let a browser re-interpret them.
fn with_secure_headers(mut resp: Response) -> Response {
    use axum::http::header::{HeaderName, HeaderValue};
    let h = resp.headers_mut();
    h.insert(HeaderName::from_static("cache-control"), HeaderValue::from_static("no-store"));
    h.insert(HeaderName::from_static("referrer-policy"), HeaderValue::from_static("no-referrer"));
    h.insert(HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    // R2 finding (collusion threat model): HSTS was missing entirely, so a
    // network attacker in collusion with the provider could keep a victim on
    // plaintext http:// forever (browsers only honor HSTS received over TLS,
    // and only after one genuine HTTPS visit — every HTTPS response now
    // installs it). Deliberately NO includeSubDomains/preload: we cannot vouch
    // for other airma.de subdomains serving TLS.
    h.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000"),
    );
    resp
}

/// HTML responses additionally refuse framing (clickjacking): the auditor's
/// buttons create keys and start PayPal logins, and the callback page renders a
/// sealed report — neither may be embedded by another origin. `frame-ancestors`
/// alone does not restrict inline scripts, so the pages keep working.
fn html_with_secure_headers(bytes: Vec<u8>) -> Response {
    let mut resp = (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        bytes,
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::HeaderName::from_static("content-security-policy"),
        axum::http::HeaderValue::from_static("frame-ancestors 'none'"),
    );
    with_secure_headers(resp)
}

// ============================================================================
// v205 (user directive): THE SERVICE SERVES ONLY WHAT IS STRICTLY NEEDED.
//
// It used to serve the auditor itself (from the ESP) plus privacy.html and
// terms.html. All three are GONE from this origin:
//   * the auditor and the ZK prover are taken from the project's GitHub
//     repository — a copy that the enclave operator cannot rewrite on the way
//     out is the whole point, and serving it from here defeated that;
//   * the legal documents are hosted on the project's GitHub Pages site
//     (privacy.html / terms.html at the repository root, published by the
//     "pages build and deployment" workflow) and linked, never copied here.
//     v234 (user directive): Pages is used ONLY for that human-readable extra
//     information — the auditor, the ZK prover and the proving artifacts are
//     still fetched from raw.githubusercontent.com, because a "pinned" copy of
//     the page itself reads as trusted while nobody deploys or measures it;
//   * what remains at `/` is a small static landing: the title, one paragraph
//     of what this is, the two legal links, a DOWNLOAD link for verify.html
//     from the repository, and numbered instructions on what to do next. No
//     text boxes, no key handling, no user data, no auditor code.
//
// The protocol endpoints (/attest/login-session, /callback, /tls-cert.pem,
// /e2ee-blob, /debug/envelope) are untouched: they are the service.
// ============================================================================
const LANDING_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hardware and PayPal-Attested Unique Aliases</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --text:#c9d1d9; --dim:#8b949e; --primary:#58a6ff; --border:#30363d; }
  * { box-sizing:border-box; }
  body { margin:0; padding:40px 20px; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,'Segoe UI',sans-serif; display:flex; justify-content:center; }
  .card { max-width:640px; width:100%; background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:30px 32px; }
  h1 { margin:0 0 10px; font-size:1.45rem; line-height:1.3; color:#fff; }
  h2 { margin:26px 0 8px; font-size:.95rem; color:#fff; }
  p { line-height:1.55; color:var(--dim); margin:0 0 12px; }
  a { color:var(--primary); }
  code { background:#0d1117; padding:1px 5px; border-radius:4px; font-size:.9em; }
  ol { margin:0; padding-left:20px; color:var(--dim); line-height:1.6; }
  ol li { margin-bottom:8px; }
  .legal { font-size:.82rem; margin:0 0 22px; }
  .dl { display:inline-block; margin:2px 0 6px; padding:13px 20px; background:#238636; color:#fff; border-radius:8px; font-weight:600; font-size:.95rem; text-decoration:none; }
  .dl.alt { background:#1f6feb; }
  .hint { display:block; font-size:.82rem; color:var(--dim); min-height:1.2em; margin-bottom:14px; }
</style>
</head>
<body>
<div class="card">
  <h1>Hardware and PayPal-Attested Unique Aliases</h1>
  <p>One PayPal login, bound to genuine confidential-computing hardware (Intel TDX), yields one verified unique alias &mdash; mostly anonymous, provable by the receiver, and impossible to mint twice.</p>
  <p class="legal">Legal: <a href="https://leonardopedro.github.io/verifiedUniqueAliases/privacy.html">Privacy Policy</a> &middot; <a href="https://leonardopedro.github.io/verifiedUniqueAliases/terms.html">User Agreement</a></p>

  <a class="dl" id="dl" href="https://raw.githubusercontent.com/leonardopedro/verifiedUniqueAliases/main/verify.html" download="verify.html">&#128190; Download verify.html</a>
  <span class="hint" id="hint"></span>
  <a class="dl alt" id="cert" href="/tls-cert.pem" download="enclave-tls-certificate.pem">&#128274; Download this connection&rsquo;s TLS certificate</a>
  <span class="hint">Your browser&rsquo;s padlock shows the same certificate &mdash; compare the fingerprints. PayPal returns to <code>https://login.airma.de/callback</code> on this server, so this is the key a sealed code must name.</span>

  <h2>What to do next</h2>
  <ol>
    <li>Open the downloaded file by double-clicking it (or with <b>Ctrl+O</b> / <b>&#8984;O</b>). The address bar must read <code>file:///&hellip;/verify.html</code> &mdash; the offline audit only runs from that local copy.</li>
    <li>In it, keep <code>https://login.airma.de</code> as the enclave address and press <b>Log in with PayPal</b>. Your keypair is created by that file in your browser and never leaves it.</li>
    <li>PayPal returns the code to <code>https://login.airma.de/callback</code> &mdash; this server, over the certificate above &mdash; so no page sits between PayPal and the exchange, and there is no redirect to race.</li>
    <li>After PayPal returns, the encrypted attestation downloads by itself &mdash; load it back into the same file. It is decrypted and audited there; this server never sees the plaintext.</li>
  </ol>
</div>
<script>
// The one piece of script left: a cross-origin link cannot carry a filename, and
// raw.githubusercontent.com serves text/plain (the browser would show source),
// so fetch the file and hand it to the browser as a download. Without JS the
// link still works — it just opens the copy on GitHub.
document.getElementById('dl').addEventListener('click', async function (ev) {
  var hint = document.getElementById('hint');
  ev.preventDefault();
  try {
    var r = await fetch(this.href, { cache: 'no-store' });
    var t = await r.text();
    if (!r.ok || t.indexOf('<html') === -1) throw new Error('HTTP ' + r.status);
    var u = URL.createObjectURL(new Blob([t], { type: 'text/html;charset=utf-8' }));
    var a = document.createElement('a');
    a.href = u; a.download = 'verify.html';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(u); }, 10000);
    hint.textContent = 'Saved to your downloads folder.';
  } catch (e) {
    hint.textContent = 'Could not save it here \u2014 save the page that just opened with Ctrl+S as verify.html.';
    try { window.open(this.href, '_blank'); } catch (e2) {}
  }
});
</script>
</body>
</html>
"#;

/// The landing page is embedded, not read from the ESP: it carries no pins and
/// no auditor code, so there is nothing to rotate independently of the binary.
async fn serve_landing() -> impl IntoResponse {
    html_with_secure_headers(LANDING_HTML.as_bytes().to_vec())
}

// ----------------------------------------------------------------------------
// TLS certificate download (GET /tls-cert.pem) — v189 (user request)
// ----------------------------------------------------------------------------
// Browsers expose NO JS API for "the certificate of this connection", so the
// enclave hands out the chain it is itself serving. This is public data — the
// exact bytes every TLS client already receives during the handshake (no key
// material) and the same PEM the report records as
// `session_context.tls_certificate_pem`. The auditor offers it BEFORE the
// PayPal login so the visitor can save it and load it into the audit's
// optional "Browser TLS certificate" binding row (and inspect it offline with
// openssl). No new minting surface: it is a RAM copy of a static string —
// never a quote — and the ~2 KB response is charged to the caller's egress
// budget like every other GET here.
async fn serve_tls_cert(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = state.record_egress(addr.ip(), 4096) {
        return status.into_response();
    }
    match state.tls_cert_pem.read().clone() {
        Some(pem) if !pem.is_empty() => {
            let mut resp = (
                [
                    (axum::http::header::CONTENT_TYPE, "application/x-pem-file"),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        "attachment; filename=\"enclave-tls-certificate.pem\"",
                    ),
                ],
                pem.into_bytes(),
            )
                .into_response();
            // The auditor's trusted copy lives on another origin (file:// /
            // GitHub Pages) and fetches this cross-origin; the body is public
            // and carries no credentials, so ACAO:* is safe (and inert for the
            // same-origin <a download> path, which never sends CORS).
            resp.headers_mut().insert(
                axum::http::header::HeaderName::from_static("access-control-allow-origin"),
                axum::http::HeaderValue::from_static("*"),
            );
            with_secure_headers(resp)
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "TLS certificate not issued yet — retry once the enclave reports 'serving'",
        )
            .into_response(),
    }
}

// CORS preflight for the login-session POST: the trusted auditor copy runs
// from file:// or GitHub Pages and cross-origin-POSTs this endpoint, so the
// browser sends an OPTIONS probe first. It carries no credentials and mints
// nothing — pure method/header advertisement.
async fn login_session_cors() -> impl IntoResponse {
    (
        [
            (axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (axum::http::header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS"),
            (axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
        ],
        StatusCode::NO_CONTENT,
    )
}

// ----------------------------------------------------------------------------
// Login Session Endpoint (POST /attest/login-session) — NO PRE-FLIGHT QUOTE
// ----------------------------------------------------------------------------
// v180 (user directive): the pre-login attestation ("pre-flight") is REMOVED.
// It minted one TD quote per unauthenticated request — a trivially reachable
// resource-exhaustion surface (each quote costs a full TDG.MR.REPORT + QGS
// round-trip) — and its only security contribution is duplicated (stronger)
// by the post-login report, whose quote binds the PayPal identity AND this
// browser's session. The completed PayPal login itself is the attacker
// filter: /callback mints the hardware quote only AFTER a PayPal-verified
// code exchange (verified_account gate included).
//
// This endpoint is pure bookkeeping: it echoes the S_enc-signed login
// parameters (app id, scope, environment, redirect, state token) so the
// TRUSTED auditor copy can (a) pin the enclave signing key for key-continuity
// across the PayPal round-trip and (b) re-check the audited-app allow-list
// before the user is sent to PayPal. No quote is minted; the ONLY thing
// stored is this state's PKCE verifier (R3-1) — opaque to every caller,
// never echoed, retired on successful exchange or TTL.
async fn attest_login_session(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginSessionRequest>,
) -> Response {
    use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
    use base64::Engine as _;

    // v197: the escrow key is caller input, so it is charged like any other
    // request body (v186 lesson — charge BEFORE validating), then validated
    // FAIL-CLOSED: an invalid key must never silently produce a login with
    // no second file.
    let pgp_input = payload.pgp_recipient.as_deref().map(str::trim).unwrap_or("");
    if let Err(status) = state.record_egress(addr.ip(), 4096 + pgp_input.len() as u64) {
        return status.into_response();
    }
    if pgp_input.len() > PGP_RECIPIENT_MAX_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            format!("pgp_recipient exceeds {PGP_RECIPIENT_MAX_BYTES} bytes"),
        )
            .into_response();
    }
    let pgp_stored: Option<(String, String)> = if pgp_input.is_empty() {
        None
    } else {
        match pgp_escrow::parse_public_key(pgp_input) {
            Ok(r) => Some((pgp_input.to_string(), r.target_fingerprint().to_string())),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("pgp_recipient is not a valid OpenPGP public key: {e}"),
                )
                    .into_response()
            }
        }
    };

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
    // v186: 512-byte bound, enforced server-side (was client-side only).
    let custom_info_str = match canonical_custom_info(payload.custom_info.as_deref().unwrap_or("")) {
        Some(s) => s,
        None => {
            return (StatusCode::BAD_REQUEST, "custom_info exceeds 512 bytes").into_response()
        }
    };

    // v225 (user directive — no redirect race): the caller may name where the
    // code should land, but ONLY from the operator's allowlist. This is the
    // difference between "the code arrives at a page the user controls, which
    // seals it before the enclave ever sees it" and an open redirect that
    // hands PayPal codes to any origin that asks.
    let requested_redirect = payload.redirect_uri.as_deref().map(str::trim).unwrap_or("");
    let redirect_uri = if requested_redirect.is_empty() {
        state.redirect_uri.clone()
    } else {
        match normalize_redirect_uri(requested_redirect) {
            Some(u) if redirect_uri_allowed(&state.allowed_redirect_uris, &u) => u,
            Some(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "redirect_uri is not one of this enclave's allow-listed redirect URIs \
                     — the operator must add it to seal_redirect_uris (and register it \
                     with PayPal) before a code can land there",
                )
                    .into_response()
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "redirect_uri must be an https:// URL with no query string, fragment \
                     or userinfo",
                )
                    .into_response()
            }
        }
    };

    // Self-describing state token (v180): the client session travels inside
    // the OAuth `state` and is re-parsed by /callback after PayPal redirects
    // back. It is UNTRUSTED input by construction — it becomes meaningful
    // only because the callback binds it into the hardware quote
    // (report_data[32..64] = SHA-256(P_client ∥ Nonce_client)), which the
    // auditor compares against ITS OWN session values. `r` is client-side
    // entropy so two logins with identical parameters never share a token.
    use rand::Rng;
    use sha2::Digest;
    // R3-1: PKCE (RFC 7636, S256). The verifier is generated HERE, parked in
    // enclave RAM keyed by the state below, and NEVER echoed in the response
    // — only its challenge travels (signed), so an observer of the login
    // session (or of the later PayPal redirect) learns nothing usable.
    let mut verifier_raw = [0u8; 32];
    rand::thread_rng().fill(&mut verifier_raw);
    let mut code_verifier = B64URL.encode(verifier_raw);
    let code_challenge = B64URL.encode(sha2::Sha256::digest(code_verifier.as_bytes()));
    let random = hex::encode(rand::thread_rng().gen::<[u8; 16]>());
    let state_obj = serde_json::json!({
        "v": 1,
        "p": payload.client_ecdh_pub_b64.trim(),
        "n": payload.client_nonce_hex.trim().to_ascii_lowercase(),
        "f": label.clone(),
        "c": custom_info_str,
        // v225: the redirect this session will actually use, carried in the
        // (untrusted) state so /callback can repeat it to PayPal — the token
        // exchange rejects a redirect_uri that differs from the authorize
        // URL's. Re-validated against the allowlist at the callback.
        "u": redirect_uri,
        "r": random,
    });
    let state_token = B64URL.encode(state_obj.to_string().as_bytes());

    // R3-1: park this state's PKCE verifier (bounded + TTL-pruned, like the
    // E2EE vault — login-session requests are budget-charged, so the table
    // cannot be flooded faster than the egress budget allows).
    {
        let mut table = state.pending_pkce.write();
        table.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(PKCE_TTL_SECS));
        if table.len() >= MAX_PENDING_PKCE {
            if let Some(k) = table.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone()) {
                table.remove(&k);
            }
        }
        table.insert(state_token.clone(), (code_verifier.clone(), Instant::now()));
    }
    zeroize_str(&mut code_verifier);

    // v197: park this state's optional escrow key (bounded + TTL, like PKCE).
    if let Some((armor, _)) = &pgp_stored {
        let mut table = state.pending_pgp.write();
        table.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(PKCE_TTL_SECS));
        if table.len() >= MAX_PENDING_PGP {
            if let Some(k) = table.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone()) {
                table.remove(&k);
            }
        }
        table.insert(state_token.clone(), (armor.clone(), Instant::now()));
    }

    let auth_base = if state.staging { PAYPAL_SANDBOX_AUTH } else { PAYPAL_PRODUCTION_AUTH };
    let mut signed_fields = serde_json::json!({
        "binding": "v180",
        "state": state_token,
        // R3-1: PKCE challenge — required by the trusted auditor BEFORE it
        // will send the user to PayPal (downgrade defense), enforced by
        // PayPal at exchange time (code_verifier required iff challenged).
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "flow": label,
        "paypal_client_id": cid,
        // v169: the environment is signed (and app-pinned) at session time,
        // so a redirect into sandbox PayPal cannot be passed off as production.
        "paypal_environment": if state.staging { "sandbox" } else { "production" },
        "redirect_uri": redirect_uri,
        "authorize_base": auth_base,
        "scope": scope,
        "custom_info": custom_info_str,
        // Echo of the binding the callback will hardware-bind; the auditor
        // compares it against ITS OWN recomputation (display/cross-check
        // only — the quote bytes are the source of trust, v179 semantics).
        "client_session_binding_hex": hex::encode(client_session_binding(&client_pub, &client_nonce)),
    });
    // v197/v198: signed fingerprint of the escrow TARGET (the encryption key
    // actually used for the sealed copy — its last 16 hex are the ciphertext's
    // PKESK key-id) so the auditor can prove the downloaded ciphertext is
    // addressed to exactly this key: substitution defense — a hostile enclave
    // cannot quietly reseal the copy to a key of its own choosing. (v198 fix:
    // it used to sign `r.fingerprint`, the PRIMARY — see target_fingerprint().)
    if let Some((_, fp)) = &pgp_stored {
        signed_fields["pgp_recipient_fingerprint"] = serde_json::Value::String(fp.clone());
    }

    // v225: both seal slots travel in the SIGNED login response. The page
    // therefore has the keys it must seal to BEFORE PayPal, on a channel this
    // enclave signed — so the return leg seals with no attestation fetch at
    // all (v180: no pre-login attestation) and never has to trust a key read
    // off an unverified route.
    {
        let (tls_pem, tls_sha) = attested_tls_key(&state);
        let (seal_pem, seal_sha) = attested_seal_key(&state);
        signed_fields["seal_slots"] = serde_json::json!({
            "code": { "pem": tls_pem, "sha256": tls_sha },
            "nonce": { "pem": seal_pem, "sha256": seal_sha },
        });
    }

    let signed_fields_str = serde_json::to_string(&signed_fields).unwrap();
    let signature = {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;
        let mut signer = Signer::new(MessageDigest::sha256(), &state.enclave_identity.pkey).unwrap();
        signer.update(signed_fields_str.as_bytes()).unwrap();
        B64STD.encode(signer.sign_to_vec().unwrap())
    };

    let body = serde_json::json!({
        "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
        "signed_fields": signed_fields,
        "login_signature_b64": signature,
    });
    let mut resp = ([(axum::http::header::CONTENT_TYPE, "application/json")], Json(body)).into_response();
    resp.headers_mut().insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
    with_secure_headers(resp)
}


// ----------------------------------------------------------------------------
// Standalone Auditor Envelope (GET /debug/envelope)
// ----------------------------------------------------------------------------
// v180 (user directive — no pre-login attestation): this route is NO LONGER
// part of the login flow. It exists only for (a) the golden-pin rotation
// tooling (scripts/calculate-golden-rtmr.mjs) and (b) an operator manually
// eyeballing a live envelope. The body carries an SEC-02 (v160) 5-component
// nonce bound into the TDX quote's report_data with NO client session bound
// (session binding belongs to the login flow's callback). Pre-login there is
// no PayPal user, so paypal_user_info_raw_hash carries a documented
// placeholder and the nonce is self-consistent with it; the real user hash is
// bound only at login. It is served from a 15-minute cache (see handler), so
// it cannot be used to exhaust enclave resources.
async fn debug_envelope(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    use sha2::Digest;
    if let Err(status) = state.record_egress(addr.ip(), 8192) {
        return status.into_response();
    }

    // v180 (user directive — no pre-login DoS surface): the envelope is minted
    // ONCE per cache window (15 min) and served from RAM afterwards, so no
    // request path can ever trigger TD-quote generation at line rate (each
    // quote costs a full TDG.MR.REPORT + QGS round-trip). The mint is kept
    // alive for the ops/rotation workflow (calculate-golden-rtmr.mjs) and the
    // manual auditor — the LOGIN flow never touches this route.
    // The notary's key is the one part of the body that can go stale inside
    // the window (a restart mints a new key), so it is probed on every request
    // — a loopback GET to the child, no quote, no measurement work. The mint
    // below then reuses this probe instead of asking twice.
    let proxy_signing_key = attested_proxy_key().await;
    let live_proxy_key = proxy_signing_key
        .get("pubkey_sha256")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    if let Some(cached) = state.boot_envelope.read().clone() {
        if envelope_cache_fresh(cached.at, &cached.proxy_key_sha256, live_proxy_key.as_deref()) {
            let mut resp = ([(axum::http::header::CONTENT_TYPE, "application/json")], Json(cached.body)).into_response();
            resp.headers_mut().insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
            return with_secure_headers(resp);
        }
        if !live_proxy_key.as_deref().unwrap_or_default().is_empty() {
            // Re-minting costs one quote; serving a body that names a dead key
            // costs every auditor a failed (fail-closed) check instead.
            info!("envelope cache invalidated: the notary's key changed");
        }
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
    let (tls_pubkey_pem, tls_pubkey_sha256) = attested_tls_key(&state);
    let (seal_pubkey_pem, seal_pubkey_sha256) = attested_seal_key(&state);
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&nonce);
    let quote_res = tpm::quote(&hex::encode(nonce), Some(report_data));

    // v168 (plan Phase 2.2): FAIL-CLOSED report minting.
    if quote_res.tdx_quote_b64.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "hardware quote unavailable — attestation report refused (fail closed)",
        )
            .into_response();
    }

    let attestation_report = serde_json::json!({
        "custom_info": custom_info,
        "paypal_user_info_raw_hash": paypal_hash,
        "enclave_config": {
            "boot_measurements": {
                "binary_sha256": binary_sha256,
                "disk_manifest": &state.boot_manifest,
            }
        },
        "session_context": {
            // v228: the certificate this boot terminates TLS with, byte-for-byte
            // what GET /tls-cert.pem serves and what the browser's padlock
            // showed. v227 made that download the visitor's proof of the
            // channel, but the pre-login envelope named only the KEY — so the
            // only way to check the download against a report was to log in
            // first. The certificate is public handshake material (the key is
            // already here); naming it makes the binding checkable before any
            // session exists.
            "tls_certificate_pem": state.tls_cert_pem.read().clone().unwrap_or_default(),
            // v223: the key a prover seals a PayPal code to, named in the
            // attestation itself so "verify, then encrypt" needs no second
            // channel. Empty only in the window before the listener exists.
            "tls_public_key_pem": &tls_pubkey_pem,
            "tls_public_key_sha256": &tls_pubkey_sha256,
            // v225 (second seal slot): BOTH things a user may seal, named by
            // this one report. Sealing a code to `code` and a nonce to `nonce`
            // and presenting both at /callback proves a single boot handled
            // both — one report, one step, no second attestation round-trip.
            "seal_slots": {
                "code": { "pem": &tls_pubkey_pem, "sha256": &tls_pubkey_sha256 },
                "nonce": { "pem": &seal_pubkey_pem, "sha256": &seal_pubkey_sha256 },
            },
            // v231: the TLSNotary notary's signing key, so a proxy record's
            // signature is anchored to this report instead of being trusted on
            // its own say-so. `available: false` with a reason when the second
            // service is not part of this deployment.
            "proxy_signing_key": proxy_signing_key,
        },
        "hardware_level_attestation": quote_res,
        "timestamp_ms": chrono::Utc::now().timestamp_millis() as u64,
    });
    let signature = sign_report(&state, &attestation_report);

    let body = serde_json::json!({
        "attestation_report": attestation_report,
        "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
        "enclave_signature_b64": signature,
    });

    // Refresh the cache window with this fresh mint, then serve it. The
    // fingerprint recorded here is what a later request compares against.
    *state.boot_envelope.write() = Some(CachedEnvelope {
        at: Instant::now(),
        proxy_key_sha256: live_proxy_key.clone().unwrap_or_default(),
        body: body.clone(),
    });

    let mut resp = ([(axum::http::header::CONTENT_TYPE, "application/json")], Json(body)).into_response();
    resp.headers_mut().insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
    with_secure_headers(resp)
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
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    // R3-2 (audit round 3): the claim used to bypass the egress budget
    // entirely — charge it (the sealed blob answers are ~17 KB each).
    if let Err(status) = state.record_egress(addr.ip(), 32 * 1024) {
        return status.into_response();
    }
    let state_token = match query.state {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "Missing state").into_response(),
    };

    let blob = state.pending_e2ee_blobs.write().remove(&state_token);
    match blob {
        Some((payload, _)) => {
            let mut resp = Json(payload).into_response();
            resp.headers_mut().insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
            with_secure_headers(resp)
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

    // R3-2 (audit round 3 — payment-flow abuse): EVERY callback forces a
    // live PayPal token exchange, and the old code only charged the egress
    // budget AFTER the exchange with `let _ =` (result discarded — no 429
    // was ever returned, so spam could burn the PayPal API quota for this
    // app/IP until the provider or PayPal throttled US). Charge and ENFORCE
    // the budget up front: over-budget callers are refused before any
    // outbound payment call can happen.
    if let Err(status) = state.record_egress(addr.ip(), 24 * 1024) {
        return status.into_response();
    }

    let mut code = query.code.clone().unwrap_or_default();
    // v223: prefer the sealed form. A caller that sealed to the attested TLS key
    // proves the code only ever existed inside this instance; a caller that sent
    // it in the query keeps the old behaviour, so nothing that works today breaks.
    if let Some(sealed) = query.code_enc.as_deref().filter(|s| !s.trim().is_empty()) {
        if !code.trim().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                "send the code either sealed (code_enc) or in the query, not both",
            )
                .into_response();
        }
        match decrypt_sealed_code(&state, sealed) {
            Ok(opened) => code = opened,
            Err(reason) => {
                return (StatusCode::BAD_REQUEST, format!("cannot open the sealed code: {reason}")).into_response();
            }
        }
    }
    // v225 (second seal slot): the optional sealed nonce. Opened with its OWN
    // key, never the TLS key, so a value sealed for one slot can never be
    // replayed into the other; the plaintext is bounded exactly like
    // custom_info (512 bytes) because it becomes a signed report field.
    let mut user_nonce_raw = String::new();
    if let Some(sealed) = query.nonce_enc.as_deref().filter(|s| !s.trim().is_empty()) {
        let key = match state.seal_private_key.read().clone() {
            Some(k) => k,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "cannot open the sealed nonce: this boot has no seal slot yet",
                )
                    .into_response()
            }
        };
        match rsa_oaep_open(&key, sealed, "nonce") {
            Ok(opened) => user_nonce_raw = opened,
            Err(reason) => {
                return (StatusCode::BAD_REQUEST, format!("cannot open the sealed nonce: {reason}"))
                    .into_response()
            }
        }
    }
    let user_nonce = match canonical_custom_info(&user_nonce_raw) {
        Some(s) => s,
        None => {
            return (StatusCode::BAD_REQUEST, "the sealed nonce exceeds 512 bytes").into_response()
        }
    };
    zeroize_str(&mut user_nonce_raw);
    let state_param = query.state.clone().unwrap_or_default();

    // R3-4: a denied/cancelled consent (or a bare /callback hit) is rejected
    // BEFORE anything is exchanged or consumed — the PKCE verifier stays
    // valid so the user can simply retry from the auditor's PayPal link.
    if query.error.as_deref().is_some_and(|s| !s.is_empty()) {
        return (
            StatusCode::BAD_REQUEST,
            "PayPal returned an error — no code was exchanged. Restart from verify.html.",
        )
            .into_response();
    }
    if code.trim().is_empty() {
        return (StatusCode::FORBIDDEN, "Invalid or expired session. Start from your saved verify.html").into_response();
    }

    // v180 (user directive — no pre-login attestation): the client session
    // rides inside the OAuth `state` token (base64url JSON {v,p,n,f,c,r})
    // instead of a server-side pending session. R3-1 (audit round 3): the
    // exchange below is a confidential-client exchange (the client_secret
    // only ever exists inside the enclave) AND PKCE-bound — the client_secret
    // assumption alone is NOT sufficient under the collusion model, because
    // the webservice owner WRITES that secret into the config and observes
    // the redirect code at their own TLS endpoint; the enclave-held
    // code_verifier is the piece no adversary can obtain.
    // Everything parsed here is UNTRUSTED by construction: its only consumer
    // is the hardware quote below, whose report_data[32..64] binds
    // SHA-256(P_client ∥ Nonce_client). The auditor compares that slot against
    // the session values IT generated, so a forged state merely produces a
    // report that fails the local audit — never a usable blob. The expensive
    // paths (PayPal exchange + TD quote) sit behind a PayPal-verified code:
    // PayPal is the attacker filter, so no unauthenticated caller can ever
    // trigger quote minting (the pre-flight's DoS surface, removed).
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let invalid_session = || (StatusCode::FORBIDDEN, "Invalid or expired session. Start from your saved verify.html").into_response();
    let state_raw = match B64URL.decode(state_param.trim()) {
        Ok(v) => v,
        Err(_) => return invalid_session(),
    };
    let st: serde_json::Value = match serde_json::from_slice(&state_raw) {
        Ok(v) => v,
        Err(_) => return invalid_session(),
    };
    let flow = match st.get("f").and_then(|v| v.as_str()) {
        Some(f @ "verified") | Some(f @ "full") => f.to_string(),
        _ => return invalid_session(),
    };
    let client_pub = match st.get("p").and_then(|v| v.as_str()).map(|s| B64STD.decode(s.trim())) {
        Some(Ok(v)) if !v.is_empty() => v,
        _ => return invalid_session(),
    };
    // Panic-safe validation (same gate the old pre-flight enforced): reject a
    // non-DER key NOW so the ECDH below cannot fail later.
    if openssl::pkey::PKey::public_key_from_der(&client_pub).is_err() {
        return invalid_session();
    }
    let client_nonce = match st.get("n").and_then(|v| v.as_str()).and_then(|s| hex::decode(s.trim()).ok()) {
        Some(v) if v.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        }
        _ => return invalid_session(),
    };
    // Same custom_info canonicalization as the login-session endpoint
    // (trim; empty → "NONE") so the SEC-02 nonce binds what the auditor
    // recorded locally. v186: the state token is UNTRUSTED — a forged state
    // could otherwise smuggle an unbounded custom_info into the quote, the
    // signed report and the vault blob (both ends now share the 512-byte
    // bound in canonical_custom_info).
    let custom_info_str = match canonical_custom_info(st.get("c").and_then(|v| v.as_str()).unwrap_or("")) {
        Some(s) => s,
        None => return invalid_session(),
    };
    // v225: repeat the redirect_uri this session's authorize URL used, or
    // PayPal refuses the exchange (a code is issued for one redirect URI).
    // `u` arrives inside an UNTRUSTED state token, so it is only ever used
    // when it still matches the startup allowlist; a token minted before this
    // field existed falls back to the default, exactly as before.
    let redirect_uri = match st.get("u").and_then(|v| v.as_str()) {
        Some(raw) => match normalize_redirect_uri(raw) {
            Some(u) if redirect_uri_allowed(&state.allowed_redirect_uris, &u) => u,
            _ => return invalid_session(),
        },
        None => state.redirect_uri.clone(),
    };

    // R3-1: resolve THIS state's PKCE verifier before any PayPal call.
    // No verifier (forged state, restarted enclave, expired TTL) ⇒ fail
    // closed HERE — a stateless forged state can no longer even REACH the
    // PayPal exchange. The entry is retired only on a SUCCESSFUL exchange
    // (keep-on-failure: a raced garbage-code request must not be able to
    // burn a victim's verifier; repeated attempts are bounded by the egress
    // budget charged at entry + the TTL).
    let mut code_verifier = {
        let mut table = state.pending_pkce.write();
        table.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(PKCE_TTL_SECS));
        match table.get(state_param.trim()) {
            Some((v, _)) => v.clone(),
            None => return invalid_session(),
        }
    };

    let (cid, csec, _, _) = state.get_flow_config(&flow);
    let api_base = if state.staging { PAYPAL_SANDBOX_API } else { PAYPAL_PRODUCTION_API };

    let token_resp = hardened_client().post(format!("{}/v1/oauth2/token", api_base))
        .basic_auth(&cid, Some(&csec))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            // R3-1: the PKCE verifier PayPal REQUIRES because the authorize
            // URL carried code_challenge — an exchange without it (any
            // observer of the redirect holding the client secret) is refused
            // by PayPal itself.
            ("code_verifier", &code_verifier),
        ])
        .send().await;

    // R3-3 (audit round 3 — side-channel/evidence integrity): the platform
    // clock on this deployment runs +8h off (Beijing wall time read as UTC —
    // and the platform clock is PROVIDER-controlled, i.e. untrusted under
    // the collusion model). The signed report timestamp therefore comes from
    // PayPal's Date header when available: it arrives over pinned-IP,
    // pinned-DigiCert-root TLS (a channel neither the owner nor the provider
    // can forge), so the signed time is collusion-resistant. Platform clock
    // is kept only as a LABELED fallback. The auditor displays this field
    // and never gates on it.
    let paypal_now_ms = match &token_resp {
        Ok(r) => r
            .headers()
            .get(axum::http::header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| chrono::DateTime::parse_from_rfc2822(s.trim()).ok())
            .map(|dt| dt.timestamp_millis()),
        Err(_) => None,
    };

    let mut token_obj: TokenResponse = match token_resp {
        Ok(r) if r.status().is_success() => {
            // R3-1: single-use — the verifier retires WITH its exchange.
            state.pending_pkce.write().remove(state_param.trim());
            r.json().await
                .unwrap_or(TokenResponse { access_token: String::new(), id_token: None })
        }
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "Token exchange failed with PayPal").into_response(),
    };
    // v197: same keep-on-failure semantics as PKCE — the escrow armor is
    // retired only alongside a SUCCESSFUL exchange (the failure arm above
    // returns, so reaching this line means the exchange succeeded).
    let pgp_armor: Option<String> = state
        .pending_pgp
        .write()
        .remove(state_param.trim())
        .map(|(a, _)| a);
    zeroize_str(&mut code_verifier);

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
    if let Some(ref mut idt) = token_obj.id_token { zeroize_str(idt); }        let minimized = userinfo.verified_only();
    // v208 (user directive): the verified-account gate is SUSPENDED while the
    // login asks PayPal for no attributes at all — `verified_account` arrives
    // only with the paypalattributes scope, so requiring it here would 403
    // every login. Flip this back to `true` in the same commit that restores
    // an attribute scope; the auditor has the matching switch
    // (REQUIRE_VERIFIED_ACCOUNT in verify.html), and both must move together.
    const REQUIRE_VERIFIED_ACCOUNT: bool = false;
    if REQUIRE_VERIFIED_ACCOUNT && minimized.verified_account.as_deref() != Some("true") {
        return (StatusCode::FORBIDDEN, "PayPal account must be verified").into_response();
    }

    // Build the final attestation report. The login report binds the REAL PayPal
    // user hash into the SEC-02 nonce and a fresh hardware quote, so the
    // post-login audit's recomputed expectedNonce matches the quote's report_data.
    let binary_sha256 = hex::encode(sha2::Sha256::digest(&std::fs::read("/init").unwrap_or_default()));
    let paypal_user_raw_hash = hex::encode(sha2::Sha256::digest(
        serde_json::to_string(&minimized).unwrap_or_default().as_bytes(),
    ));
    // v197: captured BEFORE `minimized` moves into report_payload — the
    // "visible hash obtained from the PayPal id" (id-only, independent of
    // the attested identity-record hash above) and a clone of the latter,
    // because json! below consumes it.
    let paypal_id_sha256 = hex::encode(sha2::Sha256::digest(minimized.user_id.as_bytes()));
    let seal_raw_hash = paypal_user_raw_hash.clone();
    let custom_info = custom_info_str;

    let nonce = sec02_nonce(
        &paypal_user_raw_hash,
        &state.enclave_identity.pubkey_der,
        &custom_info,
        &binary_sha256,
        &state.boot_manifest,
    );
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&nonce);
    // v179 (plan Phase 1 — session-substitution defense): the quote's SECOND
    // report_data slot binds THIS browser's client session — SHA-256(P_client
    // SPKI-DER ∥ Nonce_client) — so a report minted for another browser's
    // session can never be replayed at this one: its hardware quote carries
    // the wrong P_client/nonce and the auditor's recomputation fails closed.
    // [0..32] stays the SEC-02 identity/code nonce (formula unchanged).
    report_data[32..64].copy_from_slice(&client_session_binding(&client_pub, &client_nonce));
    let (tls_pubkey_pem, tls_pubkey_sha256) = attested_tls_key(&state);
    let (seal_pubkey_pem, seal_pubkey_sha256) = attested_seal_key(&state);
    // v231: also name the notary key here, so the report a PayPal user keeps as
    // their own evidence covers both webservices of this boot.
    let proxy_signing_key = attested_proxy_key().await;
    let quote_res = tpm::quote(&hex::encode(nonce), Some(report_data));

    // v168 (plan Phase 2.2): FAIL-CLOSED report minting.
    if quote_res.tdx_quote_b64.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "hardware quote unavailable — attestation report refused (fail closed)",
        )
            .into_response();
    }

    let report_payload = serde_json::json!({
        "paypal_user_info": minimized,
        "paypal_user_info_raw_hash": paypal_user_raw_hash,
        "custom_info": custom_info,
        // v225 (second seal slot): the nonce the user sealed to this boot's
        // `nonce` slot, signed into the same report as the PayPal identity.
        // "NONE" when the caller sent none, so the field is always present and
        // always a plain commitment — never a surprise payload.
        "user_nonce": user_nonce,
        "user_nonce_sha256": hex::encode(sha2::Sha256::digest(user_nonce.as_bytes())),
        // v168 (plan Phase 3 — Malicious PayPal App defense): WHICH app
        // minted this identity is part of the signed report, so the auditor's
        // EXPECTED_APPS gate covers the login report itself, not just the
        // pre-flight fields.
        "paypal_client_id": cid,
        // v169 (audit finding — FLOW BINDING): WHICH flow minted this report.
        // `flow` is the label the pre-flight chose ("verified" = minimal scope,
        // "full" = PII app) and it is derived server-side from the pending
        // session — never from the client. verify.html requires it to match the
        // app pin AND the flow this browser asked for, so an enclave cannot
        // silently upgrade a minimal-disclosure login into the over-scoped app.
        "flow": flow.clone(),
        // v169 (audit finding): WHICH PayPal ENVIRONMENT answered. A sandbox
        // login is a REAL hardware attestation of a SYNTHETIC identity —
        // anybody (including the owner) can mint `verified_account: true`
        // there. Without this field a sandbox report and a production report
        // audit identically green, so the owner could satisfy every check with
        // an account it controls. The auditor now requires `production` for a
        // login report and refuses `sandbox` outright.
        "paypal_environment": if state.staging { "sandbox" } else { "production" },
        // R3-3: honest signing time (PayPal Date when available, platform
        // clock only as a LABELLED fallback — see the exchange above).
        "timestamp_ms": paypal_now_ms.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
        "timestamp_source": if paypal_now_ms.is_some() { "paypal_date" } else { "platform_clock" },
        "enclave_config": {
            "boot_measurements": {
                "binary_sha256": binary_sha256,
                "disk_manifest": &state.boot_manifest,
            }
        },
        "session_context": {
            "tls_certificate_pem": state.tls_cert_pem.read().clone().unwrap_or_default(),
            // v223 (user directive): the public half of the key that terminates
            // TLS for this boot, so a report is also the answer to "what do I
            // encrypt the PayPal code to?". Sealing the code to this key is what
            // makes the second attestation provably the same enclave: the key is
            // generated in RAM at boot, never persisted, and named in the first
            // attestation the user checks.
            "tls_public_key_pem": &tls_pubkey_pem,
            "tls_public_key_sha256": &tls_pubkey_sha256,
            // v225 (second seal slot): the same two slots the data-free report
            // names, so the login report itself says which keys were live for
            // this boot. `user_nonce_sha256` above is what a nonce sealed to
            // the `nonce` slot commits to.
            "seal_slots": {
                "code": { "pem": &tls_pubkey_pem, "sha256": &tls_pubkey_sha256 },
                "nonce": { "pem": &seal_pubkey_pem, "sha256": &seal_pubkey_sha256 },
            },
            // v231: the notary's signing key, so a TLSNotary record's signature
            // can be checked against the report a user already audits.
            "proxy_signing_key": proxy_signing_key,
            // v179 (plan Phase 1.1): the client session bound into the quote's
            // report_data[32..64] is echoed here for transparency. The auditor
            // compares the QUOTE bytes against ITS OWN session values — this
            // echo is display/cross-check only, never the source of trust.
            "client_pub_b64": B64STD.encode(&client_pub),
            "client_nonce_hex": hex::encode(&client_nonce),
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
    let enclave_ecdh = match new_enclave_ecdh() {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "ECDH key generation failed").into_response(),
    };
    let mut session_key = match crypto_e2ee::derive_session_key(
        &enclave_ecdh,
        &client_pub,
        &client_nonce,
    ) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "E2EE key derivation failed").into_response(),
    };
    let report_json = match serde_json::to_string(&full_envelope) {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Envelope serialization failed").into_response(),
    };
    let (iv, ct) = match crypto_e2ee::encrypt_envelope(&session_key, report_json.as_bytes(), &client_nonce) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "E2EE encryption failed").into_response(),
    };
    // Zeroize the derived session key immediately after use (plan requirement).
    session_key.iter_mut().for_each(|b| *b = 0);

    let ecdh_pub_der = enclave_ecdh.public_key_to_der().unwrap_or_default();
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

    // Save for local claim. Bounded: a completed PayPal
    // login is required to add one, but the table must still have a ceiling so
    // it can never grow without limit between the 60 s cleanup ticks. On
    // overflow the OLDEST entry is dropped (its owner can simply log in again).
    {
        let mut blobs = state.pending_e2ee_blobs.write();
        if blobs.len() >= MAX_PENDING_E2EE_BLOBS {
            let oldest = blobs
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                blobs.remove(&k);
            }
        }
        blobs.insert(state_param.clone(), (e2ee_blob.clone(), Instant::now()));
    }

    // v197 — SECOND download (Police escrow): built NEXT TO the plaintext
    // envelope, then handed to the page. The optional escrow never blocks the
    // primary attestation — on any failure we log a warning and ship without
    // the sealed copy (the login itself is unaffected).
    let pgp_sealed_json: Option<String> = pgp_armor.as_deref().and_then(|armor| {
        match pgp_escrow::build_sealed_report(armor, &report_json, &seal_raw_hash, &paypal_id_sha256) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(error = %e, "pgp escrow sealed copy skipped");
                None
            }
        }
    });

    // Never render plaintext user info: only return the encrypted blob
    // container (v164: the page then stashes it into sessionStorage and
    // hands decryption/audit/download to verify.html in the user's tab).
    let content = CALLBACK_CONTENT
        .replace("__E2EE_BLOB__", &e2ee_blob.to_string().replace("</", "<\\/"))
        .replace("__PGP_SEALED__", &pgp_sealed_json.unwrap_or_default().replace("</", "<\\/"));
    let html = HTML_TEMPLATE.replace("{{CONTENT}}", &content);

    let _ = state.record_egress(addr.ip(), html.len() as u64);
    html_with_secure_headers(html.into_bytes())
}

// ----------------------------------------------------------------------------
// Runtime Main Loop
// ----------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Second webservice: TLSNotary proxy supervision (v2xx, user request)
// ---------------------------------------------------------------------------
// PID 1 has no shell and no PATH worth trusting, so the binary path is explicit
// and defaults to what the dual-service initramfs installs.
fn tls_proxy_binary() -> String {
    std::env::var("TLS_PROXY_BIN").unwrap_or_else(|_| "/tls-proxy".to_string())
}

static PROXY_SUPERVISOR: std::sync::OnceLock<Arc<ProxySupervisor>> = std::sync::OnceLock::new();

struct ProxySupervisor {
    session_port: u16,
    api_port: u16,
    alive: Arc<AtomicBool>,
    restarts: Arc<AtomicU64>,
    last: Arc<RwLock<Option<String>>>,
    /// v233: `POST /proxy/restart` (operator token) wakes the supervisor, which
    /// kills the child and re-execs it. This is also how the live test proves the
    /// envelope cache follows a key change without a reboot: the enclave, its
    /// cache and its listeners all stay up; only the notary cycles.
    restart: Arc<tokio::sync::Notify>,
    restart_token: Option<String>,
}

/// Start the proxy child and keep it up.
///
/// The proxy is a separate process on purpose: it links the tlsn tree, which
/// the PayPal-only image must not carry, and a crash in a TLSNotary session must
/// not take the OAuth flow down with it. Restart backoff is 2 s → 60 s so a
/// permanently broken binary cannot spin the VM.
fn spawn_tls_proxy(cfg: &TlsProxyConfig) -> Arc<ProxySupervisor> {
    let bin = tls_proxy_binary();
    let sup = Arc::new(ProxySupervisor {
        session_port: cfg.session_port,
        api_port: cfg.api_port,
        alive: Arc::new(AtomicBool::new(false)),
        restarts: Arc::new(AtomicU64::new(0)),
        last: Arc::new(RwLock::new(None)),
        restart: Arc::new(tokio::sync::Notify::new()),
        restart_token: cfg.restart_token.clone(),
    });
    let cfg = cfg.clone();
    let task_sup = sup.clone();
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(2);
        loop {
            let mut cmd = tokio::process::Command::new(&bin);
            cmd.env("TLS_PROXY_LISTEN", format!("0.0.0.0:{}", cfg.session_port))
                .env("TLS_PROXY_HTTP_LISTEN", format!("127.0.0.1:{}", cfg.api_port))
                .env(
                    "TLS_PROXY_SESSION_TIMEOUT",
                    cfg.session_timeout_secs.to_string(),
                )
                .env("TLS_PROXY_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                // stderr is inherited: PID 1's stderr is the serial console,
                // and a proxy that cannot say why it died is undebuggable in a
                // VM with no shell.
                .stderr(std::process::Stdio::inherit());
            if let Some(pem) = &cfg.signing_key_pem {
                cmd.env("TLS_PROXY_SIGNING_KEY_PEM", pem);
            }
            match cmd.spawn() {
                Ok(mut child) => {
                    task_sup.alive.store(true, Ordering::Relaxed);
                    info!("tls-proxy started (pid {})", child.id().unwrap_or(0));
                    // v233: an operator (or the live re-mint test) can ask for a
                    // cycle. `kill` + `wait` is a real restart — the child mints
                    // a fresh signing key on boot, which is exactly the event the
                    // envelope cache has to notice.
                    let requested = tokio::select! {
                        s = child.wait() => {
                            let msg = match s {
                                Ok(s) => format!("exited: {s}"),
                                Err(e) => format!("wait failed: {e}"),
                            };
                            Some(msg)
                        }
                        _ = task_sup.restart.notified() => {
                            info!("tls-proxy restart requested — cycling the child");
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            None
                        }
                    };
                    task_sup.alive.store(false, Ordering::Relaxed);
                    task_sup.restarts.fetch_add(1, Ordering::Relaxed);
                    let msg = requested
                        .clone()
                        .unwrap_or_else(|| "restart requested".to_string());
                    match requested {
                        Some(_) => warn!("tls-proxy {} — restarting in {:?}", msg, backoff),
                        // A requested cycle is not a crash: come back immediately
                        // rather than paying the crash backoff for the operator.
                        None => {
                            warn!("tls-proxy {}", msg);
                            backoff = Duration::from_secs(1);
                        }
                    }
                    *task_sup.last.write() = Some(msg);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
                Err(e) => {
                    task_sup.alive.store(false, Ordering::Relaxed);
                    error!("cannot start {}: {} — retrying in {:?}", bin, e, backoff);
                    *task_sup.last.write() = Some(format!("spawn failed: {e}"));
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    });
    sup
}

/// `/proxy/health` — says whether the second webservice is alive, without
/// requiring an operator to reach its loopback API.
async fn proxy_health() -> axum::response::Response {
    use axum::response::IntoResponse;
    match PROXY_SUPERVISOR.get() {
        Some(sup) => {
            let running = sup.alive.load(Ordering::Relaxed);
            // Only the child knows what is in flight, and during a shutdown that
            // is the number worth watching: it is what the drain waits on. Best
            // effort — a dead child reports `null`, not a failure of this route,
            // which must stay answerable precisely when things are going wrong.
            let child = if running {
                proxy_loopback_json("health", sup.api_port, "/health")
                    .await
                    .ok()
            } else {
                None
            };
            let field = |name: &str| {
                child
                    .as_ref()
                    .and_then(|v| v.get(name).cloned())
                    .unwrap_or(serde_json::Value::Null)
            };
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "service": "tls-proxy",
                    "enabled": true,
                    "running": running,
                    "session_port": sup.session_port,
                    "api_port": sup.api_port,
                    "restarts": sup.restarts.load(Ordering::Relaxed),
                    "last": sup.last.read().clone(),
                    "active_sessions": field("active_sessions"),
                    "draining": field("draining"),
                    "sessions_ok": field("sessions_ok"),
                    "sessions_failed": field("sessions_failed"),
                })),
            )
                .into_response()
        }
        None => (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"service": "tls-proxy", "enabled": false})),
        )
            .into_response(),
    }
}

/// Does this caller hold the operator's restart token?
///
/// Pure so the routing decision is testable without an enclave. Both sides are
/// hashed before comparison: the point is not to make a SHA-256 collision
/// infeasible (it already is) but to do the same amount of work for a short
/// guess and a long one, so the token's length does not leak through timing.
/// A build with no token configured has no restart route at all.
fn restart_token_ok(configured: Option<&str>, presented: Option<&str>) -> bool {
    use sha2::Digest;
    let (Some(c), Some(p)) = (configured, presented) else {
        return false;
    };
    if c.is_empty() || p.is_empty() {
        return false;
    }
    sha2::Sha256::digest(c.as_bytes()) == sha2::Sha256::digest(p.as_bytes())
}

/// `POST /proxy/restart` — cycle the notary child, keeping the enclave up.
///
/// Why this exists: the notary is a separate process with its own per-boot
/// signing key, and the only other way to restart it is to reboot the enclave —
/// which on this platform means re-running the whole attestation boot. An
/// operator who needs a fresh key (a wedged session, a rotated policy, the live
/// test below) should not have to do that.
///
/// It is a control surface, so it is gated on the operator token from the
/// instance config and it answers 404 — not 401/403 — when the token is absent or
/// wrong: a caller who cannot use the route is not told it exists. The only
/// thing a holder can do is make the notary come back with a new key, which is
/// what `/proxy/health` already reports (`restarts`).
async fn proxy_restart(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(sup) = PROXY_SUPERVISOR.get() else {
        return (axum::http::StatusCode::NOT_FOUND, "").into_response();
    };
    let presented = headers.get("x-proxy-restart").and_then(|v| v.to_str().ok());
    if !restart_token_ok(sup.restart_token.as_deref(), presented) {
        return (axum::http::StatusCode::NOT_FOUND, "").into_response();
    }
    sup.restart.notify_one();
    (
        axum::http::StatusCode::ACCEPTED,
        axum::Json(serde_json::json!({
            "service": "tls-proxy",
            "restarting": true,
            "restarts_before": sup.restarts.load(Ordering::Relaxed),
        })),
    )
        .into_response()
}

/// `/proxy/refusals` — the proxy's refusal ring, readable on the public origin.
///
/// `/proxy/health` only says the child is alive; it cannot answer "why was my
/// session rejected?", and the loopback API that can needs a shell on the VM.
/// An operator on a managed importer, or one whose serial console has scrolled
/// past the refusal, has neither. This route relays the ring so the answer is
/// reachable over HTTPS.
///
/// Reasons quote the host each prover committed to. A notary must not publish
/// who other provers were looking at, so host-shaped tokens are replaced with a
/// stable fingerprint (`api-m.paypal.com` → `host:9f2c0a1b`): repeated attempts
/// still line up, the name itself never leaves the loopback API. The full text
/// stays at `GET :8081/refusals` and in the boot log.
async fn proxy_refusals() -> axum::response::Response {
    use axum::response::IntoResponse;
    let unavailable = proxy_unavailable;

    let Some(sup) = PROXY_SUPERVISOR.get() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"service": "tls-proxy", "enabled": false})),
        )
            .into_response();
    };
    if !sup.alive.load(Ordering::Relaxed) {
        return unavailable(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!(sup.last.read().clone()),
        );
    }

    let mut parsed = match proxy_loopback_json("refusals", sup.api_port, "/refusals").await {
        Ok(value) => value,
        Err((code, detail)) => return unavailable(code, serde_json::json!(detail)),
    };
    redact_refusal_reasons(&mut parsed);
    if let Some(map) = parsed.as_object_mut() {
        map.insert("service".into(), serde_json::json!("tls-proxy"));
        map.insert("running".into(), serde_json::json!(true));
        map.insert(
            "redaction".into(),
            serde_json::json!(
                "host-shaped tokens in `reason` are replaced by host:<sha256 prefix>; \
                 full text is served by the loopback API (GET :8081/refusals) and the boot log"
            ),
        );
    }
    axum::Json(parsed).into_response()
}

/// `/proxy/attestations` — the sessions this boot has attested, on the public
/// origin.
///
/// The proxy records an attestation in guest RAM and serves it on the loopback
/// API, which means an operator on a managed importer (no shell, no serial
/// console) cannot even tell whether their session was recorded or what its id
/// is. This route relays the list: session id, when it was notarised, which host
/// it is about — the last of those fingerprinted exactly as `/proxy/refusals`
/// fingerprints a host, so the list never publishes who other provers were
/// looking at.
///
/// The transcript bytes and the signature stay where they are. They are what a
/// prover downloads over `GET :8081/attestations/<id>` (or takes from
/// `verify.html`), and publishing an attestation body on a shared origin would
/// hand every visitor everyone else's transcripts.
async fn proxy_attestations() -> axum::response::Response {
    use axum::response::IntoResponse;
    let unavailable = proxy_unavailable;

    let Some(sup) = PROXY_SUPERVISOR.get() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"service": "tls-proxy", "enabled": false})),
        )
            .into_response();
    };
    if !sup.alive.load(Ordering::Relaxed) {
        return unavailable(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!(sup.last.read().clone()),
        );
    }

    let mut parsed = match proxy_loopback_json("attestations", sup.api_port, "/attestations").await {
        Ok(value) => value,
        Err((code, detail)) => return unavailable(code, serde_json::json!(detail)),
    };
    redact_attestation_hosts(&mut parsed);
    if let Some(map) = parsed.as_object_mut() {
        map.insert("service".into(), serde_json::json!("tls-proxy"));
        map.insert("running".into(), serde_json::json!(true));
        map.insert(
            "redaction".into(),
            serde_json::json!(
                "`server_name` is replaced by host:<sha256 prefix>; a prover fetches their own \
                 signed record from GET /proxy/attestations/<id>?sent_sha256=<…>&received_sha256=<…> \
                 (the digests of the bytes their own proof reveals), and the unfiltered record is \
                 also on the loopback API (GET :8081/attestations/<id>)"
            ),
        );
    }
    axum::Json(parsed).into_response()
}

/// What a prover may present instead of being on the box.
#[derive(serde::Deserialize)]
struct AttestationDownloadQuery {
    sent_sha256: Option<String>,
    received_sha256: Option<String>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One answer for every "not yours": an id this boot never recorded, a digest
/// pair that does not match, a malformed request. Distinguishing them would turn
/// the route into an oracle for which sessions exist.
fn attestation_absent(id: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({
            "error": "no such attestation in this boot",
            "session_id": id,
        })),
    )
        .into_response()
}

/// `/proxy/attestations/{id}` — the prover's own signed record, from anywhere.
///
/// The list publishes ids but never transcripts, and the transcript is exactly
/// what a prover already holds: TLSNotary reveals it to build the proof. So the
/// capability is that knowledge — `sent_sha256` and `received_sha256`, the pair
/// the record itself signs over. Whoever ran the session can compute both; an
/// onlooker who only read the public list cannot, and the record never becomes
/// reachable by enumerating ids.
///
/// The bytes are relayed as text, never re-serialised: the signature covers the
/// field order of what the proxy stored (v221), so parsing and re-encoding here
/// would break the very thing the prover came to download.
async fn proxy_attestation_download(
    AxumPath(id): AxumPath<String>,
    Query(q): Query<AttestationDownloadQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Some(sup) = PROXY_SUPERVISOR.get() else {
        return attestation_absent(&id);
    };
    if !sup.alive.load(Ordering::Relaxed) {
        return proxy_unavailable(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!(sup.last.read().clone()),
        );
    }

    let (Some(sent), Some(received)) = (q.sent_sha256, q.received_sha256) else {
        return attestation_absent(&id);
    };
    if !is_hex32(&id) || !is_hex64(&sent) || !is_hex64(&received) {
        return attestation_absent(&id);
    }

    let path = format!("/attestations/{id}?sent_sha256={sent}&received_sha256={received}");
    match proxy_loopback_text("attestations", sup.api_port, &path).await {
        Ok((200, text)) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            text,
        )
            .into_response(),
        Ok((404, _)) => attestation_absent(&id),
        Ok((code, detail)) => {
            warn!("proxy attestations: loopback answered {code} for a download");
            proxy_unavailable(
                axum::http::StatusCode::BAD_GATEWAY,
                serde_json::json!(format!("loopback API answered {code}: {detail}")),
            )
        }
        Err((code, detail)) => proxy_unavailable(code, serde_json::json!(detail)),
    }
}

/// Read the child's loopback API **without parsing it**.
///
/// The attestation download must hand the prover the bytes the enclave signed,
/// so the status and the text are relayed untouched. `proxy_loopback_json` is
/// right for the list and the refusal ring (fields are read, never served) and
/// wrong here.
async fn proxy_loopback_text(
    what: &str,
    api_port: u16,
    path: &str,
) -> Result<(u16, String), (axum::http::StatusCode, String)> {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .map_err(|e| {
            error!("proxy {what}: cannot build the loopback client: {e}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot build the loopback client: {e}"),
            )
        })?;
    let resp = client.get(&url).send().await.map_err(|e| {
        warn!("proxy {what}: loopback API unreachable: {e}");
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("loopback API unreachable: {e}"),
        )
    })?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(|e| {
        warn!("proxy {what}: cannot read the loopback answer: {e}");
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("cannot read the loopback answer: {e}"),
        )
    })?;
    Ok((status, text))
}

/// The 503/502 shape both proxy relays answer with when the child cannot be
/// read: an operator gets the same envelope as `/proxy/health`, plus why.
fn proxy_unavailable(
    code: axum::http::StatusCode,
    detail: serde_json::Value,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        code,
        axum::Json(serde_json::json!({
            "service": "tls-proxy",
            "enabled": true,
            "running": false,
            "last": detail,
        })),
    )
        .into_response()
}

/// Read a JSON document from the proxy child's loopback API.
///
/// Loopback only: the child's API binds 127.0.0.1, so this is an in-guest read,
/// not a second network hop an attacker could redirect.
async fn proxy_loopback_json(
    what: &str,
    api_port: u16,
    path: &str,
) -> Result<serde_json::Value, (axum::http::StatusCode, String)> {
    proxy_loopback_call(what, api_port, reqwest::Method::GET, path).await
}

/// One call to the child's loopback API, any method.
///
/// Split out because the shutdown drain needs `POST /drain` while the public
/// relay routes need `GET`: the drain is a state change and must not be
/// reachable by anything that can merely fetch a page.
async fn proxy_loopback_call(
    what: &str,
    api_port: u16,
    method: reqwest::Method,
    path: &str,
) -> Result<serde_json::Value, (axum::http::StatusCode, String)> {
    let url = format!("http://127.0.0.1:{api_port}{path}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .map_err(|e| {
            error!("proxy {what}: cannot build the loopback client: {e}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot build the loopback client: {e}"),
            )
        })?;
    let resp = client.request(method, &url).send().await.map_err(|e| {
        warn!("proxy {what}: loopback API unreachable: {e}");
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("loopback API unreachable: {e}"),
        )
    })?;
    let status = resp.status();
    if !status.is_success() {
        warn!("proxy {what}: loopback API answered {status}");
        return Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("loopback API answered {status}"),
        ));
    }
    let body = resp.text().await.map_err(|e| {
        warn!("proxy {what}: cannot read the loopback answer: {e}");
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("cannot read the loopback answer: {e}"),
        )
    })?;
    serde_json::from_str(&body).map_err(|e| {
        warn!("proxy {what}: loopback answer is not JSON: {e}");
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("loopback answer is not JSON: {e}"),
        )
    })
}

/// Fingerprint the host inside every refusal reason, in place.
///
/// The counterpart of `redact_attestation_hosts` and deliberately built on the
/// same `fingerprint_hosts`, so one host reads as one token in both public
/// documents and an operator can line a session up with the refusal it replaced.
fn redact_refusal_reasons(parsed: &mut serde_json::Value) {
    if let Some(records) = parsed.get_mut("refusals").and_then(|v| v.as_array_mut()) {
        for record in records.iter_mut() {
            if let Some(reason) = record.get("reason").and_then(|v| v.as_str()) {
                record["reason"] = serde_json::Value::String(fingerprint_hosts(reason));
            }
        }
    }
}

/// Fingerprint every `server_name` in an attestation list, in place.
///
/// The same fingerprint `/proxy/refusals` uses, so an operator can line a
/// session up with the refusal it replaced without either document naming the
/// host.
fn redact_attestation_hosts(parsed: &mut serde_json::Value) {
    if let Some(sessions) = parsed.get_mut("sessions").and_then(|v| v.as_array_mut()) {
        for session in sessions.iter_mut() {
            if let Some(name) = session.get("server_name").and_then(|v| v.as_str()) {
                session["server_name"] = serde_json::json!(fingerprint_hosts(name));
            }
        }
    }
}

/// Replace host-shaped tokens in a refusal reason with a stable fingerprint.
///
/// Deliberately lexical rather than clever: it only needs to catch the things a
/// prover commits to (`api-m.paypal.com`, `example.co.uk`) and must leave
/// numbers that only look dotted (`1.99.0`, a byte count) alone, so the last
/// label has to be alphabetic and at least two characters.
fn fingerprint_hosts(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            token.push(ch);
        } else {
            push_fingerprinted(&mut out, &token);
            token.clear();
            out.push(ch);
        }
    }
    push_fingerprinted(&mut out, &token);
    out
}

fn push_fingerprinted(out: &mut String, token: &str) {
    // Leading/trailing punctuation stays outside the replacement, so
    // "(api-x.com)." keeps its brackets and full stop.
    let start = token.find(|c: char| c.is_ascii_alphanumeric());
    let end = token.rfind(|c: char| c.is_ascii_alphanumeric());
    let (Some(start), Some(end)) = (start, end) else {
        out.push_str(token);
        return;
    };
    let core = &token[start..=end];
    if is_host_shaped(core) {
        use sha2::Digest as _;
        out.push_str(&token[..start]);
        out.push_str("host:");
        out.push_str(&hex::encode(sha2::Sha256::digest(core.as_bytes()))[..8]);
        out.push_str(&token[end + 1..]);
    } else {
        out.push_str(token);
    }
}

fn is_host_shaped(core: &str) -> bool {
    let labels: Vec<&str> = core.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

/// Refuse the PayPal OAuth surface when `services.paypal` is false: a provider
/// surface with no credentials behind it is an attack surface, not a feature.
async fn paypal_disabled_gate(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    const PAYPAL_PATHS: [&str; 7] = [
        "/",
        "/verify.html",
        "/attest/login-session",
        "/callback",
        "/e2ee-blob",
        "/debug/envelope",
        "/tls-cert.pem",
    ];
    if PAYPAL_PATHS.contains(&req.uri().path()) {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "the PayPal webservice is disabled on this VM",
                "services": {"paypal": false},
            })),
        )
            .into_response();
    }
    next.run(req).await
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    enclave_init::mount_filesystems();
    // Boot self-report: resolve the sink from the ESP before anything can
    // fail, so even a boot with missing/expired `user_data` can say why it is
    // dark. Absent file = reporting simply stays off.
    selfreport::init_from_bootstrap_file("/boot/efi/selfreport.json");
    selfreport::stage("cmdline");
    enclave_init::verify_cmdline();
    selfreport::stage("drivers");
    enclave_init::load_drivers();
    selfreport::stage("shutdown");
    enclave_init::arm_shutdown_handling();
    selfreport::stage("measure");
    let boot_manifest = enclave_init::measure_boot_components();
    selfreport::stage("firewall");
    enclave_init::setup_firewall();
    selfreport::stage("harden");
    enclave_init::harden_kernel();

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

        selfreport::stage("network");
        if let Err(e) = enclave_init::configure_network().await {
            selfreport::note_failure(format!("network: {}", e));
            enclave_init::poweroff();
        }
        selfreport::progress();

        selfreport::stage("config");
        let config = fetch_config().await.unwrap_or_else(|e| {
            error!("FATAL: {}", e);
            // Most common dark-box cause: IMDS answered but the config was
            // absent/undecodable, or credentials were placeholders.
            selfreport::note_failure(format!("config: {}", e));
            enclave_init::poweroff();
        });
        // `user_data` may carry the sink too; the ESP file (if present, etc.)
        // wins because it is measured with the image.
        selfreport::init(config.self_report.clone());
        selfreport::progress();

        // Relay targets are config now, so they are pinned here — after the
        // config is known, but still before egress_lockdown() closes DNS. The
        // proxy resolves the name a prover committed to when that session
        // starts, which is long after DNS is gone; the addresses resolved here
        // are also what the lockdown rule allows on 443.
        if let Some(proxy) = config.services.as_ref().and_then(|s| s.proxy()) {
            enclave_init::pin_relay_targets(&proxy.relay_targets);
        }

        // --- service selection -------------------------------------------------
        // Both webservices can run in this VM; each can run alone. `services`
        // absent means PayPal only, and then nothing below changes the boot:
        // no child process, no extra port, no extra firewall rule.
        let services = config.services.clone().unwrap_or(Services {
            paypal: true,
            tls_proxy: None,
        });
        let paypal_enabled = services.paypal;
        if !paypal_enabled {
            info!("services.paypal=false — the PayPal OAuth routes are not served");
        }
        let proxy_supervisor = match services.proxy() {
            Some(cfg) => {
                // The prover dials this port from outside, and the boot
                // firewall admits only 80/443; open exactly this one hole
                // rather than loosening the ruleset for the PayPal flow.
                enclave_init::open_service_port(cfg.session_port);
                let sup = spawn_tls_proxy(cfg);
                if let Some(slot) = PROXY_SUPERVISOR.get() {
                    let _ = slot; // already set on a re-entrant boot path
                } else {
                    let _ = PROXY_SUPERVISOR.set(sup.clone());
                }
                info!(
                    "TLS proxy enabled: TLSNotary sessions on :{}, attestation API on 127.0.0.1:{}",
                    cfg.session_port, cfg.api_port
                );
                Some(sup)
            }
            None => {
                info!("TLS proxy disabled (no services.tls_proxy, or enabled=false)");
                None
            }
        };
        let _ = &proxy_supervisor;

        // v165 Phase 3: BOOT-TIME FAIL-CLOSED QUOTE PROBE. Before any traffic
        // is accepted, require a silicon-signed TD Quote from configfs TSM /
        // /dev/tdx_guest and replay the ACPI CCEL event log against the
        // quoted RTMR0..3. No quote → halt (the platform cannot attest).
        // CCEL replay mismatch → halt (host presents inconsistent evidence).
        // CCEL log unavailable in-guest is NOT a halt: it is recorded in the
        // probe transcript and integrity stays enforced remotely by
        // verify.html's EXPECTED_MRTD/EXPECTED_RTMR* hard pins over the quote.
        {
            let boot_nonce = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b"paypal-auth-vm-boot-attestation-probe-v165");
                h.update(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos().to_le_bytes())
                    .unwrap_or([0u8; 16]));
                hex::encode(h.finalize())
            };
            // Evidence collection reads configfs outblob / issues TDX ioctls
            // that the host VMM must answer — a wedged host TSM leaves those
            // reads blocked FOREVER (live-observed 2026-10-22: probe banner
            // printed, then silence across reboots; the host attestation
            // backend was healthy minutes earlier). Bound each attempt to
            // 10 s and RETRY: the backend can heal mid-boot, and the plan
            // only forbids serving traffic without a quote — it does not
            // require dying on the first transient outage. After ~6.5 min
            // without a quote: fail closed, never serve.
            fn collect_bounded(nonce: &str) -> intel_tdx::TdxEvidence {
                let nonce = nonce.to_string();
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let ev = intel_tdx::collect_silicon_evidence(&nonce, None);
                    let _ = tx.send(ev);
                });
                // 60 s bound: live hosts quote anywhere in 5 ms..12 s (the
                // flaky TSM service also freezes the console lock when it
                // wedges, so these transcripts also land on the ESP below).
                match rx.recv_timeout(std::time::Duration::from_secs(60)) {
                    Ok(ev) => ev,
                    Err(_) => {
                        let mut ev = intel_tdx::TdxEvidence::default();
                        ev.quote_status = Some("timeout".into());
                        ev.notes.push(
                            "evidence collection TIMED OUT after 60 s (host TSM/VMM wedged?)"
                                .into(),
                        );
                        ev
                    }
                }
            }
            // Survive console blindness (a wedged TSM freezes printk): append
            // the probe transcript to the ESP so the next operator can read it.
            fn probe_log(line: &str) {
                use std::io::Write as _;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/boot/efi/boot-probe.log")
                {
                    let _ = writeln!(f, "{} {}", std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0), line);
                }
            }
            info!("--- BOOT-TIME TDX QUOTE PROBE (fail-closed) ---");
            selfreport::stage("probe");
            probe_log("BOOT-TIME TDX QUOTE PROBE start");
            let mut attempts = 0u32;
            let ev = loop {
                attempts += 1;
                let ev = collect_bounded(&boot_nonce);
                if ev.quote_b64.is_some() || attempts >= 8 {
                    break ev;
                }
                warn!(
                    "boot quote probe attempt {}/8: no quote (status={:?}) — retrying in 20s",
                    attempts, ev.quote_status
                );
                probe_log(&format!("attempt {}/8: no quote (status={:?})", attempts, ev.quote_status));
                for n in ev.notes.iter().take(6) {
                    warn!("  probe: {}", n);
                }
                std::thread::sleep(std::time::Duration::from_secs(20));
            };
            probe_log(&format!("probe done: quote={} attempts={}", ev.quote_b64.is_some(), attempts));
            match ev.quote_b64.as_ref() {
                None => {
                    error!("FAIL-CLOSED: no silicon-signed TD Quote after {} attempts (status={:?}). Halting before serving traffic.", attempts, ev.quote_status);
                    for n in ev.notes.iter().take(20) { error!("  probe: {}", n); }
                    selfreport::note_failure(format!(
                        "probe: no silicon-signed TD Quote after {} attempts (status={:?})",
                        attempts, ev.quote_status
                    ));
                    enclave_init::poweroff();
                }
                Some(qb64) => {
                    use base64::Engine as _;
                    let quote = base64::engine::general_purpose::STANDARD
                        .decode(qb64)
                        .map_err(|e| format!("boot probe: quote b64: {}", e))?;
                    match intel_tdx::ccel_replay_vs_quote(&quote) {
                        Ok(notes) => {
                            info!("BOOT QUOTE PROBE OK ({} bytes, source={})", quote.len(), ev.quote_source.as_deref().unwrap_or("?"));
                            probe_log(&format!("BOOT QUOTE PROBE OK ({} bytes, source={})", quote.len(), ev.quote_source.as_deref().unwrap_or("?")));
                            for n in notes.iter() {
                                info!("  ccel: {}", n);
                                probe_log(&format!("ccel: {}", n));
                            }
                        }
                        Err(e) => {
                            error!("FAIL-CLOSED: {} — halting before serving traffic.", e);
                            probe_log(&format!("FAIL-CLOSED: {}", e));
                            selfreport::note_failure(format!("probe: {}", e));
                            enclave_init::poweroff();
                        }
                    }
                }
            }
        }

        // 1. Generate Ephemeral Enclave Identity (RAM ONLY, Never Logged)
        let enclave_identity = EphemeralEnclaveIdentity::generate()?;
        info!("--- EPHEMERAL ENCLAVE RSA KEY GENERATED (RAM ONLY, {} bytes) ---", enclave_identity.pubkey_der.len());

        // v225: the allowlist is built ONCE, here, so no request path can
        // widen it. The enclave's own /callback is always first; the operator's
        // extras are validated exactly like a caller-supplied value would be,
        // and anything malformed is dropped loudly rather than silently used.
        let redirect_uri = format!("https://{}/callback", config.domain);
        let mut allowed_redirect_uris = vec![redirect_uri.clone()];
        for raw in &config.seal_redirect_uris {
            match normalize_redirect_uri(raw) {
                Some(u) if !allowed_redirect_uris.contains(&u) => {
                    info!("redirect_uri allow-listed for sealed logins: {u}");
                    allowed_redirect_uris.push(u);
                }
                Some(_) => {}
                None => warn!(
                    "ignoring unusable seal_redirect_uris entry {raw:?}
                     (https:// URL, no query string or fragment)"
                ),
            }
        }

        let state = Arc::new(AppState {
            paypal_client_id: config.paypal_client_id.clone(),
            paypal_client_secret: config.paypal_client_secret.clone(),
            paypal_verified_client_id: config.paypal_verified_client_id.clone().unwrap_or_default(),
            paypal_verified_client_secret: config.paypal_verified_client_secret.clone().unwrap_or_default(),
            redirect_uri,
            allowed_redirect_uris: Arc::new(allowed_redirect_uris),
            domain: config.domain.clone(),
            https_ready: Arc::new(AtomicBool::new(false)),
            staging: config.staging,
            tls_cert_pem: Arc::new(RwLock::new(None)),
            tls_pubkey_pem: Arc::new(RwLock::new(None)),
            tls_private_key: Arc::new(RwLock::new(None)),
            seal_pubkey_pem: Arc::new(RwLock::new(None)),
            seal_private_key: Arc::new(RwLock::new(None)),
            enclave_identity,
            ip_stats: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            global_egress_bytes: Arc::new(AtomicU64::new(0)),
            last_limit_reset: Arc::new(RwLock::new(Instant::now())),
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            boot_manifest,
            pending_e2ee_blobs: Arc::new(RwLock::new(std::collections::HashMap::new())),
            pending_pkce: Arc::new(RwLock::new(std::collections::HashMap::new())),
            pending_pgp: Arc::new(RwLock::new(std::collections::HashMap::new())),
            boot_envelope: Arc::new(RwLock::new(None)),
        });

        // Periodic cleanup of expired volatile sessions
        let cleanup_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_state.pending_e2ee_blobs.write().retain(|_, (_, t)| t.elapsed() < Duration::from_secs(600));
                cleanup_state.pending_pkce.write().retain(|_, (_, at)| at.elapsed() < Duration::from_secs(PKCE_TTL_SECS));
                cleanup_state.pending_pgp.write().retain(|_, (_, at)| at.elapsed() < Duration::from_secs(PKCE_TTL_SECS));
            }
        });

        let app = Router::new()
            // v205: the service serves the landing only. The auditor and the
            // ZK prover come from the GitHub repository, the legal documents
            // from the same repository (linked, never copied).
            .route("/", get(serve_landing))
            // Kept as an alias so an old bookmark lands on the instructions
            // instead of a 404 — it serves the same landing, never the auditor.
            .route("/verify.html", get(serve_landing))
            .route("/attest/login-session", axum::routing::options(login_session_cors).post(attest_login_session))
            .route("/debug/envelope", get(debug_envelope))
            // v2xx: one line of truth about the second webservice on the public
            // origin, so an operator can see whether the proxy child is alive
            // without reaching the loopback API.
            .route("/proxy/health", get(proxy_health))
            // v233: operator-gated cycle of the notary child (404 without the
            // token from the instance config).
            .route("/proxy/restart", axum::routing::post(proxy_restart))
            // The refusal ring, on the same origin: health says the child is
            // alive, this says why a session was refused when there is no
            // shell and no serial console to read.
            .route("/proxy/refusals", get(proxy_refusals))
            // The recorded sessions, for the same reason: without this an
            // operator cannot even see whether their session was attested,
            // because the attestation list lives on the loopback API. Hosts are
            // fingerprinted; transcript bytes stay on loopback.
            .route("/proxy/attestations", get(proxy_attestations))
            // v222: the prover's own record, fetched from anywhere with the
            // digest pair their proof reveals — the list above publishes ids,
            // never transcripts, so this is the only way back to a session
            // from a machine that is not the VM.
            .route(
                "/proxy/attestations/{id}",
                get(proxy_attestation_download),
            )
            // v189 (user request): the enclave's own TLS chain as a PEM file,
            // offered by verify.html BEFORE the PayPal login (see handler).
            .route("/tls-cert.pem", get(serve_tls_cert))
            .route("/callback", get(callback))
            .route("/e2ee-blob", get(get_e2ee_blob))
            // R3-4 (audit round 3 — side channel): the default span logs the
            // FULL request URI — including /callback?code=…&state=… and
            // /e2ee-blob?state=… — into /dev/kmsg, which reaches the PROVIDER
            // in plaintext over the serial console. Path only, never query:
            // auth codes, state tokens and custom_info stay off the console.
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(|req: &axum::extract::Request| {
                        tracing::info_span!(
                            "http",
                            method = %req.method(),
                            uri = %req.uri().path()
                        )
                    }),
            )
            .with_state(state.clone());

        // v2xx: `services.paypal=false` runs the proxy alone. The OAuth routes
        // are not served then — a provider surface with no credentials behind
        // it is an attack surface, not a feature. Everything else (landing,
        // health, TLS certificate) stays, because the proxy needs the same
        // host to be reachable.
        let app = if paypal_enabled {
            app
        } else {
            app.layer(axum::middleware::from_fn(paypal_disabled_gate))
        };

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

        selfreport::stage("acme");
        let acme_mgr = InRamAcmeManager::new(&config);
        // One account for the whole boot (see `open_account`). A retry re-orders
        // on the SAME account instead of registering a new one, so a window of
        // refusals cannot snowball into the CA's per-account limits.
        let mut account: Option<std::sync::Arc<acme2_eab::Account>> = None;
        let mut attempt: u32 = 0;
        let cert_chain_pem = loop {
            attempt += 1;
            let outcome = match account.clone() {
                Some(acct) => acme_mgr.obtain_certificate_in_ram(&ephemeral_tls_key, &acct).await,
                None => match acme_mgr.open_account().await {
                    Ok(acct) => {
                        account = Some(acct.clone());
                        acme_mgr.obtain_certificate_in_ram(&ephemeral_tls_key, &acct).await
                    }
                    // Account registration itself failed: nothing to order on
                    // yet, so this is just another retry with the same policy.
                    Err(e) => Err(e),
                },
            };
            match outcome {
                Ok(chain) => {
                    info!("ACME certificate obtained in RAM successfully (attempt {}).", attempt);
                    break chain;
                }
                Err(e) => {
                    let reason = format!("acme attempt {}: {}", attempt, e);
                    // Jitter from the clock; a fresh randomness source per boot
                    // is not worth a dependency here.
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos())
                        .unwrap_or(0);
                    let retry_delay = acme_backoff(attempt, &e.to_string(), nanos as f64 / 1e9);
                    warn!("{} — retrying in {:?} (no self-signed fallback)...", reason, retry_delay);
                    // A retry loop serves NOTHING (no self-signed fallback), so
                    // this is the classic "Running + dark" state — publish it
                    // instead of leaving the operator to guess. Includes the
                    // usual `Cloudflare zone not found`, i.e. the reserved-EIP
                    // / token-scope failure. Attempts 1-3 and then every 10th,
                    // so a long window cannot flood the sink with one line per
                    // backoff round.
                    if attempt <= 3 || attempt % 10 == 0 {
                        selfreport::failure(reason);
                    }
                    selfreport::stage(&format!("acme-retry-{}", attempt));
                    tokio::time::sleep(retry_delay).await;
                }
            }
        };

        // Publish the key the certificate carries, and keep the private half:
        // the reported fingerprint is what a prover seals a code to, so the two
        // must be the same key object the listener uses.
        let tls_pubkey_pem = String::from_utf8_lossy(
            &ephemeral_tls_key
                .public_key_to_pem()
                .map_err(|e| format!("cannot export the TLS public key: {e}"))?,
        )
        .to_string();
        *state.tls_pubkey_pem.write() = Some(tls_pubkey_pem);
        *state.tls_private_key.write() = Some(ephemeral_tls_key.clone());

        // v225 (second seal slot): the user's nonce key. Independent of the
        // TLS key on purpose — two slots, two purposes, both named by every
        // report. Generated in the same RAM-only window as the TLS key, before
        // the listener can answer a single request, so no report can ever name
        // an empty slot.
        info!("Generating the second seal slot (user-nonce key, RAM ONLY)...");
        let seal_key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(4096)?)?;
        let seal_pubkey_pem = String::from_utf8_lossy(
            &seal_key
                .public_key_to_pem()
                .map_err(|e| format!("cannot export the seal-slot public key: {e}"))?,
        )
        .to_string();
        *state.seal_pubkey_pem.write() = Some(seal_pubkey_pem);
        *state.seal_private_key.write() = Some(seal_key);
        *state.tls_cert_pem.write() = Some(String::from_utf8_lossy(&cert_chain_pem).to_string());
        let ssl_acceptor = build_in_memory_ssl_acceptor(&cert_chain_pem, &ephemeral_tls_key)?;
        // v168 (plan Phase 4.1): config fetched + cert in RAM — IMDS, DNS and
        // port 80 have no legitimate user anymore. Lock egress down BEFORE
        // the first user session can carry plaintext anywhere.
        enclave_init::egress_lockdown();
        state.https_ready.store(true, Ordering::Relaxed);
        selfreport::stage("serving");
        selfreport::serving();

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

    fn proxy_config(services: &str) -> Config {
        serde_json::from_str(&format!(
            r#"{{"paypal_client_id":"id","paypal_client_secret":"sec",
                 "paypal_verified_client_id":"vid","paypal_verified_client_secret":"vsec",
                 "domain":"notary.example","services":{services}}}"#
        ))
        .expect("config parses")
    }

    /// The shutdown path must fire on a power button press and on nothing else.
    /// These frames are built the way the kernel builds them: `timeval`, then
    /// type, code and value as native-endian words.
    fn input_frame(ev_type: u16, code: u16, value: i32) -> Vec<u8> {
        let mut frame = vec![0u8; 24];
        frame[16..18].copy_from_slice(&ev_type.to_ne_bytes());
        frame[18..20].copy_from_slice(&code.to_ne_bytes());
        frame[20..24].copy_from_slice(&value.to_ne_bytes());
        frame
    }

    #[test]
    fn a_power_button_press_is_honoured() {
        assert!(enclave_init::is_power_press(&input_frame(
            enclave_init::EV_KEY,
            enclave_init::KEY_POWER,
            1
        )));
    }

    #[test]
    fn only_a_press_powers_the_machine_off() {
        // A release, a repeat, another key and another event type must all be
        // ignored: this gate is the difference between a shutdown and a VM that
        // powers itself off while serving a session.
        for (ev_type, code, value, why) in [
            (enclave_init::EV_KEY, enclave_init::KEY_POWER, 0, "release"),
            (enclave_init::EV_KEY, enclave_init::KEY_POWER, 2, "repeat"),
            (enclave_init::EV_KEY, 30, 1, "another key (KEY_A)"),
            (0x00, enclave_init::KEY_POWER, 1, "SYN_REPORT"),
            (0x04, enclave_init::KEY_POWER, 1, "MSC_SCAN"),
        ] {
            assert!(
                !enclave_init::is_power_press(&input_frame(ev_type, code, value)),
                "{why} must not power the machine off"
            );
        }
        // A partial frame is not an event at all.
        assert!(!enclave_init::is_power_press(&[0u8; 23]));
    }

    #[test]
    fn a_drain_waits_for_the_last_session_and_then_stops() {
        use enclave_init::{drain_step, DrainStep, DRAIN_BUDGET};
        use std::time::Duration;

        // Idle: power off at once, no waiting at all.
        assert_eq!(
            drain_step(0, Duration::ZERO, DRAIN_BUDGET),
            DrainStep::Done
        );
        // One session in flight and budget left: keep waiting, do not cut it.
        assert_eq!(
            drain_step(1, Duration::from_secs(5), DRAIN_BUDGET),
            DrainStep::Wait
        );
        // The last session finishing mid-drain is the point of the exercise:
        // the next poll sees zero and powers off.
        assert_eq!(
            drain_step(0, Duration::from_secs(5), DRAIN_BUDGET),
            DrainStep::Done
        );
    }

    /// A wedged session must not pin the instance open: the budget ends the wait
    /// and says how many sessions it abandoned.
    #[test]
    fn a_stuck_session_ends_the_drain_at_the_budget() {
        use enclave_init::{drain_step, DrainStep, DRAIN_BUDGET};
        use std::time::Duration;

        assert_eq!(
            drain_step(2, DRAIN_BUDGET, DRAIN_BUDGET),
            DrainStep::GiveUp(2)
        );
        assert_eq!(
            drain_step(1, DRAIN_BUDGET + Duration::from_secs(1), DRAIN_BUDGET),
            DrainStep::GiveUp(1)
        );
        // The budget is the proxy's own session timeout, so a session that
        // survives it is already dead rather than merely slow.
        assert_eq!(DRAIN_BUDGET, Duration::from_secs(120));
    }

    /// A whole graceful stop hung on this once: the drain runs on its own
    /// current-thread runtime, and that runtime was built with `enable_time()`
    /// only. The HTTP client then has no IO driver, the connect never completes,
    /// the worker parks, and the instance sits in `Stopping` until an operator
    /// force-stops it — with no console to say why. This test uses the
    /// production builder, so narrowing it back to timers fails here instead of
    /// on a hypervisor.
    #[test]
    fn the_drain_runtime_can_reach_the_loopback_api() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback server");
        listener.set_nonblocking(true).expect("non-blocking accept");
        let port = listener.local_addr().expect("address").port();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        );
                        return;
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });

        let rt = enclave_init::drain_runtime().expect("the drain runtime builds");
        let answered = rt.block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .expect("build a client");
            client
                .get(format!("http://127.0.0.1:{port}/health"))
                .send()
                .await
                .is_ok()
        });
        let _ = server.join();
        assert!(
            answered,
            "the drain runtime must be able to reach the loopback API"
        );
    }

    /// Relay targets are the proxy's egress boundary, and they are optional:
    /// absent must reproduce the PayPal-only-API behaviour exactly, so an
    /// existing config keeps working byte-for-byte.
    #[test]
    fn relay_targets_default_to_the_paypal_api_and_the_sandbox_site() {
        let config = proxy_config(r#"{"tls_proxy":{"enabled":true}}"#);
        let proxy = config.services.as_ref().and_then(|s| s.proxy()).expect("proxy on");
        assert_eq!(
            proxy.relay_targets,
            vec![
                "api-m.paypal.com".to_string(),
                "api-m.sandbox.paypal.com".to_string(),
                // The user-facing sandbox site, not just its API: a session
                // attests one TLS connection and does not follow the 301 from
                // sandbox.paypal.com to www.sandbox.paypal.com, so both names
                // have to be present for a person to attest a page there.
                "sandbox.paypal.com".to_string(),
                "www.sandbox.paypal.com".to_string(),
            ]
        );

        // An explicit list is taken as given — this is the feature: a notary
        // for something other than PayPal.
        let config = proxy_config(
            r#"{"tls_proxy":{"enabled":true,"relay_targets":["example.com","news.ycombinator.com"]}}"#,
        );
        let proxy = config.services.as_ref().and_then(|s| s.proxy()).expect("proxy on");
        assert_eq!(
            proxy.relay_targets,
            vec!["example.com".to_string(), "news.ycombinator.com".to_string()]
        );
    }

    /// Everything that is not a bare hostname is refused, because each entry
    /// becomes a /etc/hosts pin and a firewall rule: a scheme or a wildcard
    /// would either never match or quietly widen what the proxy can reach.
    #[test]
    fn relay_targets_refuse_anything_but_a_hostname_and_fail_the_boot() {
        for bad in [
            "",
            " example.com",
            "*",
            "*.example.com",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "localhost",
            "a..b",
            "-bad.example.com",
        ] {
            assert!(validate_relay_target(bad).is_err(), "{bad:?} must be rejected");
        }
        for good in ["api-m.paypal.com", "example.co.uk", "a-b.example", "127.0.0.1"] {
            assert!(validate_relay_target(good).is_ok(), "{good:?} must be accepted");
        }

        // A literal is allowed (it opens 443 without needing DNS) but it is not
        // committable: tlsn rejects an IP as a server name, so the useful form
        // for a fixed address is host@address.
        assert!(enclave_init::relay_target_is_literal("151.101.195.1"));
        assert!(!enclave_init::relay_target_is_literal("sandbox.paypal.com"));
        assert!(
            validate_relay_target("::1").is_err(),
            "IPv6 is refused: the egress rule matches `ip daddr` only"
        );

        // host@address: pinned instead of resolved, for a host whose DNS rotates.
        assert!(validate_relay_target("www.sandbox.paypal.com@151.101.195.1").is_ok());
        for bad in [
            "www.sandbox.paypal.com@",
            "@151.101.195.1",
            "www.sandbox.paypal.com@not-an-address",
            "www.sandbox.paypal.com@::1",
            "151.101.195.1@151.101.195.1",
            "a@b@c",
        ] {
            assert!(
                validate_relay_target(bad).is_err(),
                "{bad:?} must be rejected — the left side is a hostname, the right an IPv4 address"
            );
        }

        assert!(validate_relay_targets(&[]).is_err(), "an empty list serves nothing");
        assert!(
            validate_relay_targets(&["example.com".into(), "EXAMPLE.com".into()]).is_err(),
            "DNS is case-insensitive, so these collide in /etc/hosts"
        );
        let too_many: Vec<String> = (0..MAX_RELAY_TARGETS + 1)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        assert!(validate_relay_targets(&too_many).is_err());

        // And the hook is real: a bad list must stop the boot, not warn.
        let config = proxy_config(r#"{"tls_proxy":{"enabled":true,"relay_targets":["https://example.com"]}}"#);
        let err = require_credentials(config).expect_err("a URL target must fail closed");
        assert!(err.to_string().contains("relay_targets"), "{err}");

        // A disabled proxy is not validated away: nothing is pinned, so a list
        // that would never be used must not block a PayPal-only boot.
        let config = proxy_config(r#"{"tls_proxy":{"enabled":false,"relay_targets":[]}}"#);
        assert!(require_credentials(config).is_ok());
    }

    /// `/proxy/refusals` is the only path by which a refusal reason reaches the
    /// internet, so its redaction is pinned here: committed hosts get a stable
    /// fingerprint (repeated attempts still correlate), dotted numbers and
    /// versions are left alone, and no hostname survives in the output.
    #[test]
    fn public_refusal_view_fingerprints_committed_hosts() {
        let reason = "revealed server name api-m.paypal.com does not match the committed api-m.sandbox.paypal.com";
        let redacted = fingerprint_hosts(reason);
        assert!(!redacted.contains("paypal.com"), "host leaked: {redacted}");
        assert_eq!(redacted.matches("host:").count(), 2, "{redacted}");
        assert_eq!(
            redacted,
            fingerprint_hosts(reason),
            "the fingerprint must be stable across reads"
        );
        assert_ne!(
            fingerprint_hosts("api-m.paypal.com"),
            fingerprint_hosts("api-m.sandbox.paypal.com"),
            "different hosts must not collapse into one fingerprint"
        );

        // Things that only look dotted must survive verbatim, or the reason
        // stops being diagnostic (byte bounds, versions, the service tag).
        for untouched in [
            "transcript is 9000 bytes, over the 8388608-byte bound",
            "no verdict within 120s",
            "1.99.0",
            "tls-proxy/1",
            "prover requested MPC mode; proxy mode only",
        ] {
            assert_eq!(fingerprint_hosts(untouched), untouched, "{untouched}");
        }

        // Punctuation around a host is preserved, the host itself is not.
        let bracketed = fingerprint_hosts("(example.co.uk).");
        assert!(bracketed.starts_with("(host:") && bracketed.ends_with(")."), "{bracketed}");
    }

    /// `/proxy/attestations` relays the child's list, and the host each session
    /// is about must not leave the VM — the same rule `/proxy/refusals`
    /// enforces. What an operator still gets: the id, the time, and a
    /// fingerprint that lines up with the refusal ring.
    #[test]
    fn attestation_list_never_names_the_host() {
        let mut list = serde_json::json!({
            "count": 2,
            "sessions": [
                {"session_id": "aa", "server_name": "api-m.sandbox.paypal.com", "notarized_at": 1},
                {"session_id": "bb", "server_name": "news.ycombinator.com", "notarized_at": 2}
            ]
        });
        redact_attestation_hosts(&mut list);

        let sessions = list["sessions"].as_array().unwrap();
        let first = sessions[0]["server_name"].as_str().unwrap();
        assert_eq!(
            first,
            fingerprint_hosts("api-m.sandbox.paypal.com"),
            "the list must use the refusal ring's fingerprint, not its own scheme"
        );
        assert!(first.starts_with("host:"), "{first}");
        // The exact token the live origin answered for this host after v217b.
        // Pinned as a literal so a change in the prefix width, the hash or the
        // case is caught here rather than by an auditor comparing the two
        // public documents and finding they no longer agree.
        assert_eq!(fingerprint_hosts("www.sandbox.paypal.com"), "host:0a191a6a");
        assert!(!list.to_string().contains("paypal"), "{list}");
        assert!(!list.to_string().contains("ycombinator"), "{list}");
        // The fields an operator is actually looking for survive untouched.
        assert_eq!(sessions[0]["session_id"], "aa");
        assert_eq!(sessions[1]["notarized_at"], 2);
        assert_eq!(list["count"], 2);
    }

    /// The two public relays are one contract: the same envelope when the child
    /// is missing or unreadable, and the same fingerprint when a host is
    /// redacted. Nothing else pins that down, and drift here is silent — a route
    /// that started answering a bare `{}` on 503, or redacted with a second
    /// scheme, still looks fine in a browser.
    #[test]
    fn proxy_relays_share_one_redaction_and_envelope() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let read = |resp: axum::response::Response| {
            rt.block_on(axum::body::to_bytes(resp.into_body(), 1 << 20))
                .expect("body")
        };

        // 1. No proxy on this boot: both relays answer the same 404, so an
        //    operator cannot get two different stories depending on the route.
        let refusals = rt.block_on(proxy_refusals());
        let attestations = rt.block_on(proxy_attestations());
        assert_eq!(refusals.status(), axum::http::StatusCode::NOT_FOUND);
        assert_eq!(refusals.status(), attestations.status());
        let refusals_body = read(refusals);
        let attestations_body = read(attestations);
        assert_eq!(
            refusals_body, attestations_body,
            "both relays must answer an unconfigured proxy identically"
        );
        let absent: serde_json::Value = serde_json::from_slice(&refusals_body).unwrap();
        assert_eq!(absent["service"], "tls-proxy");
        assert_eq!(absent["enabled"], false);

        // 2. Every failure path answers the same envelope, and keeps its status:
        //    the shape is what a reader parses, the code is what tells them
        //    whether the child is down (503) or unreachable (502/500).
        for (code, detail) in [
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "child is not running",
            ),
            (
                axum::http::StatusCode::BAD_GATEWAY,
                "loopback API unreachable: connection refused",
            ),
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "cannot build the loopback client: tls backend",
            ),
        ] {
            let resp = proxy_unavailable(code, serde_json::json!(detail));
            assert_eq!(resp.status(), code);
            let body: serde_json::Value = serde_json::from_slice(&read(resp)).unwrap();
            assert_eq!(body["service"], "tls-proxy");
            assert_eq!(body["enabled"], true);
            assert_eq!(body["running"], false);
            assert_eq!(body["last"], detail);
            let mut keys: Vec<&str> = body
                .as_object()
                .expect("object")
                .keys()
                .map(|k| k.as_str())
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, ["enabled", "last", "running", "service"]);
        }

        // 3. One fetch path serves both routes, so there is one timeout, one
        //    JSON parse and one mapping from the child's answers to ours.
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let app = axum::Router::new()
                .route(
                    "/refusals",
                    axum::routing::get(|| async {
                        axum::Json(serde_json::json!({"refusals": []}))
                    }),
                )
                .route(
                    "/attestations",
                    axum::routing::get(|| async {
                        axum::Json(serde_json::json!({"count": 0, "sessions": []}))
                    }),
                )
                .route(
                    "/boom",
                    axum::routing::get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
                );
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

            let refusals = proxy_loopback_json("refusals", port, "/refusals")
                .await
                .expect("refusal ring");
            assert_eq!(refusals["refusals"], serde_json::json!([]));
            let attestations = proxy_loopback_json("attestations", port, "/attestations")
                .await
                .expect("attestation list");
            assert_eq!(attestations["count"], 0);

            let (code, detail) = proxy_loopback_json("attestations", port, "/boom")
                .await
                .expect_err("a failing child is an error, not a body");
            assert_eq!(code, axum::http::StatusCode::BAD_GATEWAY);
            assert!(detail.contains("500"), "{detail}");

            // A closed port: the port is real but nothing listens on it, which
            // is what a child that died after the liveness check looks like.
            let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dead_port = dead.local_addr().unwrap().port();
            drop(dead);
            let (code, detail) = proxy_loopback_json("refusals", dead_port, "/refusals")
                .await
                .expect_err("a dead child is an error");
            assert_eq!(code, axum::http::StatusCode::BAD_GATEWAY);
            assert!(detail.starts_with("loopback API unreachable"), "{detail}");

            server.abort();
        });

        // 4. Same redaction: one host, two documents, one token.
        let host = "api-m.sandbox.paypal.com";
        let mut refused = serde_json::json!({
            "refusals": [{
                "at": 1,
                "kind": "rejected",
                "reason": format!("refused {host}: committed name mismatch"),
            }]
        });
        redact_refusal_reasons(&mut refused);
        let mut attested = serde_json::json!({
            "count": 1,
            "sessions": [{"session_id": "aa", "server_name": host, "notarized_at": 1}]
        });
        redact_attestation_hosts(&mut attested);

        let session_token = attested["sessions"][0]["server_name"]
            .as_str()
            .unwrap()
            .to_string();
        let reason = refused["refusals"][0]["reason"].as_str().unwrap();
        assert_eq!(session_token, fingerprint_hosts(host));
        assert!(
            reason.contains(&session_token),
            "both documents must show the same token for the same host: {reason}"
        );
        assert!(!refused.to_string().contains(host));
        assert!(!attested.to_string().contains(host));
    }

    /// v223: what a prover seals to is what the report names. A code sealed to
    /// the reported TLS key must open here, and only with that boot's key.
    #[test]
    fn a_code_sealed_to_the_reported_key_opens_and_a_foreign_key_does_not() {
        use base64::Engine as _;
        use openssl::rsa::Padding;

        let key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let pem = String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();

        let seal = |pem: &str, code: &str| -> String {
            let pubkey = openssl::pkey::PKey::public_key_from_pem(pem.as_bytes()).unwrap();
            let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&pubkey).unwrap();
            ctx.encrypt_init().unwrap();
            ctx.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
            ctx.set_rsa_oaep_md(openssl::md::Md::sha256()).unwrap();
            ctx.set_rsa_mgf1_md(openssl::md::Md::sha256()).unwrap();
            let mut out = vec![0u8; pubkey.size() as usize];
            let n = ctx.encrypt("A1b2C3-the-paypal-code".as_bytes(), Some(&mut out)).unwrap();
            out.truncate(n);
            let _ = code;
            base64::engine::general_purpose::STANDARD.encode(out)
        };

        // The report's fingerprint names this key and nothing else.
        assert_eq!(pubkey_fingerprint(&pem).len(), 64);
        assert_eq!(pubkey_fingerprint(&pem), pubkey_fingerprint(&pem));
        assert_ne!(pubkey_fingerprint(&pem), pubkey_fingerprint("not a key"));

        let sealed = seal(&pem, "A1b2C3-the-paypal-code");
        assert_eq!(
            rsa_oaep_open(&key, &sealed, "code").unwrap(),
            "A1b2C3-the-paypal-code"
        );

        // A different boot's key cannot open it — the whole point of sealing.
        let other = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        assert!(rsa_oaep_open(&other, &sealed, "code").is_err());

        // Junk, wrong-size, and tampered seals fail closed, never silently.
        assert!(rsa_oaep_open(&key, "not base64!!", "code").is_err());
        assert!(rsa_oaep_open(&key, "AAAA", "code").is_err());
        let mut tampered = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        tampered[10] ^= 0x01;
        assert!(rsa_oaep_open(
            &key,
            &base64::engine::general_purpose::STANDARD.encode(tampered),
            "code"
        )
        .is_err());
    }

    /// v225: the `nonce` slot is a different key from the `code` slot, so a
    /// value sealed for one purpose must not open with the other's key — the
    /// two slots are independent or they are not slots at all.
    #[test]
    fn the_two_seal_slots_do_not_interchange() {
        use base64::Engine as _;
        use openssl::rsa::Padding;

        let code_key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let nonce_key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let seal_to = |key: &openssl::pkey::PKey<openssl::pkey::Private>, msg: &str| -> String {
            let pubkey = openssl::pkey::PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();
            let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&pubkey).unwrap();
            ctx.encrypt_init().unwrap();
            ctx.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
            ctx.set_rsa_oaep_md(openssl::md::Md::sha256()).unwrap();
            ctx.set_rsa_mgf1_md(openssl::md::Md::sha256()).unwrap();
            let mut out = vec![0u8; pubkey.size() as usize];
            let n = ctx.encrypt(msg.as_bytes(), Some(&mut out)).unwrap();
            out.truncate(n);
            base64::engine::general_purpose::STANDARD.encode(out)
        };

        // Each slot opens its own seal...
        assert_eq!(rsa_oaep_open(&nonce_key, &seal_to(&nonce_key, "my-nonce-42"), "nonce").unwrap(), "my-nonce-42");
        assert_eq!(rsa_oaep_open(&code_key, &seal_to(&code_key, "A1b2C3"), "code").unwrap(), "A1b2C3");
        // ...and refuses the other slot's, in both directions.
        assert!(rsa_oaep_open(&code_key, &seal_to(&nonce_key, "my-nonce-42"), "nonce").is_err());
        assert!(rsa_oaep_open(&nonce_key, &seal_to(&code_key, "A1b2C3"), "code").is_err());
        // The refusal names the slot it actually tried: an interchange bug must
        // not read as "TLS key" on a request that never touched the TLS key.
        let err = rsa_oaep_open(&code_key, &seal_to(&nonce_key, "x"), "nonce").unwrap_err();
        assert!(err.contains("sealed nonce") && err.contains("nonce key"), "{err}");
        let err = rsa_oaep_open(&nonce_key, &seal_to(&code_key, "x"), "code").unwrap_err();
        assert!(err.contains("sealed code") && err.contains("TLS key"), "{err}");

        // The plaintext becomes a signed report field, so it is bounded and
        // canonicalised exactly like custom_info.
        assert_eq!(canonical_custom_info("  my-nonce-42 ").unwrap(), "my-nonce-42");
        assert_eq!(canonical_custom_info("").unwrap(), "NONE");
        assert!(canonical_custom_info(&"x".repeat(513)).is_none());
    }

    /// v225: `redirect_uri` decides who receives the PayPal code, so the only
    /// values the enclave may use are exact allowlist entries with an https
    /// scheme and nothing that can change the target (query, fragment,
    /// userinfo, whitespace).
    #[test]
    fn redirect_uris_are_https_exact_and_allowlisted() {
        let ours = "https://login.example.com/callback".to_string();
        let page = "https://user.example.org/audit/verify.html".to_string();
        let allowed = vec![ours.clone(), page.clone()];

        assert_eq!(normalize_redirect_uri(&format!("  {page}  ")), Some(page.clone()));
        assert!(redirect_uri_allowed(&allowed, &page));
        // Exact match only: one extra character is a different origin target.
        assert!(!redirect_uri_allowed(&allowed, &format!("{page}/")));
        assert!(!redirect_uri_allowed(&allowed, "https://user.example.org/audit/verify.html?x=1"));
        assert!(!redirect_uri_allowed(&allowed, "https://evil.example/audit/verify.html"));

        // Anything that is not a plain https URL is refused outright.
        for bad in [
            "http://user.example.org/audit/verify.html",
            "file:///tmp/verify.html",
            "user.example.org/audit",
            "https://",
            "https:///path",
            "https://user.example.org/a?b=c",
            "https://user.example.org/a#frag",
            "https://user:pw@user.example.org/a",
            "https://user.example.org/a b",
            "",
        ] {
            assert!(normalize_redirect_uri(bad).is_none(), "must refuse {bad:?}");
        }
        assert!(normalize_redirect_uri(&format!("https://{}/", "x".repeat(600))).is_none());
    }

    /// The download route's two guards, pinned directly: a digest that is not
    /// 32 bytes of hex is not a digest, and an id that is not the notary's
    /// 16-byte hex session id is not an id. Both are refused before any child
    /// call, so a malformed request cannot even probe which sessions exist.
    #[test]
    fn download_guards_are_width_and_hex_only() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(is_hex64(&"0123456789abcdef".repeat(4)));
        assert!(!is_hex64(&"a".repeat(63)));
        assert!(!is_hex64(&"a".repeat(65)));
        assert!(!is_hex64(&"g".repeat(64)));
        assert!(!is_hex64(""));
        assert!(is_hex32("40fdf777e52ecea2bc5e13f74de30bb3"));
        assert!(!is_hex32("../../etc/passwd"));
        assert!(!is_hex32(&"a".repeat(64)));
    }

    /// The public download relays the child's bytes **verbatim**. This is the
    /// v221 failure mode one layer up: a JSON round-trip here would re-order
    /// the signed fields and hand the prover a record that cannot verify.
    #[test]
    fn download_relay_does_not_reorder_signed_bytes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");

        // Deliberately not alphabetical: `version` first is the signed order.
        let signed = concat!(
            r#"{"version":"tls-proxy/1","session_id":"aa","server_name":"example.com","#,
            r#""notarized_at":1,"sent_len":3,"received_len":4,"#,
            r#""sent_sha256":"00","received_sha256":"00","#,
            r#""sent_b64":"R0VU","received_b64":"T0s=","truncated":false,"#,
            r#""enclave_pubkey_pem":"pem","signature_alg":"RSA-PKCS1-v1_5-SHA256","#,
            r#""signature_b64":"sig"}"#
        );

        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let body = signed.to_string();
            let app = axum::Router::new().route(
                "/attestations/{id}",
                axum::routing::get(move |axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let body = body.clone();
                    async move {
                        // Mirrors the child: a matching pair is served, anything
                        // else is the same 404 the prover must not be able to
                        // use as an oracle.
                        if q.get("sent_sha256").map(String::as_str) == Some(&"a".repeat(64))
                            && q.get("received_sha256").map(String::as_str) == Some(&"b".repeat(64))
                        {
                            (axum::http::StatusCode::OK, body)
                        } else {
                            (
                                axum::http::StatusCode::NOT_FOUND,
                                "{\"error\":\"no such attestation in this boot\"}".to_string(),
                            )
                        }
                    }
                }),
            );
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

            let ok = format!(
                "/attestations/aa?sent_sha256={}&received_sha256={}",
                "a".repeat(64),
                "b".repeat(64)
            );
            let (status, text) = proxy_loopback_text("attestations", port, &ok)
                .await
                .expect("loopback");
            assert_eq!(status, 200);
            assert_eq!(text, signed, "the relay must not parse or re-encode");
            assert!(text.starts_with("{\"version\""), "signed order, not alphabetical");

            let (status, _) = proxy_loopback_text("attestations", port, "/attestations/aa?sent_sha256=0&received_sha256=0")
                .await
                .expect("loopback");
            assert_eq!(status, 404, "a mismatch is relayed as a 404, not a body");

            server.abort();
        });
    }

    /// Without a proxy on this boot the download route is a 404 with the child's
    /// own absence envelope — not a 500 and not a leaked path.
    #[test]
    fn download_answers_404_when_no_proxy_is_configured() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let resp = rt.block_on(proxy_attestation_download(
            AxumPath("40fdf777e52ecea2bc5e13f74de30bb3".to_string()),
            Query(AttestationDownloadQuery {
                sent_sha256: Some("a".repeat(64)),
                received_sha256: Some("b".repeat(64)),
            }),
        ));
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let body = rt
            .block_on(axum::body::to_bytes(resp.into_body(), 1 << 20))
            .expect("body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["error"], "no such attestation in this boot");
        assert_eq!(parsed["session_id"], "40fdf777e52ecea2bc5e13f74de30bb3");
    }

    /// A record with no host (or a shape the child changed) must not panic the
    /// public route: redaction is best-effort, and a missing field stays missing.
    #[test]
    fn attestation_redaction_tolerates_odd_records() {
        let mut list = serde_json::json!({
            "count": 2,
            "sessions": [{"session_id": "cc"}, {"session_id": "dd", "server_name": null}]
        });
        redact_attestation_hosts(&mut list);
        assert_eq!(list["sessions"][0]["session_id"], "cc");
        assert!(list["sessions"][1]["server_name"].is_null());

        // Not a list at all: left alone rather than replaced.
        let mut odd = serde_json::json!({"error": "no such attestation in this boot"});
        redact_attestation_hosts(&mut odd);
        assert_eq!(odd["error"], "no such attestation in this boot");
    }

    /// v169 (audit finding: identity preimage binding). verify.html recomputes
    /// SHA-256(JSON.stringify(paypal_user_info)) and requires it to equal the
    /// hash bound into the quote's report_data. That only works if the enclave
    /// serializes the minimized identity in exactly this byte layout — field
    /// order, nulls kept, compact. Pin it (and the digest) here so any change
    /// to PayPalUserInfo or its serde attributes breaks THIS test instead of
    /// silently bricking every honest login audit.
    #[test]
    fn paypal_identity_json_layout_pinned() {
        use sha2::{Digest, Sha256};
        let u = PayPalUserInfo {
            user_id: "U1".into(),
            sub: None,
            verified_account: Some("true".into()),
            payer_id: None,
        };
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(
            json,
            r#"{"user_id":"U1","sub":null,"verified_account":"true","payer_id":null}"#,
            "minimized-identity JSON layout drifted — verify.html hashes JSON.stringify() of this, so they MUST match"
        );
        assert_eq!(
            hex::encode(Sha256::digest(json.as_bytes())),
            "b66320f7fe060efa71cdd8bc7fed8a2e9d873b78aff6e5747d14326f7bf4429f",
            "identity digest drifted from the auditor's vector"
        );
    }

    /// The pre-login placeholder is part of the binding contract too: auditors
    /// REQUIRE it for envelopes with no user record (v169), so its value is a
    /// wire constant both sides must agree on.
    #[test]
    fn prelogin_placeholder_hash_pinned() {
        assert_eq!(
            crate::prelogin_paypal_hash(),
            "703d1ea4a5131eef7089ca7c41d877ba32df741a7f24ab3d580e56f297c2fb52"
        );
    }

    /// v199 — the egress caps are a COST control, priced against the provider
    /// this deployment actually runs on: a PayByTraffic BGP EIP in cn-beijing
    /// bills ¥0.80 per GB of EGRESS (inbound is free) hourly, on a purchased
    /// 5 Mbps peak. Pin the arithmetic so a casual tweak cannot silently turn
    /// the ¥30/month ceiling into an unbounded one — and so the application
    /// cap can never rise above what the line can physically push, which would
    /// make the 429 gate unreachable and the DoS bill open again.
    #[test]
    fn egress_budget_matches_alibaba_price_v199() {
        const BYTES_PER_GB: f64 = 1024.0 * 1024.0 * 1024.0;
        const PRICE_CNY_PER_GB: f64 = 0.80; // cn-beijing BGP, PayByTraffic
        const HOURS_PER_MONTH: f64 = 730.0; // Alibaba settles hourly
        // Purchased peak: 5 Mbps (DescribeEipAddresses → Bandwidth: "5").
        const LINE_RATE_BYTES_PER_HOUR: f64 = 5_000_000.0 / 8.0 * 3600.0;

        let monthly_gb = GLOBAL_EGRESS_BYTES_PER_HOUR as f64 * HOURS_PER_MONTH / BYTES_PER_GB;
        let monthly_cny = monthly_gb * PRICE_CNY_PER_GB;
        assert!(
            (29.0..=31.0).contains(&monthly_cny),
            "global egress cap now costs ¥{monthly_cny:.2}/month at ¥0.80/GB — expected the ¥30 ceiling"
        );

        let ip_monthly_cny = IP_EGRESS_BYTES_PER_HOUR as f64 * HOURS_PER_MONTH / BYTES_PER_GB * PRICE_CNY_PER_GB;
        assert!(
            ip_monthly_cny <= 3.0,
            "one client can now burn ¥{ip_monthly_cny:.2}/month — the per-IP share must stay within ¥3"
        );
        assert!(
            IP_EGRESS_BYTES_PER_HOUR * EGRESS_IP_SHARE_DIVISOR <= GLOBAL_EGRESS_BYTES_PER_HOUR,
            "per-IP cap must be a strict share of the global window"
        );
        assert!(
            (GLOBAL_EGRESS_BYTES_PER_HOUR as f64) < LINE_RATE_BYTES_PER_HOUR,
            "global cap exceeds the 5 Mbps line rate — the 429 gate would be unreachable"
        );
        // The enforcement window must match Alibaba's billing period (hourly),
        // so no cap crossing can accumulate inside one billable hour — and the
        // two inputs are what the budget arithmetic above is derived from:
        // changing either one requires re-pricing against the EIP price table.
        assert_eq!(
            EGRESS_BUDGET_CNY_PER_MONTH_TENTHS,
            300,
            "monthly egress budget changed — re-price it against ¥0.80/GB before merging"
        );
        assert_eq!(
            EGRESS_PRICE_CNY_PER_GB_TENTHS,
            8,
            "the cn-beijing BGP PayByTraffic unit price changed — re-check help.aliyun.com/zh/eip/pay-as-you-go"
        );
        assert_eq!(EGRESS_BILLING_HOURS_PER_MONTH, 730, "Alibaba settles traffic fees hourly");
    }

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
            self_report: None,
            services: None,
            seal_redirect_uris: Vec::new(),
        };
        assert!(require_credentials(bad).is_err());
    }

    /// The service switch is fail-closed in both directions, so both directions
    /// are pinned: a proxy-only enclave must boot without a PayPal app (there is
    /// none to configure), and a configuration that would serve nothing must be
    /// refused rather than starting an enclave with no listeners.
    #[test]
    fn proxy_only_services_do_not_require_paypal_credentials() {
        let cfg = Config {
            paypal_client_id: String::new(),
            paypal_client_secret: String::new(),
            paypal_verified_client_id: None,
            paypal_verified_client_secret: None,
            domain: String::new(),
            eab_key_id: None,
            eab_hmac_key: None,
            staging: false,
            dns_api_token: None,
            dns_zone: None,
            self_report: None,
            services: Some(Services {
                paypal: false,
                tls_proxy: Some(TlsProxyConfig {
                    enabled: true,
                    session_port: 8443,
                    api_port: 8081,
                    session_timeout_secs: 120,
                    signing_key_pem: None,
                    relay_targets: proxy_default_relay_targets(),
                    restart_token: None,
                }),
            }),
            seal_redirect_uris: Vec::new(),
        };
        assert!(require_credentials(cfg).is_ok());
    }

    #[test]
    fn services_that_would_serve_nothing_are_refused() {
        let cfg = Config {
            paypal_client_id: String::new(),
            paypal_client_secret: String::new(),
            paypal_verified_client_id: None,
            paypal_verified_client_secret: None,
            domain: String::new(),
            eab_key_id: None,
            eab_hmac_key: None,
            staging: false,
            dns_api_token: None,
            dns_zone: None,
            self_report: None,
            services: Some(Services {
                paypal: false,
                tls_proxy: None,
            }),
            seal_redirect_uris: Vec::new(),
        };
        assert!(require_credentials(cfg).is_err());
    }

    /// Defaults must reproduce the pre-existing deployment exactly: no
    /// `services` block means PayPal on and no proxy process.
    #[test]
    fn absent_services_means_paypal_only() {
        let services = Services {
            paypal: true,
            tls_proxy: None,
        };
        assert!(services.paypal);
        assert!(services.proxy().is_none());
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

    // =====================================================================
    // v168 (independent security audit): CROSS-IMPLEMENTATION PARITY
    // VECTORS. Every hardware-bound formula lives in THREE places — the
    // enclave (here), verify.html (JS mirror) and scripts/test-verify-security.mjs
    // (independent reference). These golden vectors (shared with the JS
    // harness and scripts/calculate-golden-rtmr.mjs --selftest) pin all
    // three to identical bytes; drift in any one fails the suite.
    // =====================================================================

    /// v232: a CA refusal must be waited out, a transient error retried fast.
    /// Getting this backwards is what turns a 30-second DNS hiccup into a
    /// half-hour dark instance (or a rate limit into a retry storm).
    #[test]
    fn acme_backoff_separates_refusals_from_hiccups() {
        use super::acme_backoff;
        let secs = |d: std::time::Duration| d.as_secs();

        // Plain failures: 10 s doubling, capped at 120 s, jitter < 1/4.
        assert_eq!(secs(acme_backoff(1, "dns error: NXDOMAIN", 0.0)), 10);
        assert_eq!(secs(acme_backoff(2, "connection reset", 0.0)), 20);
        assert_eq!(secs(acme_backoff(4, "http 503", 0.0)), 80);
        assert_eq!(secs(acme_backoff(9, "http 503", 0.0)), 120);
        assert_eq!(secs(acme_backoff(50, "http 503", 0.0)), 120);

        // Rate limits / duplicate-certificate refusals: minutes, not seconds,
        // and a much higher ceiling.
        for refusal in [
            "urn:ietf:params:acme:error:rateLimited",
            "too many certificates already issued",
            "duplicate certificate",
            "Retry after 2026-11-10T05:00:00Z",
        ] {
            assert!(secs(acme_backoff(1, refusal, 0.0)) >= 300, "{refusal}");
            assert!(secs(acme_backoff(6, refusal, 0.0)) >= 1800, "{refusal}");
        }
        assert_eq!(secs(acme_backoff(9, "rateLimited", 0.0)), 1800);

        // Jitter is bounded and never negative, whatever the caller passes.
        for attempt in 1..=8 {
            for jitter in [0.0, 0.5, 0.999] {
                let d = secs(acme_backoff(attempt, "http 503", jitter));
                let base = secs(acme_backoff(attempt, "http 503", 0.0));
                assert!(d >= base && d <= base + base / 4, "{attempt} {jitter} {d} {base}");
            }
            assert_eq!(secs(acme_backoff(attempt, "x", -1.0)), secs(acme_backoff(attempt, "x", 0.0)));
        }
    }

    /// v232: the 15-minute envelope cache is invalidated by a notary restart,
    /// and ONLY by that — a notary that cannot be reached must not turn every
    /// request into a TD-quote mint.
    #[test]
    fn envelope_cache_follows_the_notary_key() {
        use super::envelope_cache_fresh;
        use std::time::{Duration, Instant};

        let now = Instant::now();
        let old = now - Duration::from_secs(901);
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);

        // Fresh while young and the key still matches.
        assert!(envelope_cache_fresh(now, &a, Some(&a)));
        assert!(envelope_cache_fresh(now, "", Some("")));

        // A restarted notary (new key) invalidates immediately, both ways.
        assert!(!envelope_cache_fresh(now, &a, Some(&b)));
        assert!(!envelope_cache_fresh(now, "", Some(&a)));
        assert!(!envelope_cache_fresh(now, &a, Some("")));

        // An unreachable notary keeps the cache: no new key can exist.
        assert!(envelope_cache_fresh(now, &a, None));
        assert!(envelope_cache_fresh(now, "", None));

        // Window expiry wins over everything.
        assert!(!envelope_cache_fresh(old, &a, Some(&a)));
        assert!(!envelope_cache_fresh(old, &a, None));
    }

    /// v233: `/proxy/restart` is a control surface, so the gate is pinned: no
    /// token configured = no route (404), and an empty or wrong token never
    /// matches, in either direction.
    #[test]
    fn proxy_restart_requires_the_configured_token() {
        use super::restart_token_ok;

        assert!(restart_token_ok(Some("s3cret-token"), Some("s3cret-token")));

        // Unconfigured: the route does not exist, whatever the caller sends.
        assert!(!restart_token_ok(None, Some("s3cret-token")));
        assert!(!restart_token_ok(None, None));
        // Configured but nothing presented, or the empty string either way.
        assert!(!restart_token_ok(Some("s3cret-token"), None));
        assert!(!restart_token_ok(Some(""), Some("")));
        assert!(!restart_token_ok(Some("s3cret-token"), Some("")));
        // Near misses, including a prefix and a case change.
        assert!(!restart_token_ok(Some("s3cret-token"), Some("s3cret-toke")));
        assert!(!restart_token_ok(Some("s3cret-token"), Some("s3cret-token ")));
        assert!(!restart_token_ok(Some("s3cret-token"), Some("S3CRET-TOKEN")));
    }

    #[test]
    fn sec02_nonce_parity_v168() {
        use sha2::{Digest, Sha256};
        let paypal_hash = hex::encode(Sha256::digest(br#"{"sub":"user"}"#));
        let mut manifest = std::collections::BTreeMap::new();
        manifest.insert("EFI/BOOT/vmlinuz".to_string(), "cc".repeat(32));
        manifest.insert("EFI/BOOT/initrd.img".to_string(), "dd".repeat(32));
        let nonce = sec02_nonce(&paypal_hash, b"fake-der-bytes", "walletA", &"ab".repeat(32), &manifest);
        assert_eq!(
            hex::encode(nonce),
            "398c2c1b18583ac9c3935ffdea04f0b2a3dfdd927140072bd50511e9f77db8f7",
            "SEC-02 session-nonce formula drifted — update Rust + verify.html + harness together"
        );
    }

    /// v179 (plan Phase 1 — session substitution): the callback quote's
    /// report_data[32..64] is SHA-256(P_client SPKI-DER ∥ Nonce_client).
    /// Same golden vector as verify.html `clientSessionBindingHex()` and the
    /// JS harness — all three implementations must agree byte-for-byte.
    #[test]
    fn client_session_binding_parity_v179() {
        let binding = client_session_binding(b"test-client-pub-der", &[0x7f; 32]);
        assert_eq!(
            hex::encode(binding),
            "4809a12bd741f4ecc332722e5c89dc43e2d93e2ade15a974206d0bcf1f038ddb",
            "client-session binding formula drifted — update Rust + verify.html + harness together"
        );
    }

    /// v186 (audit round 5): `custom_info` is capped at 512 BYTES on BOTH
    /// ends of the state round-trip (login-session request → state token →
    /// /callback), matching verify.html's client-side TextEncoder byte
    /// check. The cap is what keeps the signed response and the vault blob
    /// inside their egress-budget charges — the field used to be accepted
    /// unbounded while the request was charged 4 KiB (a ~256x budget-bypass
    /// amplification surface under the collusion/DoS model).
    #[test]
    fn custom_info_512_byte_cap_v186() {
        assert_eq!(canonical_custom_info("  hello  ").as_deref(), Some("hello"));
        assert_eq!(canonical_custom_info("").as_deref(), Some("NONE"));
        assert_eq!(canonical_custom_info("   ").as_deref(), Some("NONE"));
        assert_eq!(canonical_custom_info("NONE").as_deref(), Some("NONE"));
        assert_eq!(canonical_custom_info(&"x".repeat(512)).map(|s| s.len()), Some(512));
        assert_eq!(canonical_custom_info(&"x".repeat(513)), None, "513 bytes must be rejected");
        // multibyte counts as BYTES, exactly like the auditor's TextEncoder check
        assert_eq!(canonical_custom_info(&"é".repeat(256)).map(|s| s.len()), Some(512));
        assert!(canonical_custom_info(&"é".repeat(257)).is_none(), "514 bytes must be rejected");

        // Source pin: BOTH handlers must route through the shared cap.
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
            .expect("src/main.rs must be readable");
        assert!(
            src.contains("canonical_custom_info(payload.custom_info.as_deref().unwrap_or(\"\"))"),
            "/attest/login-session must enforce the 512-byte custom_info cap"
        );
        assert!(
            src.contains("canonical_custom_info(st.get(\"c\")"),
            "/callback must enforce the 512-byte custom_info cap on the untrusted state token"
        );
    }

    /// v179 (plan Phase 4 — host egress defense): the kernel-hardening block
    /// must keep every protection the plan requires — swap off (fail closed),
    /// kexec disabled, suid dumps off, core dumps off. Source-level pin in the
    /// style of cmdline_pin_matches_build_script.
    #[test]
    fn kernel_hardening_covers_plan_phase4_v179() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
            .expect("src/main.rs must be readable");
        let body = src
            .split("pub fn harden_kernel()")
            .nth(1)
            .and_then(|s| s.split("\n    pub fn ").next())
            .expect("harden_kernel() body must exist");
        for (needle, why) in [
            ("swapoff", "swap must be disabled (secrets may not page to the host disk)"),
            ("kexec_load_disabled", "kexec must be disabled (an unmeasured kernel could be loaded past the RTMR pins)"),
            ("suid_dumpable", "suid core dumps must be off"),
            ("RLIMIT_CORE", "core dumps must be off (ulimit -c 0 equivalent)"),
        ] {
            assert!(body.contains(needle), "harden_kernel() lost '{}' — {}", needle, why);
        }
    }

    /// v179 (live E2E regression, 2026-10-23): the embedded "paypal.pem" was
    /// a stale EXPIRED LEAF (CN=api-m.paypal.com, notAfter 2026-09-13)
    /// masquerading as a root — decorative while system roots were trusted,
    /// then a hard fail-closed break of the PayPal token exchange the moment
    /// plan Phase 2 disabled them. The pin must be the REAL trust anchor of
    /// api-m.paypal.com / api-m.sandbox.paypal.com: DigiCert Global Root G2
    /// (thumbprint cross-checked against DigiCert's published value). Root
    /// rotation MUST update this fingerprint in the same reviewed commit.
    #[test]
    fn paypal_api_root_is_digicert_g2_v179() {
        use base64::Engine as _;
        use sha2::Digest;
        let pem = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/paypal.pem"))
            .expect("src/paypal.pem must be readable");
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .expect("paypal.pem must be valid base64 DER");
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&der)),
            "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f",
            "src/paypal.pem is NOT the DigiCert Global Root G2 anchor of the pinned PayPal API endpoints — the hardened TLS client would fail every live token exchange"
        );
        assert!(
            reqwest::Certificate::from_pem(pem.as_bytes()).is_ok(),
            "reqwest must accept the embedded root"
        );
    }

    /// v179 (plan Phase 2 — outbound TLS MITM defense): hardened_client()
    /// must NOT consult the platform root store (disk-attacker-controllable);
    /// only the two include_bytes! pins may decide trust. Source-level pin in
    /// the style of cmdline_pin_matches_build_script — dropping the flag from
    /// the builder breaks THIS test in the reviewed commit that would weaken
    /// the transport.
    #[test]
    fn hardened_client_disables_system_roots_v179() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
            .expect("src/main.rs must be readable");
        let client_fn = src
            .split("fn hardened_client()")
            .nth(1)
            .and_then(|s| s.split("\nfn ").next())
            .expect("hardened_client() body must exist");
        assert!(
            client_fn.contains(".tls_built_in_root_certs(false)"),
            "hardened_client() must disable the built-in/system root store — only the embedded PAYPAL_CA_PEM may be trusted (plan Phase 2)"
        );
        assert!(
            client_fn.contains("add_root_certificate"),
            "hardened_client() must pin the embedded roots explicitly"
        );
    }

    /// v186 (self-report heartbeat): the post-lockdown publish must survive
    /// the flush — `pin_sink_network()` runs BEFORE the output chain is
    /// flushed and lockdown pins the sink's IPv4s on 443; `put()` pins the
    /// resolver so no DNS query happens afterwards. Losing either half
    /// silently returns to the 2026-10-25 state where
    /// `selfreport::serving()` (and every later halt) was firewalled away.
    #[test]
    fn selfreport_survives_egress_lockdown_v186() {
        let main_src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
            .expect("src/main.rs must be readable");
        let lockdown = main_src
            .split("pub fn egress_lockdown()")
            .nth(1)
            .and_then(|s| s.split("\n    pub fn ").next())
            .expect("egress_lockdown() body must exist");
        let pin_at = lockdown
            .find("pin_sink_network()")
            .expect("lockdown must pin the sink's addresses while DNS is still open");
        let flush_at = lockdown
            .find("flush chain inet filter output")
            .expect("lockdown must flush the output chain");
        assert!(
            pin_at < flush_at,
            "pin_sink_network() must run BEFORE the flush — DNS egress only exists pre-lockdown"
        );
        assert!(
            lockdown.contains("ip daddr {{ {} }} tcp dport 443 accept"),
            "lockdown must add an nft allow rule for exactly the pinned sink addresses on 443"
        );
        assert!(
            !lockdown.contains("udp dport 53 accept"),
            "lockdown must NOT reopen DNS — the sink pins its resolver instead (no query-channel exfil)"
        );

        let sr_src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/selfreport.rs"))
            .expect("src/selfreport.rs must be readable");
        assert!(
            sr_src.contains("resolve_to_addrs(&sink.host(), addrs)"),
            "put() must pin the resolver to the pre-lockdown addresses (post-lockdown there is no DNS)"
        );
        assert!(
            sr_src.contains("a.is_ipv4()"),
            "only IPv4 sink addresses may be pinned — the nft rule is `ip daddr`"
        );
    }

    #[test]
    fn cmdline_pin_matches_build_script() {
        let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/build-alibaba-image.sh"))
            .expect("build-alibaba-image.sh must be readable");
        let needle = format!("linux /EFI/BOOT/vmlinuz {}", enclave_init::EXPECTED_CMDLINE);
        assert!(
            script.contains(&needle),
            "build-alibaba-image.sh grub.cfg cmdline drifted from enclave_init::EXPECTED_CMDLINE — update BOTH in the same reviewed commit"
        );
    }

    #[test]
    fn ccel_replay_selftest_v168() {
        // Synthetic TCG crypto-agile log (LEGACY-FORMAT Spec ID Event03
        // header + multi-digest event + EV_NO_ACTION + one extension per
        // MrIndex 0..3: MrIndex 0 = MRTD (never replayed), 1..3 extend
        // RTMR0..2 — the real TCG/UEFI CC-log convention, live-verified
        // against Alibaba's CCEL + the Intel-signed quote (2026-10-23).
        // Same vector as scripts/calculate-golden-rtmr.mjs --selftest —
        // Rust and JS must replay to identical bytes. The header is in the
        // TCG_PCR_EVENT fixed layout the spec mandates for the first event.
        let log = hex::decode(concat!(
            "0000000003000000000000000000000000000000000000000000000025000000",
            "53706563204944204576656e743033000000000000000000020000000b002000",
            "0c003000000000000005000000020000000b0033d30b8c9c1d527af7444096d2",
            "b224043288d17f4cf5dbe0ee08e5bf298cd6240c0091ade0d63b78f8cb3163a5",
            "f7d379803d28736d8750a81a426e5de3e00881102f3272b2f9043d30a096b6f3",
            "c5329921010c0000006576656e742d412d646174610100000003000000010000",
            "000c009600d212482f5fed7c434809b63b80169bea1512b2a1489c5cc4285fdd",
            "778df105b240fbb073c16dda5f85a5b16f29910700000069676e6f7265640100",
            "000004000000010000000c0079109388ed26aa95abbba22ba7e6ec7e7b1bb6a9",
            "5d1c0fe5fee15bfb79d308193b795f188399d1686d5d7b50c34965a80c000000",
            "6576656e742d422d646174610200000006000000010000000c00ff337190a80a",
            "44f709bbb0bb74ddd96c78bdc55cc05db46d2ab151cc1e413737fcf0cf4b27ea",
            "d87aae6b767f0ec49cdc0c0000006576656e742d432d64617461030000000400",
            "0080010000000c00eca41f8a750a060cc532afd0a6f016c9f61e5da3f116d21f",
            "39b5e7493e8fe6ac108b59d8e68c06a401a32bf0a0daa2070c0000006576656e",
            "742d442d64617461",
        ))
        .unwrap();
        let r = intel_tdx::replay_ccel(&log).expect("selftest log must parse and replay");
        assert_eq!(hex::encode(r[0]), "eebd6b944d3c5aa23713edd5d40ca48affc1293b88889884c27fb683cb5531564d65db8c442738fda0f2bf122deea144");
        assert_eq!(hex::encode(r[1]), "4a7aaec7d4d007acc2857e15a6515dcfbf5cbc659932b1cd08ea00fd5835f788ea553202f642bc405f44c7d86211cf5c");
        assert_eq!(hex::encode(r[2]), "5ff9199110228b30594d6d62215ba34d933f7de43ae402f5ab1d531a09b511bd2e82107879730afd7292caefe83584ae");
        // MrIndex 0 = MRTD: never replayed into any RTMR, so RTMR3 stays at
        // its reset value (ZERO — TDX Module Base Arch spec).
        assert_eq!(hex::encode(r[3]), "0".repeat(96));

        // Trailing padding tolerance (live Alibaba CCEL: 1626 real bytes in a
        // 65536-byte data/CCEL area, 0xFF-then-0x00 padded). The replay of the
        // padded buffer must equal the clean-log replay.
        let mut padded = log.clone();
        padded.extend(std::iter::repeat(0xFFu8).take(512));
        padded.extend(std::iter::repeat(0x00u8).take(512));
        let r2 = intel_tdx::replay_ccel(&padded).expect("padded log must parse and replay");
        assert_eq!(r, r2, "trailing 0xFF/0x00 padding must not change the replay");
    }
}
