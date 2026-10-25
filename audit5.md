An implementation plan to improve **Hardware Verification of the Running Code** for the `alibabacloud` Intel TDX deployment addresses the identified threat model, architectural constraints, and UX requirements.

---

### Key Invariants Addressed
1. **Gate 1 Must Be Cryptographically Complete**: Gate 1 is not a placeholder or a string check. It verifies the ECDSA P-256 signature on the TD Quote using the embedded Attestation Key, confirms that the Attestation Key is committed inside the Quoting Enclave (QE) Report (`SHA-256(att_key || qe_auth) == qe_report.report_data[0..32]`), verifies the QE Report's ECDSA signature using the PCK Leaf certificate, and conducts an ASN.1 signature walk (`x509SignedBy`) up to the pinned Intel SGX/TDX Root CA (`44a0196b...`).
2. **Gate 3 Zero-Wildcard Enforcement**: The `if (activeSession)` branch that allowed unverified client slots in past drafts is removed. Both 32-byte slots are enforced across all paths:
   - **Slot 1 (`REPORTDATA[0..32]`)**: Must match `expectedNonce` ($\text{SHA-256}(\text{Identity} \parallel H(P_{enc}) \parallel H(\text{custom\_info}) \parallel \text{Binary} \parallel \text{Manifest})$).
   - **Slot 2 (`REPORTDATA[32..64]`)**:
     - *Active Session*: Evaluated against local client session $\text{SHA-256}(P_{client} \parallel Nonce_{client})$.
     - *Offline/Pasted Report*: Reconstructed from `report.session_context.client_pub_b64` and `report.session_context.client_nonce_hex`. If either is missing or invalid, **the audit fails closed**.
   - Full 64-byte `REPORTDATA` must equal $\text{Slot}_1 \parallel \text{Slot}_2$ unconditionally.
3. **No Pre-Flight Attestation**: No TD Quote is minted for unauthenticated requests. `/attest/login-session` issues lightweight S_enc-signed parameters, and the PKCE verifier is stored exclusively in enclave RAM. The expensive TD Quote is only minted in `/callback` after PayPal verifies the user and issues an authorization code.
4. **Alibaba Cloud TDX + GRUB 2.12 + RTMR2**: The modular GRUB 2.12 boot chain is retained. Debian’s GRUB 2.12 executes `EFI_CC_MEASUREMENT_PROTOCOL`, measuring `vmlinuz` + `initrd.img` + `/proc/cmdline` into **`RTMR2`**. Code identity is anchored in `RTMR2`.

---

## 1. Threat Model & Adversarial Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 ADVERSARIAL COLLUSION BOUNDARY                                │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. Malicious Webservice Owner: Holds PayPal Client Secrets, Cloudflare DNS-01 tokens,         │
│    domain TLS certificates (can terminate TLS on login.airma.de), and GitHub push access.    │
│ 2. Malicious Alibaba Cloud Hypervisor: Controls virtual disks (ESP), physical RAM, virtual   │
│    NIC, QGS (Quote Generation Service), serial console, and ACPI tables.                     │
│ 3. Hostile Foreign Clouds (Oracle OCI / GCP): Collude with the owner to generate real        │
│    hardware quotes on AMD SEV-SNP instances to replay or substitute evidence.                │
│ 4. Intel Silicon Root of Trust (Uncompromised): Genuine Intel Xeon CPU (Sapphire Rapids),     │
│    authenticated TDX SEAM module, and Intel DCAP PCK PKI.                                    │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ SECURITY INVARIANT:                                                                          │
│ The relying party client rejects the attestation report and decrypts zero user data unless   │
│ genuine Intel TDX silicon certifies that:                                                    │
│  a) The running in-memory system matches the audited RTMR2 golden baseline.                  │
│  b) The hardware quote directly commits to the user browser's ephemeral public key.           │
│  c) All user identity data is end-to-end encrypted (E2EE) to that client browser key.         │
│  d) Foreign cloud evidence (OCI AMD SEV-SNP, GCP vTPM) fails closed at Gate 1.               │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Hardware Measurement Architecture (GRUB 2.12 to RTMR2)

Per Alibaba Cloud's TDX architecture:

| Register | Measured By | Measured Entities | Stability & Rotation Trigger |
| :--- | :--- | :--- | :--- |
| **`MRTD`** | Hypervisor (`TDH.MR.FINALIZE`) | Alibaba TDVF virtual firmware private memory image | Invariant across binary rebuilds |
| **`RTMR0`** | TDVF (EDK2) | ACPI tables, platform topology, CPU count (`c9i.large`) | Invariant unless instance shape changes |
| **`RTMR1`** | TDVF (`EFI_CC_MEASUREMENT_PROTOCOL`) | EFI Boot applications: `shimx64.efi` + `grubx64.efi` | Invariant unless Debian packages are upgraded |
| **`RTMR2`** | **GRUB 2.12 (`EFI_CC_MEASUREMENT_PROTOCOL`)** | **`vmlinuz` + `initrd.img` (holding `/init`) + `/proc/cmdline`** | **Dynamic: Rotates with every `/init` binary build** |
| **`RTMR3`** | Enclave Application Runtime | Custom in-guest extensions (`TDCALL [TDG.MR.RTMR.EXTEND]`) | Zero-pinned ($0^{48}$, unextended) |

---

## 3. End-to-End Cryptographic Protocol & Anti-DoS Architecture

```
User Browser                          PayPal                         Enclave (/init)
     │                                   │                                  │
     ├─── 1. POST /attest/login-session ─┼─────────────────────────────────►│ (No TD Quote generated)
     │◄── 2. S_enc(code_challenge, ...) ─┼──────────────────────────────────┤ (Stores PKCE verifier in RAM)
     │                                   │                                  │
     ├─── 3. Auth with code_challenge ──►│                                  │
     │◄── 4. Redirect with Auth Code ────┤                                  │
     │                                   │                                  │
     ├─── 5. GET /callback?code=... ─────┼─────────────────────────────────►│
     │                                   ├── 6. Token Exchange (verifier) ─►│ (PayPal validates PKCE)
     │                                   │◄─ 7. Verified Profile Data ──────┤ (Checks verified_account==true)
     │                                   │                                  │
     │                                   │                                  ├── 8. Mints Intel TDX Quote:
     │                                   │                                  │      Slot 1: Identity & Code Nonce
     │                                   │                                  │      Slot 2: Client Session Hash
     │                                   │                                  ├── 9. Encrypts report with ECDH(P_client)
     │◄── 10. AES-256-GCM Encrypted Blob ┼──────────────────────────────────┤      (Zero plaintext to proxy)
```

1. **Lightweight Login Session**: The client generates $(P_{client}, S_{client})$ and $Nonce_{client}$. Calling `POST /attest/login-session` performs only an in-memory RSA signature over login parameters and generates an ephemeral PKCE verifier stored in memory. **No hardware quotes are minted.**
2. **PayPal as Gatekeeper**: Attackers cannot spam quote generation without authenticating a real PayPal account.
3. **Dual-Slot Commitment in `/callback`**: Once PayPal returns the authorization code, the enclave calls QGS to mint the Intel TDX Quote committing to both slots:
   - **Slot 1 (`REPORTDATA[0..32]`)**: Identity + Code hash:
     $$\text{Slot}_1 = \text{SHA-256}(\text{IdentityHash} \parallel \text{SHA-256}(P_{enc}) \parallel \text{SHA-256}(custom\_info) \parallel \text{BinaryHash} \parallel \text{ManifestHash})$$
   - **Slot 2 (`REPORTDATA[32..64]`)**: Client session hash:
     $$\text{Slot}_2 = \text{SHA-256}(P_{client} \parallel Nonce_{client})$$
4. **E2EE Payload**: The attestation envelope is encrypted using $\text{AES-256-GCM}$ keyed with $\text{HKDF}(\text{ECDH}(S_{enc\_ecdh}, P_{client}), Nonce_{client})$. The malicious owner terminating TLS sees only ciphertext.

---

## 4. Simplified `verify.html` Implementation

The interface consolidates the workflow into **two input cards** and a **4-gate results display**, backed by the full cryptographic verification engine:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verified Unique Aliases | Hardware Auditor</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/forge/1.3.1/forge.min.js"
            integrity="sha384-xE6n3RBMZWgwAhyzoIMfY7HN3oDBa/+HBwFFNyxsdY8kseup7C4Blx1yDzprEESV"
            crossorigin="anonymous"></script>
    <style>
        :root {
            --bg: #090d16;
            --surface: #111827;
            --border: #1f2937;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --text: #f3f4f6;
            --text-muted: #9ca3af;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            padding: 40px 20px;
        }
        .container { max-width: 780px; width: 100%; }
        header { text-align: center; margin-bottom: 28px; }
        h1 { font-size: 2rem; font-weight: 700; color: #fff; margin-bottom: 6px; }
        .tagline { color: var(--text-muted); font-size: 0.9rem; }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
        }
        .form-group { margin-bottom: 14px; }
        label { display: block; font-size: 0.8rem; font-weight: 600; margin-bottom: 6px; color: var(--text-muted); }
        input[type="text"], textarea {
            width: 100%;
            background: #030712;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 13px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            transition: background 0.2s;
            text-decoration: none;
        }
        .btn:hover { background: var(--primary-hover); }
        .gate-card {
            background: #030712;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 10px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
        }
        .gate-icon { font-size: 1.2rem; line-height: 1; margin-top: 2px; }
        .gate-title { font-size: 0.9rem; font-weight: 600; margin-bottom: 4px; }
        .gate-desc { font-size: 0.78rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
        .verified { border-left: 4px solid var(--success); }
        .failed { border-left: 4px solid var(--danger); }
        .warning { border-left: 4px solid var(--warning); }
        .audit-summary {
            padding: 14px;
            border-radius: 8px;
            text-align: center;
            font-weight: 600;
            margin-bottom: 16px;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>Verified Unique Aliases</h1>
        <p class="tagline">Zero-Trust PayPal Identity Verification Anchored in Intel TDX Silicon</p>
    </header>

    <!-- Card 1: Single Streamlined Login & Claim -->
    <div class="card" id="actionCard">
        <div class="form-group">
            <label for="enclaveUrl">Target Enclave Host</label>
            <input type="text" id="enclaveUrl" value="https://login.airma.de">
        </div>
        <div class="form-group">
            <label for="customInfo">Optional Identity Anchor (Wallet Address, Public Key, Nonce)</label>
            <input type="text" id="customInfo" placeholder="Committed directly into Intel TDX Quote">
        </div>
        <button class="btn" id="startLoginBtn" onclick="initiateLogin()">🔒 Verify Identity with PayPal (Verified Only)</button>
        <div id="claimContainer" style="display:none; margin-top: 10px;">
            <a class="btn" id="paypalNavBtn" target="_blank" style="background: var(--success); margin-bottom: 8px;">Continue to PayPal →</a>
            <button class="btn" onclick="claimAndVerify()" style="background: var(--surface); border: 1px solid var(--border);">🔓 Claim & Verify Attestation</button>
        </div>
        <p id="statusMsg" style="margin-top: 10px; font-size: 0.8rem; color: var(--text-muted); text-align: center;"></p>
    </div>

    <!-- Card 2: Offline / Manual Audit -->
    <div class="card">
        <label for="reportJson">Audit Saved Report (JSON or Encrypted Blob)</label>
        <textarea id="reportJson" rows="3" placeholder="Paste envelope JSON or encrypted blob here..."></textarea>
        <button class="btn" style="margin-top: 10px; background: transparent; border: 1px solid var(--border);" onclick="auditInputPayload()">Run Verification</button>
    </div>

    <!-- Results: 4 Consolidated Verification Gates -->
    <div id="resultsCard" class="card" style="display:none;">
        <div id="auditBanner" class="audit-summary"></div>

        <div id="gateSilicon" class="gate-card">
            <div class="gate-icon" id="gateSiliconIcon">⚪</div>
            <div>
                <div class="gate-title">Gate 1: Intel TDX Silicon Root of Trust</div>
                <div class="gate-desc" id="gateSiliconDesc">Awaiting verification...</div>
            </div>
        </div>

        <div id="gateCode" class="gate-card">
            <div class="gate-icon" id="gateCodeIcon">⚪</div>
            <div>
                <div class="gate-title">Gate 2: Code Identity Baseline (RTMR2 Anchor)</div>
                <div class="gate-desc" id="gateCodeDesc">Awaiting verification...</div>
            </div>
        </div>

        <div id="gateSession" class="gate-card">
            <div class="gate-icon" id="gateSessionIcon">⚪</div>
            <div>
                <div class="gate-title">Gate 3: Hardware Dual-Slot Session Binding</div>
                <div class="gate-desc" id="gateSessionDesc">Awaiting verification...</div>
            </div>
        </div>

        <div id="gateIdentity" class="gate-card">
            <div class="gate-icon" id="gateIdentityIcon">⚪</div>
            <div>
                <div class="gate-title">Gate 4: PayPal Account Verification & Scope</div>
                <div class="gate-desc" id="gateIdentityDesc">Awaiting verification...</div>
            </div>
        </div>

        <button class="btn" id="dlReportBtn" style="display:none; margin-top: 10px;" onclick="downloadDecryptedReport()">💾 Download Verified Attestation Report</button>
    </div>
</div>

<script>
    // =========================================================================
    // Silicon & Hardware Baseline Constants
    // =========================================================================
    var TRUSTED_INTEL_ROOTS = [{
        sha256: '44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3',
        pem: [
            '-----BEGIN CERTIFICATE-----',
            'MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw',
            'aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv',
            'cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ',
            'BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG',
            'A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0',
            'aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT',
            'AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7',
            '1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB',
            'uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ',
            'MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50',
            'ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV',
            'Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI',
            'KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg',
            'AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=',
            '-----END CERTIFICATE-----'
        ].join('\n')
    }];

    var EXPECTED_MRTD  = 'e0199499baacb2e4f4bc73046f25bedf674d42defbe4e854242bd6554a9d155edf7f3bff8e6202e63ed230e59ab2568a';
    var EXPECTED_RTMR0 = '06a32a2f92ea455dd628bc41be9bb5910c2782a2eb93c646c6a5ddebd70291839f197792d289cca528572b6d910294db';
    var EXPECTED_RTMR1 = '6fa0352319182f7ec8cb713223cbc1853506caf719c64d04475a26975ae8ebf72003f592dcf0aafe392cc74de33d3f90';
    var EXPECTED_RTMR2 = '61ce2879ea9f31cadf09ba6498104c7501dc0ac7969d4bf1c401ad92585386332fc5cbdb45182a2193f11f71a4a30324';
    var EXPECTED_RTMR3 = '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
    var EXPECTED_PAYPAL_CLIENT_ID = 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p';

    let verifiedPayload = null;

    function trustedAuditorContext() {
        if (typeof location === 'undefined') return true;
        if (location.protocol === 'file:') return true;
        return location.hostname === 'leonardopedro.github.io';
    }

    function setStatus(msg) { document.getElementById('statusMsg').innerText = msg; }
    function hx(u8) { return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join(''); }
    function b64ToBytes(s) { return Uint8Array.from(atob(s.replace(/-----[^-]+-----|\s/g, '').replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); }

    function updateGate(gateId, pass, text) {
        const card = document.getElementById(gateId);
        const icon = document.getElementById(gateId + 'Icon');
        const desc = document.getElementById(gateId + 'Desc');
        card.className = 'gate-card ' + (pass === true ? 'verified' : pass === 'warning' ? 'warning' : 'failed');
        icon.innerText = pass === true ? '✅' : pass === 'warning' ? '⚠️' : '❌';
        desc.innerText = text;
    }

    // =========================================================================
    // ASN.1 / X.509 Cryptographic Verification Primitives
    // =========================================================================
    function p256SpkiFromRaw(rawXY) {
        if (!rawXY || rawXY.length !== 64) throw new Error('Attestation key must be a 64-byte uncompressed P-256 point');
        const der = new Uint8Array(26 + 65);
        der.set([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00], 0);
        der[26] = 0x04;
        der.set(rawXY, 27);
        return der;
    }

    function binaryToBytes(bin) {
        if (bin instanceof Uint8Array) return bin;
        return Uint8Array.from(bin, c => c.charCodeAt(0) & 0xff);
    }

    function derBytesToBinary(u8) {
        let s = '';
        for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192));
        return s;
    }

    function x509ParseAny(pem) {
        const b64 = pem.replace(/-----[^-]+-----|\s/g, '');
        const decoded = atob(b64);
        const cert = forge.asn1.fromDer(decoded);
        const tbs = cert.value[0];
        const sigAlg = cert.value[1];
        const sigBits = cert.value[2];

        let spkiNode = null;
        for (const child of tbs.value) {
            if (child.type === forge.asn1.Type.SEQUENCE && Array.isArray(child.value) && child.value.length === 2
                && child.value[1].type === forge.asn1.Type.BITSTRING) {
                spkiNode = child;
                break;
            }
        }
        if (!spkiNode) throw new Error("SPKI node not found in certificate");
        const spkiDer = binaryToBytes(forge.asn1.toDer(spkiNode).getBytes());
        return { tbs, sigAlg, sigBits, spkiDer, rawDer: b64ToBytes(b64) };
    }

    async function x509SignedBy(child, parent) {
        try {
            const tbsDer = binaryToBytes(forge.asn1.toDer(child.tbs).getBytes());
            const sigRaw = child.sigBits.value;
            const sigBytes = binaryToBytes(sigRaw);
            const content = (sigBytes.length > 0 && sigBytes[0] === 0) ? sigBytes.slice(1) : sigBytes;
            
            const seq = forge.asn1.fromDer(derBytesToBinary(content));
            const toInt = n => {
                let b = binaryToBytes(n.value);
                let i = 0;
                while (i < b.length - 1 && b[i] === 0) i++;
                return b.slice(i);
            };
            const r = toInt(seq.value[0]), s = toInt(seq.value[1]);
            const half = Math.max(r.length, s.length);
            const raw = new Uint8Array(half * 2);
            raw.set(r, half - r.length);
            raw.set(s, half * 2 - s.length);

            const key = await crypto.subtle.importKey('spki', parent.spkiDer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
            return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, tbsDer);
        } catch (e) {
            return false;
        }
    }

    // =========================================================================
    // Core Workflow: Ephemeral Login Setup (Zero Pre-Flight TD Quote)
    // =========================================================================
    async function initiateLogin() {
        try {
            if (!trustedAuditorContext()) {
                throw new Error("UNTRUSTED ORIGIN: Run verify.html locally (file://) or via GitHub Pages to avoid web auditor tampering.");
            }
            setStatus("Generating ephemeral ECDH P-256 client keypair...");
            const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
            const pubDer = await crypto.subtle.exportKey('spki', kp.publicKey);
            const pubB64 = btoa(String.fromCharCode(...new Uint8Array(pubDer)));
            
            const nonceBytes = new Uint8Array(32);
            crypto.getRandomValues(nonceBytes);
            const nonceHex = hx(nonceBytes);
            
            const customInfo = (document.getElementById('customInfo').value || 'NONE').trim() || 'NONE';
            const enclaveHost = document.getElementById('enclaveUrl').value.replace(/\/+$/, '');

            setStatus("Acquiring session token from enclave (no heavy TD Quote)...");
            const resp = await fetch(enclaveHost + '/attest/login-session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_ecdh_pub_b64: pubB64,
                    client_nonce_hex: nonceHex,
                    flow: 'verified',
                    custom_info: customInfo
                })
            });
            if (!resp.ok) throw new Error("Failed to register session on enclave (HTTP " + resp.status + ")");
            const session = await resp.json();

            // Store ephemeral private key and session parameters in sessionStorage
            const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
            sessionStorage.setItem('pav_session', JSON.stringify({
                host: enclaveHost,
                jwk,
                pubB64,
                nonceHex,
                customInfo,
                state: session.signed_fields.state,
                p_enc: session.enclave_signing_public_key
            }));

            const sf = session.signed_fields;
            const paypalUrl = `${sf.authorize_base}?client_id=${encodeURIComponent(sf.paypal_client_id)}&response_type=code&scope=${sf.scope}&redirect_uri=${encodeURIComponent(sf.redirect_uri)}&state=${sf.state}&code_challenge=${encodeURIComponent(sf.code_challenge)}&code_challenge_method=S256`;
            
            document.getElementById('paypalNavBtn').href = paypalUrl;
            document.getElementById('claimContainer').style.display = 'block';
            document.getElementById('startLoginBtn').style.display = 'none';
            setStatus("Session established. Click 'Continue to PayPal →', authenticate, then click 'Claim & Verify Attestation'.");
        } catch (e) {
            alert(e.message);
            setStatus("Error: " + e.message);
        }
    }

    async function claimAndVerify() {
        try {
            const rawSession = sessionStorage.getItem('pav_session');
            if (!rawSession) throw new Error("No active session found in browser memory.");
            const s = JSON.parse(rawSession);

            setStatus("Claiming encrypted report from enclave...");
            const resp = await fetch(`${s.host}/e2ee-blob?state=${encodeURIComponent(s.state)}`);
            if (!resp.ok) throw new Error("Claim failed (HTTP " + resp.status + "). Session expired or already claimed.");
            const blob = await resp.json();

            setStatus("Deriving session key & decrypting envelope...");
            const privKey = await crypto.subtle.importKey('jwk', s.jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
            const peerDer = b64ToBytes(blob.enclave_ecdh_public_key_b64);
            const peerKey = await crypto.subtle.importKey('spki', peerDer, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
            
            const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, privKey, 256);
            const hkdfBase = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
            
            const nonceBytes = new Uint8Array(s.nonceHex.match(/.{2}/g).map(h => parseInt(h, 16)));
            const aesKey = await crypto.subtle.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt: nonceBytes, info: new TextEncoder().encode('paypal-auth-vm/e2ee/v1') },
                hkdfBase, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
            );

            const ctBytes = b64ToBytes(blob.ct_b64);
            const ivBytes = b64ToBytes(blob.iv_b64);
            const ptBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: ivBytes, additionalData: nonceBytes },
                aesKey,
                ctBytes
            );

            const envelope = JSON.parse(new TextDecoder().decode(ptBuffer));
            document.getElementById('reportJson').value = JSON.stringify(envelope, null, 2);
            await runCoreAudit(envelope, s);
        } catch (e) {
            alert("Attestation Error: " + e.message);
            setStatus("Verification failed: " + e.message);
        }
    }

    async function auditInputPayload() {
        try {
            const rawText = document.getElementById('reportJson').value.trim();
            if (!rawText) throw new Error("Please supply report JSON or encrypted blob.");
            let payload = JSON.parse(rawText);
            
            if (!payload.attestation_report && payload.ct_b64 && payload.enclave_ecdh_public_key_b64) {
                const rawSession = sessionStorage.getItem('pav_session');
                if (!rawSession) throw new Error("Encrypted blob requires active session key. Claim from originating browser session.");
                await claimAndVerify();
                return;
            }
            await runCoreAudit(payload, null);
        } catch (e) {
            alert("Audit Failed: " + e.message);
        }
    }

    // =========================================================================
    // Core 4-Gate Hardware Verification Engine (Strict Mathematical Checks)
    // =========================================================================
    async function runCoreAudit(envelope, activeSession) {
        document.getElementById('resultsCard').style.display = 'block';
        const report = envelope.attestation_report || envelope.report;
        const hw = report.hardware_level_attestation;

        // ---------------------------------------------------------------------
        // GATE 1: Intel TDX Silicon Root of Trust (ECDSA + PCK Chain Walk)
        // ---------------------------------------------------------------------
        if (!hw.tdx_quote_b64) {
            updateGate('gateSilicon', false, "Report lacks hardware-signed Intel TDX Quote. Foreign evidence rejected.");
            throw new Error("REJECTED: Report contains no hardware-signed Intel TDX Quote.");
        }
        const quote = b64ToBytes(hw.tdx_quote_b64);
        if (quote.length < 48 + 584 + 4 + 64 + 64 + 6) throw new Error("TDX Quote truncated.");

        const version = quote[0] | (quote[1] << 8);
        const teeType = quote[4] | (quote[5] << 8) | (quote[6] << 16) | (quote[7] << 24);
        if (teeType !== 0x81) throw new Error("Foreign Quote: tee_type is not Intel TDX (0x81).");
        if (version !== 4 && version !== 5) throw new Error("Unsupported TDX Quote version: " + version);

        const bodyOff = version === 4 ? 48 : 54;
        const bodyLen = 584;
        const signedRegion = quote.subarray(0, bodyOff + bodyLen);
        const qBody = quote.subarray(bodyOff, bodyOff + bodyLen);

        // Parse Auth Data (AuthDataV4)
        const authLen = quote[signedRegion.length] | (quote[signedRegion.length + 1] << 8) | 
                       (quote[signedRegion.length + 2] << 16) | (quote[signedRegion.length + 3] << 24);
        const auth = quote.subarray(signedRegion.length + 4, signedRegion.length + 4 + authLen);
        const qSigRaw = auth.subarray(0, 64);
        const attKeyRaw = auth.subarray(64, 128);
        const certType = auth[128] | (auth[129] << 8);
        if (certType !== 6) throw new Error("Unsupported Quote cert_type: expected Type 6 (QE Report).");

        const certLen = auth[130] | (auth[131] << 8) | (auth[132] << 16) | (auth[133] << 24);
        const certBody = auth.subarray(134, 134 + certLen);
        const qeReport = certBody.subarray(0, 384);
        const qeReportSig = certBody.subarray(384, 448);
        const qeAuthLen = certBody[448] | (certBody[449] << 8);
        const qeAuthData = certBody.subarray(450, 450 + qeAuthLen);

        // 1. Verify Attestation Key Binding inside QE Report
        const qePreimage = new Uint8Array(64 + qeAuthLen);
        qePreimage.set(attKeyRaw, 0);
        qePreimage.set(qeAuthData, 64);
        const qeDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', qePreimage));
        if (hx(qeDigest) !== hx(qeReport.subarray(320, 352))) {
            updateGate('gateSilicon', false, "Attestation Key not cryptographically bound to QE Report.");
            throw new Error("QE Report Binding Mismatch!");
        }

        // 2. Parse PCK Certificates & Verify QE Signature
        const pckText = hw.pck_cert_pem;
        const pckMatches = pckText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
        if (pckMatches.length === 0) throw new Error("No PCK certificates found in report.");
        const pckChain = pckMatches.map(x509ParseAny);

        const pckLeafKey = await crypto.subtle.importKey('spki', pckChain[0].spkiDer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        
        const qeSigDer = (() => {
            const r = qeReportSig.subarray(0, 32), s = qeReportSig.subarray(32, 64);
            const trim = b => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; return (b[i] & 0x80) ? Uint8Array.from([0, ...b.subarray(i)]) : b.subarray(i); };
            const rT = trim(r), sT = trim(s);
            const der = new Uint8Array(6 + rT.length + sT.length);
            der[0] = 0x30; der[1] = 4 + rT.length + sT.length;
            der[2] = 0x02; der[3] = rT.length; der.set(rT, 4);
            der[4 + rT.length] = 0x02; der[5 + rT.length] = sT.length; der.set(sT, 6 + rT.length);
            return der;
        })();
        const qeSigOk = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pckLeafKey, qeSigDer, qeReport);
        if (!qeSigOk) {
            updateGate('gateSilicon', false, "PCK Leaf signature over QE Report is INVALID.");
            throw new Error("QE Signature Verification Failed!");
        }

        // 3. Walk PCK Certificate Chain to Pinned Intel Root CA
        const intelRoot = x509ParseAny(TRUSTED_INTEL_ROOTS[0].pem);
        let currentCert = pckChain[0];
        let chainTerminated = false;
        for (let i = 1; i < pckChain.length; i++) {
            const parent = pckChain[i];
            if (!(await x509SignedBy(currentCert, parent))) {
                updateGate('gateSilicon', false, `PCK Chain broken at link ${i}.`);
                throw new Error("Invalid certificate signature in PCK chain.");
            }
            currentCert = parent;
            const certHash = hx(new Uint8Array(await crypto.subtle.digest('SHA-256', currentCert.rawDer)));
            if (certHash === TRUSTED_INTEL_ROOTS[0].sha256) {
                chainTerminated = true;
                break;
            }
        }
        if (!chainTerminated) {
            if (await x509SignedBy(currentCert, intelRoot)) {
                chainTerminated = true;
            }
        }
        if (!chainTerminated) {
            updateGate('gateSilicon', false, "PCK Certificate Chain does NOT terminate at pinned Intel Root CA.");
            throw new Error("Untrusted Hardware Root: Failed to reach pinned Intel SGX/TDX Root CA!");
        }

        // 4. Verify Quote Signature over Header + Body
        const attKey = await crypto.subtle.importKey('spki', p256SpkiFromRaw(attKeyRaw), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        const qSigDer = (() => {
            const r = qSigRaw.subarray(0, 32), s = qSigRaw.subarray(32, 64);
            const trim = b => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; return (b[i] & 0x80) ? Uint8Array.from([0, ...b.subarray(i)]) : b.subarray(i); };
            const rT = trim(r), sT = trim(s);
            const der = new Uint8Array(6 + rT.length + sT.length);
            der[0] = 0x30; der[1] = 4 + rT.length + sT.length;
            der[2] = 0x02; der[3] = rT.length; der.set(rT, 4);
            der[4 + rT.length] = 0x02; der[5 + rT.length] = sT.length; der.set(sT, 6 + rT.length);
            return der;
        })();
        const quoteSigOk = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, attKey, qSigDer, signedRegion);
        if (!quoteSigOk) {
            updateGate('gateSilicon', false, "ECDSA signature over TDX Quote header and body is INVALID.");
            throw new Error("Quote signature verification failed!");
        }
        updateGate('gateSilicon', true, "ECDSA P-256 Quote Valid | PCK Chain Verified to Pinned Intel SGX/TDX Root CA");

        // ---------------------------------------------------------------------
        // GATE 2: Code Identity Baseline (RTMR2 & MRTD Hard Pins)
        // ---------------------------------------------------------------------
        const qMrtd  = hx(qBody.subarray(136, 184));
        const qRtmr0 = hx(qBody.subarray(328, 376));
        const qRtmr1 = hx(qBody.subarray(376, 424));
        const qRtmr2 = hx(qBody.subarray(424, 472));
        const qRtmr3 = hx(qBody.subarray(472, 520));

        if (qMrtd !== EXPECTED_MRTD) {
            updateGate('gateCode', false, "MRTD Pin Violation: TDVF firmware image differs from golden baseline!");
            throw new Error("FIRMWARE INTEGRITY VIOLATION");
        }
        if (qRtmr2 !== EXPECTED_RTMR2) {
            updateGate('gateCode', false, "RTMR2 Pin Violation: Kernel, Initrd, or Cmdline has been tampered!");
            throw new Error("CODE IDENTITY VIOLATION: GRUB 2.12 measured different in-memory binaries into RTMR2.");
        }
        if (qRtmr0 !== EXPECTED_RTMR0 || qRtmr1 !== EXPECTED_RTMR1 || qRtmr3 !== EXPECTED_RTMR3) {
            updateGate('gateCode', false, "RTMR0/1/3 Pin Violation: Platform topology or bootloader mismatch.");
            throw new Error("PLATFORM MEASUREMENT VIOLATION");
        }
        updateGate('gateCode', true, `RTMR2 Golden Pin Matched: ${qRtmr2.slice(0, 16)}... (Bitwise Kernel & Initrd Identity Verified)`);

        // ---------------------------------------------------------------------
        // GATE 3: Hardware Dual-Slot Session Binding (Zero-Wildcard Enforcement)
        // ---------------------------------------------------------------------
        const qReportData = hx(qBody.subarray(520, 584));

        // Recompute Expected Slot 1 Nonce (SEC-02 Formula)
        const pubKeyBuffer = b64ToBytes(envelope.enclave_signing_public_key || report.public_key_pem);
        const pubKeyHash = new Uint8Array(await crypto.subtle.digest('SHA-256', pubKeyBuffer));

        const pui = report.paypal_user_info;
        const identityJson = pui
            ? JSON.stringify({ user_id: pui.user_id, sub: pui.sub ?? null, verified_account: pui.verified_account, payer_id: pui.payer_id ?? null })
            : 'PRELOGIN_NO_USER';
        const expectedPaypalHash = hx(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identityJson))));
        if (expectedPaypalHash !== (report.paypal_user_info_raw_hash || '').toLowerCase()) {
            updateGate('gateSession', false, "Identity preimage mismatch! Displayed profile differs from quote commitment.");
            throw new Error("IDENTITY PREIMAGE VIOLATION");
        }
        const paypalHashBytes = new Uint8Array(expectedPaypalHash.match(/.{2}/g).map(h => parseInt(h, 16)));
        
        const customInfoStr = report.custom_info || "NONE";
        const customInfoHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(customInfoStr)));

        const diskManifest = report.enclave_config.boot_measurements.disk_manifest || {};
        const sortedManifest = Object.keys(diskManifest).sort().map(k => [k, diskManifest[k]]);
        const manifestHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(sortedManifest))));
        const binaryHashBytes = new Uint8Array(report.enclave_config.boot_measurements.binary_sha256.match(/.{2}/g).map(h => parseInt(h, 16)));

        const combined160 = new Uint8Array(160);
        combined160.set(paypalHashBytes, 0);
        combined160.set(pubKeyHash, 32);
        combined160.set(customInfoHash, 64);
        combined160.set(binaryHashBytes, 96);
        combined160.set(manifestHash, 128);
        const expectedSlot1 = hx(new Uint8Array(await crypto.subtle.digest('SHA-256', combined160)));

        // Unconditionally Enforce Slot 2 (Client Ephemeral Binding)
        let expectedSlot2;
        if (activeSession) {
            const clientPubBytes = b64ToBytes(activeSession.pubB64);
            const clientNonceBytes = new Uint8Array(activeSession.nonceHex.match(/.{2}/g).map(h => parseInt(h, 16)));
            const preSlot2 = new Uint8Array(clientPubBytes.length + clientNonceBytes.length);
            preSlot2.set(clientPubBytes, 0);
            preSlot2.set(clientNonceBytes, clientPubBytes.length);
            expectedSlot2 = hx(new Uint8Array(await crypto.subtle.digest('SHA-256', preSlot2)));
        } else {
            // Offline/paste audit: strictly reconstruct from session_context
            const sc = report.session_context || {};
            if (!sc.client_pub_b64 || !sc.client_nonce_hex || !/^[0-9a-f]{64}$/i.test(sc.client_nonce_hex)) {
                updateGate('gateSession', false, "Report lacks reconstructible client session fields (offline audit fail-closed).");
                throw new Error("UNVERIFIED CLIENT SLOT: Report does not contain client_pub_b64 and client_nonce_hex.");
            }
            const clientPubBytes = b64ToBytes(sc.client_pub_b64);
            const clientNonceBytes = new Uint8Array(sc.client_nonce_hex.match(/.{2}/g).map(h => parseInt(h, 16)));
            const preSlot2 = new Uint8Array(clientPubBytes.length + clientNonceBytes.length);
            preSlot2.set(clientPubBytes, 0);
            preSlot2.set(clientNonceBytes, clientPubBytes.length);
            expectedSlot2 = hx(new Uint8Array(await crypto.subtle.digest('SHA-256', preSlot2)));
        }

        // Full 64-Byte REPORTDATA Dual-Slot Gate (Zero Wildcards)
        const fullExpectedReportData = expectedSlot1 + expectedSlot2;
        if (qReportData !== fullExpectedReportData) {
            const s1Match = qReportData.slice(0, 64) === expectedSlot1;
            const s2Match = qReportData.slice(64) === expectedSlot2;
            updateGate('gateSession', false, `Dual-Slot Mismatch (Slot 1 Exec Nonce: ${s1Match ? 'MATCH' : 'MISMATCH'}, Slot 2 Client Binding: ${s2Match ? 'MATCH' : 'MISMATCH'})`);
            throw new Error("HARDWARE BINDING MISMATCH: The hardware quote does not commit to the active client session and verified identity!");
        }
        updateGate('gateSession', true, "Dual-Slot Commitment Verified: Quote bound to client session key & identity hash");

        // ---------------------------------------------------------------------
        // GATE 4: PayPal Account Verification & Scope
        // ---------------------------------------------------------------------
        if (report.paypal_client_id !== EXPECTED_PAYPAL_CLIENT_ID) {
            updateGate('gateIdentity', false, "Overscoped or unauthorized PayPal Application ID!");
            throw new Error("MALICIOUS APP: Report was minted with unapproved PayPal Client ID.");
        }
        if (String(report.paypal_user_info?.verified_account) !== 'true') {
            updateGate('gateIdentity', false, "PayPal did not certify verified account status.");
            throw new Error("UNVERIFIED ACCOUNT: Enclave rejected unverified profile.");
        }
        if (report.paypal_environment !== 'production') {
            updateGate('gateIdentity', 'warning', "SANDBOX IDENTITY: Enclave code is genuine, but PayPal account is sandbox.");
        } else {
            updateGate('gateIdentity', true, `PayPal Verified Identity Confirmed: ${report.paypal_user_info.user_id} (Minimal Scope)`);
        }

        // Verification Passed
        verifiedPayload = envelope;
        document.getElementById('auditBanner').style.background = 'rgba(16, 185, 129, 0.15)';
        document.getElementById('auditBanner').style.color = '#10b981';
        document.getElementById('auditBanner').innerText = '✅ ALL GATES VERIFIED: Genuine Intel TDX Enclave Executing Audited Code';
        document.getElementById('dlReportBtn').style.display = 'block';
    }

    function downloadDecryptedReport() {
        if (!verifiedPayload) return;
        const blob = new Blob([JSON.stringify(verifiedPayload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `attestation-report-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
</script>
</body>
</html>
```

---

## 5. Enclave Rust Runtime Updates (`src/main.rs`)

### 5.1 Enforcing Ephemeral Session & Mandatory PKCE
In `src/main.rs`, replace `/attest/preflight` with `/attest/login-session`. The enclave stores a 43-character base64url PKCE verifier in RAM (TTL 600 s) and returns an S_enc-signed `code_challenge` (S256).

```rust
async fn attest_login_session(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginSessionRequest>,
) -> Response {
    if let Err(status) = state.record_egress(addr.ip(), 4096) {
        return status.into_response();
    }

    let client_pub = match B64STD.decode(payload.client_ecdh_pub_b64.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid client_ecdh_pub_b64").into_response(),
    };
    if openssl::pkey::PKey::public_key_from_der(&client_pub).is_err() {
        return (StatusCode::BAD_REQUEST, "client_ecdh_pub_b64 is not a valid DER key").into_response(),
    }
    let nonce_vec = match hex::decode(payload.client_nonce_hex.trim()) {
        Ok(v) if v.len() == 32 => v,
        _ => return (StatusCode::BAD_REQUEST, "client_nonce_hex must be 32 bytes").into_response(),
    };
    let mut client_nonce = [0u8; 32];
    client_nonce.copy_from_slice(&nonce_vec);

    let (cid, _, scope, label) = state.get_flow_config("verified");
    let custom_info = payload.custom_info.as_deref().unwrap_or("NONE").trim();
    let custom_info_str = if custom_info.is_empty() { "NONE" } else { custom_info };

    // Generate PKCE code_verifier + code_challenge (RFC 7636)
    let mut verifier_raw = [0u8; 32];
    rand::thread_rng().fill(&mut verifier_raw);
    let mut code_verifier = B64URL.encode(verifier_raw);
    let code_challenge = B64URL.encode(sha2::Sha256::digest(code_verifier.as_bytes()));

    let state_obj = serde_json::json!({
        "v": 1,
        "p": payload.client_ecdh_pub_b64.trim(),
        "n": payload.client_nonce_hex.trim().to_ascii_lowercase(),
        "f": label,
        "c": custom_info_str,
        "r": hex::encode(rand::thread_rng().gen::<[u8; 16]>()),
    });
    let state_token = B64URL.encode(state_obj.to_string().as_bytes());

    // Store PKCE verifier in enclave RAM only
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

    let signed_fields = serde_json::json!({
        "binding": "v184",
        "state": state_token,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "flow": label,
        "paypal_client_id": cid,
        "paypal_environment": if state.staging { "sandbox" } else { "production" },
        "redirect_uri": state.redirect_uri,
        "authorize_base": if state.staging { PAYPAL_SANDBOX_AUTH } else { PAYPAL_PRODUCTION_AUTH },
        "scope": scope,
        "custom_info": custom_info_str,
        "client_session_binding_hex": hex::encode(client_session_binding(&client_pub, &client_nonce)),
    });

    let signature = {
        let mut signer = Signer::new(MessageDigest::sha256(), &state.enclave_identity.pkey).unwrap();
        signer.update(serde_json::to_string(&signed_fields).unwrap().as_bytes()).unwrap();
        B64STD.encode(signer.sign_to_vec().unwrap())
    };

    Json(serde_json::json!({
        "enclave_signing_public_key": state.enclave_identity.pubkey_pem,
        "signed_fields": signed_fields,
        "login_signature_b64": signature,
    })).into_response()
}
```

### 5.2 Dual-Slot Hardware Quote Commitment in `/callback`
```rust
// Inside async fn callback(...):
let mut report_data = [0u8; 64];

// Slot 1: Combined execution & identity hash (0..32)
let slot1_nonce = sec02_nonce(
    &paypal_user_raw_hash,
    &state.enclave_identity.pubkey_der,
    &custom_info,
    &binary_sha256,
    &state.boot_manifest,
);
report_data[0..32].copy_from_slice(&slot1_nonce);

// Slot 2: Active client session commitment (32..64)
let slot2_client_binding = client_session_binding(&client_pub, &client_nonce);
report_data[32..64].copy_from_slice(&slot2_client_binding);

// Hardware quote generated once per authenticated callback
let quote_res = tpm::quote(&hex::encode(slot1_nonce), Some(report_data));
if quote_res.tdx_quote_b64.is_none() {
    return (
        StatusCode::SERVICE_UNAVAILABLE,
        "Hardware quote unavailable — attestation refused (fail closed)",
    ).into_response();
}
```

---

## 6. Threat Mitigation Matrix

| Colluding Vector | Adversary Action | Defense Mechanism | Cryptographic Outcome |
| :--- | :--- | :--- | :--- |
| **Disk/Initramfs Backdoor** | Host modifies `/init` on virtual disk to exfiltrate tokens. | GRUB 2.12 measures modified initramfs into `RTMR2`. `verify.html` enforces `RTMR2 == EXPECTED_RTMR2`. | **Audit Fails Closed**: Hardware quote carries altered `RTMR2`. Client halts before sending credentials. |
| **Cross-Cloud Quote Replay** | Host/Owner presents an AMD SEV-SNP quote from an Oracle Cloud VM. | `verify.html` locks `tee_type == 0x81` and enforces Intel SGX/TDX Root CA pin `44a0196b...`. | **Replay Blocked**: Non-TDX quote rejected immediately at Gate 1. |
| **Reverse Proxy TLS MITM** | Owner terminates TLS at load balancer using domain certificate. | Report encrypted with $\text{AES-256-GCM}_K$ where $K = \text{HKDF}(\text{ECDH}(P_{client}, S_{enclave}))$. | **Data Unreadable**: Adversary captures only ciphertext. $S_{client}$ never left user's browser. |
| **Web Auditor Script Injection** | Host modifies `/boot/efi/verify.html` on disk to fake green checks. | `trustedAuditorContext()` refuses key generation on `login.airma.de`. User executes auditor on `file://` or GitHub Pages. | **Script Defeated**: Untrusted host filesystem bypassed entirely. |
| **Resource Exhaustion (DoS)** | Attacker spams attestation requests to freeze the enclave. | Pre-flight quote generation deleted. Enclave mints quotes only after PayPal verifies user. | **DoS Mitigated**: PayPal CAPTCHA and rate limits absorb attack traffic. |
| **Overscoped PayPal App** | Owner configures enclave to request full customer profile (PII). | Client pins `EXPECTED_PAYPAL_CLIENT_ID` to minimal `AZXkzMWM...` app; report commits to app ID. | **Escalation Blocked**: Client halts before opening PayPal if scope is elevated. |

---

## 7. Verification & Operational Testing Plan

1. **Verify Offline Test Harness**:
   ```bash
   npm test
   ```
   *Expectation*: All 196+ tests pass. Tests 30a–30d verify that both active session binding and reconstructed paste-audit binding pass without wildcards, and that tampered or missing session slots fail closed.
2. **Verify Cross-Cloud Quote Replay Rejection**:
   Execute Test 20 (`test-verify-security.mjs`) ensuring that GCP vTPM quotes and Oracle Cloud AMD SEV-SNP quotes are rejected at Gate 1 with `tee_type != 0x81`.
3. **Verify MRTD and RTMR2 Pin Mutation**:
   Execute Test 21e and Test 21e2 ensuring that any discrepancy in `RTMR2` (e.g., swapping `initrd.img` or modifying `/init`) causes an immediate hard fail at Gate 2.
   
To eliminate confusion between the copy-paste box and the "Claim" button without compromising the threat model:

    Keep the client keypair (

            
    Pclient,Sclient
    Pclient​,Sclient​

          

    ): It is essential for E2EE against the malicious owner terminating TLS and provides the hardware session binding in

            
    REPORTDATA[32..64]
    REPORTDATA[32..64]

          

    .

    Remove the base64 <textarea> and copy button on /callback: Users should not have to manually handle 15 KB base64 blobs.

    Choose the clean UX model "Downloadable file": The /callback page serves a single button: [ 💾 Download Attestation File (.json) ]. The user saves it and drops it into verify.html. verify.html reads the file, matches the session key from browser storage, decrypts it, and displays the 4-gate verification results.
