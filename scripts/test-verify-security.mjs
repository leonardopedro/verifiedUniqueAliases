// Functional security regression tests for verify.html.
// Loads the ACTUAL <script> from verify.html, stubs the DOM, and drives
// runAudit() against: (1) the genuine captured OCI SNP report (optional,
// GENUINE_REPORT), (2) a spoofed report that pastes a Google AK cert with
// no TPM evidence, (3) a report with a tampered (unpinned) SEV-SNP launch
// digest, (4) nonce-formula parity with the Rust enclave, (5) a legitimate
// GCP report (must still pass — no regression).
//
// Usage:  npm install --no-save node-forge && node scripts/test-verify-security.mjs
//         (or NODE_PATH=/path/to/node_modules node scripts/test-verify-security.mjs)
import { readFileSync } from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
let forge;
try {
  forge = require('node-forge');
} catch {
  console.error('Missing dev dependency: node-forge. Install with:');
  console.error('  npm install --no-save node-forge');
  process.exit(2);
}
globalThis.forge = forge;

const html = readFileSync(new URL('../verify.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*)<\/script>/)[1];

// ---- DOM stubs -------------------------------------------------------------
const elements = {};
function makeEl() {
  const p = { innerHTML: '' };
  return {
    style: {}, innerText: '', innerHTML: '', value: '', className: '',
    querySelector: () => p,
    addEventListener: () => {},
  };
}
globalThis.document = {
  getElementById: (id) => (elements[id] ||= makeEl()),
  addEventListener: () => {},
};
let lastAlert = null;
globalThis.alert = (msg) => { lastAlert = msg; };
// Provenance lookups: fail closed (offline auditor must not crash on this)
globalThis.fetch = async () => ({ ok: false, json: async () => ({}) });

// Evaluate the page script in this global scope
(0, eval)(script);

async function runAuditWith(reportJson) {
  lastAlert = null;
  elements['attestationInput'] = makeEl();
  elements['attestationInput'].value = JSON.stringify(reportJson);
  elements['certInput'] = makeEl();
  elements['certInput'].value = '';
  await runAudit();
  return lastAlert;
}

function fwStatus() {
  return elements['firmwareCheck'];
}

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✅ ${name}`); }
  else { fail++; console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`); }
}

// ---- Optional: a genuine captured OCI report (not committed — instance
// hardware captures are gitignored). Supply via GENUINE_REPORT to enable
// Tests 1 and 3; the self-contained Tests 2/4/5 always run.
const genuinePath = process.env.GENUINE_REPORT || '/tmp/report.json';
let genuine = null;
try { genuine = JSON.parse(readFileSync(genuinePath, 'utf8')); } catch { /* optional */ }
const ghw = genuine && genuine.attestation_report.hardware_level_attestation;
const snp = ghw && ghw.snp_report_b64
  ? Uint8Array.from(atob(ghw.snp_report_b64), c => c.charCodeAt(0))
  : null;
const genuineMeasurement = snp ? Buffer.from(snp.subarray(144, 192)).toString('hex') : null;

// Test 1: genuine report — launch digest must be recognized as pinned
console.log('\nTest 1: genuine OCI report — measurement pinning');
if (genuineMeasurement) {
  const pinned = script.includes(`'${genuineMeasurement}'`);
  check('captured launch digest is pinned in EXPECTED_SNP_MEASUREMENTS', pinned,
    `measurement=${genuineMeasurement}`);
} else {
  console.log('  ⚠️ skipped (no GENUINE_REPORT capture available — self-contained tests still run)');
}

// Test 2: spoofed Google-cert report must NOT pass the silicon root
console.log('\nTest 2: Google-cert paste spoof (Critical Vuln 1)');
{
  // The attacker pastes a Google AK certificate. The historical repo copies
  // were truncated, so build a syntactically-valid cert with the ALLOWLISTED
  // issuer ('EK/AK CA Intermediate') — a real complete cert is public data
  // (every GCP VM exposes its own), so issuer checks cannot be the only gate.
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const spoofCert = forge.pki.createCertificate();
  spoofCert.publicKey = keys.publicKey;
  spoofCert.serialNumber = '01';
  spoofCert.validity.notBefore = new Date(Date.now() - 86400000);
  spoofCert.validity.notAfter = new Date(Date.now() + 86400000);
  const dn = [
    { name: 'commonName', value: 'attacker-controlled' },
    { name: 'organizationName', value: 'EK/AK CA Intermediate' },
  ];
  spoofCert.setSubject(dn);
  spoofCert.setIssuer(dn); // self-signed, but issuer string matches the allowlist
  spoofCert.sign(keys.privateKey, forge.md.sha256.create());
  const cert = forge.pki.certificateToPem(spoofCert);
  // Attacker signs the report with THEIR OWN key — the enclave public key
  // travels inside the report, so the signature check passes by construction.
  // This mirrors the real threat: attacker-run code producing a self-consistent
  // report and pasting the public Google cert as the silicon anchor.
  const { generateKeyPairSync, sign: rsaSign } = await import('crypto');
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  // reorder() in the page sorts keys recursively — replicate it
  const reorder = (obj) => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return obj;
    const out = {};
    Object.keys(obj).sort().forEach(k => { out[k] = reorder(obj[k]); });
    return out;
  };
  const reportBody = {
    custom_info: 'attacker_wallet',
    enclave_config: { boot_measurements: { binary_sha256: 'aa'.repeat(32), disk_manifest: {} }, domain: 'x' },
    paypal_user_info_raw_hash: '11'.repeat(32),
    hardware_level_attestation: {
      google_ak_cert_pem: cert,   // public data pasted in
      // no ak_pub_pem / tpm_quote_msg / tpm_quote_sig, no SNP report
    },
    timestamp_ms: Date.now(),
    session_context: {},
  };
  const payload = JSON.stringify(reorder(reportBody));
  const sig = rsaSign('sha256', Buffer.from(payload), privateKey);
  const spoof = {
    attestation_report: reportBody,
    enclave_signature_b64: sig.toString('base64'),
    enclave_signing_public_key: pubPem,
  };
  const alertMsg = await runAuditWith(spoof);
  const fw = fwStatus();
  check('silicon root check fails (firmwareCheck not verified)', !fw || fw.className !== 'verified',
    `className=${fw && fw.className}`);
  check('alert reports audit failure', !!alertMsg && alertMsg.startsWith('Audit Failed'),
    `alert=${alertMsg}`);
  check('spoof blocked by TPM-evidence guard (public cert alone is not silicon)',
    !!alertMsg && /public data and cannot anchor/i.test(alertMsg),
    `alert=${alertMsg}`);
}

// Test 3: tampered launch digest must fail the measurement pin
console.log('\nTest 3: tampered SEV-SNP MEASUREMENT (ghost-enclave guard)');
if (!genuine) {
  console.log('  ⚠️ skipped (no GENUINE_REPORT capture available)');
}
if (genuine) {
  const tampered = JSON.parse(JSON.stringify(genuine));
  const hw2 = tampered.attestation_report.hardware_level_attestation;
  const raw = Buffer.from(hw2.snp_report_b64, 'base64');
  raw[144] ^= 0xff; // flip a byte in the MEASUREMENT field
  hw2.snp_report_b64 = raw.toString('base64');
  const alertMsg = await runAuditWith(tampered);
  const fw = fwStatus();
  check('firmwareCheck fails with tampered digest', fw.className !== 'verified',
    `className=${fw.className}`);
  const desc = fw.querySelector().innerHTML || fw.innerHTML || '';
  check('failure mentions unpinned launch digest', /not pinned/i.test(desc) || /Launch digest/i.test(desc) || /not pinned/i.test(alertMsg || ''),
    `desc=${desc} alert=${alertMsg}`);
}

// Test 4: nonce parity — verify.html expectedNonce must equal the enclave's
// compute_session_nonce for the same inputs (cross-implementation vector)
console.log('\nTest 4: nonce formula parity (custom_info binding)');
{
  // Independent reference implementation of SHA-256(p ∥ k ∥ SHA256(c))
  const { createHash } = await import('crypto');
  const sha256 = (buf) => createHash('sha256').update(buf).digest();
  const paypalHash = sha256(Buffer.from('{"sub":"user"}'));
  const pubkeyHash = sha256(Buffer.from('fake-der-bytes'));
  const customInfoHash = sha256(Buffer.from('walletA'));
  const reference = sha256(Buffer.concat([paypalHash, pubkeyHash, customInfoHash])).toString('hex');

  // The same computation as written in verify.html's runAudit()
  const customInfoStr = 'walletA';
  const ciHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(customInfoStr)));
  const combined = new Uint8Array(96);
  combined.set(paypalHash);
  combined.set(pubkeyHash, 32);
  combined.set(ciHash, 64);
  const jsNonce = Buffer.from(await crypto.subtle.digest('SHA-256', combined)).toString('hex');
  check('JS expectedNonce matches independent reference', jsNonce === reference,
    `js=${jsNonce} ref=${reference}`);

  // The Rust side pins this exact vector in security_tests::session_nonce_binds_custom_info
  const RUST_PIN = 'be61c8edada1a19eb7a08176084fd25c5d2c13621f020ea6c5a5713ee668f2da';
  check('JS expectedNonce matches the Rust-pinned parity vector', jsNonce === RUST_PIN,
    `js=${jsNonce} rustPin=${RUST_PIN}`);
}

// Test 5: legitimate GCP report (Google cert + fully-verified TPM quote) must PASS
console.log('\nTest 5: legitimate GCP report still passes (no regression)');
{
  const { generateKeyPairSync, sign: rsaSign, createHash } = await import('crypto');
  const sha256 = (b) => createHash('sha256').update(b).digest();

  // Enclave signing key (attacker-independent; just needs to self-consistently sign)
  const enc = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const encPem = enc.publicKey.export({ type: 'spki', format: 'pem' }).toString();

  // Session AK keypair (stands in for tpm2_createprimary AK)
  const ak = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const akPem = ak.publicKey.export({ type: 'spki', format: 'pem' }).toString();

  const customInfo = 'gcp_wallet_xyz';
  const reportBody = {
    custom_info: customInfo,
    enclave_config: {
      boot_measurements: {
        binary_sha256: 'bb'.repeat(32),
        disk_manifest: { 'EFI/BOOT/vmlinuz': 'cc'.repeat(32), 'EFI/BOOT/initrd.img': 'dd'.repeat(32), 'EFI/BOOT/grub.cfg': 'ee'.repeat(32) },
      },
      domain: 'login.example.com',
    },
    paypal_user_info_raw_hash: '11'.repeat(32),
    session_context: {},
    timestamp_ms: Date.now(),
    hardware_level_attestation: null, // filled below (needs nonce)
  };

  // Expected nonce — same formula as runAudit step 1
  // NOTE: pubkey hash is over the raw DER (SPKI), not the PEM text — matches
  // the enclave's PKey::public_key_to_der() and the page's pemToBuffer().
  const pemToDer = (pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const ciHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(customInfo)));
  const combined = new Uint8Array(96);
  combined.set(Buffer.from(reportBody.paypal_user_info_raw_hash, 'hex'));
  combined.set(new Uint8Array(sha256(pemToDer(encPem))), 32);
  combined.set(ciHash, 64);
  const expectedNonceHex = Buffer.from(await crypto.subtle.digest('SHA-256', combined)).toString('hex');

  // PCR values: all five quoted PCRs; pcr_15 must equal calculatePcr15(manifest)
  const pcr15 = await calculatePcr15(reportBody.enclave_config.boot_measurements.disk_manifest);
  const pcrValues = {};
  for (const p of [0, 4, 8, 9]) pcrValues['pcr_' + p] = sha256(Buffer.from(`pcr${p}`)).toString('hex');
  pcrValues['pcr_15'] = pcr15;

  // Composite digest = SHA256(concat of the 5 PCR digests in order 0,4,8,9,15)
  const composite = sha256(Buffer.concat([0, 4, 8, 9, 15].map(p => Buffer.from(pcrValues['pcr_' + p], 'hex'))));

  // Build TPMS_ATTEST exactly as parseTpmsAttest expects
  const qSigner = Buffer.alloc(32, 0x41);
  const extra = Buffer.from(expectedNonceHex, 'hex');
  const parts = [];
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32BE(0xFF544347, 0); // magic
  hdr.writeUInt16BE(0x8018, 4);     // ST_ATTEST_QUOTE
  hdr.writeUInt16BE(qSigner.length, 6);
  parts.push(hdr, qSigner);
  const edSz = Buffer.alloc(2); edSz.writeUInt16BE(extra.length, 0);
  parts.push(edSz, extra);
  const tail = Buffer.alloc(17 + 8, 0); // clockInfo + firmwareVersion
  parts.push(tail);
  const selCount = Buffer.alloc(4); selCount.writeUInt32BE(1, 0);
  parts.push(selCount);
  const pcrSel = Buffer.from([0x00, 0x0b, 0x03, 0x00, 0x04, 0x0f]); // sha256 bank, 3 bytes select
  parts.push(pcrSel);
  const dgSz = Buffer.alloc(2); dgSz.writeUInt16BE(composite.length, 0);
  parts.push(dgSz, composite);
  const quoteMsg = Buffer.concat(parts);
  const quoteSig = rsaSign('sha256', quoteMsg, ak.privateKey);

  // Google AK cert with the allowlisted issuer (public data by design)
  const gkeys = forge.pki.rsa.generateKeyPair(2048);
  const gcert = forge.pki.createCertificate();
  gcert.publicKey = gkeys.publicKey;
  gcert.serialNumber = '02';
  gcert.validity.notBefore = new Date(Date.now() - 86400000);
  gcert.validity.notAfter = new Date(Date.now() + 86400000);
  const gdn = [{ name: 'commonName', value: 'gcp-instance' }, { name: 'organizationName', value: 'EK/AK CA Intermediate' }];
  gcert.setSubject(gdn); gcert.setIssuer(gdn);
  gcert.sign(gkeys.privateKey, forge.md.sha256.create());
  const googleCertPem = forge.pki.certificateToPem(gcert);

  reportBody.hardware_level_attestation = {
    ak_pub_pem: akPem,
    tpm_quote_msg: quoteMsg.toString('base64'),
    tpm_quote_sig: quoteSig.toString('base64'),
    pcr_values: pcrValues,
    google_ak_cert_pem: googleCertPem,
    platform_type: 'GCP',
  };

  const payload = JSON.stringify(reorder(reportBody));
  const sig = rsaSign('sha256', Buffer.from(payload), enc.privateKey);
  const gcpReport = {
    attestation_report: reportBody,
    enclave_signature_b64: sig.toString('base64'),
    enclave_signing_public_key: encPem,
  };

  const alertMsg = await runAuditWith(gcpReport);
  const fw = fwStatus();
  check('no audit-failure alert', !alertMsg, `alert=${alertMsg}`);
  check('silicon root verified (firmwareCheck passes)', fw && fw.className.includes('verified'),
    `className=${fw && fw.className}`);
  const tpmEl = document.getElementById('tpmCheck');
  check('TPM quote verified strictly', tpmEl && tpmEl.className.includes('verified'),
    `className=${tpmEl && tpmEl.className}`);
}

// Test 6 (audit SEC-04): an OCI-claiming report (SNP evidence present) must
// NOT be satisfiable by a locally-forged TPM quote + pasted Google cert.
// Historically `googleVerified || snpVerified` let this pass: the TPM quote
// is fully self-consistent on ANY TPM 2.0 machine (right nonce, right PCR
// digest) and the Google EK cert is public data.
console.log('\nTest 6: OCI report + forged local TPM quote + Google cert (SEC-04 bypass)');
{
  const { generateKeyPairSync, sign: rsaSign, createHash } = await import('crypto');
  const sha256 = (b) => createHash('sha256').update(b).digest();

  const enc = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const encPem = enc.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const ak = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const akPem = ak.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const customInfo = 'oci_spoof_wallet';
  const reportBody = {
    custom_info: customInfo,
    enclave_config: {
      boot_measurements: { binary_sha256: 'cc'.repeat(32), disk_manifest: {} },
      domain: 'x',
    },
    paypal_user_info_raw_hash: '22'.repeat(32),
    session_context: {},
    timestamp_ms: Date.now(),
    hardware_level_attestation: null, // nonce-dependent
  };
  const pemToDer = (pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const ciHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(customInfo)));
  const combined = new Uint8Array(96);
  combined.set(Buffer.from(reportBody.paypal_user_info_raw_hash, 'hex'));
  combined.set(new Uint8Array(sha256(pemToDer(encPem))), 32);
  combined.set(ciHash, 64);
  const expectedNonceHex = Buffer.from(await crypto.subtle.digest('SHA-256', combined)).toString('hex');

  // Forged but fully self-consistent TPM quote (the attacker's own machine).
  const pcr15 = await calculatePcr15(reportBody.enclave_config.boot_measurements.disk_manifest);
  const pcrValues = {};
  for (const p of [0, 4, 8, 9]) pcrValues['pcr_' + p] = sha256(Buffer.from(`pcr${p}`)).toString('hex');
  pcrValues['pcr_15'] = pcr15;
  const composite = sha256(Buffer.concat([0, 4, 8, 9, 15].map(p => Buffer.from(pcrValues['pcr_' + p], 'hex'))));
  const qSigner = Buffer.alloc(32, 0x41);
  const extra = Buffer.from(expectedNonceHex, 'hex');
  const parts = [];
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32BE(0xFF544347, 0);
  hdr.writeUInt16BE(0x8018, 4);
  hdr.writeUInt16BE(qSigner.length, 6);
  parts.push(hdr, qSigner);
  const edSz = Buffer.alloc(2); edSz.writeUInt16BE(extra.length, 0);
  parts.push(edSz, extra, Buffer.alloc(17 + 8, 0));
  const selCount = Buffer.alloc(4); selCount.writeUInt32BE(1, 0);
  parts.push(selCount, Buffer.from([0x00, 0x0b, 0x03, 0x00, 0x04, 0x0f]));
  const dgSz = Buffer.alloc(2); dgSz.writeUInt16BE(composite.length, 0);
  parts.push(dgSz, composite);
  const quoteMsg = Buffer.concat(parts);
  const quoteSig = rsaSign('sha256', quoteMsg, ak.privateKey);

  const gkeys = forge.pki.rsa.generateKeyPair(2048);
  const gcert = forge.pki.createCertificate();
  gcert.publicKey = gkeys.publicKey;
  gcert.serialNumber = '03';
  gcert.validity.notBefore = new Date(Date.now() - 86400000);
  gcert.validity.notAfter = new Date(Date.now() + 86400000);
  const gdn = [{ name: 'commonName', value: 'spoof' }, { name: 'organizationName', value: 'EK/AK CA Intermediate' }];
  gcert.setSubject(gdn); gcert.setIssuer(gdn);
  gcert.sign(gkeys.privateKey, forge.md.sha256.create());

  // Garbage SNP evidence: the report CLAIMS OCI (vcek+report present) but the
  // bytes are attacker-controlled, so the SNP path can never verify.
  const fakeSnp = Buffer.alloc(1184, 0x5a).toString('base64');
  const fakeVcek = Buffer.from('not-a-cert').toString('base64');
  reportBody.hardware_level_attestation = {
    ak_pub_pem: akPem,
    tpm_quote_msg: quoteMsg.toString('base64'),
    tpm_quote_sig: quoteSig.toString('base64'),
    pcr_values: pcrValues,
    google_ak_cert_pem: forge.pki.certificateToPem(gcert),
    snp_report_b64: fakeSnp,
    vcek_der_b64: fakeVcek,
    platform_type: 'OCI SEV-SNP',
  };

  const payload = JSON.stringify(reorder(reportBody));
  const sig = rsaSign('sha256', Buffer.from(payload), enc.privateKey);
  const spoof = {
    attestation_report: reportBody,
    enclave_signature_b64: sig.toString('base64'),
    enclave_signing_public_key: encPem,
  };

  // Stub provenance: every lookup 404s (nothing here is CI-built)
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ attestations: [] }) });
  const alertMsg = await runAuditWith(spoof);
  globalThis.fetch = realFetch;

  const fw = fwStatus();
  check('silicon root FAILS (platform enforcement kills the OR-bypass)',
    !fw || fw.className !== 'verified', `className=${fw && fw.className}`);
  check('audit fails with an alert', !!alertMsg && alertMsg.startsWith('Audit Failed'), `alert=${alertMsg}`);
  check('failure is the silicon root, not something earlier',
    !!alertMsg && /Silicon Root of Trust/i.test(alertMsg), `alert=${alertMsg}`);
  const gh = document.getElementById('githubCheck');
  const ghDesc = (gh && (gh.innerHTML || (gh.querySelector() && gh.querySelector().innerHTML))) || '';
  check('provenance diagnostics explain the unattested binary (no bare ❌)',
    /no GitHub attestation exists for this exact SHA-256/i.test(ghDesc), `ghDesc=${ghDesc.slice(0, 200)}`);
  check('provenance diagnostics flag the empty disk_manifest',
    /empty disk_manifest/i.test(ghDesc), `ghDesc=${ghDesc.slice(0, 200)}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
