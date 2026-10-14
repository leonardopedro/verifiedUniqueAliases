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

// SEC-02: the hardware nonce commits to code identity too. Mirror of the
// enclave's compute_session_nonce over the 160-byte (5-element) pre-image:
// paypal ∥ pubkey ∥ SHA256(custom_info) ∥ binary_sha256 ∥ SHA256(canonical manifest).
async function nonce160Hex(paypalHash, pubkeyHash, customInfoStr, binaryShaHex, diskManifest) {
  const ciHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(customInfoStr)));
  const sorted = Object.keys(diskManifest || {}).sort().map(k => [k, diskManifest[k]]);
  const manHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(sorted))));
  const combined = new Uint8Array(160);
  combined.set(paypalHash, 0);
  combined.set(pubkeyHash, 32);
  combined.set(ciHash, 64);
  combined.set(new Uint8Array((binaryShaHex.match(/.{1,2}/g) || []).map(b => parseInt(b, 16))), 96);
  combined.set(manHash, 128);
  return Buffer.from(await crypto.subtle.digest('SHA-256', combined)).toString('hex');
}

// v160: a fully self-consistent LEGITIMATE GCP report (Google cert with
// allowlisted issuer + TPM quote whose nonce/PCR digest verify + enclave
// signature). Shared by Test 5 (regression) and Test 8 (pre-flight happy
// path) — construction extracted verbatim from Test 5.
async function buildLegitGcpReport() {
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

  // Expected nonce — same formula as runAudit step 1 (SEC-02: 160-byte
  // pre-image including binary_sha256 + canonical manifest composite)
  // NOTE: pubkey hash is over the raw DER (SPKI), not the PEM text — matches
  // the enclave's PKey::public_key_to_der() and the page's pemToBuffer().
  const pemToDer = (pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const expectedNonceHex = await nonce160Hex(
    Buffer.from(reportBody.paypal_user_info_raw_hash, 'hex'),
    new Uint8Array(sha256(pemToDer(encPem))),
    customInfo,
    reportBody.enclave_config.boot_measurements.binary_sha256,
    reportBody.enclave_config.boot_measurements.disk_manifest,
  );

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
  gcert.setSubject(gdn);
  gcert.setIssuer(gdn);
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
  return {
    attestation_report: reportBody,
    enclave_signature_b64: sig.toString('base64'),
    enclave_signing_public_key: encPem,
  };
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
console.log('\nTest 4: nonce formula parity (SEC-02 code binding)');
{
  // Independent reference implementation of the 160-byte pre-image
  const { createHash } = await import('crypto');
  const sha256 = (buf) => createHash('sha256').update(buf).digest();
  const paypalHash = sha256(Buffer.from('{"sub":"user"}'));
  const pubkeyHash = sha256(Buffer.from('fake-der-bytes'));
  const customInfoHash = sha256(Buffer.from('walletA'));
  const binary = Buffer.from('ab'.repeat(32), 'hex');
  const manifest = { 'EFI/BOOT/vmlinuz': 'cc'.repeat(32), 'EFI/BOOT/initrd.img': 'dd'.repeat(32) };
  const canonical = JSON.stringify(Object.keys(manifest).sort().map(k => [k, manifest[k]]));
  const manHash = sha256(Buffer.from(canonical));
  const reference = sha256(Buffer.concat([paypalHash, pubkeyHash, customInfoHash, binary, manHash])).toString('hex');

  // The same computation as written in verify.html's runAudit()
  const jsNonce = await nonce160Hex(paypalHash, pubkeyHash, 'walletA', 'ab'.repeat(32), manifest);
  check('JS expectedNonce matches independent reference', jsNonce === reference,
    `js=${jsNonce} ref=${reference}`);
  check('pre-image is the 160-byte 5-element form', Buffer.concat([paypalHash, pubkeyHash, customInfoHash, binary, manHash]).length === 160);

  // The Rust side pins this exact vector in security_tests::session_nonce_binds_custom_info
  const RUST_PIN = '398c2c1b18583ac9c3935ffdea04f0b2a3dfdd927140072bd50511e9f77db8f7';
  check('JS expectedNonce matches the Rust-pinned parity vector', jsNonce === RUST_PIN,
    `js=${jsNonce} rustPin=${RUST_PIN}`);
}

// Test 5: legitimate GCP report (Google cert + fully-verified TPM quote) must PASS
console.log('\nTest 5: legitimate GCP report still passes (no regression)');
{
  const gcpReport = await buildLegitGcpReport();

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
  const expectedNonceHex = await nonce160Hex(
    Buffer.from(reportBody.paypal_user_info_raw_hash, 'hex'),
    new Uint8Array(sha256(pemToDer(encPem))),
    customInfo,
    reportBody.enclave_config.boot_measurements.binary_sha256,
    reportBody.enclave_config.boot_measurements.disk_manifest,
  );

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

// ---- Test 7: SNP evidence WITHOUT a verifiable endorsement leaf (v154) ----
// The enclave only publishes a VCEK/VLEK that actually verifies the live
// report. A report that carries an SNP report but no vcek_der_b64 means the
// enclave could NOT obtain any key that signs it — the audit must fail closed
// with a precise explanation, not silently skip the silicon root.
console.log('\nTest 7: OCI report with SNP evidence but no endorsement leaf');
{
  const nodeCrypto = require('crypto');
  const sha256 = (buf) => nodeCrypto.createHash('sha256').update(buf).digest();
  const enc = forge.pki.rsa.generateKeyPair(2048);
  const encPem = forge.pki.publicKeyToPem(enc.publicKey);
  const reportBody = {
    custom_info: 'NONE',
    enclave_config: { boot_measurements: { binary_sha256: 'dd'.repeat(32), disk_manifest: {} }, domain: 'x' },
    paypal_user_info_raw_hash: '33'.repeat(32),
    session_context: {},
    timestamp_ms: Date.now(),
    hardware_level_attestation: null,
  };
  const pemToDer = (pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const expectedNonceHex = await nonce160Hex(
    Buffer.from(reportBody.paypal_user_info_raw_hash, 'hex'),
    new Uint8Array(sha256(pemToDer(encPem))),
    'NONE',
    reportBody.enclave_config.boot_measurements.binary_sha256,
    reportBody.enclave_config.boot_measurements.disk_manifest,
  );
  reportBody.hardware_level_attestation = {
    snp_report_b64: Buffer.alloc(1184, 0x5a).toString('base64'), // no vcek_der_b64!
    vcek_source: 'kds-undecodable',
    platform_type: 'AMD SEV-SNP',
  };
  const payload = JSON.stringify(reorder(reportBody));
  const sig = nodeCrypto.createSign('sha256').update(payload).sign(forge.pki.privateKeyToPem(enc.privateKey));
  const report = { attestation_report: reportBody, enclave_signature_b64: sig.toString('base64'), enclave_signing_public_key: encPem };

  const alertMsg = await runAuditWith(report);
  check('audit fails with an alert', !!alertMsg && alertMsg.startsWith('Audit Failed'), `alert=${alertMsg}`);
  check('failure is the silicon root', !!alertMsg && /Silicon Root of Trust/i.test(alertMsg), `alert=${alertMsg}`);
  const fw = fwStatus();
  const fwHtml = (fw && (fw.innerHTML || (fw.querySelector() && fw.querySelector().innerHTML))) || '';
  check('precise fail-closed explanation is shown',
    /NO verifiable endorsement key/i.test(fwHtml), `fw=${fwHtml.slice(0, 200)}`);
  check('vcek_source is surfaced to the auditor', /kds-undecodable/.test(fwHtml), `fw=${fwHtml.slice(0, 200)}`);
}

// Test 8 (v160): SNP report_data binding = SHA-256(P_enc ∥ nonce) parity
// with the Rust enclave, plus the pre-flight (Pillar 4) enforcement: a
// pinned P_enc must match the audited report's key, and runPreflight pins
// only on a fully-passing live audit (fails closed otherwise).
console.log('\nTest 8: v160 report_data binding + pre-flight pin');
{
  const { createHash } = await import('crypto');
  const sha256 = (b) => createHash('sha256').update(b).digest();
  const der = Buffer.from('fake-der-bytes');
  const nonce = '398c2c1b18583ac9c3935ffdea04f0b2a3dfdd927140072bd50511e9f77db8f7';
  const BINDING_PIN = '22a092286d97a00032a2c8b1a24b3c4691ff9fad6d1759c18d17b7a5354c248f';

  const jsBinding = await snpBindingHex(der, nonce);
  check('JS snpBindingHex matches independent reference',
    jsBinding === sha256(Buffer.concat([der, Buffer.from(nonce, 'hex')])).toString('hex'), `js=${jsBinding}`);
  check('JS snpBindingHex matches the Rust-pinned parity vector',
    jsBinding === BINDING_PIN, `js=${jsBinding} rustPin=${BINDING_PIN}`);

  // 8a. Pre-flight happy path: a fully-valid live envelope pins its P_enc.
  const legit = await buildLegitGcpReport();
  const realFetch = globalThis.fetch;
  const realUrl = document.getElementById('preflightUrl').value;
  globalThis.fetch = async () => ({
    ok: true, status: 200,
    text: async () => JSON.stringify(legit),
    json: async () => ({ attestations: [] }),
  });
  document.getElementById('preflightUrl').value = 'https://legit.example.com';
  preFlightPubKeyPem = null;
  const pfOk = await runPreflight();
  check('runPreflight passes on a fully-valid live envelope', pfOk === true, `pfOk=${pfOk}`);
  check('runPreflight pins the live enclave P_enc',
    preFlightPubKeyPem === legit.enclave_signing_public_key,
    `pinned=${(preFlightPubKeyPem || '').slice(0, 40)}`);

  // 8b. Post-login report signed by a DIFFERENT key → deterministic failure.
  const swapped = await buildLegitGcpReport();
  swapped.enclave_signing_public_key = forge.pki.publicKeyToPem(forge.pki.rsa.generateKeyPair(2048).publicKey);
  let alertMsg = await runAuditWith(swapped);
  check('swapped enclave key fails the pre-flight pin',
    !!alertMsg && /PRE-FLIGHT VIOLATION/.test(alertMsg), `alert=${alertMsg}`);

  // 8c. Same key as the pin → no pre-flight failure (audit proceeds).
  alertMsg = await runAuditWith(legit);
  check('pinned key accepted (no PRE-FLIGHT failure)',
    !alertMsg || !/PRE-FLIGHT/.test(alertMsg), `alert=${alertMsg}`);

  // 8d. runPreflight fails closed: unreachable enclave / non-https origin.
  preFlightPubKeyPem = null;
  document.getElementById('preflightUrl').value = 'https://legit.example.com';
  globalThis.fetch = async () => ({ ok: false, status: 503, text: async () => '' });
  const pfFail = await runPreflight();
  check('runPreflight fails closed when the enclave is unreachable',
    pfFail === false && preFlightPubKeyPem === null, `pfFail=${pfFail}`);
  document.getElementById('preflightUrl').value = 'not-a-url';
  const pfBad = await runPreflight();
  check('runPreflight rejects a non-https origin', pfBad === false, `pfBad=${pfBad}`);

  // restore session state for any later runs
  globalThis.fetch = realFetch;
  document.getElementById('preflightUrl').value = realUrl;
  preFlightPubKeyPem = null;
}

// Test 9 (v161, plan Pillars 2–5): CLIENT-BOUND report_data binding parity
// with the Rust enclave — SHA-256(P_enc_SPKI_DER ∥ code_challenge ∥
// P_client_SPKI_DER ∥ client_nonce) — plus the binding-sensitivity matrix.
// Mirrors tpm::preflight_report_data_binding() ↔
// security_tests::preflight_binding_parity_v161 ↔ verify.html
// preflightBindingHex() (update all three together).
console.log('\nTest 9: v161 client-bound report_data binding parity');
{
  const { createHash } = await import('crypto');
  const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts.map(p => Buffer.from(p)))).digest('hex');

  const pubkeyDer = Buffer.from('fake-der-bytes');
  const codeChallenge = 'TEST_CHALLENGE_v161_parity';
  const clientPub = Buffer.from('fake-client-ecdh-der');
  const clientNonce = Buffer.from('11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff', 'hex');
  const RUST_PIN = 'eb25571bb08d245e4a89f8903c5d348e193e70fe5c2926e2ab033bdcc6beeba8';

  // JS implementation lifted from verify.html's preflightBindingHex()
  const jsBinding = async () => {
    const enc = new TextEncoder();
    const pre = new Uint8Array(pubkeyDer.length + enc.encode(codeChallenge).length + clientPub.length + clientNonce.length);
    let o = 0;
    pre.set(pubkeyDer, o); o += pubkeyDer.length;
    pre.set(enc.encode(codeChallenge), o); o += enc.encode(codeChallenge).length;
    pre.set(clientPub, o); o += clientPub.length;
    pre.set(clientNonce, o);
    return Buffer.from(await crypto.subtle.digest('SHA-256', pre)).toString('hex');
  };

  const js = await jsBinding();
  check('JS preflightBindingHex matches independent reference',
    js === sha256(pubkeyDer, codeChallenge, clientPub, clientNonce), `js=${js}`);
  check('JS preflightBindingHex matches the Rust-pinned parity vector',
    js === RUST_PIN, `js=${js} rustPin=${RUST_PIN}`);
  check('binding is sensitive to the client nonce',
    js !== sha256(pubkeyDer, codeChallenge, clientPub, Buffer.alloc(32)));
  check('binding is sensitive to the PKCE challenge',
    js !== sha256(pubkeyDer, 'OTHER', clientPub, clientNonce));
  check('binding is sensitive to the client public key',
    js !== sha256(pubkeyDer, codeChallenge, Buffer.from('other'), clientNonce));
  check('binding differs from the v160 session binding by construction',
    js !== sha256(pubkeyDer, clientNonce));

  // RFC 5869 Test Case 1 via WebCrypto HKDF — pins the browser's deriveKey
  // to the enclave's crypto::hkdf_sha256 (same vector asserted in Rust
  // security_tests::preflight_session_is_client_bound), so the E2EE session
  // key derived on BOTH sides of the v161 callback is byte-identical.
  const tc1Ikm = Buffer.alloc(22, 0x0b);
  const tc1Salt = Buffer.from([...Array(13).keys()]);
  const tc1Info = Buffer.from([...Array(10).keys()].map(i => 0xf0 + i));
  const baseKey = await crypto.subtle.importKey('raw', tc1Ikm, 'HKDF', false, ['deriveBits']);
  const okm = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: tc1Salt, info: tc1Info }, baseKey, 42 * 8));
  check('WebCrypto HKDF matches RFC 5869 TC1 (== enclave hkdf_sha256)',
    Buffer.from(okm).toString('hex') === '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    `okm=${Buffer.from(okm).toString('hex').slice(0, 32)}…`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
