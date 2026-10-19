// Functional security regression tests for verify.html — the REAL <script>
// is evaluated (indirect eval) and runAudit() is driven end-to-end with
// synthetic, spec-exact fixtures. No mocked verification logic: every check
// the page performs is executed for real.
//
// Covered (TDX path — Intel quote ABI v4/v5 per Intel's DCAP reference
// implementation, dcap-qvl 0.6.3):
//   * positive audits for v4, v5/TDREPORT10, v5/TDREPORT15 quotes
//   * session binding (report_data @520..584 — NOT "last 64 bytes")
//   * MRTD display offset (mr_td @136..184 — NOT @16)
//   * quote signed by the ATTESTATION KEY (not the PCK key)
//   * attestation key bound into the QE report; QE report signed by PCK leaf
//   * PCK chain walk to the SHA-256-pinned Intel SGX Root CA
//   * negative paths: wrong nonce, tampered sigs, unpinned attacker root,
//     bad header fields, wrong cert types, unsigned TDREPORT, no evidence
//   * regression guards: Google-cert spoof, legit GCP report (port of the
//     oraclecloud harness), pre-flight pin, enclave-signature hard fail,
//     provenance fail-closed, static source pins (no old bogus offsets)
//
// Usage:  npm install --no-save node-forge && node scripts/test-verify-security.mjs
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { execFileSync, spawnSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import { createRequire } from 'module';
import { generateKeyPairSync, sign as rsaSign, createHash } from 'crypto';

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

const repoRoot = new URL('..', import.meta.url).pathname;
const html = readFileSync(join(repoRoot, 'verify.html'), 'utf8');
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

// Provenance lookups (GitHub attestations) — configurable per test.
let fetchMode = 'ok'; // 'ok' = every hash attested by run #777; '404' = unattested
globalThis.fetch = async () => {
  if (fetchMode === 'ok') {
    const payload = Buffer.from(JSON.stringify({
      predicate: { runDetails: { metadata: { invocationId: '777' } } },
    })).toString('base64');
    return {
      ok: true, status: 200,
      json: async () => ({ attestations: [{ bundle: { payload } }] }),
    };
  }
  return { ok: false, status: 404, json: async () => ({}) };
};

// Evaluate the page script in this global scope (function decls + var leak
// to globalThis; const/let stay in the eval's lexical scope).
(0, eval)(script);

async function runAuditWith(envelope) {
  lastAlert = null;
  document.getElementById('attestationInput').value = JSON.stringify(envelope);
  document.getElementById('certInput').value = '';
  const ok = await runAudit();
  return { ok, alert: lastAlert };
}
const fwDesc = () => {
  const el = elements['firmwareCheck'];
  return el ? (el.querySelector().innerHTML || el.innerHTML || '') : '';
};
const row = (id) => {
  const el = elements[id];
  return el ? { cls: el.className, desc: el.querySelector().innerHTML || '' } : { cls: '', desc: '' };
};

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✅ ${name}`); }
  else { fail++; console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`); }
}

// ---- shared crypto/serialization helpers -----------------------------------
const sha256 = (b) => createHash('sha256').update(b).digest();
const pemToDer = (pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
const concat = (...arrs) => {
  const t = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let o = 0;
  for (const a of arrs) { t.set(a, o); o += a.length; }
  return t;
};
const u16le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const u32le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const hex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const fillAt = (a, off, len, v) => a.fill(v, off, off + len);

// SEC-02 nonce mirror: SHA-256(paypal ∥ pubkey ∥ SHA256(custom_info) ∥
// binary_sha256 ∥ SHA256(canonical manifest)) over the 160-byte pre-image.
async function nonce160Hex(paypalHash, pubkeyHash, customInfoStr, binaryShaHex, diskManifest) {
  const ciHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(customInfoStr)));
  const sorted = Object.keys(diskManifest || {}).sort().map(k => [k, diskManifest[k]]);
  const manHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(sorted))));
  const combined = new Uint8Array(160);
  combined.set(paypalHash, 0);
  combined.set(pubkeyHash, 32);
  combined.set(ciHash, 64);
  combined.set(fromHex(binaryShaHex), 96);
  combined.set(manHash, 128);
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', combined)));
}

const INTEL_VENDOR = Uint8Array.from([0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07]);
const REAL_INTEL_PIN = '44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3';

// ---- synthetic PCK-style certificate chains (openssl, EC P-256) ------------
// Structurally identical to Intel's hierarchy (root → PCK CA → PCK leaf) so
// only the root SHA-256 pin separates a real chain from an attacker's.
const dir = mkdtempSync(join(tmpdir(), 'verify-harness-'));
function openssl(args) {
  try {
    return execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  } catch (e) {
    console.error('openssl failed:', args.join(' '), '\n', (e.stderr || '') + '');
    process.exit(3);
  }
}
async function makeCertChain({ rootSubject, intSubject, leafSubject }) {
  const extCa = join(dir, 'ca.ext');
  const extLeaf = join(dir, 'leaf.ext');
  writeFileSync(extCa, '[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
  writeFileSync(extLeaf, '[v3_leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
  const out = {};
  // keys: WebCrypto (needed for signing qe_report/quote) ⇄ openssl (certs)
  for (const who of ['root', 'int', 'leaf']) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pk8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const derPath = join(dir, `${who}.pk8.der`);
    const pemPath = join(dir, `${who}.key.pem`);
    writeFileSync(derPath, pk8);
    openssl(['pkcs8', '-topk8', '-nocrypt', '-inform', 'DER', '-in', derPath, '-out', pemPath]);
    out[who] = { key: kp.privateKey, pemPath };
  }
  const subjects = { root: rootSubject, int: intSubject, leaf: leafSubject };
  for (const who of ['root', 'int', 'leaf']) {
    const csr = join(dir, `${who}.csr`);
    openssl(['req', '-new', '-key', out[who].pemPath, '-sha256', '-subj', subjects[who], '-out', csr]);
    const cert = join(dir, `${who}.pem`);
    if (who === 'root') {
      openssl(['x509', '-req', '-in', csr, '-signkey', out[who].pemPath, '-sha256', '-days', '3650',
               '-extfile', extCa, '-extensions', 'v3_ca', '-out', cert]);
    } else if (who === 'int') {
      openssl(['x509', '-req', '-in', csr, '-CA', join(dir, 'root.pem'), '-CAkey', out.root.pemPath,
               '-CAcreateserial', '-sha256', '-days', '3650',
               '-extfile', extCa, '-extensions', 'v3_ca', '-out', cert]);
    } else {
      openssl(['x509', '-req', '-in', csr, '-CA', join(dir, 'int.pem'), '-CAkey', out.int.pemPath,
               '-CAcreateserial', '-sha256', '-days', '3650',
               '-extfile', extLeaf, '-extensions', 'v3_leaf', '-out', cert]);
    }
    out[who].pem = readFileSync(cert, 'utf8');
    out[who].derHex = pemToDer(out[who].pem).toString('hex');
    out[who].sha256 = sha256(pemToDer(out[who].pem)).toString('hex');
  }
  return out;
}

// The audited (positive) chain: structurally Intel-shaped, self-made key.
const goodChain = await makeCertChain({
  rootSubject: '/C=US/ST=CA/L=Santa Clara/O=Intel Corporation/CN=Intel SGX Root CA',
  intSubject: '/C=US/ST=CA/L=Santa Clara/O=Intel Corporation/CN=Intel SGX PCK Platform CA',
  leafSubject: '/C=US/O=Intel Corporation/CN=PCK CntrTest-00aa11bb22cc33dd',
});
// The attacker chain: same DNs (issuer regex cannot tell them apart), fresh keys.
const evilChain = await makeCertChain({
  rootSubject: '/C=US/ST=CA/L=Santa Clara/O=Intel Corporation/CN=Intel SGX Root CA',
  intSubject: '/C=US/ST=CA/L=Santa Clara/O=Intel Corporation/CN=Intel SGX PCK Platform CA',
  leafSubject: '/C=US/O=Intel Corporation/CN=PCK CntrTest-evil99ee88dd77cc',
});
const goodRootSha = goodChain.root.sha256;

// ---- synthetic TD Quote builder (Intel ABI, offsets from dcap-qvl) ---------
async function buildTdxQuote(o) {
  const {
    version = 4, bodyType = 2, reportData, innerChainPems, leafKey,
    tamperQuoteSig = false, corruptQeReportData = false, quoteSigByPckKey = false,
    vendorId = INTEL_VENDOR, teeType = 0x81, attKeyType = 2,
    outerCertType = 6, forceBodySize = null, mrtdFill = 0x42,
  } = o;
  if (!reportData || reportData.length !== 64) throw new Error('reportData must be 64 bytes');
  const bodyLen = bodyType === 3 ? 648 : 584;
  const hdr = new Uint8Array(48 + (version === 5 ? 6 : 0) + bodyLen);
  // header: version u16@0, att_key_type u16@2, tee_type u32@4, svn@8/10, vendor@12, user_data@28
  hdr.set(u16le(version), 0);
  hdr.set(u16le(attKeyType), 2);
  hdr.set(u32le(teeType), 4);
  hdr[8] = 1; hdr[10] = 1;
  hdr.set(vendorId, 12);
  let bodyOff = 48;
  if (version === 5) {
    hdr.set(u16le(bodyType), 48);
    hdr.set(u32le(forceBodySize ?? bodyLen), 50);
    bodyOff = 54;
  }
  const body = hdr.subarray(bodyOff);
  // TDREPORT10 body layout (584 B)
  fillAt(body, 0, 16, 0x11);    // tee_tcb_svn
  fillAt(body, 16, 48, 0x22);   // mr_seam
  fillAt(body, 64, 48, 0x33);   // mr_signer_seam
  fillAt(body, 112, 8, 0x44);   // seam_attributes
  fillAt(body, 120, 8, 0x55);   // td_attributes
  fillAt(body, 128, 8, 0x66);   // xfam
  fillAt(body, 136, 48, mrtdFill); // mr_td (MRTD) @136
  fillAt(body, 184, 48, 0x77);  // mr_config_id
  fillAt(body, 232, 48, 0x88);  // mr_owner
  fillAt(body, 280, 48, 0x99);  // mr_owner_config
  for (let k = 0; k < 4; k++) fillAt(body, 328 + k * 48, 48, 0xa0 + k); // rt_mr0..3
  body.set(reportData, 520);    // report_data @520..584 (TD15 appends AFTER it)
  if (bodyLen === 648) { fillAt(body, 584, 16, 0xbb); fillAt(body, 600, 48, 0xcc); } // tee_tcb_svn2 + mr_service_td
  // attestation key (raw X||Y) + quote signature over header(+preamble)||body
  const att = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const attRaw = new Uint8Array(await crypto.subtle.exportKey('raw', att.publicKey)).subarray(1); // strip 0x04
  const signed = hdr.subarray(0, bodyOff + bodyLen);
  let qsig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
    quoteSigByPckKey ? leafKey : att.privateKey, signed));
  if (tamperQuoteSig) qsig[10] ^= 0xff;
  // QE report certification data (cert_type 6)
  const qeAuth = new Uint8Array(32).fill(0x5a);
  const qeReport = new Uint8Array(384);
  fillAt(qeReport, 0, 16, 0x10);  // cpu_svn
  fillAt(qeReport, 48, 16, 0x07); // attributes
  fillAt(qeReport, 64, 32, 0x3d); // mr_enclave
  fillAt(qeReport, 128, 32, 0x4e);// mr_signer
  const pre = concat(attRaw, qeAuth);
  let qhash = new Uint8Array(await crypto.subtle.digest('SHA-256', pre));
  if (corruptQeReportData) qhash[0] ^= 0xff;
  qeReport.set(qhash, 320); // report_data[0..32]; [32..64] stays zero
  const qeSig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, leafKey, qeReport));
  const innerText = innerChainPems.join('\n') + '\n';
  const innerBytes = Uint8Array.from(Buffer.from(innerText, 'utf8'));
  let certBody;
  if (outerCertType === 6) {
    certBody = concat(qeReport, qeSig, u16le(32), qeAuth, u16le(5), u32le(innerBytes.length), innerBytes);
  } else {
    certBody = innerBytes; // raw chain as cert body (rejected: no QE binding possible)
  }
  const auth = concat(qsig, attRaw, u16le(outerCertType), u32le(certBody.length), certBody);
  const quote = concat(signed, u32le(auth.length), auth);
  return { b64: Buffer.from(quote).toString('base64') };
}

// ---- report/envelope builder ----------------------------------------------
const DISK_MANIFEST = {
  'EFI/BOOT/vmlinuz': 'cc'.repeat(32),
  'EFI/BOOT/initrd.img': 'dd'.repeat(32),
  'EFI/BOOT/grub.cfg': 'ee'.repeat(32),
};
const BINARY_SHA = 'bb'.repeat(32);
async function buildEnvelope({ hw, customInfo = 'wallet_test_1', corruptEnclaveSig = false, hwBuilder }) {
  const enc = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const encPem = enc.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const report = {
    custom_info: customInfo,
    enclave_config: {
      boot_measurements: { binary_sha256: BINARY_SHA, disk_manifest: DISK_MANIFEST },
      domain: 'login.airma.de',
    },
    paypal_user_info_raw_hash: '11'.repeat(32),
    session_context: {},
    timestamp_ms: Date.now(),
    hardware_level_attestation: hw || null,
  };
  const nonce = await nonce160Hex(
    fromHex(report.paypal_user_info_raw_hash),
    new Uint8Array(sha256(pemToDer(encPem))),
    customInfo, BINARY_SHA, DISK_MANIFEST,
  );
  if (hwBuilder) report.hardware_level_attestation = await hwBuilder(nonce);
  const payload = JSON.stringify(reorder(report));
  let sig = rsaSign('sha256', Buffer.from(payload), enc.privateKey);
  if (corruptEnclaveSig) { const b = Buffer.from(sig); b[5] ^= 0xff; sig = b; }
  return {
    envelope: {
      attestation_report: report,
      enclave_signature_b64: sig.toString('base64'),
      enclave_signing_public_key: encPem,
    },
    nonce, encPem,
  };
}
function tdxHw({ quoteB64, chain = goodChain, markerOverrides = {}, probeNotes = ['configfs-tsm: report obtained'] }) {
  return {
    tdx_quote_b64: quoteB64,
    pck_cert_pem: chain.leaf.pem + chain.int.pem,
    tdx_evidence_source: 'configfs-tsm',
    tdx_evidence_marker: Object.assign({
      hardware_signed_tdx_quote: !!quoteB64,
      tdx_quote_status: quoteB64 ? 'ok' : 'unavailable_no_guest_device',
      tdx_td_report_present: !quoteB64,
    }, markerOverrides),
    tdx_evidence_probe: { notes: probeNotes },
    platform_type: 'Intel TDX',
  };
}
const reportDataFor = (nonce) => concat(fromHex(nonce), new Uint8Array(32)); // nonce || zeros

// ===========================================================================
console.log('Test 0: extracted script passes node --check');
{
  const tmp = join(dir, 'verify-script.js');
  writeFileSync(tmp, script);
  const r = spawnSync(process.execPath, ['--check', tmp], { encoding: 'utf8' });
  check('syntax gate', r.status === 0, (r.stderr || '').split('\n')[0]);
}

console.log('\nTest 1: static trust anchors in source (drift guards)');
{
  const defRoots = globalThis.TRUSTED_INTEL_ROOTS;
  check('Intel root pin present verbatim', script.includes(REAL_INTEL_PIN));
  check('bogus v4 body_size parser removed', !script.includes('qdv.getUint32(48, true)'));
  check('Google branch no longer uses RSA-only forge cert parser',
    !script.includes('parseAnyCertToForge(akCertPem'));
  check('runtime default roots = exactly the Intel DCAP root',
    Array.isArray(defRoots) && defRoots.length === 1 && defRoots[0].sha256 === REAL_INTEL_PIN,
    JSON.stringify(defRoots && defRoots.map(r => r.sha256)));
  check('embedded Intel root PEM matches its pinned sha256 (self-consistent anchor)',
    Array.isArray(defRoots) && defRoots[0].pem
      && sha256(pemToDer(defRoots[0].pem)).toString('hex') === REAL_INTEL_PIN);
}

// Positive tests substitute the anchor with the synthetic root (the DEFAULT is
// guarded by Test 1 and exercised again in Test 8 against an attacker chain).
const DEFAULT_ROOTS = JSON.parse(JSON.stringify(globalThis.TRUSTED_INTEL_ROOTS));
const GOOD_ROOTS = [{ sha256: goodRootSha, pem: goodChain.root.pem }];
globalThis.TRUSTED_INTEL_ROOTS = GOOD_ROOTS;

console.log('\nTest 2: valid quote v4 (TDREPORT10) — full green audit');
let v4Envelope;
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  v4Envelope = built;
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit returns true', ok === true, `alert=${alert}`);
  check('firmwareCheck verified', row('firmwareCheck').cls === 'check-item verified', `cls=${row('firmwareCheck').cls}`);
  check('TDX silicon root message', fw.includes('Intel TDX Silicon Root Verified'), fw.slice(0, 900));
  check('chain pinned (leaf → Intel root)', /leaf → Intel SGX Root CA pinned/.test(fw), fw.slice(0, 900));
  check('MRTD read at mr_td @136 (0x42 fill)', fw.includes('42'.repeat(16)) && !fw.includes('22'.repeat(16)), fw.match(/MRTD: [0-9a-f]+…/)?.[0]);
  check('session binding stated', fw.includes("report_data[0..32] == this session's combined nonce"));
  check('tpmCheck green (TPM-less platform)', row('tpmCheck').cls === 'check-item verified', row('tpmCheck').cls);
  check('githubCheck green (attested provenance)', row('githubCheck').cls === 'check-item verified', row('githubCheck').cls);
  check('enclaveCheck green', row('enclaveCheck').cls === 'check-item verified', row('enclaveCheck').cls);
}

console.log('\nTest 3: valid quote v5 body_type=2 (TDREPORT10) — chain incl. root dedupe');
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 5, bodyType: 2, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem, goodChain.root.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit returns true', ok === true, `alert=${alert}`);
  check('v5 accepted with pinned chain', fw.includes('Intel TDX Silicon Root Verified') && fw.includes('leaf → Intel SGX Root CA pinned'), fw.slice(0, 900));
  check('MRTD correct', fw.includes('42'.repeat(16)) && !fw.includes('22'.repeat(16)), fw.match(/MRTD: [0-9a-f]+…/)?.[0]);
}

console.log('\nTest 4: valid quote v5 body_type=3 (TDREPORT15, 648 B) — report_data NOT last 64');
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 5, bodyType: 3, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit returns true (binding read at @520, not tail)', ok === true, `alert=${alert}`);
  check('TD15 verified', fw.includes('Intel TDX Silicon Root Verified'), fw.slice(0, 900));
}

console.log('\nTest 5: report_data does not carry this session nonce → binding=false');
{
  const built = await buildEnvelope({
    hwBuilder: async () => {
      const wrong = new Uint8Array(64).fill(0x7e);
      const q = await buildTdxQuote({
        version: 4, reportData: wrong,
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('binding=false in verdict', fw.includes('binding=false'), fw.slice(0, 900));
  check('shows expected nonce vs quote', fw.includes('expected session nonce'), fw.slice(0, 900));
  check('silicon row failed', row('firmwareCheck').cls === 'check-item failed', row('firmwareCheck').cls);
}

console.log('\nTest 6: tampered quote signature → quote_sig=false (other checks still hold)');
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce), tamperQuoteSig: true,
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('quote_sig=false, binding still true', fw.includes('quote_sig=false') && fw.includes('binding=true'), fw.slice(0, 900));
}

console.log('\nTest 6b: quote signed by the PCK key (old-bug shape) → must FAIL');
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce), quoteSigByPckKey: true,
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('quote_sig=false while attkey_bind=true (key roles enforced)',
    fw.includes('quote_sig=false') && fw.includes('attkey_bind=true'), fw.slice(0, 900));
}

console.log('\nTest 7: QE-report binding corrupted → attkey_bind=false');
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce), corruptQeReportData: true,
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('attkey_bind=false', fw.includes('attkey_bind=false'), fw.slice(0, 900));
}

console.log('\nTest 8: attacker chain with LOOKALIKE Intel DNs (default pin active)');
{
  globalThis.TRUSTED_INTEL_ROOTS = DEFAULT_ROOTS; // real Intel anchor
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce),
        // attacker chain INCLUDING its own lookalike root — every link inside
        // is valid; only the sha256 anchor tells it apart from Intel's.
        innerChainPems: [evilChain.leaf.pem, evilChain.int.pem, evilChain.root.pem],
        leafKey: evilChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64, chain: evilChain });
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('root_chain=false (anchor is the only thing that catches it)',
    fw.includes('root_chain=false'), fw.slice(0, 900));
  check('issuer regex alone was satisfied (lookalike DNs)', fw.includes('issuer_intel=true'), fw.slice(0, 900));
  check('chain message names the pinned root', fw.includes('does NOT reach a pinned Intel root'), fw.slice(0, 900));
  check('alert is the silicon-root failure', /No valid Silicon Root/.test(alert || ''), alert);
  globalThis.TRUSTED_INTEL_ROOTS = GOOD_ROOTS; // restore for remaining positive-path fixtures
}

console.log('\nTest 9–12: header field guards (vendor / tee / version / key type)');
async function headerCase(name, opts, expectRe) {
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote(Object.assign({
        version: 4, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      }, opts));
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check(name + ' rejected', ok === false, `ok=${ok}`);
  check(name + ' precise reason', expectRe.test(fw), fw.slice(0, 900));
}
await headerCase('foreign QE vendor id', { vendorId: new Uint8Array(16).fill(0xab) }, /unknown QE vendor id/);
await headerCase('tee_type 0 (SGX)', { teeType: 0x00000000 }, /is not TDX/);
await headerCase('quote version 3', { version: 3 }, /unsupported quote version 3/);
await headerCase('att_key_type 3', { attKeyType: 3 }, /ECDSA P-256 \(type 2\)/);

console.log('\nTest 13: certification data type 5 (no QE report) → rejected');
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce), outerCertType: 5,
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('type-6 requirement stated', /certification data type 5 unsupported/.test(fw), fw.slice(0, 900));
}

console.log('\nTest 13b: v5 body_size field inconsistent with body_type → rejected');
{
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 5, bodyType: 2, forceBodySize: 648, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('size/type mismatch stated', /implies 584 bytes, size field says 648/.test(fw), fw.slice(0, 900));
}

console.log('\nTest 14: unsigned TDREPORT only → honest verdict + probe transcript');
{
  const built = await buildEnvelope({
    // attach the TDREPORT BEFORE signing (any post-sign mutation breaks the
    // enclave signature by design — Test 16 relies on exactly that)
    hwBuilder: async () => {
      const hw = tdxHw({
        quoteB64: null,
        markerOverrides: { hardware_signed_tdx_quote: false, tdx_td_report_present: true },
        probeNotes: ['probe: configfs-tsm timeout after 2000 ms', 'probe: /dev/tdx_guest absent'],
      });
      hw.tdx_td_report_b64 = Buffer.from(new Uint8Array(1024).fill(0x01)).toString('base64');
      return hw;
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails', ok === false, `ok=${ok}`);
  check('honest verdict text', fw.includes('No hardware-signed TDX evidence'), fw.slice(0, 900));
  check('probe transcript surfaced', fw.includes('configfs-tsm timeout'), fw.slice(0, 900));
  check('alert names the silicon-root failure', /No valid Silicon Root/.test(alert || ''), alert);
}

console.log('\nTest 15: no silicon evidence at all → fail closed');
{
  const built = await buildEnvelope({
    hw: { platform_type: 'AMD SEV-SNP' } // no SNP report, no TDX, no Google/TPM
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  check('audit fails', ok === false, `ok=${ok}`);
  check('alert names silicon-root failure', /No valid Silicon Root/.test(alert || ''), alert);
}

console.log('\nTest 16: tampered enclave signature → hard fail (unauthenticated report)');
{
  const built = await buildEnvelope({
    hw: tdxHw({ quoteB64: null }), corruptEnclaveSig: true,
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  check('audit fails', ok === false, `ok=${ok}`);
  check('enclave signature INVALID reason', /enclave signature over this report is INVALID/.test(alert || ''), alert);
  check('enclaveCheck row failed', row('enclaveCheck').cls === 'check-item failed', row('enclaveCheck').cls);
}

console.log('\nTest 17: pre-flight pin violation → deterministic fail before anything else');
{
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey
    .export({ type: 'spki', format: 'pem' }).toString();
  globalThis.preFlightPubKeyPem = other;
  const { ok, alert } = await runAuditWith(v4Envelope.envelope);
  check('audit fails', ok === false, `ok=${ok}`);
  check('PRE-FLIGHT VIOLATION reason', /PRE-FLIGHT VIOLATION/.test(alert || ''), alert);
  globalThis.preFlightPubKeyPem = '';
}

console.log('\nTest 18: Google-cert paste spoof (no TPM evidence) → blocked, DN extraction works');
{
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const spoof = forge.pki.createCertificate();
  spoof.publicKey = keys.publicKey;
  spoof.serialNumber = '01';
  spoof.validity.notBefore = new Date(Date.now() - 86400000);
  spoof.validity.notAfter = new Date(Date.now() + 86400000);
  const dn = [
    { name: 'commonName', value: 'attacker-controlled' },
    { name: 'organizationName', value: 'EK/AK CA Intermediate' },
  ];
  spoof.setSubject(dn);
  spoof.setIssuer(dn);
  spoof.sign(keys.privateKey, forge.md.sha256.create());
  const built = await buildEnvelope({
    hw: { google_ak_cert_pem: forge.pki.certificateToPem(spoof), platform_type: 'GCP' },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  check('audit fails', ok === false, `ok=${ok}`);
  check('reached the TPM-guard (issuer DN parsed correctly)',
    /cannot anchor/.test(alert || ''), alert);
  check('NOT rejected at issuer stage (would mean DN extraction broke)',
    !/not issued by a known Google/.test(alert || ''), alert);
}

console.log('\nTest 19: provenance unattested → GitHub row fails with the precise reason');
{
  fetchMode = '404';
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok } = await runAuditWith(built.envelope);
  const gh = row('githubCheck');
  check('GitHub provenance row failed', gh.cls === 'check-item failed', gh.cls);
  check('reason names missing attestation', gh.desc.includes('NO GitHub attestation exists'), gh.desc.slice(0, 200));
  check('hardware root still verified (layered: silicon is the hard gate)',
    row('firmwareCheck').cls === 'check-item verified', row('firmwareCheck').cls);
  fetchMode = 'ok';
}

console.log('\nTest 20: legit GCP report still passes (Google-branch regression, ported)');
{
  // TPM evidence: TPMS_ATTEST over the session nonce + PCRs, signed by an AK.
  const ak = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const akPem = ak.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const pcrValues = {};
      for (const p of [0, 4, 8, 9]) pcrValues['pcr_' + p] = sha256(Buffer.from(`pcr${p}`)).toString('hex');
      pcrValues['pcr_15'] = await calculatePcr15(DISK_MANIFEST);
      const composite = sha256(Buffer.concat([0, 4, 8, 9, 15].map(p => Buffer.from(pcrValues['pcr_' + p], 'hex'))));
      const qSigner = Buffer.alloc(32, 0x41);
      const extra = Buffer.from(nonce, 'hex');
      const parts = [];
      const hdrB = Buffer.alloc(8);
      hdrB.writeUInt32BE(0xFF544347, 0);
      hdrB.writeUInt16BE(0x8018, 4);
      hdrB.writeUInt16BE(qSigner.length, 6);
      parts.push(hdrB, qSigner);
      const edSz = Buffer.alloc(2); edSz.writeUInt16BE(extra.length, 0);
      parts.push(edSz, extra, Buffer.alloc(25, 0)); // clockInfo + firmwareVersion
      const selCount = Buffer.alloc(4); selCount.writeUInt32BE(1, 0);
      parts.push(selCount, Buffer.from([0x00, 0x0b, 0x03, 0x00, 0x04, 0x0f]));
      const dgSz = Buffer.alloc(2); dgSz.writeUInt16BE(composite.length, 0);
      parts.push(dgSz, composite);
      const quoteMsg = Buffer.concat(parts);
      const quoteSig = rsaSign('sha256', quoteMsg, ak.privateKey);
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
      return {
        ak_pub_pem: akPem,
        tpm_quote_msg: quoteMsg.toString('base64'),
        tpm_quote_sig: quoteSig.toString('base64'),
        pcr_values: pcrValues,
        google_ak_cert_pem: forge.pki.certificateToPem(gcert),
        platform_type: 'GCP',
      };
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  check('audit returns true', ok === true, `alert=${alert}`);
  check('Google silicon anchor verified', fwDesc().includes('Google Confidential Hardware Verified'), fwDesc().slice(0, 200));
  // GOLDEN_PCRS is unset on this branch → the TPM row is the AMBER degraded
  // state (never green, never red) once quote+nonce+composite verify.
  check('TPM row amber-degraded (quote+nonce+composite verified, no golden pins)',
    row('tpmCheck').cls === 'check-item warning', row('tpmCheck').cls + ' — ' + row('tpmCheck').desc.slice(0, 120));
}

console.log('\nTest 21: nonce formula parity (SEC-02 reference vector)');
{
  const paypalHash = sha256(Buffer.from('{"sub":"user"}'));
  const pubkeyHash = sha256(Buffer.from('fake-der-bytes'));
  const binary = Buffer.from('ab'.repeat(32), 'hex');
  const manifest = { 'EFI/BOOT/vmlinuz': 'cc'.repeat(32), 'EFI/BOOT/initrd.img': 'dd'.repeat(32) };
  const reference = sha256(Buffer.concat([
    paypalHash, pubkeyHash, sha256(Buffer.from('walletA')), binary,
    sha256(Buffer.from(JSON.stringify(Object.keys(manifest).sort().map(k => [k, manifest[k]])))),
  ])).toString('hex');
  const jsNonce = await nonce160Hex(paypalHash, pubkeyHash, 'walletA', 'ab'.repeat(32), manifest);
  check('harness mirror matches independent reference', jsNonce === reference, `js=${jsNonce} ref=${reference}`);
}

console.log('\nTest 21b: untrusted-report HTML injection neutralized (esc() sink audit)');
{
  // The report under audit is UNTRUSTED input: updateStatus() renders with
  // innerHTML, so report-derived fragments (marker fields, probe notes,
  // error messages, cert DNs) MUST arrive escaped — otherwise a forged
  // report can inject markup into the auditor's verdict DOM even while every
  // cryptographic gate fails.
  const IMG = '<img src=x onerror="window.__pwned=1">';
  const built = await buildEnvelope({
    hwBuilder: async () => tdxHw({
      quoteB64: null,
      markerOverrides: {
        auditor_note: IMG,
        tdx_quote_status: '">' + IMG,
      },
      probeNotes: ['<svg onload="window.__pwned=1"> configfs ok'],
    }),
  });
  const { ok } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('injected-marker report still fails closed (no silicon root)', ok === false, `ok=${ok}`);
  check('auditor_note rendered escaped (no raw <img tag in HTML)',
    !fw.includes('<img src=x') && fw.includes('&lt;img src=x'), fw.slice(0, 400));
  check('probe note rendered escaped (no raw <svg tag in HTML)',
    !fw.includes('<svg') && fw.includes('&lt;svg'), fw.slice(0, 400));
  check('marker status rendered escaped (no attribute-breakout quote pair)',
    !fw.includes('">' + '<img'), fw.slice(0, 400));
}

// ---- Optional: a REAL report captured from the live enclave ---------------
// (node scripts/e2e-sandbox.mjs sets this setup: REAL_REPORT=/tmp/report-verified.json)
// Runs against the DEFAULT Intel anchor — the synthetic root is swapped out so
// the genuine PCK chain must reach the pinned Intel DCAP root for real.
if (process.env.REAL_REPORT) {
  console.log(`\nTest 22: REAL live report (${process.env.REAL_REPORT}) — DEFAULT Intel anchor`);
  globalThis.TRUSTED_INTEL_ROOTS = DEFAULT_ROOTS;
  let live = null;
  try {
    live = JSON.parse(readFileSync(process.env.REAL_REPORT, 'utf8'));
  } catch (e) {
    check('live report parses as JSON', false, e.message);
  }
  if (live) {
    const { ok, alert } = await runAuditWith(live);
    const fw = fwDesc();
    check('live audit returns true', ok === true, `alert=${alert}`);
    check('live TDX silicon root verified', /Intel TDX Silicon Root Verified/.test(fw), fw.slice(0, 900));
    check('live chain reaches the REAL pinned Intel root', /leaf → Intel SGX Root CA pinned \(44a0196b/.test(fw), fw.slice(0, 900));
    check('live session-nonce binding in report_data', fw.includes("report_data[0..32] == this session's combined nonce"), fw.slice(0, 900));
    check('live MRTD surfaced', /MRTD: [0-9a-f]{32}…/.test(fw), fw.match(/MRTD: [0-9a-f]+…/)?.[0]);
    check('live provenance row green', row('githubCheck').cls === 'check-item verified',
      row('githubCheck').cls + ' — ' + row('githubCheck').desc.slice(0, 300));
    check('live tpmCheck green (TPM-less TDX)', row('tpmCheck').cls === 'check-item verified', row('tpmCheck').cls);
  }
}

// ===========================================================================
rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
