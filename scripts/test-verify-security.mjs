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
let fetchMode = 'ok'; // 'ok' = every hash attested by run #777; '404' = unattested; 'xss' = attested by a hostile run id
globalThis.fetch = async () => {
  if (fetchMode === 'ok' || fetchMode === 'xss') {
    const invocationId = fetchMode === 'xss' ? '<img src=x onerror=window.__pwned=1>' : '777';
    const payload = Buffer.from(JSON.stringify({
      predicate: { runDetails: { metadata: { invocationId } } },
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
    outerCertType = 6, forceBodySize = null, mrtdFill = null, rtmrFill = null,
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
  // mr_td (MRTD) @136 — default fixture = the PINNED audited MRTD
  // (EXPECTED_MRTD gate rejects anything else); pass mrtdFill as a byte to
  // exercise the mismatch path. Empty/absent pin → zeros → never matches
  // (fail-closed, same as verify.html).
  if (mrtdFill === null) {
    const pin = (typeof EXPECTED_MRTD === 'string' && /^[0-9a-f]{96}$/.test(EXPECTED_MRTD)) ? EXPECTED_MRTD : '';
    body.set(Uint8Array.from(Buffer.from(pin, 'hex')), 136);
  } else {
    fillAt(body, 136, 48, mrtdFill);
  }
  fillAt(body, 184, 48, 0x77);  // mr_config_id
  fillAt(body, 232, 48, 0x88);  // mr_owner
  fillAt(body, 280, 48, 0x99);  // mr_owner_config
  // RTMR0..3 @328..520 — v166: default fixture = the PINNED golden values
  // (EXPECTED_RTMR0..3 gates reject anything else); pass rtmrFill as a byte
  // to fill ALL four registers with it (exercises the mismatch path), or a
  // 1-based register number [1..4] to hit just that one. Empty/absent pins →
  // zeros → never match (fail-closed, same as verify.html).
  for (let k = 0; k < 4; k++) {
    const pin = [EXPECTED_RTMR0, EXPECTED_RTMR1, EXPECTED_RTMR2, EXPECTED_RTMR3][k];
    const pinHex = (typeof pin === 'string' && /^[0-9a-f]{96}$/.test(pin)) ? pin : '';
    if (rtmrFill === null) {
      body.set(Uint8Array.from(Buffer.from(pinHex, 'hex')), 328 + k * 48);
    } else if (typeof rtmrFill === 'number' && rtmrFill >= 1 && rtmrFill <= 4) {
      if (rtmrFill === k + 1) fillAt(body, 328 + k * 48, 48, 0x42); else body.set(Uint8Array.from(Buffer.from(pinHex, 'hex')), 328 + k * 48);
    } else {
      fillAt(body, 328 + k * 48, 48, rtmrFill);
    }
  }
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
  // v165: full boot chain — shim/UKI + grub are now inside the atomicity gate
  'EFI/BOOT/BOOTX64.EFI': 'aa'.repeat(32),
  'EFI/BOOT/grubx64.efi': '99'.repeat(32),
};
// v165: fixtures must produce the PINNED audited binary (see
// EXPECTED_ENCLAVE_SHA256 in verify.html) — the code-pin gate rejects
// anything else, by design.
const BINARY_SHA = EXPECTED_ENCLAVE_SHA256;
// v169: the auditor now RECOMPUTES the identity hash from the report's own
// `paypal_user_info` and fails closed unless the declared hash matches. Fixtures
// therefore derive the hash exactly like the enclave does; pre-login envelopes
// must carry the documented placeholder.
const PRELOGIN_HASH = sha256(Buffer.from('PRELOGIN_NO_USER', 'utf8')).toString('hex');
const identityHashOf = (userInfo) => sha256(Buffer.from(JSON.stringify(userInfo), 'utf8')).toString('hex');

async function buildEnvelope({ hw, customInfo = 'wallet_test_1', corruptEnclaveSig = false, hwBuilder, binarySha = BINARY_SHA, sessionContext = {}, reportExtras = null }) {
  const enc = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const encPem = enc.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  // An explicit value in reportExtras wins (negative tests need to lie).
  const declaredIdentityHash = (reportExtras && reportExtras.paypal_user_info_raw_hash)
    || ((reportExtras && reportExtras.paypal_user_info) ? identityHashOf(reportExtras.paypal_user_info) : PRELOGIN_HASH);
  const report = {
    custom_info: customInfo,
    enclave_config: {
      boot_measurements: { binary_sha256: binarySha, disk_manifest: DISK_MANIFEST },
      domain: 'login.airma.de',
    },
    paypal_user_info_raw_hash: declaredIdentityHash,
    // v169: login reports declare the PayPal environment; reportExtras may
    // override it (the sandbox-refusal test needs to).
    paypal_environment: 'production',
    // v169: and the flow that minted them (see Test 29).
    flow: 'verified',
    session_context: sessionContext,
    timestamp_ms: Date.now(),
    hardware_level_attestation: hw || null,
  };
  // v168: reportExtras lets fixtures add login-report fields (paypal_user_info,
  // paypal_client_id) BEFORE the envelope is signed — the S_enc signature
  // covers them, exactly like the enclave's callback report.
  if (reportExtras) Object.assign(report, reportExtras);
  const nonce = await nonce160Hex(
    fromHex(report.paypal_user_info_raw_hash),
    new Uint8Array(sha256(pemToDer(encPem))),
    customInfo, binarySha, DISK_MANIFEST,
  );
  // hwBuilder(nonce, pEncDer): the second arg lets pre-flight fixtures build
  // the v161 client-binding hash over THIS envelope's real P_enc.
  if (hwBuilder) report.hardware_level_attestation = await hwBuilder(nonce, pemToDer(encPem));
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

  // v169: the auditor's only third-party dependency must be SRI-pinned to the
  // exact bytes this harness evaluates — an unpinned CDN copy could ship a
  // forge whose x509SignedBy() accepts any PCK chain.
  const forgeTag = (/<script[^>]*forge[^>]*>/.exec(html) || [''])[0];
  const sri = (/integrity="(sha384-[^"]+)"/.exec(forgeTag) || [])[1];
  const localForge = createHash('sha384')
    .update(readFileSync(join(repoRoot, 'node_modules/node-forge/dist/forge.min.js')))
    .digest('base64');
  check('forge bundle is SRI-pinned', !!sri, forgeTag.slice(0, 160));
  check('SRI pin equals the audited forge bytes', sri === 'sha384-' + localForge,
    `tag=${sri} local=sha384-${localForge}`);
  check('SRI-pinned script requests CORS (required for integrity checks)',
    /crossorigin="anonymous"/.test(forgeTag), forgeTag.slice(0, 160));
  check('auditor fails closed when forge is missing (no silent chain skip)',
    /AUDITOR DEPENDENCY MISSING/.test(script));
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
  check('MRTD read at mr_td @136 equals pinned EXPECTED_MRTD', fw.includes(EXPECTED_MRTD.slice(0, 32)) && !fw.includes('22'.repeat(16)), fw.match(/MRTD: [0-9a-f]+…/)?.[0]);
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
  // v165: fixture MRTD now defaults to EXPECTED_MRTD (the pin gate rejects
  // anything else), so assert the displayed value equals the pin prefix.
  check('MRTD correct (pinned EXPECTED_MRTD)', fw.includes(EXPECTED_MRTD.slice(0, 32)) && !fw.includes('22'.repeat(16)), fw.match(/MRTD: [0-9a-f]+…/)?.[0]);
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

console.log('\nTest 6c: TDX pre-flight v161 client binding (regression 2026-10-21)');
{
  // The TDX branch must honour session_context.preflight exactly like the SNP
  // branch: a pre-flight envelope's report_data carries
  //   SHA-256(P_enc ∥ code_challenge ∥ P_client ∥ client_nonce ∥ custom_info),
  // [32..64] zero — NOT the SEC-02 session nonce (no PayPal user yet).
  // The TDX path lacked this branch until 2026-10-21 and failed EVERY live
  // pre-flight envelope with binding=false.
  const clientEnc = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const clientPubDer = clientEnc.publicKey.export({ type: 'spki', format: 'der' });
  const clientNonceHex = '7f'.repeat(32);
  const codeChallenge = 'E9xrX1s2qO0hAaBcDeFgHiJkLmNoPqRsTuVwXyZ012345';
  const pfCustom = 'wallet_pref_1';
  // v168 (plan Phase 3.1): the PayPal APP id is the SIXTH element of the
  // hardware binding — a swapped/over-scoped app must change the quoted
  // REPORTDATA. Mirrors compute_preflight_binding() (Rust) ↔
  // preflightBindingHex (verify.html) ↔ the vector in
  // security_tests::preflight_binding_parity_v168.
  const pfAppId = 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p';
  const v161ReportData = (pEncDer, appId = pfAppId) => {
    const pre = Buffer.concat([
      pEncDer, Buffer.from(codeChallenge, 'utf8'), clientPubDer,
      Buffer.from(clientNonceHex, 'hex'), Buffer.from(pfCustom, 'utf8'),
      Buffer.from(appId, 'utf8'),
    ]);
    return concat(new Uint8Array(sha256(pre)), new Uint8Array(32)); // digest ‖ zeros
  };
  const pfCtx = {
    binding: 'v161', code_challenge: codeChallenge,
    client_pub_b64: clientPubDer.toString('base64'),
    client_nonce_hex: clientNonceHex, custom_info: pfCustom,
    paypal_client_id: pfAppId,
  };

  // (a) quote binds the v161 client inputs → binding=true, silicon verified
  const good = await buildEnvelope({
    sessionContext: { preflight: pfCtx },
    hwBuilder: async (_nonce, pEncDer) => tdxHw({
      quoteB64: (await buildTdxQuote({
        version: 4, reportData: v161ReportData(pEncDer),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      })).b64,
    }),
  });
  const g = await runAuditWith(good.envelope);
  const gfw = fwDesc();
  check('audit returns true (v161 binding honoured on TDX)', g.ok === true, `alert=${g.alert}`);
  check('silicon root verified with v161 binding', gfw.includes('Intel TDX Silicon Root Verified'), gfw.slice(0, 900));
  check('silicon row green (verified)', row('firmwareCheck').cls === 'check-item verified', row('firmwareCheck').cls);
  check('success message names the v161.2 client binding',
    gfw.includes('report_data == v161.2 client binding'), gfw.match(/report_data[^<]*/)?.[0]);

  // (b) envelope claims v161 pre-flight but the quote carries SEC-02-shaped
  //     data → binding=false (substituted/foreign quote fails closed)
  const bad = await buildEnvelope({
    sessionContext: { preflight: pfCtx },
    hwBuilder: async (nonce) => tdxHw({
      quoteB64: (await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      })).b64,
    }),
  });
  const b = await runAuditWith(bad.envelope);
  const bfw = fwDesc();
  check('audit fails on foreign quote data', b.ok === false, `ok=${b.ok}`);
  check('binding=false in verdict', bfw.includes('binding=false'), bfw.slice(0, 900));
  check('failure names the expected v161.2 client binding',
    bfw.includes('expected v161.2 client binding'), bfw.slice(0, 900));

  // (c) v168: the APP id is HARDWARE-BOUND — a quote bound to a different
  //     (over-scoped) app id verifies its own binding but must fail the
  //     EXPECTED_APPS gate (and vice versa: an audited app id in the report
  //     with a quote bound to a foreign app fails binding).
  const evilCtx = Object.assign({}, pfCtx, { paypal_client_id: 'EVIL-OVERSCOPED-APP-ID' });
  const evil = await buildEnvelope({
    sessionContext: { preflight: evilCtx },
    hwBuilder: async (_nonce, pEncDer) => tdxHw({
      quoteB64: (await buildTdxQuote({
        version: 4, reportData: v161ReportData(pEncDer, 'EVIL-OVERSCOPED-APP-ID'),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      })).b64,
    }),
  });
  const ev = await runAuditWith(evil.envelope);
  check('over-scoped app id fails closed (APP PIN)', ev.ok === false, `ok=${ev.ok}`);
  check('failure names the pre-flight APP PIN VIOLATION',
    /APP PIN VIOLATION \(pre-flight\)/.test(ev.alert || ''), (ev.alert || '').slice(0, 240));
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

  // 21b cont.: the GitHub provenance row renders runIds from the API payload
  // and the atomicity run number — both must arrive escaped too.
  fetchMode = 'xss';
  await runAuditWith(built.envelope);
  const ghDesc = row('githubCheck').desc;
  fetchMode = 'ok';
  check('github-runId rendered escaped (no raw <img in provenance row)',
    !ghDesc.includes('<img src=x') && ghDesc.includes('&lt;img src=x'), ghDesc.slice(0, 400));
}

console.log('\nTest 21c: golden-PCR pcr_values injection neutralized');
{
  // Test 20's self-consistent TPM fixture, but with a hostile pcr_0 value.
  // The quote still verifies internally (composite built over the same
  // values), so the DEGRADED-TRUST warning renders goldenDetails — which
  // interpolates the quoted value and MUST escape it.
  const IMG = '<img src=x onerror="window.__pwned=1">';
  const ak = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const akPem = ak.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const pcrValues = {};
      pcrValues['pcr_0'] = IMG + '00'.repeat(16); // hostile, 16-char window keeps the payload prefix
      for (const p of [4, 8, 9]) pcrValues['pcr_' + p] = sha256(Buffer.from(`pcr${p}`)).toString('hex');
      pcrValues['pcr_15'] = await calculatePcr15(DISK_MANIFEST);
      // Use the PAGE's own composite function so the fixture is self-consistent
      // with how verify.html parses hostile hex (NaN→0 pairs).
      const composite = Buffer.from(await calculatePcrCompositeDigest(pcrValues), 'hex');
      const qSigner = Buffer.alloc(32, 0x41);
      const extra = Buffer.from(nonce, 'hex');
      const parts = [];
      const hdrB = Buffer.alloc(8);
      hdrB.writeUInt32BE(0xFF544347, 0);
      hdrB.writeUInt16BE(0x8018, 4);
      hdrB.writeUInt16BE(qSigner.length, 6);
      parts.push(hdrB, qSigner);
      const edSz = Buffer.alloc(2); edSz.writeUInt16BE(extra.length, 0);
      parts.push(edSz, extra, Buffer.alloc(25, 0));
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
  const { ok } = await runAuditWith(built.envelope);
  const tpmDesc = row('tpmCheck').desc;
  check('hostile-pcr report still passes its self-consistent checks', ok === true, `ok=${ok}`);
  check('golden-PCR UNPINNED detail rendered escaped (no raw <img in tpm row)',
    !tpmDesc.includes('<img src=x') && tpmDesc.includes('&lt;img src=x'), tpmDesc.slice(0, 400));
}

console.log('\nTest 21d: self-reported binary digest is INFORMATIONAL (v168) — silicon pins gate');
{
  // plan Phase 1.2: binary_sha256 is computed by the very binary under
  // suspicion (a backdoored /init claims the audited hash — the
  // "self-measurement fallacy"), so it must NOT decide the verdict. A FULLY
  // hardware-verified report (MRTD + RTMR pins green) whose self-report
  // differs passes with a loud warning saying exactly that; the MRTD/RTMR
  // tests (21e/21e2) are the gates that reject tampered code.
  const built = await buildEnvelope({
    binarySha: 'ff'.repeat(32),
    hwBuilder: async (nonce) => tdxHw({
      quoteB64: (await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      })).b64,
    }),
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  check('hardware-verified report passes — the self-report is not a gate', ok === true, `alert=${alert}`);
  check('mismatch surfaced as a loud informational warning',
    /SELF-REPORTED CODE DIGEST MISMATCH/.test(row('githubCheck').desc), row('githubCheck').desc.slice(0, 300));
  check('warning explicitly says it is NOT a gate',
    /informational, NOT a gate/.test(row('githubCheck').desc), row('githubCheck').desc.slice(0, 300));
  // …and an evidence-less report still fails closed for lack of a silicon
  // root (the old fixture's verdict — now attributed to the RIGHT cause).
  const bare = await buildEnvelope({ binarySha: 'ff'.repeat(32), hw: {} });
  const e2 = await runAuditWith(bare.envelope);
  check('evidence-less report still fails closed (no silicon root)', e2.ok === false, `ok=${e2.ok}`);
}

console.log('\nTest 21g: APP PIN — the PayPal app that minted the identity is gated (v168)');
{
  const green = async (nonce) => tdxHw({
    quoteB64: (await buildTdxQuote({
      version: 4, reportData: reportDataFor(nonce),
      innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
      leafKey: goodChain.leaf.key,
    })).b64,
  });
  // (a) login report minted by an app NOT in the audited allow-list → fail
  const evil = await buildEnvelope({
    hwBuilder: green,
    reportExtras: {
      paypal_user_info: { user_id: 'U1', sub: 'evil-sub', verified_account: 'true' },
      paypal_client_id: 'EVIL-OVERSCOPED-APP-ID',
    },
  });
  const e = await runAuditWith(evil.envelope);
  check('over-scoped app fails closed', e.ok === false, `ok=${e.ok}`);
  check('failure names the login-report APP PIN VIOLATION',
    /APP PIN VIOLATION \(login report\)/.test(e.alert || ''), (e.alert || '').slice(0, 240));
  // (b) the audited app id → the very same report passes
  const good = await buildEnvelope({
    hwBuilder: green,
    reportExtras: {
      paypal_user_info: { user_id: 'U1', sub: 'good-sub', verified_account: 'true' },
      paypal_client_id: 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p',
    },
  });
  const g = await runAuditWith(good.envelope);
  check('audited app id passes', g.ok === true, `alert=${g.alert}`);
  // (c) a login report that carries NO app id at all fails closed too
  const missing = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info: { user_id: 'U1', sub: 'x', verified_account: 'true' } },
  });
  const m = await runAuditWith(missing.envelope);
  check('login report without an app id fails closed', m.ok === false, `ok=${m.ok}`);
}

console.log('\nTest 26: identity preimage binding — the quote must attest the identity SHOWN (v169)');
{
  const green = async (nonce) => tdxHw({
    quoteB64: (await buildTdxQuote({
      version: 4, reportData: reportDataFor(nonce),
      innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
      leafKey: goodChain.leaf.key,
    })).b64,
  });
  const AUDITED_APP = 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p';
  const shown = { user_id: 'U1', sub: 'shown-sub', verified_account: 'true', payer_id: null };

  // (a) honest login report: declared hash == hash of the identity carried
  const good = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info: shown, paypal_client_id: AUDITED_APP },
  });
  const g = await runAuditWith(good.envelope);
  check('honest login report passes the preimage gate', g.ok === true, `alert=${g.alert}`);

  // (b) THE ATTACK: quote binds hash H, envelope displays a different record
  const other = { user_id: 'EVIL-PAYER', sub: 'other-sub', verified_account: 'true', payer_id: null };
  const spoof = await buildEnvelope({
    hwBuilder: green,
    reportExtras: {
      paypal_user_info: other,                      // displayed record
      paypal_user_info_raw_hash: identityHashOf(shown), // hardware-bound record
      paypal_client_id: AUDITED_APP,
    },
  });
  const s = await runAuditWith(spoof.envelope);
  check('identity/quote mismatch fails closed', s.ok === false, `ok=${s.ok}`);
  check('failure names the IDENTITY PREIMAGE VIOLATION',
    /IDENTITY PREIMAGE VIOLATION/.test(s.alert || ''), (s.alert || '').slice(0, 240));

  // (c) a pre-login envelope may not assert an arbitrary hash: without a user
  //     record it MUST carry the documented placeholder.
  const arbitrary = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info_raw_hash: 'ab'.repeat(32) },
  });
  const a = await runAuditWith(arbitrary.envelope);
  check('pre-login report with an arbitrary identity hash fails closed', a.ok === false, `ok=${a.ok}`);
  check('placeholder hash is accepted for pre-login', PRELOGIN_HASH.length === 64);
}

console.log('\nTest 27: environment binding — two-verdict model: sandbox = green integrity, non-green identity (v169/v177)');
{
  const green = async (nonce) => tdxHw({
    quoteB64: (await buildTdxQuote({
      version: 4, reportData: reportDataFor(nonce),
      innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
      leafKey: goodChain.leaf.key,
    })).b64,
  });
  const AUDITED_APP = 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p';
  const who = { user_id: 'U9', sub: 'sandbox-sub', verified_account: 'true', payer_id: null };

  // (a) production login audits green
  const prod = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info: who, paypal_client_id: AUDITED_APP, paypal_environment: 'production' },
  });
  const p = await runAuditWith(prod.envelope);
  check('production login passes', p.ok === true, `alert=${p.alert}`);

  // (b) THE ATTACK: the owner points users at sandbox PayPal and logs them in
  //     with an account it controls — every integrity check is genuinely green.
  //     v177 two-verdict model: the INTEGRITY audit passes (it is a real TDX
  //     attestation of the audited code) but the IDENTITY verdict must be the
  //     non-green SANDBOX state — never a verified production identity.
  const sandbox = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info: who, paypal_client_id: AUDITED_APP, paypal_environment: 'sandbox' },
  });
  const s = await runAuditWith(sandbox.envelope);
  check('sandbox report returns the SANDBOX verdict (truthy, not green-true)', s.ok === 'sandbox', `ok=${JSON.stringify(s.ok)}`);
  const idRow = row('identityCheck');
  check('identity row carries the SANDBOX banner', /SANDBOX IDENTITY/.test(idRow.desc), idRow.desc.slice(0, 200));
  check('identity row is NOT green', idRow.cls !== 'verified' && !/✅/.test(idRow.desc.split('<br>')[0]), idRow.cls);
  check('sandbox banner states it proves the enclave, not the user',
    /proves the enclave, not the person/i.test(idRow.desc), idRow.desc.slice(0, 240));
  check('sandbox banner demands production before trusting an identity',
    /paypal_environment="production"/.test(idRow.desc), idRow.desc.slice(0, 240));

  // (c) an UNVERIFIED PayPal account must not produce a green report either
  const unverified = await buildEnvelope({
    hwBuilder: green,
    reportExtras: {
      paypal_user_info: { user_id: 'U8', sub: 'unv', verified_account: 'false', payer_id: null },
      paypal_client_id: AUDITED_APP,
      paypal_environment: 'production',
    },
  });
  const u = await runAuditWith(unverified.envelope);
  check('unverified account fails closed', u.ok === false, `ok=${u.ok}`);
  check('failure names the unverified-account refusal',
    /UNVERIFIED ACCOUNT REFUSED/.test(u.alert || ''), (u.alert || '').slice(0, 200));

  // (d) an older report that does not declare the environment is refused too
  //     (fail closed on absence — the verdict split never relaxes this).
  const legacy = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info: who, paypal_client_id: AUDITED_APP, paypal_environment: '' },
  });
  const l = await runAuditWith(legacy.envelope);
  check('undeclared environment fails closed', l.ok === false, `ok=${l.ok}`);
  check('message names the undeclared case', /undeclared/i.test(l.alert || ''), (l.alert || '').slice(0, 220));

  // (e) a made-up environment value must not be silently accepted as either
  //     verdict — only "production" and "sandbox" are defined.
  const weird = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info: who, paypal_client_id: AUDITED_APP, paypal_environment: 'staging' },
  });
  const w = await runAuditWith(weird.envelope);
  check('unknown environment value fails closed', w.ok === false, `ok=${w.ok}`);
  check('message names the unknown-environment case', /ENVIRONMENT UNKNOWN/.test(w.alert || ''), (w.alert || '').slice(0, 220));
}

console.log('\nTest 29: flow binding — the sealed report must match the flow the user chose (v169)');
{
  const green = async (nonce) => tdxHw({
    quoteB64: (await buildTdxQuote({
      version: 4, reportData: reportDataFor(nonce),
      innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
      leafKey: goodChain.leaf.key,
    })).b64,
  });
  const AUDITED_APP = 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p';
  const who = { user_id: 'U7', sub: 'flow-sub', verified_account: 'true', payer_id: null };
  const mk = (extra) => buildEnvelope({
    hwBuilder: green,
    reportExtras: Object.assign({ paypal_user_info: who, paypal_client_id: AUDITED_APP }, extra),
  });

  // (a) matching intent audits green
  globalThis.selectedFlow = 'verified';
  const okFlow = await runAuditWith((await mk({ flow: 'verified' })).envelope);
  check('matching flow passes', okFlow.ok === true, `alert=${okFlow.alert}`);

  // (b) THE ATTACK: minimal disclosure requested, but the sealed report was
  //     minted by the audited PII app (so the app pin itself passes).
  const AUDITED_FULL_APP = 'ARDDrFepkPcuh-bWdtKPLeMNptSHp2BvhahGiPNt3n317a-Uu68Xu4c9F_4N0hPI5YK60R3xRMNYr-B0';
  const escalated = await runAuditWith((await mk({ flow: 'full', paypal_client_id: AUDITED_FULL_APP })).envelope);
  check('flow escalation fails closed', escalated.ok === false, `ok=${escalated.ok}`);
  check('failure names FLOW ESCALATION', /FLOW ESCALATION/.test(escalated.alert || ''), (escalated.alert || '').slice(0, 200));

  // (c) a report with no flow at all is refused (cannot tell which app minted it)
  const noFlow = await runAuditWith((await mk({ flow: '' })).envelope);
  check('undeclared flow fails closed', noFlow.ok === false, `ok=${noFlow.ok}`);
  check('failure names the missing flow binding', /FLOW BINDING MISSING/.test(noFlow.alert || ''), (noFlow.alert || '').slice(0, 200));

  // (d) flow must be consistent with the app that produced it
  globalThis.selectedFlow = null;
  const mismatch = await runAuditWith((await mk({ flow: 'verified', paypal_client_id: AUDITED_FULL_APP })).envelope);
  check('flow/app mismatch fails closed', mismatch.ok === false, `ok=${mismatch.ok}`);
  check('failure names FLOW/APP MISMATCH', /FLOW\/APP MISMATCH/.test(mismatch.alert || ''), (mismatch.alert || '').slice(0, 200));
  globalThis.selectedFlow = null;
}

console.log('\nTest 21e: MRTD pin gate rejects a different launch chain');
{
  // A fully valid Intel-signed quote + valid binding/chain, but MRTD from a
  // different (ghost) launch image → silicon root must FAIL (mrtd_pin=false).
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
        mrtdFill: 0x42, // ghost launch chain
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails closed despite valid quote', ok === false, `ok=${ok}`);
  check('silicon row shows mrtd_pin=false', /mrtd_pin=false/.test(fw), fw.slice(0, 400));
  check('ghost-launch wording surfaced', /MRTD pin mismatch/.test(fw), fw.slice(0, 400));
}

console.log('\nTest 21e2: RTMR pin gate rejects a tampered measurement register');
{
  // Fully valid Intel-signed quote + valid binding/chain + valid MRTD, but
  // RTMR2 (the running-code register) filled from a DIFFERENT image → the
  // HARDWARE measurement gate must fail (rtmr_pin=false, rtmr_pin=false).
  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4, reportData: reportDataFor(nonce),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
        rtmrFill: 3, // ghost RTMR2 only (register #3)
      });
      return tdxHw({ quoteB64: q.b64 });
    },
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  const fw = fwDesc();
  check('audit fails closed despite valid quote+MRTD', ok === false, `ok=${ok}`);
  check('silicon row shows rtmr_pin=false', /rtmr_pin=false/.test(fw), fw.slice(0, 500));
  check('RTMR violation names the register', /RTMR HARDWARE PIN VIOLATION on register\(s\) RTMR2/.test(fw), fw.slice(0, 600));
}

console.log('\nTest 21f: unattested boot-chain files (shim/grub) fail the provenance row');
{
  // v165: BOOTX64.EFI (shim/UKI) and grubx64.efi must be IN the row — a
  // backdoored loader swapped by the cloud provider shows up here.
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
  await runAuditWith(built.envelope);
  const gh = row('githubCheck');
  fetchMode = 'ok';
  check('provenance row failed without CI attestations', gh.cls === 'check-item failed', gh.cls);
  check('row names the unattested shim/BOOTX64 component',
    gh.desc.includes('EFI Boot Chain (BOOTX64.EFI') && gh.desc.includes('NO GitHub attestation'), gh.desc.slice(0, 700));
  check('row names the unattested grubx64 component', gh.desc.includes('EFI Bootloader (grubx64.efi)'), gh.desc.slice(0, 700));
}

console.log('\nTest 23: v164 post-login handoff — E2EE decrypt round-trip + report download');
{
  // The /callback page (v164) performs no crypto: it stashes the ciphertext
  // blob into sessionStorage and verify.html decrypts it fail-closed. These
  // tests exercise exactly that path: a correct blob decrypts via WebCrypto,
  // a substituted P_enc pin fails closed, a tampered ciphertext fails closed
  // (GCM auth), and the unlocked download button saves the audited envelope
  // with a sanitized filename (untrusted flow tag).
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
  const envJson = JSON.stringify(built.envelope);
  const b64 = (u8) => Buffer.from(u8).toString('base64');

  // Build the E2EE blob exactly like the enclave:
  // HKDF-SHA256(shared, salt=nonce, info='paypal-auth-vm/e2ee/v1') -> AES-256-GCM, AAD=nonce
  const client = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const enclaveKp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const jwkStr = JSON.stringify(await crypto.subtle.exportKey('jwk', client.privateKey));
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonceHex = [...nonceBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: enclaveKp.publicKey }, client.privateKey, 256);
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: nonceBytes, info: new TextEncoder().encode('paypal-auth-vm/e2ee/v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: nonceBytes }, key, new TextEncoder().encode(envJson)));
  const blobBase = {
    alg: 'AES-256-GCM+HKDF-SHA256+ECDH-P256',
    aad: 'client_nonce',
    iv_b64: b64(iv),
    ct_b64: b64(ct),
    enclave_ecdh_public_key_b64: b64(new Uint8Array(await crypto.subtle.exportKey('spki', enclaveKp.publicKey))),
    enclave_signing_public_key: built.encPem,
    state: 'handoff-test',
    flow: 'verified',
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));

  const dec = await localDecryptAndVerify(clone(blobBase), jwkStr, nonceHex, built.encPem);
  check('handoff blob decrypts to the login envelope',
    dec.attestation_report.custom_info === built.envelope.attestation_report.custom_info);

  let threw = '';
  try {
    await localDecryptAndVerify(clone(blobBase), jwkStr, nonceHex,
      '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n');
  } catch (e) { threw = e.message; }
  check('substituted P_enc pin fails closed', /PRE-FLIGHT VIOLATION/.test(threw), threw);

  const bad = clone(blobBase);
  const rawCt = Uint8Array.from(atob(bad.ct_b64), (c) => c.charCodeAt(0));
  rawCt[0] ^= 0xff;
  bad.ct_b64 = b64(rawCt);
  threw = '';
  try { await localDecryptAndVerify(bad, jwkStr, nonceHex, built.encPem); } catch (e) { threw = e.message; }
  check('tampered ciphertext fails closed (GCM auth)', threw !== '', threw);

  // --- the unlocked download button (v164 downloadReportFile)
  elements['attestationInput'].value = '';
  lastAlert = null;
  check('download refuses when no decrypted report is present',
    downloadReportFile() === false && /No decrypted report/.test(lastAlert), lastAlert);

  const clicks = [];
  const origCreate = document.createElement;
  const origBody = document.body;
  document.createElement = (tag) => ({ tagName: tag, href: '', download: '', click() { clicks.push(this); }, remove() {} });
  document.body = { appendChild() {} };
  let dlBlob = null;
  const origCuo = URL.createObjectURL;
  const origRuo = URL.revokeObjectURL;
  URL.createObjectURL = (b) => { dlBlob = b; return 'blob:fake'; };
  URL.revokeObjectURL = () => {};
  elements['attestationInput'].value = JSON.stringify({ ...built.envelope, flow: '../../evil<script>name' });
  const got = downloadReportFile();
  if (origCreate === undefined) delete document.createElement; else document.createElement = origCreate;
  if (origBody === undefined) delete document.body; else document.body = origBody;
  if (origCuo === undefined) delete URL.createObjectURL; else URL.createObjectURL = origCuo;
  if (origRuo === undefined) delete URL.revokeObjectURL; else URL.revokeObjectURL = origRuo;
  const dlText = dlBlob ? await dlBlob.text() : '';
  check('download saves the audited envelope',
    got === true && clicks.length === 1 && JSON.parse(dlText).attestation_report !== undefined,
    `got=${got} clicks=${clicks.length} bytes=${dlText.length}`);
  check('download filename flow tag is sanitized',
    /^attestation-report-evilscriptname-\d{4}-/.test(clicks[0] ? clicks[0].download : ''),
    clicks[0] ? clicks[0].download : '(no click)');
}

console.log('\nTest 24: auditor isolation — key generation refused outside file:// / GitHub Pages (v168)');
{
  // plan Phase 3.3: a copy served by the enclave's own origin is attacker-
  // script (Web Auditor Tampering) — every key-generating entry point must
  // REFUSE there, while file:// and the pinned GitHub Pages copy work.
  const setLoc = (loc) => { if (loc === null) delete globalThis.location; else globalThis.location = loc; };
  const el = (id) => document.getElementById(id);
  setLoc({ protocol: 'https:', host: 'login.airma.de', origin: 'https://login.airma.de' });
  check('enclave-origin copy is untrusted', trustedAuditorContext() === false);
  el('localEnclaveHost').value = 'https://login.airma.de';
  await executePreflightAndLogin('verified');
  check('secure-login refuses on the enclave origin',
    /UNTRUSTED AUDITOR ORIGIN/.test(el('secureLoginStatus').innerText),
    el('secureLoginStatus').innerText.slice(0, 140));
  await localPreflight();
  check('local pre-flight refuses on the enclave origin',
    /UNTRUSTED AUDITOR ORIGIN/.test(el('localLoginStatus').innerText),
    el('localLoginStatus').innerText.slice(0, 140));
  await localClaim();
  check('claim refuses on the enclave origin',
    /UNTRUSTED AUDITOR ORIGIN/.test(el('localLoginStatus').innerText),
    el('localLoginStatus').innerText.slice(0, 140));
  setLoc({ protocol: 'file:', host: '', origin: 'null' });
  check('file:// copy is trusted', trustedAuditorContext() === true);
  setLoc({ protocol: 'https:', host: 'leonardopedro.github.io', origin: 'https://leonardopedro.github.io' });
  check('GitHub Pages copy is trusted', trustedAuditorContext() === true);
  setLoc({ protocol: 'https:', host: 'attacker.example', origin: 'https://attacker.example' });
  check('any other https origin is untrusted', trustedAuditorContext() === false);
  setLoc(null);
}

console.log('\nTest 25: scripts/calculate-golden-rtmr.mjs --selftest (CCEL replay parity, plan Phase 5)');
{
  const r = spawnSync(process.execPath, [join(repoRoot, 'scripts', 'calculate-golden-rtmr.mjs'), '--selftest'], { encoding: 'utf8' });
  check('golden-RTMR tool selftest passes (same vector as the Rust replay_ccel test)',
    r.status === 0, ((r.stdout || '') + (r.stderr || '')).slice(0, 400));
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
    check('live RTMR hard pins all four enforced', /RTMR0–3 hard pins/.test(fw), fw.slice(fw.indexOf('RTMR0–3'), fw.indexOf('RTMR0–3') + 260));
    check('live provenance row green', row('githubCheck').cls === 'check-item verified',
      row('githubCheck').cls + ' — ' + row('githubCheck').desc.slice(0, 300));
    check('live tpmCheck green (TPM-less TDX)', row('tpmCheck').cls === 'check-item verified', row('tpmCheck').cls);
  }
}

console.log('\nTest 28: README publishes the auditor digest (out-of-band integrity)');
{
  // The auditor is the one component users must be able to check WITHOUT
  // trusting this repository's live contents. README.md carries its SHA-256 so
  // a downloaded copy can be verified offline; this guard fails the suite if
  // that published value drifts from the file it describes — a stale digest is
  // worse than none, because it teaches users to ignore mismatches.
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  const verifyBytes = readFileSync(join(repoRoot, 'verify.html'));
  const digest = createHash('sha256').update(verifyBytes).digest('hex');
  check('README publishes the CURRENT verify.html sha256', readme.includes(digest), digest);
  check('published digest is a 64-hex token', /[0-9a-f]{64}/.test(readme));
  const sizeLine = /verify\.html` \| ?([\d,]+) bytes/.exec(readme);
  check('published size matches the file',
    !!sizeLine && parseInt(sizeLine[1].replace(/,/g, ''), 10) === verifyBytes.length,
    `readme=${sizeLine && sizeLine[1]} file=${verifyBytes.length}`);
}

// ===========================================================================
rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
