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
//   * regression guards: cross-cloud substitution (Google-cert spoof and a
//     fully self-consistent GCP report are REJECTED by the Intel-only gate),
//     pre-flight pin, enclave-signature hard fail,
//     provenance fail-closed, static source pins (no old bogus offsets)
//
// Usage:  npm install --no-save node-forge && node scripts/test-verify-security.mjs
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { execFileSync, spawnSync } from 'child_process';
import * as https from 'https';
import { tmpdir } from 'os';
import { join } from 'path';
import { createRequire } from 'module';
import { generateKeyPairSync, sign as rsaSign, createHash, createSign } from 'crypto';

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
// v194 (split): the ZK engine lives in its OWN page (zk.html, GitHub Pages
// origin) so it can be debugged without an enclave rebuild — load both.
const zkHtml = readFileSync(join(repoRoot, 'zk.html'), 'utf8');
const zkScript = zkHtml.match(/<script>([\s\S]*)<\/script>/)[1];
// v195: the RSA escrow prover (zk-rsa.html) — a standalone alternative for
// OpenPGP/S-MIME RSA keys (GQ Fiat–Shamir, no setup). Its script co-evals
// too; every top-level name in it is `zkRsa`-prefixed so nothing collides.
const zkRsaHtml = readFileSync(join(repoRoot, 'zk-rsa.html'), 'utf8');
const zkRsaScript = zkRsaHtml.match(/<script>([\s\S]*)<\/script>/)[1];

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

// Evaluate the page scripts in this global scope (function decls + var leak
// to globalThis; const/let stay in the eval's lexical scope). The auditor
// runs FIRST, then zk.html's script — so every ZK binding the tests touch
// resolves exactly as it would on the real zk.html (its own reportFileText
// and stash win any name overlap). zk-rsa.html loads last (zkRsa-prefixed,
// no overlaps by construction).
(0, eval)(script);
(0, eval)(zkScript);
(0, eval)(zkRsaScript);

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
const PRELOGIN_HASH = sha256(Buffer.from('PRELOGIN_NO_USER', 'utf8')).toString('hex');  // Mirror of verify.html's canonical struct-layout serialization (the enclave:
  // serde_json::to_string of PayPalUserInfo — user_id, sub, verified_account,
  // payer_id, nulls kept). The live report's paypal_user_info text arrives
  // ALPHABETICALLY reordered (serde_json::json! uses a sorted map), so hashing
  // the fixture's own key order would hide the live byte-drift bug that made
  // every honest login fail the preimage gate (v178 live debug).
  const identityHashOf = (userInfo) => sha256(Buffer.from(JSON.stringify({
    user_id: userInfo.user_id, sub: userInfo.sub ?? null,
    verified_account: userInfo.verified_account, payer_id: userInfo.payer_id ?? null,
  }), 'utf8')).toString('hex');

async function buildEnvelope({ hw, customInfo = 'wallet_test_1', corruptEnclaveSig = false, hwBuilder, binarySha = BINARY_SHA, sessionContext = {}, reportExtras = null, noClientSession = false }) {
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
  // F1: model the honest enclave's login shape — when the report carries a
  // PayPal identity and no client session fields, inject the fixture session
  // and quote its binding (unless the test opts out with noClientSession).
  HARNESS_SLOT = '00'.repeat(32);
  if (report.paypal_user_info && !noClientSession) {
    const sc = report.session_context || {};
    if (!sc.client_pub_b64) {
      report.session_context = Object.assign({}, sc, {
        client_pub_b64: FIXTURE_CLIENT_PUB_B64,
        client_nonce_hex: FIXTURE_CLIENT_NONCE_HEX,
      });
      HARNESS_SLOT = clientBindingFor(FIXTURE_CLIENT_PUB_B64, FIXTURE_CLIENT_NONCE_HEX);
    } else {
      HARNESS_SLOT = clientBindingFor(sc.client_pub_b64, sc.client_nonce_hex || '00'.repeat(32));
    }
  }
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
const reportDataFor = (nonce) => concat(fromHex(nonce), fromHex(HARNESS_SLOT));
// F1 (v182 hardening): the honest enclave ALWAYS binds login reports into
// BOTH report_data slots (src/main.rs: report_data[32..64] =
// client_session_binding + echoed session_context fields). buildEnvelope
// auto-injects that shape for login fixtures below, and sets HARNESS_SLOT so
// every green hwBuilder built on reportDataFor quotes the matching slot.
// Non-login fixtures keep [32..64] zero (pre-login/pre-flight shape).
let HARNESS_SLOT = '00'.repeat(32);
const FIXTURE_CLIENT_PUB_B64 = Buffer.from('client-pub-der-30').toString('base64');
const FIXTURE_CLIENT_NONCE_HEX = '7f'.repeat(32);
// Mirror of verify.html clientSessionBindingHex / src/main.rs
// client_session_binding: SHA-256(P_client SPKI-DER ∥ Nonce_client).
const clientBindingFor = (pubB64, nonceHex) =>
  sha256(Buffer.concat([Buffer.from(pubB64, 'base64'), Buffer.from(nonceHex, 'hex')])).toString('hex');

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
  check('tpmCheck row removed (v184 — no TPM evidence exists on this platform; blank rows are not evidence)', row('tpmCheck').cls === '', 'cls=' + row('tpmCheck').cls);
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

console.log('\nTest 6c: TDX pre-flight v161 client binding (legacy-report regression 2026-10-21)');
{
  // v180: the enclave no longer MINTS pre-flight reports (no pre-login
  // attestation), but the auditor must keep auditing SAVED pre-v180 reports:
  // a pre-flight envelope's report_data carries
  //   SHA-256(P_enc ∥ code_challenge ∥ P_client ∥ client_nonce ∥ custom_info),
  // [32..64] zero — NOT the SEC-02 session nonce (no PayPal user yet).
  // Mirrors preflightBindingHex (verify.html); the Rust mint-side formula
  // (compute_preflight_binding) was removed in v180 with the pre-flight.
  const clientEnc = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const clientPubDer = clientEnc.publicKey.export({ type: 'spki', format: 'der' });
  const clientNonceHex = '7f'.repeat(32);
  const codeChallenge = 'E9xrX1s2qO0hAaBcDeFgHiJkLmNoPqRsTuVwXyZ012345';
  const pfCustom = 'wallet_pref_1';
  // v168 (plan Phase 3.1): the PayPal APP id is the SIXTH element of the
  // hardware binding — a swapped/over-scoped app must change the quoted
  // REPORTDATA. Mirrors preflightBindingHex (verify.html legacy branch).
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

console.log('\nTest 15: no Intel TDX evidence at all → rejected outright (v180 Intel-only gate)');
{
  const built = await buildEnvelope({
    hw: { platform_type: 'AMD SEV-SNP' } // no TDX evidence of any class
  });
  const { ok, alert } = await runAuditWith(built.envelope);
  check('audit fails', ok === false, `ok=${ok}`);
  check('alert rejects at the Intel TDX-only gate',
    /REJECTED: Report contains no hardware-signed Intel TDX Quote/.test(alert || ''), alert);
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
  // v186 (audit round 5): the identity row used to be painted green BEFORE
  // the signature check, so a forged report rendered a green "Identity"
  // row next to the red signature row. It must be failed + explained now.
  check('identity row NOT green on an unauthenticated report (v186)',
    row('identityCheck').cls !== 'check-item verified', row('identityCheck').cls);
  check('identity row explains the report is unauthenticated',
    /unauthenticated/i.test(row('identityCheck').desc), row('identityCheck').desc.slice(0, 200));
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

console.log('\nTest 18: Google-cert paste spoof → REJECTED at the Intel TDX-only gate (v180)');
{
  // v180 (audit.md §5.1): the Google AK verification path is gone. A forged
  // EK/AK cert pasted into google_ak_cert_pem can no longer even REACH the
  // silicon logic — the Intel-only gate rejects any report whose evidence
  // class is not Intel TDX.
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
  check('rejected by the Intel TDX-only gate (Google evidence can never anchor)',
    /REJECTED: Report contains no hardware-signed Intel TDX Quote/.test(alert || ''), alert);
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

console.log('\nTest 20: fully self-consistent GCP report → REJECTED (cross-cloud substitution, v180)');
{
  // v180 (audit.md §9 — Cross-Cloud Quote Substitution): this fixture is a
  // PERFECT legacy GCP report — valid AK-signed TPMS_ATTEST over the exact
  // session nonce, self-consistent PCR composite, Google-issued EK cert. It
  // used to audit green through the Google branch; the Intel-only auditor
  // must now reject it at the silicon gate: an owner presenting evidence
  // from another cloud can never satisfy this service's root.
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
  check('audit fails', ok === false, `ok=${ok} alert=${alert}`);
  check('rejected by the Intel TDX-only gate (no TDX evidence in a GCP report)',
    /REJECTED: Report contains no hardware-signed Intel TDX Quote/.test(alert || ''), alert);
  check('silicon row states the Intel-only policy',
    fwDesc().includes('No Intel TDX evidence in report'), fwDesc().slice(0, 200));
  check('tpmCheck row absent (v184 — TPM row removed entirely)', row('tpmCheck').cls === '', 'cls=' + row('tpmCheck').cls);
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
// Test 21c (golden-PCR pcr_values injection) REMOVED in v180: the GCP TPM
// verification path and GOLDEN_PCRS rendering it exercised are deleted with
// the Intel-only auditor (audit.md §5.1). esc() sink coverage for
// report-derived fragments lives on in Test 21b.


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

  // (a2) REGRESSION (v178 live debug): the live enclave embeds
  // paypal_user_info via serde_json::json! — ALPHABETICAL key order in the
  // report text — while the hardware hash covers the struct layout. A carried
  // object whose key order differs must still pass the preimage gate.
  const shownAlpha = { payer_id: null, sub: 'shown-sub', user_id: 'U1', verified_account: 'true' };
  const ga = await buildEnvelope({
    hwBuilder: green,
    reportExtras: { paypal_user_info: shownAlpha, paypal_client_id: AUDITED_APP },
  });
  const g2 = await runAuditWith(ga.envelope);
  check('alphabetically-keyed paypal_user_info still matches the struct-order hash',
    g2.ok === true, `alert=${g2.alert}`);

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
  check('substituted P_enc pin fails closed', /KEY-CONTINUITY VIOLATION/.test(threw), threw);

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
  // v188: localClaim() was deleted together with the claim button — the
  // render-time key generator (ensureThrowawayKey) is now the second
  // key-generating entry point besides executePreflightAndLogin and must
  // refuse here too, with the on-page notice saying so.
  let keygenRefused = false;
  try { await ensureThrowawayKey(); } catch (e) { keygenRefused = /UNTRUSTED AUDITOR ORIGIN/.test(e.message); }
  check('render-time key generation refuses on the enclave origin',
    keygenRefused, 'ensureThrowawayKey did not refuse on login.airma.de');
  renderKeyNotice('refused');
  check('key notice announces the refusal on-page',
    /NO KEY GENERATED HERE/.test(el('keyNotice').innerText), el('keyNotice').innerText.slice(0, 120));
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
    // verify.html v177: a SANDBOX deployment passes the INTEGRITY audit
    // (silicon root + MRTD/RTMR pins + every binding) but must never render
    // as a verified PRODUCTION identity — the identity row is downgraded to a
    // loud warning and runAudit() returns the string 'sandbox' (truthy), NOT
    // true. Asserting `ok === true` therefore fails on every genuine sandbox
    // report; the honest gate is that the VERDICT MATCHES the environment the
    // report itself declares, and that the downgrade is present.
    const liveEnv = String((live.attestation_report || live).paypal_environment || '').toLowerCase();
    check('live audit verdict matches the declared PayPal environment',
      (ok === 'sandbox' && liveEnv === 'sandbox') || (ok === true && liveEnv === 'production'),
      `ok=${JSON.stringify(ok)} env=${liveEnv} alert=${alert}`);
    check('live report declares a known paypal_environment',
      liveEnv === 'production' || liveEnv === 'sandbox', liveEnv);
    check('sandbox verdict still carries the SANDBOX IDENTITY downgrade',
      ok !== 'sandbox' || /SANDBOX IDENTITY/.test(row('identityCheck').desc),
      row('identityCheck').desc.slice(0, 160));
    check('live TDX silicon root verified', /Intel TDX Silicon Root Verified/.test(fw), fw.slice(0, 900));
    check('live chain reaches the REAL pinned Intel root', /leaf → Intel SGX Root CA pinned \(44a0196b/.test(fw), fw.slice(0, 900));
    check('live session-nonce binding in report_data', fw.includes("report_data[0..32] == this session's combined nonce"), fw.slice(0, 900));
    check('live MRTD surfaced', /MRTD: [0-9a-f]{32}…/.test(fw), fw.match(/MRTD: [0-9a-f]+…/)?.[0]);
    check('live RTMR hard pins all four enforced', /RTMR0–3 hard pins/.test(fw), fw.slice(fw.indexOf('RTMR0–3'), fw.indexOf('RTMR0–3') + 260));
    check('live provenance row green', row('githubCheck').cls === 'check-item verified',
      row('githubCheck').cls + ' — ' + row('githubCheck').desc.slice(0, 300));
    check('live tpmCheck row absent (v184 — TPM row removed entirely)', row('tpmCheck').cls === '', row('tpmCheck').cls);
  }
}

console.log('\nTest 30: v179 client-session binding — report_data[32..64] = SHA-256(P_client ∥ Nonce_client) (plan Phase 1)');
{
  // Fixture chain: the REAL_REPORT block above may have swapped in the real
  // Intel anchor — these synthetic fixtures need the harness anchor back
  // (same restore discipline as Test 8).
  globalThis.TRUSTED_INTEL_ROOTS = GOOD_ROOTS;
  const AUDITED_APP = 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p';
  const who = { user_id: 'U7', sub: 'sess-sub', verified_account: 'true', payer_id: null };
  // Mirror of src/main.rs::client_session_binding and verify.html's
  // clientSessionBindingHex(): SHA-256(P_client SPKI-DER ∥ Nonce_client).
  // (The golden vector of the formula itself is pinned by Rust
  // security_tests::client_session_binding_parity_v179.)
  const bindingFor = (pubDer, nonceFill) =>
    sha256(Buffer.concat([Buffer.from(pubDer), Buffer.alloc(32, nonceFill)])).toString('hex');
  const myBinding = bindingFor('client-pub-der-30', 0x7f);
  const otherBinding = bindingFor('client-pub-evil', 0x11);
  const greenSlot = (slotHex) => async (nonce) => tdxHw({
    quoteB64: (await buildTdxQuote({
      version: 4, reportData: concat(fromHex(nonce), fromHex(slotHex)),
      innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
      leafKey: goodChain.leaf.key,
    })).b64,
  });
  const loginExtras = { paypal_user_info: who, paypal_client_id: AUDITED_APP, paypal_environment: 'production' };

  // (a) session in hand + quote bound to THIS session → green.
  globalThis.auditorSessionBindingHex = myBinding;
  const mine = await buildEnvelope({ hwBuilder: greenSlot(myBinding), reportExtras: loginExtras });
  const a = await runAuditWith(mine.envelope);
  check('30a session-bound login passes with the matching client session', a.ok === true,
    `ok=${JSON.stringify(a.ok)} alert=${a.alert}`);

  // (b) THE ATTACK (plan Phase 1 — session substitution): a report minted for
  //     ANOTHER browser's session replayed at this one. The hardware quote
  //     carries the wrong P_client/nonce in report_data[32..64].
  const theirs = await buildEnvelope({ hwBuilder: greenSlot(otherBinding), reportExtras: loginExtras });
  const b = await runAuditWith(theirs.envelope);
  check('30b substituted session fails closed', b.ok === false, `ok=${JSON.stringify(b.ok)}`);
  check('30b silicon row names the client-session binding',
    /client-session binding/.test(fwDesc()), fwDesc().slice(0, 400));

  // (c) paste audit WITHOUT any local session and WITHOUT reconstructible
  //     client session fields (legacy/pre-v179 report): built with
  //     noClientSession so the report carries NO session_context fields —
  //     the slot cannot be verified, so it must FAIL CLOSED — the v179
  //     "informational slot" wildcard is gone (audit.md Step 4: no unverified
  //     quote slots). Under the collusion model an authentic-but-stale report
  //     must not replay as green through the paste path.
  globalThis.auditorSessionBindingHex = null;
  const theirsNoSC = await buildEnvelope({
    hwBuilder: greenSlot(otherBinding), reportExtras: loginExtras, noClientSession: true,
  });
  const c = await runAuditWith(theirsNoSC.envelope);
  check('30c paste audit without session fields fails closed (no wildcard slot)', c.ok === false,
    `ok=${JSON.stringify(c.ok)}`);

  // (c2) paste audit WITHOUT a local session but WITH the report's own
  //      session_context: the slot is RECOMPUTED from client_pub_b64/
  //      client_nonce_hex and STRICTLY enforced — green exactly when the
  //      quote commits to those fields.
  const repPubB64 = Buffer.from('client-pub-der-30').toString('base64');
  const repNonceHex = '7f'.repeat(32);
  const repBinding = bindingFor('client-pub-der-30', 0x7f);
  const scExtras = { ...loginExtras, session_context: { client_pub_b64: repPubB64, client_nonce_hex: repNonceHex } };
  const minePaste = await buildEnvelope({ hwBuilder: greenSlot(repBinding), reportExtras: scExtras });
  const c2 = await runAuditWith(minePaste.envelope);
  check('30c2 paste audit recomputes the slot from the report session_context (green)', c2.ok === true,
    `ok=${JSON.stringify(c2.ok)} alert=${c2.alert}`);
  check('30c2 success row names both verified slots',
    /both slots bound/.test(fwDesc()), fwDesc().slice(0, 400));

  // (c3) THE PASTE ATTACK: the report's session_context claims one client
  //      session while the hardware quote commits to another → fail closed.
  const theirsPaste = await buildEnvelope({ hwBuilder: greenSlot(otherBinding), reportExtras: scExtras });
  const c3 = await runAuditWith(theirsPaste.envelope);
  check('30c3 substituted client session fails closed in paste audit', c3.ok === false,
    `ok=${JSON.stringify(c3.ok)}`);

  // (d) an UNBOUND (zero-slot) report with a session in hand must fail: the
  //     slot is strictly enforced whenever the auditor holds the session.
  globalThis.auditorSessionBindingHex = myBinding;
  const legacy = await buildEnvelope({ hwBuilder: greenSlot('00'.repeat(32)), reportExtras: loginExtras });
  const d = await runAuditWith(legacy.envelope);
  check('30d zero-slot (pre-binding) report fails when the session is in hand', d.ok === false,
    `ok=${JSON.stringify(d.ok)}`);
  globalThis.auditorSessionBindingHex = null;

  // (e) THE F1 GAP: a LOGIN report whose quote carries a ZERO [32..64] slot,
  //     no local session, and no session_context fields. Pre-fix this fell
  //     through to the NON-LOGIN branch ("session nonce" expected, zeros
  //     matched) and passed GREEN — an owner-crafted pre-v179-shaped report
  //     replayed through the paste path. The honest enclave never mints this
  //     shape (src/main.rs always binds the slot + echoes the fields), so it
  //     must now be REJECTED (v182: no wildcard slots in EVERY audit mode).
  const f1 = await buildEnvelope({
    hwBuilder: greenSlot('00'.repeat(32)), reportExtras: loginExtras, noClientSession: true,
  });
  const e = await runAuditWith(f1.envelope);
  check('30e zero-slot login report fails closed without any session (F1)', e.ok === false,
    `ok=${JSON.stringify(e.ok)}`);
  check('30e silicon row names the rejected missing binding',
    /WITHOUT any client session binding — REJECTED/.test(fwDesc()), fwDesc().slice(0, 400));

  // (e2) over-block guard: the honest PRE-LOGIN envelope (no PayPal identity,
  //      session_context {}, zero slot) must still pass — F1 must only gate
  //      LOGIN reports.
  const prelogin = await buildEnvelope({
    hwBuilder: greenSlot('00'.repeat(32)),
  });
  const e2 = await runAuditWith(prelogin.envelope);
  check('30e2 pre-login zero-slot envelope still green (F1 gates login only)',
    e2.ok === true, `ok=${JSON.stringify(e2.ok)} alert=${e2.alert}`);
}

console.log('\nTest 31: v179 PayPal API trust-root parity — src/paypal.pem ↔ Rust pin ↔ published thumbprint');
{
  // The enclave's hardened TLS client trusts ONLY what is compiled into the
  // binary (plan Phase 2), so which root that is must agree in three places:
  // the PEM file, the Rust test's pinned fingerprint
  // (paypal_api_root_is_digicert_g2_v179), and DigiCert's published
  // thumbprint. Any drift in one without the others fails here — the failure
  // mode this guards (an expired LEAF masquerading as the root) silently
  // broke every live login in the v179 cycle.
  const DIGICERT_G2_FP = 'cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f';
  const pem = readFileSync(join(repoRoot, 'src', 'paypal.pem'), 'utf8');
  const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const fp = createHash('sha256').update(der).digest('hex');
  check('src/paypal.pem IS the DigiCert Global Root G2 (published thumbprint)', fp === DIGICERT_G2_FP, fp);
  const rust = readFileSync(join(repoRoot, 'src', 'main.rs'), 'utf8');
  check('Rust test pins the same fingerprint the PEM carries', rust.includes(`\"${DIGICERT_G2_FP}\"`), 'constant absent from src/main.rs');
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  check('README publishes the root fingerprint out-of-band', readme.includes('cb3ccbb7'), 'README lost the root note');
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

  // R2 finding (F3 — collusion model): without HSTS a colluding network
  // can keep a victim on plaintext http:// forever after the first HTTPS
  // visit. Every response passes through with_secure_headers(), so the
  // header must be pinned here or a refactor can silently drop it.
  const rustSrc = readFileSync(join(repoRoot, 'src', 'main.rs'), 'utf8');
  check('src/main.rs serves HSTS (strict-transport-security max-age=31536000) — F3',
    rustSrc.includes('strict-transport-security') && rustSrc.includes('max-age=31536000'),
    'HSTS header missing from with_secure_headers');
}

console.log('\nTest 32: v180 no pre-login attestation — login-session flow, no quote minting (user directive)');
{
  // Source pins: the pre-flight endpoint and its per-request quote minting
  // are GONE (user directive — an unauthenticated TD quote per click is a
  // trivially reachable enclave resource-exhaustion surface; the completed
  // PayPal login is the attacker filter). The login flow must touch NO
  // attestation route before PayPal, and the standalone envelope route must
  // be served from a cache.
  const verifySrc = readFileSync(join(repoRoot, 'verify.html'), 'utf8');
  check('verify.html no longer references /attest/preflight', !verifySrc.includes('/attest/preflight'), 'found /attest/preflight');
  check('verify.html no longer fetches /debug/envelope', !verifySrc.includes('/debug/envelope'), 'found /debug/envelope');
  check('verify.html drives /attest/login-session', verifySrc.includes('/attest/login-session'), 'missing /attest/login-session');
  check('verify.html has no pre-flight card button (runPreflight gone)', !verifySrc.includes('runPreflight('), 'runPreflight still present');
  const rustSrc = readFileSync(join(repoRoot, 'src', 'main.rs'), 'utf8');
  check('main.rs route table has /attest/login-session', rustSrc.includes('"/attest/login-session"'), 'route missing');
  check('main.rs has no /attest/preflight route', !rustSrc.includes('"/attest/preflight"'), 'route still present');
  check('main.rs debug_envelope serves from the boot cache', rustSrc.includes('boot_envelope'), 'cache missing');
  check('main.rs callback parses the state-carried session (no pending_oauth)',
    !rustSrc.includes('pending_oauth'), 'pending_oauth still present');

  // Functional flow: drive executePreflightAndLogin end-to-end against a
  // stub of /attest/login-session that mirrors the enclave contract
  // (S_enc-signed fields + client-session binding echo). Assert the browser
  // performs NO attestation work pre-login: no quote fetch, no pre-login
  // audit run, and an authorize URL that CARRIES the required PKCE
  // challenge (R3-1 — PKCE-less signed fields must be refused).
  globalThis.localStorage = (() => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; })();
  globalThis.sessionStorage = (() => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; })();
  const setLoc = (loc) => { if (loc === null) delete globalThis.location; else globalThis.location = loc; };
  setLoc({ protocol: 'file:', host: '', origin: 'null' });

  const enc = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const encPem = enc.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  // R3-1: the enclave contract now includes a PKCE challenge; 43-char
  // base64url per RFC 7636. `omitPkce` lets the downgrade case be driven.
  const PKCE_CHALLENGE = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'; // 43 chars
  let omitPkce = false;
  // v186: simulate the collusion-model request substitution — the stub
  // answers with the audited FULL-flow app no matter what flow was asked for
  // (every signature/pin/app allow-list check legitimately passes).
  let substituteFlow = false;
  const requests = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    requests.push(String(url));
    if (String(url).endsWith('/attest/login-session')) {
      const body = JSON.parse(opts.body);
      const pubDer = Buffer.from(body.client_ecdh_pub_b64, 'base64');
      const binding = await clientSessionBindingHex(pubDer, body.client_nonce_hex);
      const app = globalThis.EXPECTED_APPS.find(a => a.flow ===
        (substituteFlow ? 'full' : (body.flow || 'verified')));
      const sf = reorder({
        binding: 'v180', state: 'teststate-abc', flow: app.flow,
        paypal_client_id: app.client_id, paypal_environment: 'sandbox',
        redirect_uri: 'https://login.airma.de/callback',
        authorize_base: app.authorize_base, scope: app.scope,
        custom_info: (body.custom_info || '').trim() || 'NONE',
        client_session_binding_hex: binding,
        ...(omitPkce ? {} : { code_challenge: PKCE_CHALLENGE, code_challenge_method: 'S256' }),
      });
      const sig = createSign('sha256').update(JSON.stringify(sf)).sign(enc.privateKey).toString('base64');
      return { ok: true, status: 200, json: async () => ({
        enclave_signing_public_key: encPem,
        signed_fields: sf,
        login_signature_b64: sig,
      }) };
    }
    throw new Error('unexpected fetch in the pre-login flow: ' + url);
  };
  try {
    document.getElementById('localEnclaveHost').value = 'https://login.airma.de';
    document.getElementById('customInfoInput').value = '';
    elements['attestationInput'].value = '';
    await executePreflightAndLogin('verified');
    check('exactly one network call, to /attest/login-session',
      requests.length === 1 && requests[0].endsWith('/attest/login-session'), JSON.stringify(requests));
    check('no pre-login audit ran (report textarea untouched)',
      elements['attestationInput'].value === '', elements['attestationInput'].value.slice(0, 60));
    const href = elements['loginVerifiedLink'].href || '';
    check('flow link becomes the authorize handoff (v188 two explicit links)',
      typeof href === 'string' && href.startsWith('https://www.sandbox.paypal.com'),
      String(href).slice(0, 140));
    check('authorize URL carries the state token', href.includes('&state=teststate-abc'), href.slice(0, 220));
    check('authorize URL carries the required PKCE challenge + S256 method (R3-1)',
      href.includes('&code_challenge=' + PKCE_CHALLENGE) && href.includes('&code_challenge_method=S256'),
      href.slice(0, 260));
    const chParam = (href.match(/code_challenge=([A-Za-z0-9_-]+)/) || [])[1] || '';
    check('PKCE challenge shape is RFC 7636 base64url (43 chars)', /^[A-Za-z0-9_-]{43}$/.test(chParam), chParam);
    const sess = JSON.parse(globalThis.localStorage.getItem('pav_local_session') || 'null');
    check('local session stored with binding + pinned enclave key',
      !!sess && !!sess.sessionBindingHex && sess.p_enc === encPem && sess.state === 'teststate-abc',
      JSON.stringify(sess && { state: sess.state, hasBinding: !!sess.sessionBindingHex }));

    // F6 (live e2e finding 2026-10-25): a SECOND click on the already-
    // prepared handoff link must NAVIGATE with the EXISTING session and
    // mint nothing. Before the fix every login re-ran the login-session
    // request: the popup carried state #1 to PayPal while state #2's fresh
    // nonce overwrote this tab's storage, so the callback's ciphertext
    // (sealed to #1) failed GCM auth against #2 — every real login.
    {
      const reqsBefore = requests.length;
      const nonceBefore = globalThis.sessionStorage.getItem('pav_client_nonce');
      const sessBefore = globalThis.localStorage.getItem('pav_local_session');
      const hrefBefore = elements['loginVerifiedLink'].href;
      await executePreflightAndLogin('verified');
      check('F6: repeat click on a prepared handoff makes NO new session call',
        requests.length === reqsBefore,
        `requests ${reqsBefore} -> ${requests.length}`);
      check('F6: repeat click does NOT rotate the client nonce (blob seal nonce preserved)',
        globalThis.sessionStorage.getItem('pav_client_nonce') === nonceBefore,
        `nonce ${String(nonceBefore).slice(0, 12)} -> ${String(globalThis.sessionStorage.getItem('pav_client_nonce')).slice(0, 12)}`);
      check('F6: repeat click does NOT rewrite pav_local_session (state #1 stays live)',
        globalThis.localStorage.getItem('pav_local_session') === sessBefore);
      check('F6: the authorize href is untouched by the repeat click',
        elements['loginVerifiedLink'].href === hrefBefore
        && String(elements['loginVerifiedLink'].href).includes('authorize'));
    }

    // R3-1 downgrade defense: S_enc-signed login fields WITHOUT a PKCE
    // challenge (stale enclave, or a relay stripping fields before signing)
    // must be refused BEFORE the user is sent to PayPal. Start from an
    // UNPREPARED link (F6 keeps a prepared link from re-entering prepare).
    elements['loginVerifiedLink'].href = '';
    omitPkce = true;
    await executePreflightAndLogin('verified');
    omitPkce = false;
    check('PKCE-less signed login fields are refused (downgrade defense)',
      /PKCE MISSING OR WEAK/.test(elements['secureLoginStatus'].innerText || ''),
      (elements['secureLoginStatus'].innerText || '').slice(0, 160));
    check('refusal made exactly one further session call and built no new link',
      requests.length === 2, JSON.stringify(requests));

    // v186 (audit round 5 — session-time FLOW binding): a request whose flow
    // label was swapped in transit (owner+provider own the path) gets a
    // fully-valid signed response for the WRONG app — app pin and PKCE both
    // pass — so the auditor must compare the signed flow against the one THIS
    // tab requested, before any authorize link exists.
    elements['loginVerifiedLink'].href = ''; // clear the happy-path href
    substituteFlow = true;
    await executePreflightAndLogin('verified');
    substituteFlow = false;
    check('flow-substituted session is refused before PayPal (v186)',
      /FLOW SUBSTITUTION/.test(elements['secureLoginStatus'].innerText || ''),
      (elements['secureLoginStatus'].innerText || '').slice(0, 200));
    check('flow substitution built no authorize link',
      requests.length === 3 && !elements['loginVerifiedLink'].href,
      JSON.stringify({ requests: requests.length, href: elements['loginVerifiedLink'].href }));

    // v186: the client-side custom_info cap counts BYTES (TextEncoder),
    // matching the enclave's new server-side 512-byte rejection. 257 two-byte
    // chars = 257 UTF-16 units (the old char-count check passed them) but
    // 514 bytes — must be refused BEFORE any network call.
    document.getElementById('customInfoInput').value = 'é'.repeat(257);
    await executePreflightAndLogin('verified');
    document.getElementById('customInfoInput').value = '';
    check('oversized custom_info refused client-side by BYTES (v186)',
      /exceeds 512 bytes/.test(elements['secureLoginStatus'].innerText || ''),
      (elements['secureLoginStatus'].innerText || '').slice(0, 160));
    check('oversized custom_info made no network call',
      requests.length === 3, JSON.stringify(requests));
  } finally {
    globalThis.fetch = origFetch;
    setLoc(null);
    delete globalThis.localStorage;
    delete globalThis.sessionStorage;
  }
}

console.log('\nTest 33: v181 pasted-ENCRYPTED-blob audit — decrypt with this copy\'s session key, fail closed elsewhere');
{
  // User report (2026-10-23): pasting the success page\'s "Copy encrypted
  // report" blob into the auditor answered "Audit Failed: Invalid report."
  // — runAudit only understood decrypted envelopes. v181 makes the
  // documented recovery flow work: a TRUSTED copy that still holds the
  // throwaway S_client key decrypts the pasted blob and audits the envelope
  // (all localDecryptAndVerify checks intact); every other situation fails
  // closed with actionable guidance, never a bare parse error.
  globalThis.localStorage = (() => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; })();
  globalThis.sessionStorage = (() => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; })();
  const setLoc = (loc) => { if (loc === null) delete globalThis.location; else globalThis.location = loc; };
  setLoc({ protocol: 'file:', host: '', origin: 'null' });

  // Real login-session material: client ECDH key + nonce + v179 binding
  // slot, exactly like the flow that produced the user's pasted blob.
  const client = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const jwkStr = JSON.stringify(await crypto.subtle.exportKey('jwk', client.privateKey));
  const clientNonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const clientNonceHex = [...clientNonceBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  const clientPubDer = new Uint8Array(await crypto.subtle.exportKey('spki', client.publicKey));
  const bindingHex = await clientSessionBindingHex(clientPubDer, clientNonceHex);

  const built = await buildEnvelope({
    hwBuilder: async (nonce) => {
      const q = await buildTdxQuote({
        version: 4,
        // report_data = quote nonce ‖ client-session binding (v179 slot), so
        // the keyed paste path enforces the binding exactly like localClaim.
        reportData: concat(fromHex(nonce), fromHex(bindingHex)),
        innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
        leafKey: goodChain.leaf.key,
      });
      return tdxHw({ quoteB64: q.b64 });
    },
    // A genuine login report (paypal_user_info present) — the shape the
    // enclave mints post-PayPal and the shape the user actually pasted. The
    // session_context echoes THIS test's client session (honest enclave
    // behavior) so the auditor's paste-path recomputation matches the quote
    // slot bound above (F1: a login report with no client session is now
    // rejected outright).
    reportExtras: {
      paypal_user_info: { user_id: 'U1', sub: 'paste-sub', verified_account: 'true', payer_id: null },
      paypal_client_id: 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p',
      session_context: {
        client_pub_b64: Buffer.from(clientPubDer).toString('base64'),
        client_nonce_hex: clientNonceHex,
      },
    },
  });

  // Seal the envelope to the client key exactly like the enclave does
  // (Test 23's construction): HKDF-SHA256(shared, salt=nonce) → AES-256-GCM,
  // AAD = nonce.
  const enclaveKp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: enclaveKp.publicKey }, client.privateKey, 256);
  const kdfBase = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const e2eKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: clientNonceBytes, info: new TextEncoder().encode('paypal-auth-vm/e2ee/v1') },
    kdfBase, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: clientNonceBytes }, e2eKey, new TextEncoder().encode(JSON.stringify(built.envelope))));
  const b64 = (u8) => Buffer.from(u8).toString('base64');
  const blobBase = {
    alg: 'AES-256-GCM+HKDF-SHA256+ECDH-P256',
    aad: 'client_nonce',
    iv_b64: b64(iv),
    ct_b64: b64(ct),
    enclave_ecdh_public_key_b64: b64(new Uint8Array(await crypto.subtle.exportKey('spki', enclaveKp.publicKey))),
    enclave_signing_public_key: built.encPem,
    state: 'paste-test-state',
    flow: 'verified',
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const sessionFor = (over = {}) => JSON.stringify({
    host: 'https://login.airma.de', jwk: jwkStr, nonceHex: clientNonceHex,
    customInfo: 'NONE', p_enc: built.encPem, state: 'paste-test-state',
    flow: 'verified', clientPubB64: '', sessionBindingHex: bindingHex, ...over,
  });
  const auditBlob = async (blob) => {
    lastAlert = null;
    elements['attestationInput'].value = JSON.stringify(blob);
    elements['certInput'].value = '';
    const ok = await runAudit();
    return { ok, alert: lastAlert };
  };

  try {
    // (a) keyed trusted copy — the documented recovery flow — decrypts and
    // audits the envelope fully green.
    globalThis.localStorage.setItem('pav_local_session', sessionFor());
    let r = await auditBlob(clone(blobBase));
    check('keyed trusted copy decrypts the pasted blob and audits green', r.ok === true, String(r.alert).slice(0, 200));
    const persisted = JSON.parse(elements['attestationInput'].value || 'null');
    check('textarea now holds the decrypted envelope (re-audit + 💾 download work)',
      persisted && !!persisted.attestation_report, elements['attestationInput'].value.slice(0, 60));
    check('decrypted envelope persisted for the download button',
      /"attestation_report"/.test(globalThis.sessionStorage.getItem('pav_e2ee_report') || ''), 'missing pav_e2ee_report');

    // (b) no key in this copy → actionable guidance, never the old parse error.
    globalThis.localStorage.removeItem('pav_local_session');
    r = await auditBlob(clone(blobBase));
    check('no key: fails closed with ENCRYPTED BLOB guidance',
      r.ok === false && /ENCRYPTED BLOB/.test(r.alert) && /encrypted-attestation-report\.json/.test(r.alert), String(r.alert).slice(0, 220));
    check('no key: the old cryptic error is gone', !/Invalid report\./.test(r.alert), String(r.alert).slice(0, 120));

    // (c) enclave-served copy → decryption refused outright even WITH a key
    // (Web Auditor Tampering defense — decryption never runs there).
    globalThis.localStorage.setItem('pav_local_session', sessionFor());
    setLoc({ protocol: 'https:', host: 'login.airma.de', origin: 'https://login.airma.de' });
    r = await auditBlob(clone(blobBase));
    check('enclave-origin copy refuses the pasted blob outright',
      r.ok === false && /UNTRUSTED AUDITOR ORIGIN/.test(r.alert), String(r.alert).slice(0, 200));
    setLoc({ protocol: 'file:', host: '', origin: 'null' });

    // (d) blob sealed to a DIFFERENT login session's key → fail closed with
    // the decrypt-failure guidance (GCM auth / wrong shared secret).
    const other = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const wrongJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', other.privateKey));
    globalThis.localStorage.setItem('pav_local_session', sessionFor({ jwk: wrongJwk }));
    r = await auditBlob(clone(blobBase));
    check('wrong-session key: fail closed with decrypt-failure guidance',
      r.ok === false && /Could not decrypt the pasted blob/.test(r.alert), String(r.alert).slice(0, 220));
  } finally {
    setLoc(null);
    delete globalThis.localStorage;
    delete globalThis.sessionStorage;
    globalThis.preFlightPubKeyPem = null;
    globalThis.auditorSessionBindingHex = null;
    elements['attestationInput'].value = '';
  }
}

console.log('\nTest 34: audit round 3 — payment-flow abuse + side-channel hardening (R3-1..R3-4)');
{
  const verifySrc = readFileSync(join(repoRoot, 'verify.html'), 'utf8');
  const rustSrc = readFileSync(join(repoRoot, 'src', 'main.rs'), 'utf8');

  // --- R3-1: PKCE end-to-end (owner holds the PayPal client secret AND can
  // observe the redirect code at their own TLS endpoint — without PKCE they
  // exchange the code directly and read the identity in plaintext,
  // bypassing the enclave, the silicon gates and E2EE entirely).
  check('main.rs mints verifier + S256 challenge (SHA-256 over the verifier)',
    rustSrc.includes('let code_challenge = B64URL.encode(sha2::Sha256::digest(code_verifier.as_bytes()))'), 'challenge mint missing');
  check('main.rs signs code_challenge + method into the login fields',
    rustSrc.includes('"code_challenge": code_challenge') && rustSrc.includes('"code_challenge_method": "S256"'), 'signed PKCE fields missing');
  check('main.rs never echoes the verifier to any caller',
    !rustSrc.includes('"code_verifier":'), 'verifier appears in a json! payload');
  check('main.rs resolves the verifier before ANY PayPal call (fail closed)',
    /let mut code_verifier = \{[\s\S]{0,600}None => return invalid_session\(\)/.test(rustSrc), 'no fail-closed lookup');
  check('main.rs presents code_verifier at the token exchange',
    rustSrc.includes('("code_verifier", &code_verifier)'), 'exchange not PKCE-bound');
  check('verifier retired only on successful exchange',
    rustSrc.includes('state.pending_pkce.write().remove(state_param.trim())'), 'no retirement on success');
  check('PKCE table bounded + TTL-pruned',
    rustSrc.includes('const MAX_PENDING_PKCE: usize = 4096') && rustSrc.includes('const PKCE_TTL_SECS: u64 = 600'), 'ceiling/TTL missing');
  check('user-cancel/empty code handled BEFORE any exchange or consumption',
    rustSrc.includes('PayPal returned an error — no code was exchanged'), 'error-path early return missing');
  check('auditor requires PKCE before PayPal (definition + login path)',
    // v186: was >=3 (definition + executePreflightAndLogin + localPreflight);
    // localPreflight was deleted as dead duplication, so the invariant is now
    // definition + the single remaining login path (the claim path never
    // builds an authorize URL).
    (verifySrc.match(/requirePkceChallenge\(/g) || []).length >= 2,
    String((verifySrc.match(/requirePkceChallenge\(/g) || []).length));
  check('auditor carries the challenge + S256 method into the authorize URL',
    verifySrc.includes('&code_challenge=${encodeURIComponent(sf.code_challenge)}&code_challenge_method=S256'), 'authorize URL lacks PKCE');

  // --- R3-2: every route that can trigger outbound work is charged AND
  // enforced against the per-IP/global egress budget (the callback used to
  // charge after the exchange with the result discarded — never a 429).
  check('callback charges/enforces the budget BEFORE the PayPal exchange',
    /record_egress\(addr\.ip\(\), 24 \* 1024\)/.test(rustSrc)
      && rustSrc.indexOf('record_egress(addr.ip(), 24 * 1024)') < rustSrc.indexOf('oauth2/token'),
    'entry gate missing or after the exchange');
  check('claim route (/e2ee-blob) charges the budget',
    rustSrc.includes('record_egress(addr.ip(), 32 * 1024)'), 'claim unbudgeted');

  // --- R3-3: the platform clock is provider-controlled and runs +8h off
  // (observed live) — the signed timestamp comes from PayPal's Date over
  // pinned TLS when available, labelled either way.
  check('login report timestamp prefers PayPal Date (pinned-TLS source)',
    rustSrc.includes('paypal_now_ms') && rustSrc.includes('"timestamp_source"'), 'honest-timestamp logic missing');
  check('timestamp source is explicitly labelled (paypal_date | platform_clock)',
    rustSrc.includes('"paypal_date"') && rustSrc.includes('"platform_clock"'), 'labels missing');

  // --- R3-4: the default TraceLayer span logged the FULL URI (incl.
  // /callback?code=…&state=…) into kmsg — plaintext to the provider over the
  // serial console. Spans must carry the path only.
  check('console spans log method + path only (query redacted)',
    rustSrc.includes('make_span_with') && rustSrc.includes('uri = %req.uri().path()'), 'span redaction missing');
  check('no span field logs the raw URI (query would leak code/state)',
    !/uri = %req\.uri\(\)(?!\.path)/.test(rustSrc), 'raw URI still logged');
}

// ===========================================================================

console.log('\nTest 35: deploy-alibaba.sh keeps the self-report sink (v186 — a future deploy must not drop it)');
{
  // HANDOVER §0.10 found prod user_data hand-pushed with self_report while
  // deploy-alibaba.sh did NOT emit it — the next deploy would have silently
  // gone dark. The emission is now env-gated and source-pinned here.
  const depSrc = readFileSync(join(repoRoot, 'deploy-alibaba.sh'), 'utf8');
  // 2026-10-26: these three pins tracked the FIRST (env-gated) draft of the
  // emission and went stale when commit 3ddf904 replaced it with the
  // verified always-emit implementation (env → /tmp/pav-ak.* mirror → config
  // file block, bucket/endpoint/prefix env → file → prod default). Re-pinned
  // to the committed behaviour — same properties, current spelling.
  check('emission keyed on the write-only RAM key (env pair, else pav-ak mirror)',
    depSrc.includes('SR_KEY_ID="${SELF_REPORT_ACCESS_KEY_ID:-}"')
      && depSrc.includes('SR_KEY_SECRET="${SELF_REPORT_ACCESS_KEY_SECRET:-}"')
      && /\[\[ -n "\$SR_KEY_ID" && -n "\$SR_KEY_SECRET" \]\]/.test(depSrc),
    'env gate missing');
  check('emission merges self_report via jq (JSON-safe, not string concat)',
    depSrc.includes('.self_report = {')
      && depSrc.includes('sts_token: (.self_report.sts_token // null)')
      && depSrc.includes('> "$SELF_REPORT_MERGED"'),
    'jq merge missing');
  check('sink defaults match the live prod config (HK bucket, hongkong endpoint, boot prefix)',
    depSrc.includes('SELF_REPORT_BUCKET_DEF="paypal-tdx-relay-1792227992"')
      && depSrc.includes('SELF_REPORT_ENDPOINT_DEF="oss-cn-hongkong.aliyuncs.com"')
      && depSrc.includes('SELF_REPORT_PREFIX_DEF="boot"'),
    'defaults drifted from the deployed sink');
  check('emission runs BEFORE user_data is base64-encoded',
    depSrc.indexOf('SELF_REPORT_MERGED') > 0
      && depSrc.indexOf('USER_DATA_B64=') > depSrc.indexOf('SELF_REPORT_MERGED'),
    'emission after base64 — the sink would never reach user_data');
  check('deploy script never echoes the sink secret',
    !/echo[^\n]*\$SELF_REPORT_ACCESS_KEY_SECRET/.test(depSrc),
    'secret appears in an echo line');
}

console.log('\nTest 36: two explicit login links + key auto-generated on render (v188 — workflow button and claim step removed)');
{
  const verifySrc2 = readFileSync(join(repoRoot, 'verify.html'), 'utf8');
  // Structure: the v187 morphing workflow button and the whole claim state
  // machine are GONE; both login flows are explicit links from page load and
  // the throwaway key is created at RENDER with an on-page record of it.
  check('page has both explicit login links with inline flow handlers',
    verifySrc2.includes('id="loginVerifiedLink"')
      && verifySrc2.includes('id="loginFullLink"')
      && verifySrc2.includes("onclick=\"executePreflightAndLogin('verified')\"")
      && verifySrc2.includes("onclick=\"executePreflightAndLogin('full')\""),
    'explicit login links missing');
  check('initial workflow button is suppressed (removed entirely)',
    !verifySrc2.includes('id="workflowBtn"') && !verifySrc2.includes('workflowClick'),
    'workflow button still present');
  check('claim button and claim function are gone',
    !verifySrc2.includes('localClaim') && !verifySrc2.includes('Claim Encrypted Report')
      && !verifySrc2.includes('setWorkflow') && !verifySrc2.includes('applyWorkflowState'),
    'claim/workflow machinery still present');
  check('key-notice element exists for the on-page keygen record',
    verifySrc2.includes('id="keyNotice"'), 'keyNotice missing');
  check('key is generated on DOMContentLoaded (trusted copies only)',
    /if \(trustedAuditorContext\(\)\) \{\s*\n\s*const k = await ensureThrowawayKey\(\)/.test(verifySrc2),
    'render-time keygen hook missing');

  globalThis.sessionStorage = (() => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }; })();
  try {
    // render → key generated automatically + notice rendered on the page
    const k1 = await ensureThrowawayKey();
    check('key is generated on render (fresh) and stored in this tab',
      k1.fresh === true && !!k1.at && !!globalThis.sessionStorage.getItem('pav_client_jwk'),
      JSON.stringify({ fresh: k1.fresh, at: k1.at }));
    check('public half is a valid P-256 SPKI (91 bytes)',
      k1.pubRaw instanceof Uint8Array && k1.pubRaw.length === 91, String(k1.pubRaw && k1.pubRaw.length));
    renderKeyNotice(k1.fresh ? 'generated' : 'restored', k1.at);
    check('page announces the automatic key generation',
      /GENERATED AUTOMATICALLY when this page loaded/.test(elements['keyNotice'].innerText),
      elements['keyNotice'].innerText.slice(0, 140));
    const k2 = await ensureThrowawayKey();
    check('second call REUSES the stored key (no silent regeneration)',
      k2.fresh === false && k2.jwkStr === k1.jwkStr, JSON.stringify({ fresh: k2.fresh }));
    renderKeyNotice(k2.fresh ? 'generated' : 'restored', k2.at);
    check('reload path announces the restored key',
      /RESTORED from this tab/.test(elements['keyNotice'].innerText), elements['keyNotice'].innerText.slice(0, 140));
  } finally {
    delete globalThis.sessionStorage;
    document.getElementById('loginVerifiedLink').href = '';
    document.getElementById('loginVerifiedLink').textContent = '';
    document.getElementById('loginFullLink').textContent = '';
    document.getElementById('keyNotice').innerText = '';
  }
}

console.log('\nTest 37: /callback AUTO-DOWNLOADS the attestation, no landing page (v188)');
{
  const rustSrc2 = readFileSync(join(repoRoot, 'src', 'main.rs'), 'utf8');
  const cbStart = rustSrc2.indexOf('const CALLBACK_CONTENT');
  const cbEnd = rustSrc2.indexOf('"#;', cbStart);
  const cbContent = cbStart >= 0 && cbEnd > cbStart ? rustSrc2.slice(cbStart, cbEnd) : '';
  check('callback content present', !!cbContent, 'CALLBACK_CONTENT not found');
  check('page auto-downloads the encrypted attestation on load (no click)',
    cbContent.includes("URL.createObjectURL(new Blob([__b],{type:'application/json'})")
      && cbContent.includes("__a.download='encrypted-attestation-report.json'")
      && cbContent.includes('__a.click()'),
    'auto-download plumbing missing');
  check('auto-download and the rendered textarea read the SAME blob source',
    cbContent.includes('var __b=')
      && cbContent.includes("document.getElementById('e2ee-blob-view').value=__b;"),
    'sources diverged');
  check('no landing page: the tab tries to close itself after the download',
    cbContent.includes('window.close()'), 'auto-close missing');
  check('fallback keeps copy + re-download on the SAME ciphertext textarea',
    cbContent.includes('📋 Copy encrypted report')
      && cbContent.includes("a.download='encrypted-attestation-report.json'")
      && cbContent.includes("getElementById('e2ee-blob-view'); var blob=new Blob"),
    'fallback buttons missing');
  check('no claim reference on the callback page',
    !cbContent.includes('Claim Encrypted'), 'claim wording still present');
  check('callback content carries ONLY the __E2EE_BLOB__ ciphertext (no plaintext field introduced)',
    cbContent.includes('__E2EE_BLOB__') && !cbContent.includes('paypal_user_info'),
    'callback content shape changed');
  check('heading advertises the automatic download',
    cbContent.includes('Your encrypted attestation is downloading automatically'),
    'heading not updated');
  // v192 (user request): the page must NO LONGER close itself — it is the only
  // place its own TLS certificate can still be exported from the browser's
  // certificate panel, and that panel is the one channel a hostile host cannot
  // fake. It must instead walk the user through that export, and it must say
  // plainly that /tls-cert.pem is NOT an independent source for it.
  check('callback warns the download is IN PROGRESS (1/3)',
    cbContent.includes('1/3 — download in progress'), 'step 1 warning missing');
  check('callback NO LONGER force-closes the tab (no countdown, no timer close)',
    !cbContent.includes('autoclose-secs') && !cbContent.includes('autoclose-notice')
      && !/__secs\s*=\s*3/.test(cbContent) && !/__timer\s*=/.test(cbContent),
    'auto-close machinery still present');
  check('manual ✖ Close this tab button is still offered (v187 pinned fallback)',
    cbContent.includes('Close this tab') && cbContent.includes('window.close()'),
    'manual close button missing');
  check("step 2/3 walks the user through exporting THIS tab's certificate",
    cbContent.includes('2/3 — save the TLS certificate of THIS page')
      && cbContent.includes('Certificate is valid') && cbContent.includes('View Certificate'),
    'per-browser cert-export instructions missing');
  check('step 2/3 names /tls-cert.pem as NOT an independent source',
    cbContent.includes('/tls-cert.pem') && cbContent.includes('can never disagree with the report'),
    'self-comparison warning missing');
  check('step 3/3 says to load BOTH files in the previous local tab',
    cbContent.includes('3/3 — go back to the PREVIOUS (local) tab')
      && cbContent.includes('Browser TLS certificate')
      && cbContent.includes('Attestation JSON report'),
    'post-login instruction missing');
  check('the export reminder sits ABOVE the close button',
    cbContent.includes('cert-reminder')
      && cbContent.indexOf('cert-reminder') < cbContent.indexOf('Close this tab'),
    'cert reminder missing or below the close button');
}

console.log('\nTest 41: TLS certificate download offered BEFORE login (v189)');
{
  const rust = readFileSync(join(repoRoot, 'src', 'main.rs'), 'utf8');
  check('enclave routes GET /tls-cert.pem',
    rust.includes('.route("/tls-cert.pem", get(serve_tls_cert))'), 'route missing');
  check('handler serves application/x-pem-file with attachment disposition',
    rust.includes('application/x-pem-file')
      && rust.includes('CONTENT_DISPOSITION')
      && rust.includes('enclave-tls-certificate.pem'),
    'PEM response shape missing');
  check('handler fails closed before the cert is issued (503, no empty body)',
    rust.includes("TLS certificate not issued yet"), 'no not-ready branch');
  check('cert download is charged to the egress budget like every other GET',
    rust.includes('record_egress(addr.ip(), 4096)'), 'egress not charged');
  check('verify.html offers the cert download BEFORE the PayPal login links',
    html.indexOf('id="tlsCertDownload"') > -1
      && html.indexOf('id="tlsCertDownload"') < html.indexOf('id="loginVerifiedLink"'),
    'cert block missing or after the login links');
  check('download targets the enclave origin (https-validated), not a hard-coded host',
    html.includes("base + '/tls-cert.pem'") && html.includes("function downloadTlsCert()"),
    'downloadTlsCert missing');
  check('instructions cover the audit cert picker AND manual openssl inspection',
    html.includes('Browser TLS certificate (optional)') && html.includes('openssl x509')
      && html.includes('openssl s_client'), 'instructions incomplete');
  const idx2 = readFileSync(join(repoRoot, 'index.html'), 'utf8');
  check('index.html carries the cert block too (root page parity)',
    idx2.includes('id="tlsCertDownload"'), 'index.html missing the block');
}

console.log('\nTest 39: ZK escrow credential card — prove/verify wiring (v188, circom.md §5)');
{
  // ---- (0) pin sanity: constants must match the artifacts on disk --------
  const wasmSha = createHash('sha256').update(readFileSync(join(repoRoot, 'zk/identity_escrow.wasm'))).digest('hex');
  check('ZK_WASM_SHA256 pin matches zk/identity_escrow.wasm', globalThis.ZK_WASM_SHA256 === wasmSha,
    `pin=${globalThis.ZK_WASM_SHA256} file=${wasmSha}`);
  // F5: the assembled zkey (>100 MB) can never be pushed to GitHub, so CI
  // and fresh clones only carry the SPLIT parts — the pin is verified over
  // the concatenation, exactly like zkFetchZkey() does in the browser.
  check('ZK_ZKEY_PARTS names the two split parts',
    Array.isArray(globalThis.ZK_ZKEY_PARTS) && globalThis.ZK_ZKEY_PARTS.length === 2
      && globalThis.ZK_ZKEY_PARTS.every((p) => /^identity_escrow_final\.zkey\.part\d$/.test(p)),
    JSON.stringify(globalThis.ZK_ZKEY_PARTS));
  const partBufs = (globalThis.ZK_ZKEY_PARTS || []).map((p) => readFileSync(join(repoRoot, 'zk', p)));
  check('every zkey part exists and is under GitHub\'s 100 MB object limit',
    partBufs.length === 2 && partBufs.every((b) => b.length > 0 && b.length < 100 * 1024 * 1024),
    partBufs.map((b) => b && b.length).join(' + '));
  check('split zkey parts are TRACKED by git (not ignored)',
    partBufs.length === 2 && spawnSync('git', ['check-ignore', ...globalThis.ZK_ZKEY_PARTS.map((p) => join(repoRoot, 'zk', p))], { encoding: 'utf8', cwd: repoRoot }).status === 1,
    'a part is gitignored — Pages could never serve it');
  const zkeySha = createHash('sha256').update(Buffer.concat(partBufs)).digest('hex');
  check('ZK_ZKEY_SHA256 pin matches the ASSEMBLED split parts (browser fetch order)',
    globalThis.ZK_ZKEY_SHA256 === zkeySha,
    `pin=${globalThis.ZK_ZKEY_SHA256} assembled=${zkeySha}`);
  {
    // if the local (gitignored) assembled file exists, it must agree too
    let disk = '';
    try { disk = createHash('sha256').update(readFileSync(join(repoRoot, 'zk/identity_escrow_final.zkey'))).digest('hex'); } catch (e) { disk = 'absent'; }
    check('assembled-on-disk zkey agrees with the parts (or is absent)',
      disk === 'absent' || disk === zkeySha, `disk=${disk.slice(0, 24)}`);
  }
  const snarkSha = 'sha384-' + createHash('sha384').update(readFileSync(join(repoRoot, 'node_modules/snarkjs/build/snarkjs.min.js'))).digest('base64');
  check('snarkjs SRI pin matches the installed 0.7.5 bundle bytes', globalThis.ZK_SNARKJS_SRI === snarkSha,
    `pin=${globalThis.ZK_SNARKJS_SRI} file=${snarkSha}`);
  const vkeyFile = JSON.parse(readFileSync(join(repoRoot, 'zk/identity_escrow_vkey.json'), 'utf8'));
  check('embedded vkey is byte-identical to zk/identity_escrow_vkey.json',
    JSON.stringify(globalThis.zkCredVkey) === JSON.stringify(vkeyFile));
  check('zkParseVkey() accepts the embedded key (protocol/curve/nPublic guards)',
    (() => { try { const v = zkParseVkey(); return v.nPublic === 271; } catch (e) { return false; } })());
  check('example escrow key constants present (77-digit decimals)',
    /^\d{70,80}$/.test(globalThis.ZK_EXAMPLE_ESCROW_X) && /^\d{70,80}$/.test(globalThis.ZK_EXAMPLE_ESCROW_Y));

  // ---- (1) green login audit stashes the canonical identity + reveals card
  const greenQ = async (nonce) => tdxHw({
    quoteB64: (await buildTdxQuote({
      version: 4, reportData: reportDataFor(nonce),
      innerChainPems: [goodChain.leaf.pem, goodChain.int.pem],
      leafKey: goodChain.leaf.key,
    })).b64,
  });
  const AUDITED_APP = 'AZXkzMWMioIQ-lYG1lrKrgiDAwtx2rWtigoGqdJssecNIdcp2q5FxHmvxyDaUJcvz1zAwVeSgIzOuI6p';
  // Realistic-length identity: the circuit band is msg_len ∈ [248, 300] bytes
  // (circom.md §1) — the fixture must exercise that band, not a 70-byte toy.
  const who = {
    user_id: 'U' + '7'.repeat(60),
    sub: 'zk-sub-' + 'a'.repeat(120),
    verified_account: 'true',
    payer_id: 'P' + '9'.repeat(40),
  };
  const canonicalId = JSON.stringify({
    user_id: who.user_id, sub: who.sub, verified_account: who.verified_account, payer_id: who.payer_id,
  });
  check('fixture identity lands inside the circuit band [248,300]',
    canonicalId.length >= 248 && canonicalId.length <= 300, `len=${canonicalId.length}`);
  const built = await buildEnvelope({
    hwBuilder: greenQ,
    reportExtras: { paypal_user_info: who, paypal_client_id: AUDITED_APP },
  });
  const res = await runAuditWith(built.envelope);
  check('green login audit passes', res.ok === true, `alert=${res.alert}`);
  const zkCard = document.getElementById('zkHandoffCard');
  check('ZK handoff card revealed by the green login audit', zkCard.style.display === 'block');
  check('auditor carries the pinned zk.html link + postMessage sender',
    html.includes('id="zkOpenBtn"')
      && html.includes('onclick="return openZkProver(this.href)"')
      && html.includes("ZK_PROVER_URL = 'https://leonardopedro.github.io/verifiedUniqueAliases/zk.html'")
      && html.includes('ev.origin !== ZK_PROVER_ORIGIN'));
  check('the ZK CARD itself lives in zk.html, not in the auditor (v194 split)',
    zkHtml.includes('id="zkCard"') && !html.includes('id="zkCard"'));
  check('stash === the canonical preimage bytes the gate hashed',
    globalThis.zkIdentityJson === canonicalId,
    `stashLen=${globalThis.zkIdentityJson && globalThis.zkIdentityJson.length} wantLen=${canonicalId.length}`);
  check('stash hash === identityHashOf(fixture) (one-serializer guarantee)',
    globalThis.zkIdentityHashHex === identityHashOf(who),
    `stash=${globalThis.zkIdentityHashHex && globalThis.zkIdentityHashHex.slice(0, 16)}`);

  // ---- (2) a FAILING audit must not overwrite a prior green stash --------
  const other = { user_id: 'EVIL', sub: 'other', verified_account: 'true', payer_id: null };
  const spoof = await buildEnvelope({
    hwBuilder: greenQ,
    reportExtras: {
      paypal_user_info: other,
      paypal_user_info_raw_hash: identityHashOf(who),
      paypal_client_id: AUDITED_APP,
    },
  });
  const s = await runAuditWith(spoof.envelope);
  check('spoofed identity audit fails', s.ok === false);
  check('failed audit does NOT overwrite the stashed identity',
    globalThis.zkIdentityJson === canonicalId, 'stash was clobbered by a failed audit');
  // restore a green envelope in the textarea for the prove step
  await runAuditWith(built.envelope);

  // ---- (2.5) v194 HANDOFF: zk.html re-verifies the stash fail-closed -------
  // band → hash re-derivation → SIGNED raw-hash cross-check → report bytes.
  // This is exactly what the real postMessage receiver runs before it acks.
  const handoffText = JSON.stringify(built.envelope, null, 2);
  check('handoff accepted by zk.html (band + hash + signed raw-hash)',
    await globalThis.zkStashIdentity(canonicalId, identityHashOf(who), handoffText) === true,
    document.getElementById('zkIdentityStatus').innerText.slice(0, 160));
  check('zk.html holds the exact report bytes report_sha256 must bind',
    globalThis.zkReportText === handoffText,
    `len=${globalThis.zkReportText && globalThis.zkReportText.length} want=${handoffText.length}`);
  {
    const stashBefore = globalThis.zkIdentityJson;
    check('handoff with a TAMPERED hash is refused',
      await globalThis.zkStashIdentity(canonicalId, '0'.repeat(64), handoffText) === false,
      document.getElementById('zkIdentityStatus').innerText.slice(0, 120));
    check('a refused handoff never overwrites the stash',
      globalThis.zkIdentityJson === stashBefore, 'stash clobbered by a refused handoff');
    // identity == ours but the REPORT carries another user's record: the
    // report-side preimage cross-check must refuse (auditor-gate parity).
    check('handoff whose identity ≠ the report identity is refused',
      await globalThis.zkStashIdentity(canonicalId, identityHashOf(who),
        JSON.stringify(spoof.envelope, null, 2)) === false,
      document.getElementById('zkIdentityStatus').innerText.slice(0, 120));
    // restore the good stash for the prove step
    check('good handoff re-applied for the prove step',
      await globalThis.zkStashIdentity(canonicalId, identityHashOf(who), handoffText) === true);
  }

  // ---- (3) generate: mocked snarkjs, REAL artifact fetch+pin verification --
  const realFetch = globalThis.fetch;
  let fetchTamper = false;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('/zk/')) {
      const name = u.split('/zk/')[1].split('?')[0];
      let buf = readFileSync(join(repoRoot, 'zk', name));
      if (fetchTamper) { const b = Buffer.from(buf); b[0] ^= 0xff; buf = b; }
      return {
        ok: true, status: 200,
        arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
      };
    }
    return realFetch(url);
  };
  // URL/document stubs for the download step
  const capturedBlobs = [];
  const realCreateURL = URL.createObjectURL, realRevokeURL = URL.revokeObjectURL;
  URL.createObjectURL = (b) => { capturedBlobs.push(b); return 'blob:test'; };
  URL.revokeObjectURL = () => {};
  const realCreateEl = document.createElement, realBody = document.body;
  document.createElement = () => ({ click() {}, remove() {}, style: {}, href: '', download: '' });
  document.body = { appendChild() {}, removeChild() {} };

  let proveInput = null, verifyCall = null, verifyResult = true;
  globalThis.zkSnarkjsModule = {
    groth16: {
      fullProve: async (input, wasmBuf, zkeyBuf) => {
        proveInput = input;
        // the buffers reaching the prover MUST be the pin-verified real bytes
        check('prover receives the real pinned wasm bytes',
          createHash('sha256').update(Buffer.from(wasmBuf)).digest('hex') === wasmSha);
        check('prover receives the real pinned zkey bytes',
          createHash('sha256').update(Buffer.from(zkeyBuf)).digest('hex') === zkeySha);
        // snarkjs fastfile only accepts a Uint8Array / string / {type} object:
        // handing it the raw ArrayBuffer made the LIVE Generate button throw
        // "Invalid FastFile type: undefined" (2026-10-26 user report) — the
        // mocked prover can't reproduce that, so pin the type here.
        check('prover receives Uint8Array FastFiles (raw ArrayBuffer ⇒ "Invalid FastFile type: undefined")',
          wasmBuf instanceof Uint8Array && zkeyBuf instanceof Uint8Array,
          `wasm=${Object.prototype.toString.call(wasmBuf)} zkey=${Object.prototype.toString.call(zkeyBuf)}`);
        // public signal layout: [R.x, R.y, verified, C0..C9, hashBits(256), ex, ey]
        const bits = [];
        for (let i = 0; i < input.identity_hash_bits.length; i++) bits.push(String(input.identity_hash_bits[i]));
        const ps = [
          '1556631486497778477605397274746159966306848378885429798549421757913197467405',
          '16893061115786568867716241603005123395306176793643233966794415383620167560086',
          '1',
          ...Array.from({ length: 10 }, (_, i) => String(1000 + i)),
          ...bits,
          globalThis.ZK_EXAMPLE_ESCROW_X,
          globalThis.ZK_EXAMPLE_ESCROW_Y,
        ];
        if (ps.length !== 271) throw new Error('fixture layout bug: ' + ps.length);
        return { proof: { pi_a: ['1', '2', '1'], pi_b: [['1', '2'], ['1', '2'], ['1', '1']], pi_c: ['1', '2', '1'], protocol: 'groth16', curve: 'bn128' }, publicSignals: ps };
      },
      verify: async (vkey, ps, proof) => {
        verifyCall = { vkey, ps, proof };
        return verifyResult;
      },
    },
  };

  const pg = zkGenerateCredential();
  if (pg) await pg;
  const proveStatus = document.getElementById('zkProveStatus').innerText;
  check('credential generated + self-verified (status ✅)', proveStatus.startsWith('✅'), proveStatus.slice(0, 260));
  check('prover got the stashed identity bytes with msg_len in band',
    proveInput && proveInput.msg_len === String(canonicalId.length)
      && Buffer.from(Uint8Array.from(proveInput.raw_json_bytes.slice(0, canonicalId.length))).toString('utf8') === canonicalId,
    `msg_len=${proveInput && proveInput.msg_len}`);
  check('prover got msg_len ∈ [248,300] and a 300-byte padded buffer',
    proveInput && proveInput.raw_json_bytes.length === 300
      && Number(proveInput.msg_len) >= 248 && Number(proveInput.msg_len) <= 300);
  {
    // identity_hash_bits: 256 bits MSB-first of the stash hash
    const expectBits = [];
    for (let i = 0; i < globalThis.zkIdentityHashHex.length; i += 2) {
      const b = parseInt(globalThis.zkIdentityHashHex.substr(i, 2), 16);
      for (let t = 7; t >= 0; t--) expectBits.push((b >> t) & 1);
    }
    check('identity_hash_bits = 256 MSB-first bits of the audited hash',
      JSON.stringify(proveInput && proveInput.identity_hash_bits) === JSON.stringify(expectBits));
  }
  check('escrow defaults to the example key when inputs are empty',
    proveInput && proveInput.escrow_pubkey_x === globalThis.ZK_EXAMPLE_ESCROW_X
      && proveInput.escrow_pubkey_y === globalThis.ZK_EXAMPLE_ESCROW_Y);
  check('ephemeral key is a 256-bit scalar string',
    proveInput && /^\d{70,80}$/.test(proveInput.ephemeral_private_key));
  check('verification ran against the EMBEDDED vkey',
    verifyCall && JSON.stringify(verifyCall.vkey) === JSON.stringify(globalThis.zkCredVkey));
  check('a credential blob was downloaded', capturedBlobs.length === 1);
  let cred = null;
  if (capturedBlobs.length === 1) cred = JSON.parse(await capturedBlobs[0].text());
  check('credential parses as JSON', !!cred);
  check('credential schema + 271 raw signals + verified bit',
    cred && cred.schema === 'pav-circom-escrow/v1'
      && Array.isArray(cred.public_signals.raw) && cred.public_signals.raw.length === 271
      && cred.public_signals.verified_account_bit === 1,
    cred && `raw=${cred.public_signals.raw && cred.public_signals.raw.length}`);
  check('credential identity hash === audited hash (explicit + raw[13..269] bits)',
    cred && cred.public_signals.identity_hash_hex === globalThis.zkIdentityHashHex
      && cred.public_signals.raw.slice(13, 269).join('') ===
        (globalThis.zkIdentityHashHex.match(/./g).map(h => parseInt(h, 16).toString(2).padStart(4, '0')).join('')));
  {
    // report_sha256 must bind the SAME canonical bytes the download button uses
    const text = reportFileText();
    const wantSha = createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
    check('report_sha256 === sha256(reportFileText()) (one canonical serialization)',
      cred && cred.report_sha256 === wantSha,
      `cred=${cred && cred.report_sha256.slice(0, 16)} want=${wantSha.slice(0, 16)}`);
    const dl = downloadReportFile();
    const dlText = capturedBlobs.length ? await capturedBlobs[capturedBlobs.length - 1].text() : '';
    check('downloadReportFile emits the same canonical bytes it hashes',
      dl === true && dlText === text);
  }
  check('proving refuses a verify=false self-check (fail closed)', await (async () => {
    verifyResult = false;
    capturedBlobs.length = 0;
    const p2 = zkGenerateCredential();
    if (p2) { try { await p2; } catch (e) { /* expected */ } }
    verifyResult = true;
    const st = document.getElementById('zkProveStatus').innerText;
    document.getElementById('zkProveStatus').innerText = '';
    return st.includes('self-verification FAILED') && capturedBlobs.length === 0;
  })());

  // ---- (4) verify path: green, then every fail-closed branch --------------
  const vs = () => document.getElementById('zkVerifyStatus').innerText;
  document.getElementById('zkVerifyStatus').innerText = '';
  let vp = zkVerifyCredential(cred);
  if (vp) await vp;
  check('credential verifies green with BOTH cross-checks (identity hash + report sha)',
    vs().startsWith('✅') && vs().includes('identity-hash ↔ audited report ✓')
      && vs().includes('report_sha256 ↔ audited file bytes ✓'), vs().slice(0, 300));

  document.getElementById('zkVerifyStatus').innerText = '';
  const tampered = JSON.parse(JSON.stringify(cred));
  tampered.public_signals.identity_hash_hex = 'ab'.repeat(32);
  vp = zkVerifyCredential(tampered);
  if (vp) await vp;
  check('identity-hash mismatch fails closed (MISMATCH named)',
    vs().includes('IDENTITY HASH MISMATCH'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const wrongReport = JSON.parse(JSON.stringify(cred));
  wrongReport.report_sha256 = '00'.repeat(32);
  vp = zkVerifyCredential(wrongReport);
  if (vp) await vp;
  check('report_sha256 mismatch fails closed (REPORT BINDING named)',
    vs().includes('REPORT BINDING MISMATCH'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const wrongSchema = JSON.parse(JSON.stringify(cred));
  wrongSchema.schema = 'something/else';
  vp = zkVerifyCredential(wrongSchema);
  if (vp) await vp;
  check('foreign schema rejected', vs().includes('not a pav-circom-escrow/v1 credential'));

  // ---- F4 (R2 finding): every summary field must be bound to the PROVEN
  // signals. A valid proof over DIFFERENT raw[] values must never be
  // displayed as the audited identity / verified bit / escrow recipient.
  document.getElementById('zkVerifyStatus').innerText = '';
  const f4Bits = JSON.parse(JSON.stringify(cred));
  f4Bits.public_signals.raw[13] = f4Bits.public_signals.raw[13] === '0' ? '1' : '0'; // flip first hash bit
  vp = zkVerifyCredential(f4Bits);
  if (vp) await vp;
  check('F4: forged summary hash vs proven raw[] bits → IDENTITY HASH MISMATCH (proven-signals wording)',
    vs().includes('IDENTITY HASH MISMATCH') && vs().includes('PROVEN signals'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const f4Bit = JSON.parse(JSON.stringify(cred));
  f4Bit.public_signals.raw[2] = '0';               // proof constrains verified=0…
  f4Bit.public_signals.verified_account_bit = 1;   // …summary claims 1
  vp = zkVerifyCredential(f4Bit);
  if (vp) await vp;
  check('F4: forged verified_account_bit → VERIFIED-BIT MISMATCH',
    vs().includes('VERIFIED-BIT MISMATCH'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const f4Escrow = JSON.parse(JSON.stringify(cred));
  f4Escrow.public_signals.escrow_pubkey = ['12345', '67890'];
  vp = zkVerifyCredential(f4Escrow);
  if (vp) await vp;
  check('F4: forged escrow_pubkey → ESCROW KEY MISMATCH',
    vs().includes('ESCROW KEY MISMATCH'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const f4Ct = JSON.parse(JSON.stringify(cred));
  f4Ct.public_signals.ciphertext = f4Ct.public_signals.ciphertext.map(() => '999');
  vp = zkVerifyCredential(f4Ct);
  if (vp) await vp;
  check('F4: forged ciphertext → CIPHERTEXT MISMATCH',
    vs().includes('CIPHERTEXT MISMATCH'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const f4Eph = JSON.parse(JSON.stringify(cred));
  f4Eph.public_signals.ephemeral_pubkey = ['42', '43'];
  vp = zkVerifyCredential(f4Eph);
  if (vp) await vp;
  check('F4: forged ephemeral_pubkey → EPHEMERAL KEY MISMATCH',
    vs().includes('EPHEMERAL KEY MISMATCH'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const f4Mal = JSON.parse(JSON.stringify(cred));
  f4Mal.public_signals.raw[13] = '7'; // not a bit
  vp = zkVerifyCredential(f4Mal);
  if (vp) await vp;
  check('F4: non-bit raw signal → PROVEN SIGNAL MALFORMED',
    vs().includes('PROVEN SIGNAL MALFORMED'), vs().slice(0, 240));

  document.getElementById('zkVerifyStatus').innerText = '';
  const shortSignals = JSON.parse(JSON.stringify(cred));
  shortSignals.public_signals.raw = ['1', '2'];
  vp = zkVerifyCredential(shortSignals);
  if (vp) await vp;
  check('signal-count mismatch rejected (271 enforced)', vs().includes('271 raw public signals'));

  document.getElementById('zkVerifyStatus').innerText = '';
  verifyResult = false;
  vp = zkVerifyCredential(cred);
  if (vp) await vp;
  check('Groth16 verify=false fails closed', vs().includes('Groth16 verification FAILED'), vs().slice(0, 200));
  verifyResult = true;

  // ---- (5) artifact integrity: tampered fetch must refuse to prove --------
  fetchTamper = true;
  globalThis.zkAssetCache = {};
  document.getElementById('zkProveStatus').innerText = '';
  let threw = false;
  try {
    const p3 = zkGenerateCredential();
    if (p3) await p3;
  } catch (e) { threw = /INTEGRITY FAILURE/.test(e.message); }
  const tamperStatus = document.getElementById('zkProveStatus').innerText;
  check('tampered wasm fetch refuses to prove (INTEGRITY FAILURE)',
    threw || tamperStatus.includes('INTEGRITY FAILURE'), `${tamperStatus.slice(0, 240)}`);
  fetchTamper = false;

  // ---- (6) no-audit guard: generate without a stash fails closed ----------
  document.getElementById('zkProveStatus').innerText = '';
  const savedId = globalThis.zkIdentityJson, savedHash = globalThis.zkIdentityHashHex;
  globalThis.zkIdentityJson = null; globalThis.zkIdentityHashHex = null;
  const p4 = zkGenerateCredential();
  if (p4) await p4;
  check('generate with no identity loaded (handoff/paste) fails closed',
    document.getElementById('zkProveStatus').innerText.includes('no identity loaded on this page'),
    document.getElementById('zkProveStatus').innerText.slice(0, 160));
  globalThis.zkIdentityJson = savedId; globalThis.zkIdentityHashHex = savedHash;

  // ---- restore everything ----------------------------------------------
  globalThis.fetch = realFetch;
  URL.createObjectURL = realCreateURL; URL.revokeObjectURL = realRevokeURL;
  document.createElement = realCreateEl; document.body = realBody;
  globalThis.zkSnarkjsModule = null;
  globalThis.zkAssetCache = {};
}

console.log('\nTest 40: index.html ↔ verify.html auditor parity (F2 — no stale duplicate verifier)');
{
  // index.html (the GitHub Pages ROOT and login app) embeds the SAME auditor
  // script. Two copies of security-critical verification logic drift silently
  // (F2 finding: they had already diverged when verify.html gained the ZK
  // layer). This gate makes ANY drift fail the suite until the copies are
  // re-synced — the script is the verifier; the HTML bodies may differ.
  const idxHtml = readFileSync(join(repoRoot, 'index.html'), 'utf8');
  const grab = (s, name) => {
    const m = s.match(/<script>([\s\S]*)<\/script>/);
    if (!m) throw new Error('no inline auditor script in ' + name);
    return m[1];
  };
  const vScript = grab(html, 'verify.html');
  const iScript = grab(idxHtml, 'index.html');
  check('auditor scripts are byte-identical (index.html ↔ verify.html)',
    vScript === iScript,
    `verify=${vScript.length}B index=${iScript.length}B` +
      (vScript === iScript ? '' : ' — RE-SYNC index.html from verify.html'));
  check('both copies carry the ZK HANDOFF markup (id="zkHandoffCard")',
    html.includes('id="zkHandoffCard"') && idxHtml.includes('id="zkHandoffCard"'));
  check('ZK card + embedded vkey moved OUT of the auditor (v194: zk.html owns them)',
    !html.includes('id="zkCard"') && !html.includes('var zkCredVkey = {')
      && zkHtml.includes('id="zkCard"') && zkHtml.includes('var zkCredVkey = {'));
  check('index.html inline script passes node --check', (() => {
    const tmp = join(dir, 'index-script.js');
    writeFileSync(tmp, iScript);
    const r = spawnSync(process.execPath, ['--check', tmp], { encoding: 'utf8' });
    return r.status === 0;
  })());
}

console.log('\nTest 42: authority escrow public key — paste field + file picker (v190)');
{
  const parse = globalThis.zkParseAuthorityKey;
  check('zkParseAuthorityKey exposed by zk.html', typeof parse === 'function');

  const EX = globalThis.ZK_EXAMPLE_ESCROW_X, EY = globalThis.ZK_EXAMPLE_ESCROW_Y;
  check('decimal "x y" pair parses to the same coordinates',
    parse(EX + ' ' + EY).x === EX && parse(EX + ' ' + EY).y === EY);

  // BabyJubjub Base8 — a SECOND valid point (on-curve verified offline
  // against circomlibjs, a=168700 d=168696 over the BN254 scalar field).
  const BX = '5299619240641551281634865583518297030282874472190772894086521144482721001553';
  const BY = '16950150798460657717958625567821834550301663161624707787222815936182638968203';
  check('labelled "x: … / y: …" form parses', parse('x: ' + BX + '\n  y: ' + BY).x === BX);
  check('JSON {"x","y"} form parses', parse(JSON.stringify({ x: BX, y: BY })).x === BX);
  check('JSON {"pubkey":[x,y]} form parses', parse(JSON.stringify({ pubkey: [BX, BY] })).y === BY);
  const err = (t) => { try { parse(t); return '(accepted!)'; } catch (e) { return e.message; } };
  check('PEM input rejected with a BabyJubjub-specific message',
    /BabyJubjub/.test(err('-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqghello')), err('-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqghello').slice(0, 90));
  check('off-curve point rejected (fails closed before proving)',
    /NOT on BabyJubjub/.test(err('1 1')), err('1 1'));
  check('non-decimal coordinate rejected', /decimal/.test(err('0x1234 abcd')), err('0x1234 abcd'));
  check('wrong token count rejected', /two decimal/.test(err('123')), err('123'));

  const savedX = document.getElementById('zkEscrowX').value;
  const savedY = document.getElementById('zkEscrowY').value;
  globalThis.zkApplyAuthorityKey(BX + ' ' + BY, 'file "authority.txt"');
  check('apply() writes the authority key into the fields the prover reads',
    document.getElementById('zkEscrowX').value === BX
      && document.getElementById('zkEscrowY').value === BY,
    document.getElementById('zkEscrowX').value.slice(0, 22));

  const idxNow = readFileSync(join(repoRoot, 'index.html'), 'utf8');
  const pos = (s, id) => s.indexOf('id="' + id + '"');
  check('zk.html: paste field + file picker BOTH before the ⚡ button',
    pos(zkHtml, 'zkAuthorityKey') > -1 && pos(zkHtml, 'zkAuthorityKeyFile') > -1
      && pos(zkHtml, 'zkAuthorityKey') < pos(zkHtml, 'zkProveBtn')
      && pos(zkHtml, 'zkAuthorityKeyFile') < pos(zkHtml, 'zkProveBtn'));
  check('the auditor copies no longer carry the ZK controls (v194 split)',
    !html.includes('id="zkAuthorityKey"') && !idxNow.includes('id="zkAuthorityKey"'));
  check('prove path re-validates a pasted key (source-pinned in zk.html)',
    /akRaw = \(\(document\.getElementById\('zkAuthorityKey'\)/.test(zkHtml)
      && zkHtml.includes('if (akRaw) zkApplyAuthorityKey(akRaw,'));

  // ---- end-to-end: the pasted authority key reaches the PROOF ------------
  const savedId2 = globalThis.zkIdentityJson, savedHash2 = globalThis.zkIdentityHashHex;
  const repEl = document.getElementById('attestationInput');
  const savedRep = repEl.value;
  if (!repEl.value) repEl.value = JSON.stringify({ fixture: 'authority-key-flow' });
  const realFetch2 = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('/zk/')) {
      const buf = readFileSync(join(repoRoot, 'zk', u.split('/zk/')[1].split('?')[0]));
      return { ok: true, status: 200, arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) };
    }
    return realFetch2(url);
  };
  const realCU = URL.createObjectURL, realRU = URL.revokeObjectURL;
  const realCE2 = document.createElement, realBD2 = document.body;
  const blobs2 = [];
  URL.createObjectURL = (b) => { blobs2.push(b); return 'blob:t2'; };
  URL.revokeObjectURL = () => {};
  document.createElement = () => ({ click() {}, remove() {}, style: {}, href: '', download: '' });
  document.body = { appendChild() {}, removeChild() {} };
  let proveInput2 = null;
  globalThis.zkSnarkjsModule = { groth16: {
    fullProve: async (input) => {
      proveInput2 = input;
      const ps = [
        '1556631486497778477605397274746159966306848378885429798549421757913197467405',
        '16893061115786568867716241603005123395306176793643233966794415383620167560086',
        '1',
        ...Array.from({ length: 10 }, (_, i) => String(1000 + i)),
        ...input.identity_hash_bits.map(String),
        input.escrow_pubkey_x, input.escrow_pubkey_y,
      ];
      if (ps.length !== 271) throw new Error('fixture layout bug: ' + ps.length);
      return { proof: { pi_a: ['1', '2', '1'], pi_b: [['1', '2'], ['1', '2'], ['1', '1']], pi_c: ['1', '2', '1'], protocol: 'groth16', curve: 'bn128' }, publicSignals: ps };
    },
    verify: async () => true,
  } };
  document.getElementById('zkAuthorityKey').value = BX + ' ' + BY;
  try { const pA = zkGenerateCredential(); if (pA) await pA; } catch (e) { /* surfaced below */ }
  const stA = document.getElementById('zkProveStatus').innerText;
  const credA = blobs2.length ? JSON.parse(await blobs2[0].text()) : null;
  check('prove flow runs green with an authority key pasted', stA.startsWith('✅'), stA.slice(0, 240));
  check('the PROOF is bound to the authority key (escrow_pubkey === pasted key)',
    proveInput2 && proveInput2.escrow_pubkey_x === BX && proveInput2.escrow_pubkey_y === BY,
    proveInput2 && String(proveInput2.escrow_pubkey_x).slice(0, 22));
  check('the credential carries the authority key as escrow recipient',
    credA && credA.public_signals.escrow_pubkey[0] === BX
      && credA.public_signals.escrow_pubkey[1] === BY,
    credA && JSON.stringify(credA.public_signals.escrow_pubkey));

  document.getElementById('zkAuthorityKey').value = '1 1';
  document.getElementById('zkProveStatus').innerText = '';
  blobs2.length = 0; proveInput2 = null;
  const pB = zkGenerateCredential();
  if (pB) { try { await pB; } catch (e) { /* expected */ } }
  check('an off-curve authority key fails closed BEFORE proving',
    !proveInput2
      && document.getElementById('zkProveStatus').innerText.includes('NOT on BabyJubjub'),
    document.getElementById('zkProveStatus').innerText.slice(0, 200));

  // ---- restore ----------------------------------------------------------
  globalThis.fetch = realFetch2;
  URL.createObjectURL = realCU; URL.revokeObjectURL = realRU;
  document.createElement = realCE2; document.body = realBD2;
  globalThis.zkSnarkjsModule = null; globalThis.zkAssetCache = {};
  document.getElementById('zkAuthorityKey').value = '';
  document.getElementById('zkEscrowX').value = savedX;
  document.getElementById('zkEscrowY').value = savedY;
  document.getElementById('zkProveStatus').innerText = '';
  globalThis.zkIdentityJson = savedId2; globalThis.zkIdentityHashHex = savedHash2;
  repEl.value = savedRep;
}

console.log('\nTest 43: browser-side BabyJubjub keypair generator — no circomlibjs (v191)');
{
  const { buildBabyjub } = require('circomlibjs');
  const bj = await buildBabyjub();
  const toBig = (x) => (typeof x === 'bigint' ? x : bj.F.toObject(x));
  const SUB = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');

  check('keygen functions exposed (scalar / random / button / save)',
    ['zkKeypairFromScalar', 'zkRandomScalar', 'zkGenerateAuthorityKeypair', 'zkSaveAuthorityKeypair']
      .every((n) => typeof globalThis[n] === 'function'));

  // Deterministic scalar → the page's own point arithmetic must agree with
  // circomlibjs (the reference implementation the decryptor uses), exactly.
  const SK = 75834567890123456789012345678901234567890123456789n;
  const kp = globalThis.zkKeypairFromScalar(SK);
  const ref = bj.mulPointEscalar(bj.Base8, SK);
  check('deterministic scalar: x byte-identical to circomlibjs', kp.x === toBig(ref[0]).toString(),
    kp.x.slice(0, 24) + ' vs ' + toBig(ref[0]).toString().slice(0, 24));
  check('deterministic scalar: y byte-identical to circomlibjs', kp.y === toBig(ref[1]).toString(),
    kp.y.slice(0, 24) + ' vs ' + toBig(ref[1]).toString().slice(0, 24));
  check('sk stays < subOrder (so decryptor and circuit agree)', kp.sk === SK && SK < SUB);
  check('generated point passes the page own on-curve check',
    globalThis.zkPointOnBabyJub(BigInt(kp.x), BigInt(kp.y)));

  // Random keygen from Web Crypto → fills exactly what the prover reads.
  const escX = document.getElementById('zkEscrowX'), escY = document.getElementById('zkEscrowY');
  const ak = document.getElementById('zkAuthorityKey');
  escX.value = ''; escY.value = ''; ak.value = '';
  const g = globalThis.zkGenerateAuthorityKeypair();
  check('random keygen returns a keypair', !!g, document.getElementById('zkKeygenStatus').innerText.slice(0, 120));
  check('status line reports success', document.getElementById('zkKeygenStatus').innerText.startsWith('✅'));
  if (g) {
    check('sk drawn from Web Crypto lands in [1, subOrder)', g.sk > 0n && g.sk < SUB);
    const ref2 = bj.mulPointEscalar(bj.Base8, g.sk);
    check('random keypair matches circomlibjs for the same sk',
      g.x === toBig(ref2[0]).toString() && g.y === toBig(ref2[1]).toString());
    check('public key written into the fields the prover reads',
      escX.value === g.x && escY.value === g.y);
    check('public key written into the authority field (bound + re-validated on prove)',
      ak.value === g.x + ' ' + g.y);
    check('generated key survives the strict parser',
      globalThis.zkParseAuthorityKey(g.x + ' ' + g.y).x === g.x);

    // Save path — the ONLY place the private scalar is written out.
    const realCU = URL.createObjectURL, realRU = URL.revokeObjectURL;
    const realCE = document.createElement, realBD = document.body;
    const blobs = [];
    URL.createObjectURL = (b) => { blobs.push(b); return 'blob:t43'; };
    URL.revokeObjectURL = () => {};
    document.createElement = () => ({ click() {}, remove() {}, style: {}, href: '', download: '' });
    document.body = { appendChild() {}, removeChild() {} };
    const doc = globalThis.zkSaveAuthorityKeypair();
    const savedOk = doc && doc.schema === 'pav-babyjubjub-keypair/v1'
      && doc.private_key === g.sk.toString()
      && doc.public_key && doc.public_key.x === g.x && doc.public_key.y === g.y;
    check('save emits a pav-babyjubjub-keypair/v1 file holding the SAME scalar', !!savedOk,
      doc && JSON.stringify(doc.public_key).slice(0, 60));
    check('save offers exactly one download', blobs.length === 1, String(blobs.length));
    check('saved document names the decryptor CLI (schema + note pinned)',
      !!doc && /zk-decrypt-escrow\.mjs credential\.json/.test(doc.note));
    URL.createObjectURL = realCU; URL.revokeObjectURL = realRU;
    document.createElement = realCE; document.body = realBD;
  }

  // Fail closed #1 — no Web Crypto, no key (never improvise entropy).
  const cryptoDesc = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  delete globalThis.crypto;
  document.getElementById('zkKeygenStatus').innerText = '';
  const noCrypto = globalThis.zkGenerateAuthorityKeypair();
  check('without crypto.getRandomValues keygen fails closed',
    noCrypto === null && /Web Crypto is unavailable/.test(document.getElementById('zkKeygenStatus').innerText),
    document.getElementById('zkKeygenStatus').innerText.slice(0, 120));
  if (cryptoDesc) Object.defineProperty(globalThis, 'crypto', cryptoDesc);

  // Fail closed #2 — the enclave-origin copy must not mint keys either
  // (Web Auditor Tampering defense, same as the throwaway login key).
  globalThis.location = { protocol: 'https:', host: 'login.airma.de' };
  document.getElementById('zkKeygenStatus').innerText = '';
  const onEnclave = globalThis.zkGenerateAuthorityKeypair();
  check('enclave-origin copy refuses to generate keys',
    onEnclave === null && /UNTRUSTED AUDITOR ORIGIN/.test(document.getElementById('zkKeygenStatus').innerText),
    document.getElementById('zkKeygenStatus').innerText.slice(0, 120));
  delete globalThis.location;

  // Structural pins: the controls exist, they sit BEFORE the ⚡ button, the
  // generator is dependency-free (no fetch/import/eval inside its block), and
  // index.html mirrors them.
  const pos = (s, t) => s.indexOf(t);
  check('generate + save buttons are wired into the authority block (zk.html)',
    zkHtml.includes('id="zkKeygenBtn"') && zkHtml.includes('onclick="zkGenerateAuthorityKeypair()"')
      && zkHtml.includes('onclick="zkSaveAuthorityKeypair()"'));
  check('keygen controls sit BEFORE the prove button',
    pos(zkHtml, 'zkKeygenBtn') > -1 && pos(zkHtml, 'zkKeygenBtn') < pos(zkHtml, 'zkProveBtn'));
  const block = zkHtml.slice(pos(zkHtml, 'v191 (user request): BabyJubjub keypair generator'), pos(zkHtml, '⚡ Prove.'));
  check('generator block makes no network or eval calls',
    block.length > 0 && !/fetch\s*\(|import\s*\(|\beval\s*\(|require\s*\(/.test(block),
    block.slice(0, 80));
  const idxNow = readFileSync(join(repoRoot, 'index.html'), 'utf8');
  check('the auditor copies no longer carry the keygen controls (v194 split)',
    !html.includes('id="zkKeygenBtn"') && !idxNow.includes('id="zkKeygenBtn"'));

  // restore
  escX.value = ''; escY.value = ''; ak.value = '';
  document.getElementById('zkKeygenStatus').innerText = '';
  if (typeof globalThis.zkLastKeypair !== 'undefined') globalThis.zkLastKeypair = null;
}

// Shared by every REAL-prover gate below (Tests 44/45): locate the committed
// wasm + verification key, and the assembled proving key. The full zkey is
// gitignored (GitHub's 100 MB object limit) — rebuild it from the TRACKED
// split parts when absent, exactly like the browser does.
function zkProverPaths() {
  const wasmPath = join(repoRoot, 'zk/identity_escrow.wasm');
  const vkey = JSON.parse(readFileSync(join(repoRoot, 'zk/identity_escrow_vkey.json'), 'utf8'));
  let zkeyPath = join(repoRoot, 'zk/identity_escrow_final.zkey');
  try { readFileSync(zkeyPath); } catch {
    zkeyPath = join(tmpdir(), 'identity_escrow_final.zkey');
    writeFileSync(zkeyPath, Buffer.concat((globalThis.ZK_ZKEY_PARTS || [])
      .map((p) => readFileSync(join(repoRoot, 'zk', p)))));
  }
  return { wasmPath, vkey, zkeyPath };
}

console.log('\nTest 44: odd-length + band-floor identities prove end-to-end (v191 circuit)');
{
  // Regression gate for the two circuit bugs fixed in v191: the padded
  // stream used to drop msg_len's bit 0 (every ODD identity failed the
  // in-circuit SHA-256) and lenGeMin used a strict LessThan (msg_len == 248
  // was rejected). This runs the REAL Groth16 prover over the committed
  // wasm/zkey — a mocked prover can never catch a witness-calc assert.
  const snarkjs = require('snarkjs');
  const { EXAMPLE_ESCROW_SK, decryptCredential } = await import('./zk-decrypt-escrow.mjs');
  const { wasmPath, vkey, zkeyPath } = zkProverPaths();

  // Canonical identity JSON of an EXACT target length (circom.md §1 band).
  const identityOf = (len) => {
    const base = JSON.stringify({ user_id: '', sub: null, verified_account: 'true', payer_id: null });
    const pad = len - base.length;
    if (pad < 0) throw new Error('fixture too short');
    const d = JSON.stringify({ user_id: 'U'.repeat(pad), sub: null, verified_account: 'true', payer_id: null });
    if (d.length !== len) throw new Error(`fixture length drift: ${d.length} != ${len}`);
    return d;
  };
  const inputsFor = (D) => {
    const bits = [];
    for (const b of createHash('sha256').update(D).digest()) for (let t = 7; t >= 0; t--) bits.push((b >> t) & 1);
    const raw = new Array(300).fill(0);
    for (const [i, b] of [...Buffer.from(D, 'utf8')].entries()) raw[i] = b;
    return {
      identity_hash_bits: bits,
      escrow_pubkey_x: globalThis.ZK_EXAMPLE_ESCROW_X,
      escrow_pubkey_y: globalThis.ZK_EXAMPLE_ESCROW_Y,
      raw_json_bytes: raw,
      msg_len: D.length,
      ephemeral_private_key: '98765432109876543210987654321098765432109876543210',
    };
  };
  const proveAndOpen = async (len) => {
    const D = identityOf(len);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputsFor(D), wasmPath, zkeyPath);
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    const opened = await decryptCredential({
      schema: 'pav-circom-escrow/v1',
      public_signals: {
        ephemeral_pubkey: [publicSignals[0], publicSignals[1]],
        ciphertext: publicSignals.slice(3, 13),
        identity_hash_hex: createHash('sha256').update(D).digest('hex'),
      },
    }, EXAMPLE_ESCROW_SK);
    return { D, publicSignals, ok, opened };
  };

  // 1. the exact shape that FAILED before v191: odd length (251 = today's
  //    live verified-flow capture).
  const odd = await proveAndOpen(251);
  check('identity fixture is odd-length + inside the band',
    odd.D.length === 251 && odd.D.length % 2 === 1 && odd.D.length >= 248 && odd.D.length <= 300);
  check('ODD identity: real Groth16 prove succeeded (wasm assert would throw)',
    odd.publicSignals.length === 271, String(odd.publicSignals.length));
  check('ODD identity: proof verifies against the committed vkey', odd.ok === true);
  check('ODD identity: verified_account_bit proven = 1', odd.publicSignals[2] === '1');
  check('ODD identity: ciphertext decrypts to the exact bytes the hash covers',
    odd.opened.identityJson === odd.D);

  // 2. the band floor that lenGeMin's strict LessThan used to reject.
  const floor = await proveAndOpen(248);
  check('msg_len == 248 (band floor) proves', floor.publicSignals.length === 271 && floor.ok === true);
  check('msg_len == 248 decrypts to the exact identity', floor.opened.identityJson === floor.D);

  // 3. static guards: cheap checks that catch a revert of either fix without
  //    paying for another proof.
  const csrc = readFileSync(join(repoRoot, 'zk/identity_escrow.circom'), 'utf8');
  check('circuit maps msg_len bit 0 into byte 319 (t < 5 branch)',
    /if \(t < 5\)\s+streamBits\[j \* 8 \+ t\] <== lenBits\.out\[4 - t\]/.test(csrc));
  check('circuit band floor is LessThan(247, msg_len) ⇔ msg_len ≥ 248',
    /lenGeMin\.in\[0\] <== 247/.test(csrc));
  check('pinned wasm is byte-identical to the one just proven with',
    createHash('sha256').update(readFileSync(wasmPath)).digest('hex') === globalThis.ZK_WASM_SHA256);

  // 4. v194 input-contract regression (live user failure 2026-10-27):
  //    "Assert Failed. Error in template Num2Bits_103 line: 38 /
  //     BabyPbk_114 line: 97 / IdentityEscrow_191 line: 267"
  //    The circuit decomposes the ephemeral scalar with Num2Bits(253) — an
  //    UNREDUCED 256-bit draw (what zk.html used to generate) dies in witness
  //    calculation. The mocked prover can never see that, so run the REAL
  //    wtns calculate on both sides of the contract.
  const wtnsCalc = (inputs) => {
    const wi = join(dir, 'v194-in.json'), wo = join(dir, 'v194-out.wtns');
    writeFileSync(wi, JSON.stringify(inputs));
    const r = spawnSync(process.execPath,
      [join(repoRoot, 'node_modules/snarkjs/build/cli.cjs'), 'wtns', 'calculate', wasmPath, wi, wo],
      { encoding: 'utf8' });
    try { rmSync(wo, { force: true }); } catch (e) { /* absent on failure */ }
    // snarkjs CLI splits the report across streams — match BOTH.
    r.all = String(r.stdout || '') + '\n' + String(r.stderr || '');
    return r;
  };
  {
    const base = inputsFor(identityOf(251));
    const bad = wtnsCalc({ ...base, ephemeral_private_key: ((1n << 253n) + 12345n).toString() });
    check('circuit REJECTS an unreduced ≥2^253 ephemeral key (the live failure, exact chain)',
      bad.status !== 0 && /Num2Bits/.test(bad.all) && /BabyPbk/.test(bad.all)
        && /IdentityEscrow/.test(bad.all),
      bad.all.split('\n').filter((l) => l.trim()).slice(0, 5).join(' | ').slice(0, 220));
    const pageR = globalThis.zkRandomScalar();
    check('zk.html scalar draws are reduced (0 < r < subOrder < 2^253)',
      typeof pageR === 'bigint' && pageR > 0n && pageR < (1n << 253n), String(pageR).slice(0, 24));
    const good = wtnsCalc({ ...base, ephemeral_private_key: pageR.toString() });
    check('a page-drawn scalar passes REAL witness generation', good.status === 0,
      good.all.split('\n').filter((l) => l.trim()).slice(-3).join(' | ').slice(0, 200));
    check('prove path draws the ephemeral key via zkRandomScalar() (source-pinned)',
      /var r = zkRandomScalar\(\);/.test(zkHtml)
        && !/getRandomValues\(new Uint8Array\(32\)\);\s*\n\s*var r = 0n/.test(zkHtml));
  }
}

console.log('\nTest 45: real Groth16 credential from the CAPTURED odd-length report');
{
  // Test 44 proves a SYNTHESIZED 251-byte identity. This gate proves the
  // identity extracted from a SAVED live capture (scripts/fixtures/
  // captured-odd-report.json — sandbox 'verified' flow) — the artifact that
  // exposed both v191 circuit bugs. It covers report → identity extraction
  // (canonical key order, null handling, UTF-8) AND the circuit, so a
  // regression cannot come back through either path.
  const snarkjs = require('snarkjs');
  const { EXAMPLE_ESCROW_SK, decryptCredential } = await import('./zk-decrypt-escrow.mjs');
  const { wasmPath, vkey, zkeyPath } = zkProverPaths();

  const capture = JSON.parse(readFileSync(
    join(repoRoot, 'scripts', 'fixtures', 'captured-odd-report.json'), 'utf8'));
  const rep = capture.attestation_report;
  check('captured report present and carries paypal_user_info',
    !!rep && !!rep.paypal_user_info, String(rep && Object.keys(rep).length));
  const u = rep.paypal_user_info;

  // The enclave's canonical preimage — key order fixed by identityHashOf()
  // (user_id, sub, verified_account, payer_id) and signed into the report.
  const D = JSON.stringify({
    user_id: u.user_id, sub: u.sub ?? null,
    verified_account: u.verified_account, payer_id: u.payer_id ?? null,
  });
  const Dsha = createHash('sha256').update(D, 'utf8').digest('hex');

  check('captured identity is ODD length (the pre-v191 failure shape)',
    D.length % 2 === 1, `len=${D.length}`);
  check('captured identity is inside the circuit band [248,300]',
    D.length >= 248 && D.length <= 300, `len=${D.length}`);
  check('extracted identity hash === the report\'s signed paypal_user_info_raw_hash',
    Dsha === rep.paypal_user_info_raw_hash, Dsha.slice(0, 16));

  // REAL Groth16 over the committed wasm/zkey (no mocked prover here).
  const bits = [];
  for (const b of createHash('sha256').update(D).digest())
    for (let t = 7; t >= 0; t--) bits.push((b >> t) & 1);
  const raw = new Array(300).fill(0);
  for (const [i, b] of [...Buffer.from(D, 'utf8')].entries()) raw[i] = b;
  const { proof, publicSignals } = await snarkjs.groth16.fullProve({
    identity_hash_bits: bits,
    escrow_pubkey_x: globalThis.ZK_EXAMPLE_ESCROW_X,
    escrow_pubkey_y: globalThis.ZK_EXAMPLE_ESCROW_Y,
    raw_json_bytes: raw,
    msg_len: D.length,
    ephemeral_private_key: '98765432109876543210987654321098765432109876543210',
  }, wasmPath, zkeyPath);

  check('CAPTURED identity: 271 public signals emitted',
    publicSignals.length === 271, String(publicSignals.length));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  check('CAPTURED identity: real Groth16 proof verifies against the committed vkey',
    ok === true, String(ok));
  check('CAPTURED identity: verified_account_bit proven = 1', publicSignals[2] === '1');

  const opened = await decryptCredential({
    schema: 'pav-circom-escrow/v1',
    public_signals: {
      ephemeral_pubkey: [publicSignals[0], publicSignals[1]],
      ciphertext: publicSignals.slice(3, 13),
      identity_hash_hex: Dsha,
    },
  }, EXAMPLE_ESCROW_SK);
  check('CAPTURED identity: credential decrypts to the exact captured bytes',
    opened.identityJson === D);
  check('CAPTURED identity: decrypted hash re-derives the signed raw_hash',
    opened.sha256 === rep.paypal_user_info_raw_hash);
}

console.log('\nTest 46: GitHub Pages copy == repo verify.html (served-auditor drift gate)');
{
  // Found in the v192 cycle (2026-10-26): GitHub Pages publishes from `main`
  // while the active line of work is `alibabacloud`. After the v192 pin
  // rotation Pages kept serving the PREVIOUS verify.html — old RTMR2 /
  // EXPECTED_ENCLAVE_SHA256 pins — so the "GitHub Pages auditor" link failed
  // every audit against the deployment the enclave, repo and README all
  // agreed on. The ZK artifacts (wasm + zkey parts) live on the SAME Pages
  // branch, so a stale branch serves a stale AUDITOR next to correct
  // downloads: silent, and only visible by comparing digests across the wire.
  //
  // This gate fetches the Pages copy over HTTPS and compares it byte-for-byte
  // with the working tree. A MISMATCH fails; a network failure only fails
  // under PAGES_PARITY=1 (offline `node scripts/…` stays usable), and
  // PAGES_PARITY=0 skips the test entirely.
  const mode = process.env.PAGES_PARITY || '';
  if (mode === '0') {
    console.log('  ⏭  PAGES_PARITY=0 — skipped by request');
  } else {
    const strict = mode === '1';
    const PAGES_VERIFY_URL = process.env.PAGES_VERIFY_URL
      || 'https://leonardopedro.github.io/verifiedUniqueAliases/verify.html';
    const git = (...args) => {
      try { return execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8' }).trim(); }
      catch { return null; }
    };
    const sha = (buf) => createHash('sha256').update(buf).digest('hex');
    // Raw https (NOT globalThis.fetch): the harness stubs fetch from line ~63
    // to drive the provenance row offline.
    const httpGet = (url, redirects = 3) => new Promise((resolve) => {
      let req;
      try { req = https.get(url, { headers: { 'User-Agent': 'test-verify-security', Accept: '*/*' }, timeout: 15000 }, (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location && redirects > 0) {
          res.resume();
          return resolve(httpGet(new URL(res.headers.location, url).href, redirects - 1));
        }
        if (status !== 200) { res.resume(); return resolve(null); }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      }); } catch { return resolve(null); }
      req.on('error', () => resolve(null));
      req.on('timeout', () => req.destroy(new Error('timeout')));
    });

    const repoDigest = sha(readFileSync(join(repoRoot, 'verify.html')));
    const body = await httpGet(PAGES_VERIFY_URL);
    if (!body) {
      // Not drift — we learned nothing about the served bytes.
      if (strict) check('GitHub Pages copy fetched over HTTPS', false, `GET ${PAGES_VERIFY_URL} failed`);
      else console.log(`  ⚠️  Pages copy NOT fetched (${PAGES_VERIFY_URL}) — network down? PAGES_PARITY=1 makes this fatal`);
    } else {
      const pagesDigest = sha(body);
      if (pagesDigest === repoDigest) {
        check('GitHub Pages serves byte-identical verify.html', true, pagesDigest.slice(0, 16));
        const rm = await httpGet(new URL('README.md', PAGES_VERIFY_URL).href);
        if (rm) check('Pages README publishes the CURRENT verify.html digest',
          rm.toString('utf8').includes(repoDigest), 'Pages README digest is stale');
        else console.log('  ⚠️  Pages README not fetched — verify.html parity already proven');

        // v194: zk.html (the ZK engine) is a Pages-served security file too —
        // the SAME stale-branch trap that bit verify.html applies to it, and
        // the prover's pins only protect you if Pages serves THIS build.
        const zkRepoBuf = readFileSync(join(repoRoot, 'zk.html'));
        const zkBody = await httpGet(new URL('zk.html', PAGES_VERIFY_URL).href);
        if (zkBody) {
          const zkPages = sha(zkBody), zkRepo = sha(zkRepoBuf);
          check('GitHub Pages serves byte-identical zk.html', zkPages === zkRepo,
            `pages=${zkPages.slice(0, 16)} repo=${zkRepo.slice(0, 16)} — push to the Pages branch (both-branches rule)`);
        } else {
          check('GitHub Pages zk.html fetched over HTTPS', !strict, `GET ${new URL('zk.html', PAGES_VERIFY_URL).href} failed`);
        }

        // v193: the ZK artifacts live on the SAME Pages branch and are fetched
        // by the auditor with `force-cache` — so a stale Pages (or a stale
        // browser copy of it) serves the WRONG wasm/zkey beside a correct
        // auditor. That is the live incident behind the `6300a547… vs
        // b8ce562f…` INTEGRITY FAILURE: the gate fired, but only in the
        // victim's browser. Pin them here too, byte-for-byte, against the
        // repo files AND against the digests the auditor embeds.
        if (process.env.PAGES_ZK_ARTIFACTS !== '0') {
          // v194: the pins moved into zk.html with the engine.
          const vsrc = zkHtml;
          const wasmPin = (vsrc.match(/var ZK_WASM_SHA256 = '([0-9a-f]{64})'/) || [])[1];
          const zkeyPin = (vsrc.match(/var ZK_ZKEY_SHA256 = '([0-9a-f]{64})'/) || [])[1];
          const wasmLocal = readFileSync(join(repoRoot, 'zk', 'identity_escrow.wasm'));
          const part0 = readFileSync(join(repoRoot, 'zk', 'identity_escrow_final.zkey.part0'));
          const part1 = readFileSync(join(repoRoot, 'zk', 'identity_escrow_final.zkey.part1'));
          check('repo wasm == the ZK_WASM_SHA256 the auditor embeds',
            sha(wasmLocal) === wasmPin, `${sha(wasmLocal).slice(0, 16)} vs pin ${String(wasmPin).slice(0, 16)}`);
          check('repo zkey parts assemble to the ZK_ZKEY_SHA256 the auditor embeds',
            sha(Buffer.concat([part0, part1])) === zkeyPin,
            `${sha(Buffer.concat([part0, part1])).slice(0, 16)} vs pin ${String(zkeyPin).slice(0, 16)}`);
          const zkBase = new URL('zk/', PAGES_VERIFY_URL).href;
          const wanted = [
            ['identity_escrow.wasm', wasmLocal],
            ['identity_escrow_final.zkey.part0', part0],
            ['identity_escrow_final.zkey.part1', part1],
          ];
          for (const [file, localBuf] of wanted) {
            const got = await httpGet(zkBase + file);
            if (!got) {
              check(`Pages serves zk/${file}`, strict, `GET ${zkBase}${file} failed`);
              continue;
            }
            const pagesSha = sha(got), repoSha = sha(localBuf);
            check(`Pages zk/${file} byte-identical to the repo artifact`,
              pagesSha === repoSha,
              `pages=${pagesSha.slice(0, 16)} repo=${repoSha.slice(0, 16)} — every browser auditing from Pages would hit INTEGRITY FAILURE`);
          }
        }
      } else {
        // Classify the mismatch so the failure says WHICH branch is stale.
        // GITHUB_REF_NAME covers CI's detached checkout (git reports `HEAD`).
        const branchRaw = git('rev-parse', '--abbrev-ref', 'HEAD');
        const branch = (branchRaw && branchRaw !== 'HEAD') ? branchRaw
          : (process.env.GITHUB_REF_NAME || null);
        const headSha = git('rev-parse', 'HEAD');
        const ageMin = headSha
          ? (Date.now() / 1000 - Number(git('log', '-1', '--format=%ct') || 0)) / 60
          : Number.POSITIVE_INFINITY;
        let pagesRun = null;
        let apiOk = false;
        const m = /^https?:\/\/([^.]+)\.github\.io\/([^/]+)\//.exec(PAGES_VERIFY_URL);
        if (m) {
          const raw = await httpGet(`https://api.github.com/repos/${m[1]}/${m[2]}/actions/runs?per_page=20`);
          try {
            const j = JSON.parse(raw.toString('utf8'));
            pagesRun = (j.workflow_runs || []).find((r) => r.name === 'pages build and deployment') || null;
            apiOk = !!pagesRun || Array.isArray(j.workflow_runs);
          } catch { /* API unavailable → fall through to the age rule */ }
        }
        let reason;
        if (pagesRun && branch && pagesRun.head_branch && pagesRun.head_branch !== branch) {
          // Pages publishes from ANOTHER branch. If that branch ALREADY has
          // this commit (the push-both-branches rule was followed) the site is
          // simply about to update — that is the push race, not drift. Only a
          // commit that is NOT on the Pages branch is real drift.
          git('fetch', '--quiet', 'origin', pagesRun.head_branch);
          const tip = git('rev-parse', 'FETCH_HEAD');
          let onPagesBranch = !!tip && tip === headSha;
          if (!onPagesBranch && tip && headSha) {
            const r = spawnSync('git', ['merge-base', '--is-ancestor', headSha, tip], { cwd: repoRoot });
            onPagesBranch = r.status === 0;
          }
          if (onPagesBranch && (!strict || process.env.CI) && ageMin < 20) {
            check('GitHub Pages verify.html == repo verify.html (Pages branch push race, grace)', true,
              `pages=${pagesDigest.slice(0, 16)} repo=${repoDigest.slice(0, 16)} — Pages builds from \`${pagesRun.head_branch}\`, which already has ${headSha.slice(0, 7)}; rebuild pending`);
            reason = undefined;
          } else if (onPagesBranch) {
            reason = `Pages builds from \`${pagesRun.head_branch}\` and ${headSha.slice(0, 7)} IS on it, but the served copy still differs — the Pages rebuild for that commit has not landed (check the 'pages build and deployment' run)`;
          } else {
            reason = `Pages builds from \`${pagesRun.head_branch}\` but ${headSha ? headSha.slice(0, 7) : 'this commit'} is not on it — push it too (git push origin ${branch}:${pagesRun.head_branch}) or repoint the Pages source`;
          }
        } else if (pagesRun && headSha && pagesRun.head_sha === headSha
              && pagesRun.status === 'completed' && pagesRun.conclusion === 'success') {
          reason = `Pages finished building ${headSha.slice(0, 7)} yet serves a different file`;
        } else if (pagesRun && headSha && pagesRun.head_sha === headSha
              && pagesRun.status && pagesRun.status !== 'completed') {
          // Pages is building THIS commit right now — in flight, not drift.
          // Survives strict mode so CI on a push-to-both-branches is not red
          // for the ~1-3 min the Pages job needs.
          check('GitHub Pages verify.html == repo verify.html (Pages build in flight, grace)', true,
            `pages=${pagesDigest.slice(0, 16)} repo=${repoDigest.slice(0, 16)} — ${pagesRun.status}; re-run after it completes`);
          reason = undefined;
        } else if ((!strict || process.env.CI) && ageMin < 20) {
          // CI runs seconds after the push, before Pages can rebuild a matching
          // branch — strict there would be red for a race, not a regression.
          check('GitHub Pages verify.html == repo verify.html (rebuild pending, grace)', true,
            `pages=${pagesDigest.slice(0, 16)} repo=${repoDigest.slice(0, 16)} — commit is ${ageMin.toFixed(0)} min old, Pages has not rebuilt it yet; re-run after the pages build`);
          reason = undefined;
        } else {
          reason = `pages=${pagesDigest.slice(0, 16)} repo=${repoDigest.slice(0, 16)}`
            + `${apiOk ? '' : ' (GitHub API unavailable — could not classify)'}`
            + `${strict ? ' (PAGES_PARITY=1: no grace)' : ''}`;
        }
        if (reason) check('GitHub Pages serves byte-identical verify.html', false, reason);
      }
    }
  }
}

console.log('\nTest 47: zk-rsa.html — RSA ZK escrow credential (PGP / X.509 / PEM / raw)');
{
  const fix = (f) => readFileSync(join(repoRoot, 'zk', 'rsa-test', f), 'utf8');
  const sec = await zkRsaParseAny(fix('signer-sec.asc'));
  const pub = await zkRsaParseAny(fix('signer-pub.asc'));
  const crt = await zkRsaParseAny(fix('signer-cert.pem'));
  const pem = await zkRsaParseAny(fix('signer-key.pem'));
  const raw = await zkRsaParseAny(fix('signer-raw.txt'));
  const recip = await zkRsaParseAny(fix('recipient-pub.asc'));

  check('PGP v4 secret key parses (s2k usage 0 → private part present)',
    sec.format === 'pgp-secret' && sec.hasPrivate === true, sec.format);
  check('all five encodings agree on the same RSA key',
    [pub, crt, pem, raw].every((k) => k.fp === sec.fp),
    [sec, pub, crt, pem, raw].map((k) => k.fp.slice(0, 8)).join(' '));
  check('PGP fingerprint = SHA1(0x99 ‖ len ‖ material) in uppercase hex',
    /^[0-9A-F]{40}$/.test(sec.pgp_fingerprint || ''), sec.pgp_fingerprint);
  check('RSA-2048 fixture over the 1024-bit floor', sec.bits === 2048, 'bits=' + sec.bits);
  check('public encodings cannot prove', pub.hasPrivate === false && crt.hasPrivate === false && raw.hasPrivate === false);

  // passphrase-protected secret key must be REFUSED (never touch passphrases):
  // flip the s2k usage octet inside the packet and drop the (now invalid) CRC.
  {
    const armored = fix('signer-sec.asc');
    const b64 = armored.split('\n\n')[1].split('\n=')[0].replace(/\s+/g, '');
    const bin = Buffer.from(b64, 'base64');
    let off = 3 + 6;                       // old-format hdr (3) + v4/time/algo (6)
    for (let k = 0; k < 2; k++) {          // skip n, e MPIs
      const bits = bin.readUInt16BE(off);
      off += 2 + Math.ceil(bits / 8);
    }
    bin[off] = 0xfe;                       // s2k usage 254 = SHA1-checked sym-encrypted
    const tampered = '-----BEGIN PGP SECRET KEY BLOCK-----\n\n' +
      bin.toString('base64').replace(/.{1,64}/g, '$&\n') +
      '-----END PGP SECRET KEY BLOCK-----\n';
    let refused = null;
    try { await zkRsaParseAny(tampered); } catch (e) { refused = e.message; }
    check('passphrase-protected secret key refused with instructions',
      !!refused && /PASSPHRASE-PROTECTED/.test(refused), String(refused).slice(0, 80));
  }

  const nonce = 'ab12'.repeat(8);
  const cred = await zkRsaProve({
    key: sec, attrsText: JSON.stringify({ label: 'harness' }),
    recipientKey: recip, domain: 'harness.test', nonce, purpose: 'Test 47',
  });
  check('credential produced (type/version/shape)',
    cred.type === 'pav-rsa-escrow' && cred.version === 1 &&
    /^[0-9a-f]{64}$/.test(cred.identity_hash) && !!cred.escrow.ct,
    cred.type + ' v' + cred.version);
  const res = await zkRsaVerify(cred, { nonce, domain: 'harness.test' });
  check('proof verifies green (GQ relation + challenge re-derivation + expected nonce/domain)',
    res.ok === true, res.rows.filter((r) => r.cls === 'failed').map((r) => r.title).join('; '));
  check('no-circuit binding-completeness caveat is stated (warning row, not hidden)',
    res.rows.some((r) => r.cls === 'warning' && /binding/i.test(r.title)), 'caveat row missing');

  const t1 = JSON.parse(JSON.stringify(cred)); t1.statement.nonce = 'ffff'.repeat(8);
  check('altered nonce fails the challenge', !(await zkRsaVerify(t1, {})).ok);
  const t2 = JSON.parse(JSON.stringify(cred));
  t2.escrow.ct = t2.escrow.ct.slice(0, -4) + (t2.escrow.ct.endsWith('AAAA') ? 'BBBB' : 'AAAA');
  check('altered ciphertext fails the challenge', !(await zkRsaVerify(t2, {})).ok);
  const t3 = JSON.parse(JSON.stringify(cred));
  t3.proof.z = (BigInt('0x' + cred.proof.z) - 1n).toString(16);
  check('altered response z fails the GQ relation', !(await zkRsaVerify(t3, {})).ok);
  const t4 = JSON.parse(JSON.stringify(cred));
  t4.issuer_key.n = (BigInt('0x' + cred.issuer_key.n) - 2n).toString(16);
  check('foreign modulus fails (fingerprint + relation)', !(await zkRsaVerify(t4, {})).ok);
  const resW = await zkRsaVerify(cred, { nonce: 'not-my-nonce', domain: 'other.test' });
  check('expected-nonce/domain mismatch is flagged', resW.ok === false);

  const opened = await zkRsaEscrowOpen(cred, fix('recipient-key.pem'));
  check('recipient opens the escrow; plaintext hash == identity_hash', opened.matches === true, opened.hash);
  check('attrs survive the escrow round-trip', JSON.parse(opened.json).attrs.label === 'harness');
  let wrongRejected = false;
  try { await zkRsaEscrowOpen(cred, fix('signer-key.pem')); } catch { wrongRejected = true; }
  check('wrong recipient key cannot open the escrow', wrongRejected);

  let refusedPub = null;
  try {
    await zkRsaProve({ key: pub, attrsText: '{}', recipientKey: recip, domain: '', nonce: 'x', purpose: '' });
  } catch (e) { refusedPub = e.message; }
  check('proving with a PUBLIC key fails closed', /no private part/.test(String(refusedPub)), String(refusedPub).slice(0, 70));

  const rsaDigest = sha256(readFileSync(join(repoRoot, 'zk-rsa.html'))).toString('hex');
  const readmeNow = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  check('README publishes the CURRENT zk-rsa.html sha256',
    readmeNow.includes(rsaDigest), rsaDigest.slice(0, 24) + '…');
  check('zk-rsa.html loads NO external subresources (zero-network by construction)',
    !/<script[^>]+\bsrc\s*=/i.test(zkRsaHtml) && !/<link[^>]+\bhref\s*=\s*["']https?:/i.test(zkRsaHtml),
    'external <script src> or <link href> found');
  const rsaRes = await zkRsaVerify(JSON.parse(JSON.stringify(cred)), { nonce, domain: 'harness.test' });
  check('fresh verify of a re-parsed credential (JSON round-trip)', rsaRes.ok === true);
}

rmSync(dir, { recursive: true, force: true });;;
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
