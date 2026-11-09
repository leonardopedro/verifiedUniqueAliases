#!/usr/bin/env node
// v225: the auditor page is now the only component that produces ciphertext the
// enclave must OPEN (a PayPal code sealed to one slot, a user nonce to another),
// so its wire format and its fail-closed refusals are pinned here rather than
// trusted to a live deployment. The harness evals the REAL verify.html script
// with DOM stubs — the same technique as scripts/test-verify-security.mjs — and
// then checks what the page actually emitted.
//
// Two phases, each in its own process so a phase cannot inherit the other's
// globals:
//
//   node scripts/test-seal-page.mjs card          # the seal button (code + nonce)
//   node scripts/test-seal-page.mjs sealed-return # PayPal returning to the page
//
// Both are CI steps (see .github/workflows/build-attest.yml). Requires openssl
// on PATH (it is how the ciphertext is opened, independently of the page).
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2] || 'card';
const html = readFileSync(join(repoRoot, 'verify.html'), 'utf8');
const script = html.match(/<script>([\s\S]*)<\/script>/)[1];

// ---- DOM / browser stubs ---------------------------------------------------
const elements = {};
const makeEl = () => ({
  style: {}, innerText: '', textContent: '', innerHTML: '', value: '', className: '',
  querySelector: () => ({ innerHTML: '' }),
  addEventListener: () => {},
});
globalThis.document = { getElementById: (id) => (elements[id] ||= makeEl()), addEventListener: () => {} };
globalThis.alert = () => {};
globalThis.fetch = async () => ({ ok: false, status: 404, json: async () => ({}) });
const store = new Map();
const mkStorage = () => ({
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
});
globalThis.localStorage = mkStorage();
globalThis.sessionStorage = mkStorage();

// ---- keys: two independent slots, opened with openssl ----------------------
const dir = process.env.TMPDIR || '/tmp';
const keyPath = (name, kind) => join(dir, `pav-seal-test-${process.pid}-${name}.${kind}`);
function makeKey(name) {
  const priv = keyPath(name, 'key');
  execFileSync('openssl', ['genrsa', '-out', priv, '2048']);
  const pub = execFileSync('openssl', ['pkey', '-in', priv, '-pubout']).toString();
  return { priv, pub };
}
const codeKey = makeKey('code');
const nonceKey = makeKey('nonce');
const openedWith = (priv, b64) => execFileSync('openssl', [
  'pkeyutl', '-decrypt', '-inkey', priv,
  '-pkeyopt', 'rsa_padding_mode:oaep',
  '-pkeyopt', 'rsa_oaep_md:sha256',
  '-pkeyopt', 'rsa_mgf1_md:sha256',
], { input: Buffer.from(b64, 'base64'), stdio: ['pipe', 'pipe', 'ignore'] }).toString();
const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');

let jumped = null;
globalThis.location = {
  protocol: 'https:',
  origin: 'https://auditor.test',
  pathname: '/audit/verify.html',
  search: '',
  assign: (u) => { jumped = u; },
};
globalThis.window = { location: globalThis.location, addEventListener: () => {}, origin: 'https://auditor.test' };

let bad = 0;
const check = (name, cond, extra = '') => {
  console.log((cond ? '  ✅ ' : '  ❌ ') + name + (cond ? '' : '  ' + String(extra).slice(0, 240)));
  if (!cond) bad++;
};

// ============================================================================
// Phase: sealed-return — PayPal came back to THIS page (v225, no Esc needed).
// ============================================================================
if (mode === 'sealed-return') {
  const state = 'eyJ2IjoiY29kZS1zdGF0ZSJ9';
  const code = 'C21AAsealed-return';
  const nonce = 'order-4711/commitment';
  globalThis.location.search = '?code=' + encodeURIComponent(code) + '&state=' + encodeURIComponent(state);
  // The marker the login step leaves behind: which enclave, which state, the
  // user's nonce (never the code), and BOTH seal slots exactly as the enclave
  // signed them into the login response — the return leg seals from these and
  // fetches nothing (v180: the page never calls an attestation route).
  const derOf = (pem) => execFileSync('openssl', ['pkey', '-pubin', '-outform', 'DER'], { input: pem });
  localStorage.setItem('pav_sealed_login_v1', JSON.stringify({
    host: 'https://login.example',
    redirect: 'https://auditor.test/audit/verify.html',
    state,
    p_enc: 'PINNED-ENCLAVE-KEY',
    slots: {
      code: { pem: codeKey.pub, sha256: sha256Hex(derOf(codeKey.pub)) },
      nonce: { pem: nonceKey.pub, sha256: sha256Hex(derOf(nonceKey.pub)) },
    },
    nonce,
    at: Date.now(),
  }));
  // A fetch here would mean the page reached for an attestation after login;
  // the harness fails on it instead of quietly serving a report.
  const fetched = [];
  globalThis.fetch = async (u) => { fetched.push(String(u)); throw new Error('unexpected fetch: ' + u); };

  (0, eval)(script);
  await new Promise((r) => setTimeout(r, 100));

  check('the return leg fetches nothing (keys came signed at login)', fetched.length === 0, fetched.join(', '));

  check('PayPal returning to the page navigates onward by itself', !!jumped,
    String(jumped) + ' | page says: ' + ((elements['loginProgress'] || {}).textContent || ''));
  if (jumped) {
    const u = new URL(jumped);
    check('it opens /callback on the enclave the login pinned', u.origin === 'https://login.example' && u.pathname === '/callback', jumped);
    check('the clear PayPal code is NOT in the URL', !u.searchParams.get('code') && !jumped.includes(code), jumped);
    check('the state travels with the sealed code', u.searchParams.get('state') === state, u.searchParams.get('state'));
    const ct = Buffer.from(u.searchParams.get('code_enc') || '', 'base64');
    check('code_enc is one RSA-OAEP/SHA-256 seal (256 B here)', ct.length === 256, String(ct.length));
    check('the shell recipe opens code_enc to the PayPal code', openedWith(codeKey.priv, u.searchParams.get('code_enc')) === code);
    const nonceCt = Buffer.from(u.searchParams.get('nonce_enc') || '', 'base64');
    check('nonce_enc is a second seal, to the OTHER slot', nonceCt.length === 256, String(nonceCt.length));
    check('the nonce opens with the nonce key', openedWith(nonceKey.priv, u.searchParams.get('nonce_enc')) === nonce);
    let cross = '';
    try { openedWith(codeKey.priv, u.searchParams.get('nonce_enc')); } catch (e) { cross = String(e.status || e.message); }
    check('and NOT with the code slot key (slots are independent)', cross !== '', 'the code key opened the nonce seal');
  }
  // The guard that makes all of the above trustworthy: a slot whose signed
  // sha256 does not hash the PEM it shipped is refused, never sealed to.
  check('the page refuses a slot whose fingerprint does not hash its key',
    /declared !== s\.fp/.test(script), 'self-consistency comparison missing from the page');

  const rec = JSON.parse(localStorage.getItem('pav_sealed_nonce_v1') || 'null');
  check('the nonce commitment is remembered as a hash, never the text', !!rec && rec.sha256 === sha256Hex(nonce) && !JSON.stringify(rec).includes(nonce), JSON.stringify(rec));
  check('the one-shot login marker is consumed', localStorage.getItem('pav_sealed_login_v1') === null);

  console.log(bad === 0 ? '\n✅ sealed-return: all checks passed' : `\n❌ ${bad} failed`);
  process.exit(bad === 0 ? 0 : 1);
}

// ============================================================================
// Phase: card — the manual seal card (code + optional nonce), fail-closed.
// ============================================================================
(0, eval)(script);

let p = parseCallbackUrl('https://login.example/callback?code=C21AAabc%2B1&state=eyJ2IjoiQQ');
check('parseCallbackUrl takes code + state from a redirect URL', p.code === 'C21AAabc+1' && p.state === 'eyJ2IjoiQQ', JSON.stringify(p));
p = parseCallbackUrl('C21AAbarecode');
check('a bare code stays a bare code', p.code === 'C21AAbarecode' && p.state === '', JSON.stringify(p));
check('empty input yields nothing', parseCallbackUrl('   ').code === '');

const fpDer = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'DER'], { input: codeKey.pub });
check('the page fingerprint is sha256(SPKI DER), as openssl computes it', await tlsKeyFingerprint(codeKey.pub) === sha256Hex(fpDer));

// --- the button, code only --------------------------------------------------
document.getElementById('localEnclaveHost').value = 'https://login.example';
document.getElementById('sealKeyInput').value = codeKey.pub;
document.getElementById('sealCodeInput').value = 'https://login.example/callback?code=C21AAabc%2B1&state=eyJ2IjoiQQ';
document.getElementById('sealStateInput').value = '';
document.getElementById('sealNonceInput').value = '';
await sealCodeAndOpen();
check('the button navigates', !!jumped, String(jumped));
let u = new URL(jumped);
check('it targets /callback with code_enc and no clear code', u.pathname === '/callback' && u.searchParams.get('code_enc') && !u.searchParams.get('code'), jumped);
check('state comes from the pasted URL', u.searchParams.get('state') === 'eyJ2IjoiQQ');
check('the ciphertext opens to the code (empty OAEP label, MGF1-SHA-256)', openedWith(codeKey.priv, u.searchParams.get('code_enc')) === 'C21AAabc+1');
check('no nonce_enc when no nonce was typed', !u.searchParams.get('nonce_enc'));

// --- the button, code AND nonce (two slots, one submission) ------------------
globalThis.lastAuditedNonceKeyPem = nonceKey.pub;
document.getElementById('sealNonceInput').value = 'my-nonce-42';
jumped = null;
await sealCodeAndOpen();
u = new URL(jumped);
check('the nonce rides along as nonce_enc', !!u.searchParams.get('nonce_enc'), jumped);
check('the nonce opens with the second slot', openedWith(nonceKey.priv, u.searchParams.get('nonce_enc')) === 'my-nonce-42');
let crossErr = '';
try { openedWith(codeKey.priv, u.searchParams.get('nonce_enc')); } catch (e) { crossErr = 'x'; }
check('the code slot key cannot open the nonce', crossErr !== '');
const nonceRec = JSON.parse(localStorage.getItem('pav_sealed_nonce_v1') || 'null');
check('the nonce commitment is stored as a hash only', !!nonceRec && nonceRec.sha256 === sha256Hex('my-nonce-42') && !JSON.stringify(nonceRec).includes('my-nonce-42'), JSON.stringify(nonceRec));

// --- fail-closed paths ------------------------------------------------------
jumped = null;
document.getElementById('sealNonceInput').value = 'x';
globalThis.lastAuditedNonceKeyPem = null;
document.getElementById('sealKeyInput').value = codeKey.pub;
document.getElementById('sealCodeInput').value = 'C21AAother';
document.getElementById('sealStateInput').value = 'eyJ2IjoiQQ';
await sealCodeAndOpen();
check('a typed nonce with no second slot key refuses instead of dropping it', jumped === null && /second seal slot/.test(document.getElementById('sealStatus').innerText), document.getElementById('sealStatus').innerText);

document.getElementById('sealNonceInput').value = '';
jumped = null;
document.getElementById('sealKeyInput').value = '';
await sealCodeAndOpen();
check('no key refuses before encrypting', jumped === null && /❌/.test(document.getElementById('sealStatus').innerText));

document.getElementById('sealKeyInput').value = codeKey.pub;
document.getElementById('sealStateInput').value = '';
await sealCodeAndOpen();
check('a code without a state refuses (never an unbound code)', jumped === null && /session state/.test(document.getElementById('sealStatus').innerText), document.getElementById('sealStatus').innerText);

const otherKey = makeKey('other');
document.getElementById('sealKeyInput').value = otherKey.pub;
await sealShowKeyFingerprint();
check('a key that is not the sealed one is called out', /NOT the key this tab sealed to/.test(document.getElementById('sealKeyStatus').innerHTML), document.getElementById('sealKeyStatus').innerHTML);

console.log(bad === 0 ? '\n✅ seal card: all checks passed' : `\n❌ ${bad} failed`);
process.exit(bad === 0 ? 0 : 1);
