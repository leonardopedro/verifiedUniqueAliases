// Browser end-to-end for the v188 login → AUTO-DOWNLOAD → audit → report
// flow (the AGENTS.md debugging playbook's browser step). Runs the REAL
// secure login from a trusted file:// copy of verify.html against the live
// enclave (explicit login link → PayPal sandbox consent), then FAILS unless:
//   * the /callback page AUTO-DOWNLOADS the encrypted attestation (no
//     landing page, no button — the v188 main.rs change),
//   * loading that ciphertext into the trusted tab's report box decrypts it
//     (decryptPastedBlob — there is deliberately NO claim button any more),
//   * the audit goes green and the plain attestation-report-*.json downloads.
//
// Why this exists: the download is the first casualty of any red audit row —
// a missing file is a SYMPTOM (v178: the identity-preimage gate failed on
// every honest login and silently suppressed the download). This script makes
// the whole chain observable: login-session status, callback auto-download,
// the paste-decrypt verdict, download events, and the decrypted report JSON
// (saved for offline inspection of the failing gate).
//
// Usage:
//   npm install --no-save playwright          # once
//   CHROMIUM_PATH=$(command -v chromium) node scripts/e2e-login-download.mjs [verified|full]
//
// Env:
//   PPEMAIL / PPPASS — PayPal sandbox user (defaults to the project test user)
//   VERIFY_HTML      — path to the auditor copy (default: repo verify.html)
//   CHROMIUM_PATH    — required on NixOS/containers: the bundled playwright
//                      chromium dies on missing distro libs (e.g. libglib)
//
// Exit code 0 = ciphertext auto-downloaded, paste-decrypt audited green AND
// the plain report file downloaded.
import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';
import { createRequire } from 'module';

// v197 — fingerprint(s) of an armored PGP public key, exactly as the enclave's
// `pgp_escrow::parse_public_key` and the auditor's `pgpPublicFingerprints`
// compute them: SHA-1(0x99 ‖ len16(key material)) over each v4 key packet,
// uppercase hex. Used to prove the second download was sealed to the key the
// login actually pasted (no private key needed for an addressing proof).
function armorFingerprints(armor) {
  const m = /-----BEGIN PGP PUBLIC KEY BLOCK-----([\s\S]*?)-----END PGP PUBLIC KEY BLOCK-----/.exec(armor);
  if (!m) throw new Error('not a PGP PUBLIC KEY BLOCK');
  const blank = m[1].indexOf('\n\n');
  if (blank < 0) throw new Error('missing armor blank line');
  const b64 = m[1].slice(blank + 2).replace(/\s+$/, '').replace(/\n=[A-Za-z0-9+/]{4}$/, '').replace(/\s+/g, '');
  const buf = Buffer.from(b64, 'base64');
  const out = [];
  let i = 0;
  while (i < buf.length) {
    const ctb = buf[i++];
    if (!(ctb & 0x80)) throw new Error('malformed packet header');
    let tag, len;
    if (ctb & 0x40) {
      tag = ctb & 0x3f;
      if (buf[i] < 192) { len = buf[i]; i += 1; }
      else if (buf[i] < 224) { len = (((buf[i] - 192) << 8) + buf[i + 1] + 192); i += 2; }
      else if (buf[i] === 255) { len = buf.readUInt32BE(i + 1); i += 5; }
      else throw new Error('partial-body lengths unsupported');
    } else {
      tag = (ctb >> 2) & 0xf;
      if ((ctb & 3) === 0) { len = buf[i]; i += 1; }
      else if ((ctb & 3) === 1) { len = buf.readUInt16BE(i); i += 2; }
      else if ((ctb & 3) === 2) { len = buf.readUInt32BE(i); i += 4; }
      else { len = buf.length - i; }
    }
    if (i + len > buf.length) throw new Error('packet overruns buffer');
    const material = buf.subarray(i, i + len);
    i += len;
    if (tag === 6 || tag === 14) {
      out.push(createHash('sha1')
        .update(Buffer.concat([Buffer.from([0x99, (material.length >> 8) & 0xff, material.length & 0xff]), material]))
        .digest('hex').toUpperCase());
    }
  }
  if (!out.length) throw new Error('no OpenPGP key packets found');
  return out;
}

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  console.error('playwright not installed. Run:');
  console.error('  npm install --no-save playwright && npx playwright install chromium');
  process.exit(2);
}

const FLOW = (process.argv[2] || 'verified') === 'full' ? 'full' : 'verified';
const EMAIL = process.env.PPEMAIL || 'sb-fuobx47090577@personal.example.com';
const PASSWORD = process.env.PPPASS || '4&itWr>M';
// VERIFY_HTML may be a local path (→ file:// copy) or a full https:// URL
// (→ the pinned GitHub Pages auditor, exercising the real remote trust path).
const VERIFY_RAW = process.env.VERIFY_HTML
  || new URL('../verify.html', import.meta.url).pathname;
const VERIFY = /^https?:\/\//.test(VERIFY_RAW) ? VERIFY_RAW : 'file://' + VERIFY_RAW;
const log = (...a) => console.log(...a);

const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
});
const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 } });
const page = await ctx.newPage();

let downloaded = null;     // final plain attestation-report-*.json
let encDownload = null;    // callback's automatic encrypted-attestation-report.json
let sealedDownload = null; // v197: the callback's SECOND auto-download (Police escrow)
// F6 (production race detector): exactly ONE prepare per login. The double-
// prepare race sealed the callback ciphertext to a nonce that a second,
// racing round had already overwritten (live GCM OperationError on every
// login, 2026-10-25). Count the POSTs at the network layer — the guard in
// executePreflightAndLogin must hold in production, not just in the harness.
let preparePosts = 0;
page.on('request', (r) => {
  if (r.method() === 'POST' && r.url().includes('/attest/login-session')) preparePosts++;
});
page.on('download', (d) => {
  downloaded = d.suggestedFilename();
  log('  [DOWNLOAD]', downloaded);
});
page.on('console', (m) => {
  if (m.type() === 'error') log('  [console.error]', m.text().slice(0, 200));
});

try {
  await page.goto(VERIFY, { waitUntil: 'domcontentloaded' });
  await page.fill('#localEnclaveHost', 'https://login.airma.de');
  log('1. loaded', VERIFY, '(trusted copy)');

  // Step 1 — login session (v180: NO pre-login attestation — S_enc-signed
  // fields only; the hardware audit runs on the post-login report).
  // v188: TWO EXPLICIT login links (#loginVerifiedLink / #loginFullLink);
  // the v187 morphing button is gone. A click prepares the signed session
  // and turns THAT link into the "Continue to PayPal →" handoff; the second
  // click (target=_blank, a real user gesture) opens PayPal and is never
  // popup-blocked.
  const flowLink = FLOW === 'full' ? '#loginFullLink' : '#loginVerifiedLink';
  await page.click(flowLink);
  await page.waitForFunction(
    (sel) => { const a = document.querySelector(sel); return a && a.href && a.href.includes('authorize'); },
    flowLink, { timeout: 90000 });
  log('1b. flow link ready:', (await page.textContent(flowLink).catch(() => '')).slice(0, 80));
  const [popup] = await Promise.all([
    ctx.waitForEvent('page', { timeout: 30000 }).catch(() => null),
    page.click(flowLink),
  ]);
  // v197: capture the login status NOW — the audit below overwrites it.
  const escrowStatus = (await page.textContent('#secureLoginStatus').catch(() => '')) || '';
  log('2. step-1 status:', escrowStatus.slice(0, 240));

  const pp = popup;
  if (!pp) throw new Error('no PayPal tab opened from the flow link (login-session failed?)');
  // Capture downloads from the very start of the popup's life: the callback
  // page fires its automatic download on LOAD (v188).
  pp.on('download', (d) => {
    const f = d.suggestedFilename();
    log('  [DOWNLOAD:popup]', f);
    if (f === 'encrypted-attestation-report.json') encDownload = { d, f };
    else if (f === 'pgp-sealed-attestation.json') sealedDownload = { d, f };
    else downloaded = f;
  });
  await pp.waitForLoadState('domcontentloaded').catch(() => {});
  log('3. popup landed:', pp.url().slice(0, 110));

  // PayPal classic split form: DOM-focus each field and type REAL keystrokes
  // (Playwright actionability is unreliable on the z-stacked panes).
  const domClick = (id) => pp.evaluate((b) => { const n = document.getElementById(b); if (n) n.click(); }, id);
  const typeInto = async (id, text) => {
    await pp.evaluate((b) => { const n = document.getElementById(b); if (n) { n.focus(); n.select?.(); } }, id);
    await pp.keyboard.press('Control+A').catch(() => {});
    await pp.keyboard.type(text, { delay: 15 });
  };
  for (let attempt = 1; attempt <= 3; attempt++) {
    await pp.waitForSelector('#email, #password', { timeout: 30000 }).catch(() => {});
    if (!/Sorry about that/.test(await pp.content())) break;
    log('   PayPal transient error page — retry', attempt);
    await pp.waitForTimeout(15000);
    await pp.reload();
  }
  const hasEmail = (await pp.locator('#email').count()) > 0;
  let navigated = false;
  for (let attempt = 0; attempt < 3 && !navigated; attempt++) {
    if (hasEmail) {
      await typeInto('email', EMAIL);
      await domClick('btnNext');
      await pp.waitForTimeout(2500);
    }
    await typeInto('password', PASSWORD);
    await domClick('btnLogin').catch(() => domClick('btnNext'));
    log('   credentials submit #' + (attempt + 1));
    navigated = await pp.waitForURL((u) => !/signin|authorize/.test(u.pathname), { timeout: 20000 })
      .then(() => true).catch(() => false);
    if (!navigated) await pp.waitForTimeout(3000);
  }
  if (!navigated) throw new Error('PayPal login did not navigate after 3 submit attempts');
  log('4. paypal navigated:', pp.url().slice(0, 110));

  // Consent: auto-redirect if previously granted; else approve the consent UI
  // (cookie banner first), falling back to the embedded /callback URL.
  const isCallback = (u) => u.host === 'login.airma.de' && u.pathname === '/callback';
  try {
    await pp.waitForURL((u) => isCallback(u), { timeout: 15000 });
    log('5. consent auto-completed (previously granted)');
  } catch {
    await pp.waitForSelector('button', { timeout: 25000 }).catch(() => {});
    const banner = pp.locator('button.acceptButton, button:has-text("Yes, I accept")').first();
    if (await banner.count()) { await banner.click({ timeout: 5000 }).catch(() => {}); await pp.waitForTimeout(1000); }
    const agree = pp.locator('button:not([disabled])').filter({ hasText: /zustimmen|agree|contin|autoriz|allow|genehmig|akzept|accept/i }).first();
    if (await agree.count()) {
      log('   consent click →', ((await agree.textContent().catch(() => '')) || '').trim().slice(0, 50));
      await agree.click({ timeout: 10000 }).catch((e) => log('   click failed:', e.message.slice(0, 100)));
    }
    try {
      await pp.waitForURL((u) => isCallback(u), { timeout: 15000 });
    } catch {
      const html2 = await pp.content();
      const m = html2.match(/https:\/\/login\.airma\.de\/callback\?[^"'\s<>\\]+/);
      const cb = m && m[0].replace(/&amp;/g, '&');
      if (cb && /[?&]code=/.test(cb)) {
        log('   consent fallback: hopping to embedded callback URL');
        await pp.goto(cb, { waitUntil: 'domcontentloaded', timeout: 30000 });
      } else {
        throw new Error('no consent approval and no embedded callback URL');
      }
    }
  }
  await pp.waitForLoadState('networkidle', { timeout: 45000 }).catch(() => {});
  log('6. callback:', pp.url().slice(0, 120));

  // v188: the callback must AUTO-DOWNLOAD the ciphertext on load — no
  // landing page, no button click. Hard-fail if the automatic download never
  // fires (this is the deployed-feature check for the main.rs change).
  for (let i = 0; i < 40 && !encDownload; i++) await pp.waitForTimeout(500);
  if (!encDownload) throw new Error('callback did NOT auto-download encrypted-attestation-report.json (v188 main.rs change not deployed?)');
  log('6b. callback auto-download fired:', encDownload.f);
  const encPath = await encDownload.d.path();
  const encJson = readFileSync(encPath, 'utf8');
  log('   ciphertext saved (' + encJson.length + ' bytes) →', encPath.slice(0, 80));

  // Step 2 — the trusted tab: load the downloaded ciphertext into the report
  // box (there is deliberately NO claim button any more) and run the audit;
  // decryptPastedBlob() performs the keyed decryption + fail-closed checks.
  await page.bringToFront();
  await page.fill('#attestationInput', encJson);
  await page.click('button:has-text("Perform Cryptographic Audit")');
  await page.waitForTimeout(12000);
  const status = (await page.textContent('#secureLoginStatus').catch(() => '')).slice(0, 350);
  log('8. audit status:', status);
  const rows = await page.evaluate(() => ({
    enclave: document.getElementById('enclaveCheck').className,
    firmware: document.getElementById('firmwareCheck').className,
    btn: document.getElementById('reportDownloadBtn').style.display,
  }));
  log('   verdict rows:', JSON.stringify(rows));
  const green = /verified/.test(rows.enclave) && /verified/.test(rows.firmware) && rows.btn === 'block';
  if (!green) {
    throw new Error('paste-decrypt audit did NOT go green (enclave=' + rows.enclave + ' firmware=' + rows.firmware + ') — ' + status.slice(0, 200));
  }

  const rep = await page.evaluate(() => document.getElementById('attestationInput').value);
  if (rep && rep.trim().startsWith('{')) {
    writeFileSync('/tmp/claimed-report.json', rep);
    log('   decrypted report saved → /tmp/claimed-report.json (' + rep.length + ' bytes)');
  }

  // ── v197 — the SECOND auto-download (Police escrow) ──────────────────
  // The auditor ships the BKA key PREFILLED, so this login must have sealed
  // a copy to it. Assert the addressing (fingerprint + clear hashes), which
  // needs no private key: the ciphertext is only readable by whoever holds
  // that key, so proving it is *addressed to it* is the observable claim.
  const bkaArmor = readFileSync(new URL('../zk/rsa-test/police-bka-pub.asc', import.meta.url), 'utf8');
  const wantFp = armorFingerprints(bkaArmor);
  let sealedOk = false;
  if (!sealedDownload) throw new Error('v197: callback did NOT auto-download pgp-sealed-attestation.json (escrow box prefilled, enclave should have sealed a copy)');
  const sealedPath = await sealedDownload.d.path();
  const sealed = JSON.parse(readFileSync(sealedPath, 'utf8'));
  writeFileSync('/tmp/pgp-sealed-attestation.json', JSON.stringify(sealed, null, 2));
  const reportObj = rep && rep.trim().startsWith('{') ? JSON.parse(rep) : null;
  const signedRawHash = reportObj?.attestation_report?.paypal_user_info_raw_hash || '';
  const fp = String(sealed.recipient_fingerprint || '').toUpperCase();
  sealedOk = sealed.type === 'pav-pgp-sealed-attestation/v1'
    && wantFp.includes(fp)
    && !!signedRawHash && sealed.paypal_user_info_raw_hash === signedRawHash
    && /^[0-9a-f]{64}$/i.test(String(sealed.paypal_id_sha256 || ''))
    && /^-----BEGIN PGP MESSAGE-----/.test(String(sealed.ciphertext || ''))
    && /-----END PGP MESSAGE-----\s*$/.test(String(sealed.ciphertext || '').trim());
  log('   sealed copy → /tmp/pgp-sealed-attestation.json', JSON.stringify({
    type: sealed.type, fp: fp.slice(0, 16) + '…',
    addressedToBka: wantFp.includes(fp),
    clearHashMatchesSigned: !!signedRawHash && sealed.paypal_user_info_raw_hash === signedRawHash,
    idHash: sealed.paypal_id_sha256,
    ctBytes: String(sealed.ciphertext || '').length,
  }));
  const escrowNoted = /Police escrow ON/.test(escrowStatus);
  log('   login status escrow note:', escrowNoted ? 'yes ✓' : 'MISSING');

  // Step 3 — the green audit unlocks the plain-report download (v164).
  await page.click('#reportDownloadBtn');
  await page.waitForTimeout(3000);
  await browser.close();

  log('9. prepare POSTs to /attest/login-session:', preparePosts, preparePosts === 1 ? '(F6 single-prepare ✓)' : '← F6 VIOLATION (must be exactly 1)');
  const ok = !!encDownload && green && !!downloaded && /^attestation-report-/.test(downloaded) && preparePosts === 1 && sealedOk && escrowNoted;
  log('\n' + (ok
    ? `RESULT: PASS — callback auto-download ✓, audit green ✓, report downloaded (${downloaded}), single-prepare ✓, police-sealed copy ✓`
    : `RESULT: FAIL — enc=${encDownload ? 'yes' : 'no'} green=${green} downloaded=${downloaded || 'none'} preparePosts=${preparePosts} sealed=${sealedOk} escrowNoted=${escrowNoted} status=${String(status).slice(0, 120)}`));
  process.exit(ok ? 0 : 1);
} catch (e) {
  await browser.close().catch(() => {});
  console.error('E2E FAILED:', e.message.slice(0, 300));
  process.exit(1);
}
