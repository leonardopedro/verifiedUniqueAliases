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
import { createRequire } from 'module';

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
  log('2. step-1 status:', (await page.textContent('#secureLoginStatus').catch(() => '')).slice(0, 240));

  const pp = popup;
  if (!pp) throw new Error('no PayPal tab opened from the flow link (login-session failed?)');
  // Capture downloads from the very start of the popup's life: the callback
  // page fires its automatic download on LOAD (v188).
  pp.on('download', (d) => {
    const f = d.suggestedFilename();
    log('  [DOWNLOAD:popup]', f);
    if (f === 'encrypted-attestation-report.json') encDownload = { d, f };
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

  // Step 3 — the green audit unlocks the plain-report download (v164).
  await page.click('#reportDownloadBtn');
  await page.waitForTimeout(3000);
  await browser.close();

  const ok = !!encDownload && green && !!downloaded && /^attestation-report-/.test(downloaded);
  log('\n' + (ok
    ? `RESULT: PASS — callback auto-download ✓, audit green ✓, report downloaded (${downloaded})`
    : `RESULT: FAIL — enc=${encDownload ? 'yes' : 'no'} green=${green} downloaded=${downloaded || 'none'} status=${String(status).slice(0, 120)}`));
  process.exit(ok ? 0 : 1);
} catch (e) {
  await browser.close().catch(() => {});
  console.error('E2E FAILED:', e.message.slice(0, 300));
  process.exit(1);
}
