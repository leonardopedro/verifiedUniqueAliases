// Browser end-to-end for the login → claim → DOWNLOAD flow (the AGENTS.md
// debugging playbook's browser step). Runs the REAL secure login from a
// trusted file:// copy of verify.html against the live enclave, drives the
// PayPal sandbox consent, presses "Claim Encrypted Report" (the v187 single
// workflow button's claim state), and FAILS unless the attestation report is
// actually downloaded.
//
// Why this exists: the download is the first casualty of any red audit row —
// a missing file is a SYMPTOM (v178: the identity-preimage gate failed on
// every honest login and silently suppressed the download). This script makes
// the whole chain observable: login-session status, callback handoff, the
// ?afterlogin=1 page, the claim verdict, download events, and the claimed
// report JSON (saved for offline inspection of the failing gate).
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
// Exit code 0 = claim audited AND the report file downloaded.
import { writeFileSync } from 'fs';
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
const VERIFY = 'file://' + (process.env.VERIFY_HTML
  || new URL('../verify.html', import.meta.url).pathname);
const log = (...a) => console.log(...a);

const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
});
const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 } });
const page = await ctx.newPage();

let downloaded = null;
page.on('download', (d) => {
  downloaded = d.suggestedFilename();
  log('  [DOWNLOAD]', downloaded);
});
page.on('console', (m) => {
  if (m.type() === 'error') log('  [console.error]', m.text().slice(0, 200));
});

try {
  // v187: for the full round, land WITH the hash so the DOMContentLoaded
  // auto-login starts it (a later hash-only goto would not re-fire load).
  await page.goto(VERIFY + (FLOW === 'full' ? '#login-full' : ''), { waitUntil: 'domcontentloaded' });
  await page.fill('#localEnclaveHost', 'https://login.airma.de');
  log('1. loaded', VERIFY, '(trusted copy)', FLOW === 'full' ? '#login-full' : '');

  // Step 1 — login session (v180: NO pre-login attestation — S_enc-signed
  // fields only; the hardware audit runs on the post-login report) + client
  // keypair.
  // Popup FIX (user report): the handoff is a plain link (#securePaypalUrl),
  // NOT window.open() — an async-time popup is blocked by every browser. The
  // button requests the login session and reveals the link; clicking the link
  // (target=_blank) is a real user gesture, so the new tab is never blocked.
  // v187 (single workflow button): only ONE login button is visible at a
  // time — the verified button on a fresh page; `#login-full` (used above)
  // auto-started the full round, so no click is needed there.
  if (FLOW !== 'full') {
    await page.click('button:has-text("Log in with PayPal (Verified account only)")');
  }
  await page.waitForSelector('#securePaypalUrl', { state: 'visible', timeout: 90000 });
  const [popup] = await Promise.all([
    ctx.waitForEvent('page', { timeout: 30000 }).catch(() => null),
    page.click('#securePaypalUrl'),
  ]);
  log('2. step-1 status:', (await page.textContent('#secureLoginStatus').catch(() => '')).slice(0, 240));

  const pp = popup;
  if (!pp) throw new Error('no PayPal tab opened from the #securePaypalUrl link (login-session failed?)');
  await pp.waitForLoadState('domcontentloaded').catch(() => {});
  log('3. popup landed:', pp.url().slice(0, 110));
  pp.on('download', (d) => { downloaded = d.suggestedFilename(); log('  [DOWNLOAD]', downloaded); });

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

  // v187: the callback landing page must offer a real DOWNLOAD of the
  // encrypted report (the user-reported gap: copy only). Hard-fail otherwise
  // — this is the deployed-feature check for the main.rs change.
  const dlCount = await pp.locator('button:has-text("Download encrypted report")').count();
  log('6b. callback download button count:', dlCount);
  if (!dlCount) throw new Error('callback landing page lacks the "Download encrypted report" button (v187 main.rs change not deployed?)');

  // The callback's report button leads to the webservice copy — it can only
  // show guidance (the key lives in THIS local page), but exercise it anyway.
  const btn = pp.locator('a:has-text("Get my attestation report")').first();
  if (await btn.count()) {
    await btn.click({ timeout: 10000 }).catch(() => {});
    await pp.waitForLoadState('domcontentloaded').catch(() => {});
    await pp.waitForTimeout(4000);
    log('7. afterlogin page:', pp.url().slice(0, 110), '|',
      (await pp.textContent('#secureLoginStatus').catch(() => '')).slice(0, 140));
  }

  // Step 2 — claim on the trusted page: decrypt + verify + audit + auto-download.
  await page.bringToFront();
  await page.click('button:has-text("Claim Encrypted Report")');
  await page.waitForTimeout(12000);
  // v186: single status line — localClaim() now reports on #secureLoginStatus
  // (the #localLoginStatus paragraph was removed in the simplification pass).
  const status = (await page.textContent('#secureLoginStatus').catch(() => '')).slice(0, 350);
  log('8. claim status:', status);

  const rep = await page.evaluate(() => document.getElementById('attestationInput').value);
  if (rep && rep.trim().startsWith('{')) {
    writeFileSync('/tmp/claimed-report.json', rep);
    log('   claimed report saved → /tmp/claimed-report.json (' + rep.length + ' bytes)');
  }
  await browser.close();

  const ok = downloaded && /✅/.test(status);
  log('\n' + (ok
    ? `RESULT: PASS — audit green and report downloaded (${downloaded})`
    : `RESULT: FAIL — downloaded=${downloaded || 'none'} status=${status.slice(0, 120)}`));
  process.exit(ok ? 0 : 1);
} catch (e) {
  await browser.close().catch(() => {});
  console.error('E2E FAILED:', e.message.slice(0, 300));
  process.exit(1);
}
