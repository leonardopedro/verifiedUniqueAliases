// Live sandbox end-to-end: drives the REAL enclave + PayPal sandbox consent in
// headless Chromium, captures the attestation result page and report JSON, and
// saves whatever report JSON it sees for the offline auditor (REAL_REPORT=…).
//
// Usage:
//   npm install --no-save playwright && npx playwright install chromium
//   node scripts/e2e-sandbox.mjs [verified|full|both]
//
// Env:
//   PPEMAIL / PPPASS — sandbox account (defaults to the project test user)
//
// The consent step is a React SPA (PayPal ICE) whose decision API is not
// worth reimplementing — a real browser is the honest way to drive it.
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

const BASE = 'https://login.airma.de';
const EMAIL = process.env.PPEMAIL || 'sb-fuobx47090577@personal.example.com';
const PASSWORD = process.env.PPPASS || '4&itWr>M';
const FLOWS = (process.argv[2] || 'both') === 'both' ? ['verified', 'full'] : [process.argv[2] || 'verified'];

const log = (...a) => console.log(...a);

async function runFlow(browser, FLOW) {
  log(`\n===== FLOW: ${FLOW} =====`);
  const ctx = await browser.newContext({
    locale: 'en-US',
    timezoneId: 'Europe/Berlin',
    ignoreHTTPSErrors: false,
    viewport: { width: 1280, height: 900 },
  });
  const page = await ctx.newPage();

  let reportJson = null;
  page.on('response', async (r) => {
    try {
      if (r.request().method() !== 'GET') return;
      const ct = r.headers()['content-type'] || '';
      if (!/json/.test(ct)) return;
      const t = await r.text();
      if (t.includes('attestation_report') || t.includes('enclave_signature_b64')) {
        reportJson = t;
        log(`  captured report JSON from ${r.url().slice(0, 120)}`);
      }
    } catch { /* ignore */ }
  });
  page.on('download', async (d) => {
    const name = d.suggestedFilename() || `download-${FLOW}`;
    const p = `/tmp/e2e-${FLOW}-${name}`;
    await d.saveAs(p);
    log(`  download saved → ${p}`);
    if (/\.json$/.test(name)) {
      try { reportJson = (await import('fs')).readFileSync(p, 'utf8'); } catch { /* ignore */ }
    }
  });

  try {
    // 1. Enclave login → PayPal (auto-follows through authorize)
    await page.goto(`${BASE}/login?flow=${FLOW}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
    log(`  landed: ${page.url().split('?')[0]}`);

    // 2. PayPal signin — split flow: email step then password step. The
    // hidden pane also exists in the DOM, so decide by VISIBILITY, not count.
    const emailSel = 'input[type="email"], input[name="login_email"], #email';
    const passSel = 'input[type="password"], input[name="login_password"], #password';
    const email = page.locator(emailSel).first();
    const pw = page.locator(passSel).first();
    await email.or(pw).first().waitFor({ state: 'visible', timeout: 30000 });
    if (await pw.isVisible()) {
      await pw.fill(PASSWORD);
      log('  password step: filled');
    } else {
      await email.fill(EMAIL);
      await page.locator('button[type="submit"], [data-e2e="btnNext"], button:has-text("Next"), button:has-text("Weiter")').first().click();
      log('  email step: submitted');
      await pw.waitFor({ state: 'visible', timeout: 20000 });
      await pw.fill(PASSWORD);
    }
    await page.locator('button[type="submit"], [data-e2e*="Login"], button:has-text("Log In"), button:has-text("Anmelden")').first().click();
    log('  credentials submitted');

    const onCallback = () => page.url().includes('login.airma.de/callback');

    // 3. Consent SPA: maybe it auto-redirects; otherwise click the approve button
    try {
      await page.waitForURL((u) => u.host === 'login.airma.de' && u.pathname === '/callback', { timeout: 12000 });
      log('  consent auto-completed (previously granted)');
    } catch {
      await page.waitForSelector('button', { timeout: 20000 });
      const agree = page.locator('button:not([disabled])').filter({
        hasText: /zustimmen|agree|contin|autoriz|allow|genehmig|akzept|accept|weiter|next/i,
      }).first();
      const target = (await agree.count()) ? agree : page.locator('button:not([disabled])').last();
      const txt = ((await target.textContent().catch(() => '')) || '').trim().slice(0, 60);
      log(`  consent click → "${txt}"`);
      await target.click({ timeout: 10000 }).catch((e) => log(`  click failed: ${e.message.slice(0, 120)}`));
      await page.waitForURL((u) => u.host === 'login.airma.de' && u.pathname === '/callback', { timeout: 30000 });
    }

    // 4. Enclave callback: code exchange + hardware attestation (can take seconds)
    log(`  callback: ${page.url().slice(0, 140)}`);
    await page.waitForLoadState('networkidle', { timeout: 45000 }).catch(() => { /* attestation may stream */ });
    await page.waitForTimeout(3000);
    const html = await page.content();
    const finalUrl = page.url();
    writeFileSync(`/tmp/result-${FLOW}.html`, html);
    log(`  final URL: ${finalUrl.slice(0, 160)}`);
    log(`  result page saved (${html.length} bytes)`);

    // 5. Inline report fallback (page-embedded JSON blob)
    if (!reportJson) {
      const m = html.match(/\{[\s\S]{0,200}"attestation_report"[\s\S]*\}/);
      const inline = [...html.matchAll(/<script[^>]*type="application\/json"[^>]*>([\s\S]*?)<\/script>/g)].map((x) => x[1]);
      for (const cand of [m?.[0], ...inline].filter(Boolean)) {
        try {
          const j = JSON.parse(cand.trim());
          if (j.attestation_report || j.report) { reportJson = cand.trim(); break; }
        } catch { /* not it */ }
      }
    }
    // 6. Explicit download link on the page
    if (!reportJson) {
      const dl = page.locator('a[download], a:has-text("JSON"), a:has-text("Download")').first();
      if (await dl.count()) {
        log('  clicking report download link…');
        const [download] = await Promise.all([
          page.waitForEvent('download', { timeout: 15000 }).catch(() => null),
          dl.click().catch(() => null),
        ]);
        if (download) {
          const p = `/tmp/report-${FLOW}.json`;
          await download.saveAs(p);
          reportJson = (await import('fs')).readFileSync(p, 'utf8');
          log(`  report download → ${p}`);
        }
      }
    }

    if (reportJson) {
      writeFileSync(`/tmp/report-${FLOW}.json`, reportJson);
      log(`  REPORT SAVED → /tmp/report-${FLOW}.json (${reportJson.length} bytes)`);
    } else {
      log('  ⚠️ no report JSON captured');
    }

    // Page markers for the data-split verdict
    for (const marker of [
      'verified_account: true', 'PayPal-verified', 'No name, email',
      'sb-fuobx47090577', 'personal.example.com', 'Blocked attestation',
      'Attestation Certificate', 'Hardware Attestation', 'login-verified', 'login-full',
    ]) {
      if (html.includes(marker)) log(`  PAGE CONTAINS: "${marker}"`);
    }
    await ctx.close();
    return { flow: FLOW, ok: true, finalUrl, hasReport: !!reportJson };
  } catch (e) {
    log(`  ❌ FAILED: ${e.message.slice(0, 300)}`);
    await page.screenshot({ path: `/tmp/e2e-fail-${FLOW}.png`, fullPage: true }).catch(() => {});
    try { writeFileSync(`/tmp/e2e-fail-${FLOW}.html`, await page.content()); } catch { /* ignore */ }
    await ctx.close();
    return { flow: FLOW, ok: false, error: e.message.slice(0, 300) };
  }
}

// CHROMIUM_PATH lets NixOS/containers point at a system Chromium instead of
// playwright's own download (which needs distro shared libs).
const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
  args: ['--disable-blink-features=AutomationControlled'],
});
const results = [];
for (const f of FLOWS) results.push(await runFlow(browser, f));
await browser.close();

log('\n===== E2E SUMMARY =====');
for (const r of results) log(` ${r.flow}: ${r.ok ? '✅' : '❌'} report=${r.hasReport ? 'yes' : 'no'} ${r.error || r.finalUrl?.slice(0, 90) || ''}`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
