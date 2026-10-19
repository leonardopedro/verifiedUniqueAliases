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
    // 1. Enclave login → PayPal (auto-follows through authorize). PayPal
    // sometimes serves a transient "Sorry about that" error page — retry it.
    for (let attempt = 1; attempt <= 3; attempt++) {
      await page.goto(`${BASE}/login?flow=${FLOW}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
      log(`  landed: ${page.url().split('?')[0]}`);
      await page.waitForSelector('#email, #password', { timeout: 30000 }).catch(() => {});
      const body = await page.content();
      if (!/Sorry about that/.test(body)) break;
      log(`  PayPal error page (attempt ${attempt}), retrying in 15s…`);
      await page.waitForTimeout(15000);
    }

    // 2. PayPal classic split form: one <form> with #email/#password and two
    // submit buttons (#btnNext = email step, #btnLogin = password step). The
    // panes are z-stacked, so Playwright actionability (fill/click) is
    // unreliable — instead DOM-focus each field and type REAL keystrokes,
    // which PayPal's keyup/blur validation listeners definitely observe.
    const domClick = (id) => page.evaluate((b) => { const n = document.getElementById(b); if (n) n.click(); }, id);
    const valOf = (id) => page.evaluate((b) => (document.getElementById(b) || {}).value || '', id);
    const typeInto = async (id, text) => {
      await page.evaluate((b) => {
        const n = document.getElementById(b);
        if (n) { n.focus(); n.select?.(); }
      }, id);
      await page.keyboard.press('Control+A').catch(() => {});
      await page.keyboard.type(text, { delay: 15 });
    };
    const hasEmail = (await page.locator('#email').count()) > 0;
    let navigated = false;
    for (let attempt = 0; attempt < 3 && !navigated; attempt++) {
      // step A: email → Next
      if (hasEmail) {
        await typeInto('email', EMAIL);
        log(`  email field: "${(await valOf('email')).slice(0, 32)}"`);
        await domClick('btnNext');
        await page.waitForTimeout(2500);
      }
      // step B: password → Login (btnLogin may share the form with btnNext)
      await typeInto('password', PASSWORD);
      log(`  password field: ${(await valOf('password')).length} chars`);
      await domClick('btnLogin').catch(() => domClick('btnNext'));
      log(`  credentials submit #${attempt + 1}`);
      navigated = await page
        .waitForURL((u) => !/signin|authorize/.test(u.pathname), { timeout: 20000 })
        .then(() => true)
        .catch(() => false);
      if (!navigated) {
        const body = await page.content().catch(() => '');
        if (/too many times/i.test(body)) {
          log('  ⚠️ rate-limited by PayPal, backing off 60s…');
          await page.waitForTimeout(60000);
        } else {
          await page.waitForTimeout(2500);
        }
      }
    }
    log(`  credentials submitted (navigated=${navigated})`);
    if (!navigated) throw new Error('login did not navigate after 3 submit attempts');

    // 3. Consent: auto-redirect if previously granted; otherwise approve via
    //    the consent UI (cookie banner first), falling back to the /callback
    //    URL (with a real ?code=) that the consent page embeds — the same hop
    //    the curl-based driver used successfully.
    const isCallback = (u) => u.host === 'login.airma.de' && u.pathname === '/callback';
    try {
      await page.waitForURL((u) => isCallback(u), { timeout: 15000 });
      log('  consent auto-completed (previously granted)');
    } catch {
      await page.waitForSelector('button', { timeout: 25000 });
      // dismiss the cookie/overlay banner if it is in the way
      const banner = page.locator('button.acceptButton, button:has-text("Yes, I accept")').first();
      if (await banner.count()) {
        await banner.click({ timeout: 5000 }).catch(() => {});
        log('  cookie banner dismissed');
        await page.waitForTimeout(1000);
      }
      const agree = page.locator('button:not([disabled])').filter({
        hasText: /zustimmen|agree|contin|autoriz|allow|genehmig|akzept|accept/i,
      }).first();
      if (await agree.count()) {
        const txt = ((await agree.textContent().catch(() => '')) || '').trim().slice(0, 60);
        log(`  consent click → "${txt}"`);
        await agree.click({ timeout: 10000 }).catch((e) => log(`  click failed: ${e.message.slice(0, 120)}`));
      }
      try {
        await page.waitForURL((u) => isCallback(u), { timeout: 15000 });
      } catch {
        // Fallback: the consent page embeds the final callback URL incl. the
        // authorization code — navigate to it directly.
        const html2 = await page.content();
        const m = html2.match(/https:\/\/login\.airma\.de\/callback\?[^"'\s<>\\]+/);
        const cb = m && m[0].replace(/&amp;/g, '&');
        if (cb && /[?&]code=/.test(cb)) {
          log(`  consent fallback: hopping to embedded callback URL`);
          await page.goto(cb, { waitUntil: 'domcontentloaded', timeout: 30000 });
        } else {
          throw new Error('no consent approval and no embedded callback URL');
        }
      }
    }

    // 4. Enclave callback: code exchange + hardware attestation (can take seconds)
    log(`  callback: ${page.url().slice(0, 140)}`);
    await page.waitForLoadState('networkidle', { timeout: 45000 }).catch(() => { /* attestation may stream */ });
    await page.waitForTimeout(3000);
    writeFileSync(`/tmp/result-${FLOW}-landing.html`, await page.content());

    // 4b. One-time report generation: the landing page holds a POST /generate
    // form (session_id + optional custom_info) whose submit triggers the
    // hardware attestation report. Bind a flow marker as custom data.
    const genBtn = page.locator('form[action="/generate"] button[type="submit"], button:has-text("Generate Certificate")').first();
    if (await genBtn.count()) {
      const custom = page.locator('form[action="/generate"] input[name="custom_info"]').first();
      if (await custom.count()) await custom.fill(`e2e-${FLOW}-${Date.now()}`).catch(() => {});
      log('  clicking Generate Certificate…');
      await Promise.all([
        page.waitForLoadState('networkidle', { timeout: 60000 }).catch(() => {}),
        genBtn.click({ timeout: 10000 }),
      ]);
      await page.waitForTimeout(3000);
      log(`  generate → ${page.url().slice(0, 140)}`);
    } else {
      log('  no generate form found (already generated?)');
    }
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
    // 6. The result page embeds the report verbatim in <pre id="raw_report">
    //    (the Download button just blobs that innerText) — read it directly.
    if (!reportJson) {
      const raw = await page.locator('#raw_report').innerText().catch(() => '');
      if (raw.trim().startsWith('{')) {
        reportJson = raw.trim();
        log(`  report extracted from #raw_report (${reportJson.length} bytes)`);
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
for (const f of FLOWS) {
  if (f !== FLOWS[0]) await new Promise((r) => setTimeout(r, 15000));
  let r = await runFlow(browser, f);
  if (!r.ok) {
    log(`  retrying ${f} once after 20s…`);
    await new Promise((x) => setTimeout(x, 20000));
    r = await runFlow(browser, f);
  }
  results.push(r);
}
await browser.close();

log('\n===== E2E SUMMARY =====');
for (const r of results) log(` ${r.flow}: ${r.ok ? '✅' : '❌'} report=${r.hasReport ? 'yes' : 'no'} ${r.error || r.finalUrl?.slice(0, 90) || ''}`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
