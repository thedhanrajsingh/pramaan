// Smoke test for the assembled PRAMAAN prototype (index.html).
// Usage: node test/smoke.js
// Exits 1 on any failure. Writes test/shots/*.png.
const path = require('path');
const fs = require('fs');
const { boot } = require('./harness');

const SHOTS = path.join(__dirname, 'shots');
const SCREENS = ['overview', 'analyze', 'trace', 'forensics'];
const BAD_TEXT = [/\bundefined\b/, /\bNaN\b/, /\[object Object\]/, /\bnull\b/];

(async () => {
  fs.mkdirSync(SHOTS, { recursive: true });
  const failures = [];
  const fail = (screen, msg) => failures.push({ screen, msg });

  const { browser, page, errors: consoleErrors, go, select } = await boot();

  // App booted?
  const bootInfo = await page.evaluate(() => ({
    hasApp: !!window.App, screens: window.App ? Object.keys(window.App.screens || {}) : [],
    emails: window.EFP_DATA ? window.EFP_DATA.emails.length : 0,
    selected: window.App && window.App.state ? window.App.state.selectedEmailId : null,
    leftovers: (window.__screens || []).length,
  }));
  if (!bootInfo.hasApp) fail('shell', 'window.App missing');
  for (const s of SCREENS) if (!bootInfo.screens.includes(s)) fail(s, 'screen not registered with App');
  if (bootInfo.emails < 5) fail('data', 'fewer than 5 emails in EFP_DATA');
  if (!bootInfo.selected) fail('shell', 'no email selected after init');

  const emailIds = await page.evaluate(() => window.EFP_DATA.emails.map((e) => e.id));

  const checkScreen = async (screen, label) => {
    await go(screen);
    const info = await page.evaluate((s) => {
      const el = document.getElementById('screen-' + s);
      if (!el) return { missing: true };
      const r = el.getBoundingClientRect();
      const others = Array.from(document.querySelectorAll('section.screen')).filter((x) => x !== el && !x.hidden).map((x) => x.id);
      return {
        hidden: el.hidden, height: r.height, text: el.innerText, html: el.innerHTML.length, others,
        overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 2,
      };
    }, screen);
    if (info.missing) return fail(screen, `section #screen-${screen} missing`);
    if (info.hidden) fail(screen, `still hidden after go() [${label}]`);
    if (info.others.length) fail(screen, `other screens visible at same time: ${info.others.join(',')}`);
    if (info.height < 300) fail(screen, `section too short (${Math.round(info.height)}px) [${label}]`);
    if (info.html < 1500) fail(screen, `section nearly empty (${info.html} chars of HTML) [${label}]`);
    if (info.overflow) fail(screen, `page scrolls horizontally [${label}]`);
    for (const re of BAD_TEXT) {
      const m = info.text.match(re);
      if (m) {
        const i = info.text.indexOf(m[0]);
        fail(screen, `bad text "${m[0]}" near: …${info.text.slice(Math.max(0, i - 40), i + 40).replace(/\s+/g, ' ')}… [${label}]`);
      }
    }
  };

  // Pass 1: each screen with the default email, screenshots
  for (const s of SCREENS) {
    await checkScreen(s, 'default email');
    await page.screenshot({ path: path.join(SHOTS, `${s}.png`), fullPage: true });
  }

  // Pass 2: every email through every screen (onSelect re-render)
  for (const id of emailIds) {
    await select(id);
    for (const s of SCREENS) await checkScreen(s, `email ${id}`);
  }

  // Pass 3: selector wired?
  const selOk = await page.evaluate((ids) => {
    const sel = document.getElementById('email-select');
    if (!sel || sel.options.length !== ids.length) return false;
    sel.value = ids[ids.length - 1];
    sel.dispatchEvent(new Event('change', { bubbles: true }));
    return window.App.state.selectedEmailId === ids[ids.length - 1];
  }, emailIds);
  if (!selOk) fail('shell', 'email selector missing, wrong option count, or change does not select');

  // Pass 4: click every button on every screen; expect no errors, and toasts or navigation to happen
  const preClickErrorCount = consoleErrors.length;
  for (const s of SCREENS) {
    await go(s);
    const n = await page.evaluate((x) => document.querySelectorAll(`#screen-${x} button`).length, s);
    let toasts = 0, navs = 0;
    for (let i = 0; i < n; i++) {
      const before = consoleErrors.length;
      const res = await page.evaluate(async ({ x, i }) => {
        const btn = document.querySelectorAll(`#screen-${x} button`)[i];
        if (!btn || btn.disabled) return { skipped: true };
        const t0 = document.querySelectorAll('#toasts .toast').length;
        btn.click();
        await new Promise((r) => setTimeout(r, 120));
        return { label: (btn.textContent || '').trim().slice(0, 40), toast: document.querySelectorAll('#toasts .toast').length > t0, screen: window.App.state.screen };
      }, { x: s, i });
      if (res.skipped) continue;
      if (res.toast) toasts++;
      if (res.screen !== s) navs++;
      if (consoleErrors.length > before) fail(s, `clicking "${res.label}" threw: ${consoleErrors.slice(before).join(' | ').slice(0, 200)}`);
    }
    if (n > 0 && toasts + navs === 0) fail(s, `${n} buttons but none produced a toast or navigation`);
  }

  // Pass 5: hash routing
  await page.evaluate(() => { location.hash = '#/trace'; });
  await page.waitForTimeout(150);
  const hashed = await page.evaluate(() => window.App.state.screen);
  if (hashed !== 'trace') fail('shell', 'hash routing #/trace did not switch screen');

  // Pass 6: explicit body background
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  if (!bg || bg === 'rgba(0, 0, 0, 0)') fail('shell', 'body has no explicit background');

  // Errors from clicking buttons in Pass 4 are already reported per-button above; report only
  // errors that happened outside a button click (boot, Pass 1/2 screen switches, etc.).
  for (const e of consoleErrors.slice(0, preClickErrorCount)) fail('console', e.slice(0, 300));

  await browser.close();
  console.log(`screens registered: ${bootInfo.screens.join(', ')} | emails: ${bootInfo.emails}`);
  if (failures.length) {
    console.log(`FAIL (${failures.length})`);
    for (const f of failures) console.log(` - [${f.screen}] ${f.msg}`);
    process.exit(1);
  }
  console.log('PASS');
})().catch((e) => { console.error('RUNNER ERROR', e); process.exit(2); });
