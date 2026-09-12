// Shared harness for screen tests. Boots the assembled index.html in headless Chrome.
// Usage in a test file:
//   const { boot, expect, run } = require('./harness');
//   run('overview', async ({ page, data, go, select }) => { ... await expect(cond, 'message') ... });
const path = require('path');
const fs = require('fs');
const { chromium } = require('playwright-core');

const ROOT = path.resolve(__dirname, '..');
const INDEX = path.join(ROOT, 'index.html');

async function boot() {
  const html = fs.readFileSync(INDEX, 'utf8');
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  // Serve the page from a virtual file:// URL so navigator.clipboard behaves as it does for a local file.
  await page.route('**/pramaan-smoke.html', (route) => route.fulfill({ contentType: 'text/html', body: html }));
  await page.goto('file:///pramaan-smoke.html');
  await page.waitForTimeout(500);
  const data = await page.evaluate(() => JSON.parse(JSON.stringify(window.EFP_DATA)));
  const go = async (s) => { await page.evaluate((x) => window.App.go(x), s); await page.waitForTimeout(120); };
  const select = async (id) => { await page.evaluate((x) => window.App.select(x), id); await page.waitForTimeout(120); };
  const text = async (sel) => page.evaluate((s) => { const el = document.querySelector(s); return el ? el.innerText : null; }, sel);
  const count = async (sel) => page.evaluate((s) => document.querySelectorAll(s).length, sel);
  const click = async (sel) => { await page.evaluate((s) => { const el = document.querySelector(s); if (!el) throw new Error('no element ' + s); el.click(); }, sel); await page.waitForTimeout(150); };
  const clickByText = async (root, txt) => {
    const ok = await page.evaluate(({ r, t }) => {
      const btn = Array.from(document.querySelectorAll(r + ' button')).find((b) => (b.textContent || '').trim().toLowerCase().includes(t.toLowerCase()));
      if (!btn) return false; btn.click(); return true;
    }, { r: root, t: txt });
    await page.waitForTimeout(150);
    return ok;
  };
  const toasts = async () => page.evaluate(() => Array.from(document.querySelectorAll('#toasts .toast')).map((t) => t.innerText));
  return { browser, page, data, errors, go, select, text, count, click, clickByText, toasts };
}

function run(name, fn) {
  (async () => {
    const failures = [];
    const expect = async (cond, msg) => { if (!(await cond)) failures.push(msg); };
    let ctx;
    try {
      ctx = await boot();
      await fn({ ...ctx, expect });
      for (const e of ctx.errors) failures.push('console error: ' + e.slice(0, 200));
    } catch (e) {
      failures.push('runner exception: ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join(' ') : e));
    } finally {
      if (ctx) await ctx.browser.close();
    }
    const out = { screen: name, passed: failures.length === 0, failures };
    fs.writeFileSync(path.join(__dirname, `report.${name}.json`), JSON.stringify(out, null, 2));
    console.log(JSON.stringify(out, null, 2));
    process.exit(failures.length ? 1 : 0);
  })();
}

module.exports = { boot, run };
