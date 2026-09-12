// Screen test for the "analyze" screen. Usage: node test/analyze.test.js
const { run } = require('./harness');

run('analyze', async (t) => {
  const emails = t.data.emails;

  for (const email of emails) {
    await t.select(email.id);
    await t.go('analyze');
    const P = `${email.id}:`;

    const ringVal = await t.text('#analyze-verdict-card .score-ring__val');
    await t.expect(Number(ringVal) === Number(email.riskScore), `${P} score ring shows ${ringVal}, expected ${email.riskScore}`);
    const badge = await t.text('#analyze-verdict-card .badge');
    await t.expect(badge && badge.toLowerCase().includes(String(email.verdict).toLowerCase()), `${P} verdict badge "${badge}" != "${email.verdict}"`);
    const verdictText = await t.text('#analyze-verdict-card');
    await t.expect(verdictText && verdictText.includes(email.subject), `${P} subject not shown in verdict card`);

    const authText = await t.text('#analyze-auth-card');
    for (const k of ['spf', 'dkim', 'dmarc']) {
      const result = String(email.auth[k].result);
      await t.expect(authText && authText.toLowerCase().includes(result.toLowerCase()), `${P} ${k} result "${result}" missing from auth card`);
    }

    const rowCount = await t.count('#analyze-signals-table tbody tr');
    await t.expect(rowCount === email.signals.length, `${P} signal rows ${rowCount} != ${email.signals.length}`);
    const rows = await t.page.evaluate(() => Array.from(document.querySelectorAll('#analyze-signals-table tbody tr')).map((tr) => ({
      name: tr.children[0].textContent.trim(),
      status: tr.children[3].textContent.trim().toLowerCase(),
    })));
    const firstClear = rows.findIndex((r) => r.status.includes('clear'));
    await t.expect(firstClear === -1 || rows.slice(0, firstClear).every((r) => r.status.includes('fired')), `${P} fired rows must precede clear rows`);
    const fired = email.signals.filter((s) => s.status === 'fired');
    const top = fired.length ? fired.reduce((a, b) => (b.weight > a.weight ? b : a)) : null;
    await t.expect(!top || (rows[0] && rows[0].name.startsWith(top.name)), `${P} first signal row "${rows[0] && rows[0].name}" != top fired "${top && top.name}"`);

    if (email.links.length === 0) {
      const zeroText = await t.text('#analyze-links-body');
      await t.expect(zeroText && /zero payload/i.test(zeroText), `${P} expected zero-payload empty state`);
    } else {
      const linkBlocks = await t.count('#analyze-links-body .link-block');
      await t.expect(linkBlocks === email.links.length, `${P} link rows ${linkBlocks} != ${email.links.length}`);
      const linksText = await t.text('#analyze-links-body');
      for (const l of email.links) {
        await t.expect(linksText && linksText.includes(l.shown), `${P} link "shown" not shown: ${l.shown}`);
        await t.expect(linksText && linksText.includes(l.actual), `${P} link "actual" not shown: ${l.actual}`);
        if (l.redirects && l.redirects.length) {
          await t.expect(l.redirects.every((r) => linksText.includes(r)), `${P} redirect chain not fully shown for ${l.shown}`);
        }
      }
    }

    const attRows = await t.count('#analyze-attachments-body tbody tr');
    if (email.attachments.length === 0) {
      const attText = await t.text('#analyze-attachments-body');
      await t.expect(attText && /no attachments/i.test(attText), `${P} expected empty attachments state`);
    } else {
      await t.expect(attRows === email.attachments.length, `${P} attachment rows ${attRows} != ${email.attachments.length}`);
    }

    const idText = await t.text('#analyze-identity-card');
    await t.expect(idText && idText.includes(email.from.address), `${P} identity card missing from.address`);
    await t.expect(idText && idText.includes(email.replyTo), `${P} identity card missing replyTo`);

    const explText = await t.text('#analyze-explanation-card');
    await t.expect(explText && explText.includes(email.aiExplanation.trim()), `${P} AI explanation text missing`);
  }

  // Focused interaction test on one malicious email.
  const malicious = emails.find((e) => e.verdict === 'Malicious') || emails[0];
  await t.select(malicious.id);
  await t.go('analyze');

  const errorsBefore = t.errors.length;
  const clicked = await t.clickByText('#screen-analyze', 'run analysis');
  await t.expect(clicked, 'Run analysis button not found/clicked');
  await t.page.waitForTimeout(1600);
  const stillDisabled = await t.page.evaluate(() => document.querySelector('#analyze-run-btn').disabled);
  const toastList = await t.toasts();
  const ranOk = !stillDisabled || toastList.some((tx) => /confirmed/i.test(tx));
  await t.expect(ranOk, 'Run analysis did not complete: button still disabled and no completion toast');
  await t.expect(t.errors.length === errorsBefore, `console errors during run analysis: ${t.errors.slice(errorsBefore).join(' | ')}`);

  // Action buttons — re-select/re-go between each since navigation hides #screen-analyze.
  await t.select(malicious.id);
  await t.go('analyze');
  await t.clickByText('#screen-analyze', 'trace origin');
  let screen = await t.page.evaluate(() => window.App.state.screen);
  await t.expect(screen === 'trace', `"Trace origin" navigated to "${screen}", expected "trace"`);

  await t.select(malicious.id);
  await t.go('analyze');
  await t.clickByText('#screen-analyze', 'open case');
  screen = await t.page.evaluate(() => window.App.state.screen);
  await t.expect(screen === 'forensics', `"Open case" navigated to "${screen}", expected "forensics"`);

  await t.select(malicious.id);
  await t.go('analyze');
  const toastsBefore = (await t.toasts()).length;
  await t.clickByText('#screen-analyze', 'block sender');
  const toastsAfter = await t.toasts();
  await t.expect(toastsAfter.length > toastsBefore, '"Block sender" should produce a toast');
});
