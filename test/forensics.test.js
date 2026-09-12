// Screen test for sections/forensics.html — case header, timeline, evidence ledger,
// verify/anchor actions, export buttons, and the recent-cases strip.
const { run } = require('./harness');

const GENESIS = '0'.repeat(64);
function trunc(h) {
  if (!h) return '';
  return h.length <= 20 ? h : h.slice(0, 10) + '…' + h.slice(-6);
}

run('forensics', async (t) => {
  const cases = (t.data.dashboard && t.data.dashboard.recentCases) || [];

  for (const email of t.data.emails) {
    await t.select(email.id);
    await t.go('forensics');

    // Replicate the screen's own case lookup: first recentCases row matching this email.
    const kase = cases.find((c) => c.emailId === email.id) || null;
    const headerText = await t.text('#forensics-case-card');
    // badges render upper-cased via CSS (text-transform), so compare case-insensitively
    const headerLower = headerText.toLowerCase();

    if (kase) {
      await t.expect(headerText.includes(kase.caseId), `${email.id}: header missing case id ${kase.caseId}`);
      await t.expect(headerText.includes(email.id) || headerText.includes(email.subject), `${email.id}: header missing email id/subject`);
      await t.expect(headerLower.includes(email.verdict.toLowerCase()), `${email.id}: header missing verdict ${email.verdict}`);
      await t.expect(headerText.includes(kase.assignee), `${email.id}: header missing assignee ${kase.assignee}`);
    } else {
      await t.expect(headerText.includes('No open case for ' + email.id), `${email.id}: expected no-case state`);
      await t.expect(headerLower.includes(email.verdict.toLowerCase()), `${email.id}: no-case state missing verdict`);
    }

    // Timeline
    const tlCount = await t.count('#forensics-timeline .timeline-item');
    await t.expect(tlCount === email.timeline.length, `${email.id}: timeline count ${tlCount} != ${email.timeline.length}`);
    const tlText = await t.text('#forensics-timeline');
    for (const ev of email.timeline) {
      await t.expect(tlText.includes(ev.event), `${email.id}: timeline missing event "${ev.event}"`);
    }

    // Evidence ledger — row count, seq order, truncated sha256 + chained hash
    const ledgerCount = await t.count('#forensics-ledger-body tr');
    await t.expect(ledgerCount === email.evidenceLedger.length, `${email.id}: ledger count ${ledgerCount} != ${email.evidenceLedger.length}`);
    const rows = await t.page.evaluate(() => Array.from(document.querySelectorAll('#forensics-ledger-body tr')).map((tr) => {
      const c = tr.querySelectorAll('td');
      return { seq: c[0].textContent.trim(), sha: c[2].textContent.trim(), hash: c[5].textContent.trim() };
    }));
    for (let i = 0; i < email.evidenceLedger.length; i++) {
      const row = email.evidenceLedger[i];
      const got = rows[i];
      if (!got) { await t.expect(false, `${email.id}: missing ledger row ${i}`); continue; }
      await t.expect(got.seq === String(row.seq), `${email.id}: row ${i} out of seq order (${got.seq} != ${row.seq})`);
      await t.expect(got.sha === trunc(row.sha256), `${email.id}: row ${i} sha256 truncation mismatch`);
      await t.expect(got.hash === trunc(row.hash), `${email.id}: row ${i} chained hash truncation mismatch`);
    }

    // Verify chain — ledgers are built to be internally consistent, so this should report intact.
    await t.clickByText('#forensics-ledger-card', 'Verify chain');
    const verifyText = await t.text('#forensics-verify-result');
    let toastList = await t.toasts();
    const lastToast = toastList[toastList.length - 1] || '';
    await t.expect(/intact|verified/i.test(verifyText) || /verified|intact/i.test(lastToast),
      `${email.id}: verify chain produced no intact/verified state (result="${verifyText}", toast="${lastToast}")`);

    // Anchor to blockchain — toast should carry a hex tx id or say "anchored"/"notarised".
    await t.click('#forensics-btn-anchor');
    toastList = await t.toasts();
    const anchorToast = toastList[toastList.length - 1] || '';
    await t.expect(/0x[0-9a-f]+/i.test(anchorToast) || /anchor/i.test(anchorToast),
      `${email.id}: anchor toast missing hex tx id / "anchored" (toast="${anchorToast}")`);

    // Export / action bar — each button should raise its own toast.
    const exportBtns = [
      ['#forensics-btn-pdf', /pdf/i],
      ['#forensics-btn-json', /json/i],
      ['#forensics-btn-stix', /stix/i],
      ['#forensics-btn-push', /gateway|blocklist/i],
      ['#forensics-btn-cert', /cert-in/i],
    ];
    for (const [sel, re] of exportBtns) {
      await t.click(sel);
      const after = await t.toasts();
      const newest = after[after.length - 1] || '';
      await t.expect(re.test(newest), `${email.id}: ${sel} did not produce expected toast (got "${newest}")`);
    }

    // Recent cases strip — always dashboard.recentCases, regardless of selection.
    const casesRowCount = await t.count('#forensics-cases-body tr');
    await t.expect(casesRowCount === cases.length, `${email.id}: recent cases rows ${casesRowCount} != ${cases.length}`);
  }
});
