// Screen test for "overview". See harness.js for boot()/run() contract.
const { run } = require('./harness');

function digits(s) { return String(s).replace(/[^\d]/g, ''); }
// Leading integer of a string like "46 (4%)" -> "46" (ignores trailing parenthetical %).
function leadingNum(s) { const m = String(s).trim().match(/^\d+/); return m ? m[0] : ''; }
// Parses fmt.ms output ("2.14 s" or "0 ms") back to a millisecond integer.
function parseMs(s) {
  s = String(s).trim();
  if (s.endsWith(' s')) return Math.round(parseFloat(s) * 1000);
  return parseInt(digits(s), 10) || 0;
}

run('overview', async (t) => {
  await t.go('overview');
  const d = t.data.dashboard;
  const emails = t.data.emails;

  // 1. KPI strip: 6 cards in fixed order.
  const kpiVals = await t.page.evaluate(() =>
    Array.from(document.querySelectorAll('#overview-kpis .kpi__value')).map((e) => e.textContent));
  const kpiExpected = [d.kpis.analysedToday, d.kpis.malicious, d.kpis.suspicious, d.kpis.safe, null, d.kpis.casesOpen];
  await t.expect(kpiVals.length === 6, 'expected 6 KPI cards, got ' + kpiVals.length);
  for (let i = 0; i < 6; i++) {
    if (i === 4) { await t.expect(parseMs(kpiVals[i]) === d.kpis.avgAnalysisMs, 'KPI 4 avg analysis time mismatch: ' + kpiVals[i]); continue; }
    await t.expect(digits(kpiVals[i]) === String(kpiExpected[i]), 'KPI ' + i + ' mismatch: ' + kpiVals[i] + ' vs ' + kpiExpected[i]);
  }

  // 2. 14-day chart: exactly one malicious + one suspicious bar per day, plus axis labels.
  const malCount = await t.count('#overview-chart .ch-mal');
  const susCount = await t.count('#overview-chart .ch-sus');
  await t.expect(malCount === d.threatsByDay.length, 'malicious bar count ' + malCount + ' != ' + d.threatsByDay.length);
  await t.expect(susCount === d.threatsByDay.length, 'suspicious bar count ' + susCount + ' != ' + d.threatsByDay.length);
  const lblCount = await t.count('#overview-chart .ch-lbl');
  const capCount = await t.count('#overview-chart .ch-cap');
  await t.expect(lblCount > 0, 'no axis labels (.ch-lbl) rendered');
  await t.expect(capCount === 2, 'expected 2 scale captions (.ch-cap), got ' + capCount);

  // 3. Category breakdown rows = non-Legitimate categories, counts matching.
  const threats = d.categoryBreakdown.filter((c) => c.category !== 'Legitimate');
  const catRows = await t.page.evaluate(() =>
    Array.from(document.querySelectorAll('#overview-categories .bar-row')).map((r) => ({
      label: r.querySelector('.bar-label').textContent.trim(), count: r.querySelector('.bar-count').textContent
    })));
  await t.expect(catRows.length === threats.length, 'category rows ' + catRows.length + ' != ' + threats.length);
  const byCat = {}; threats.forEach((c) => { byCat[c.category] = c.count; });
  for (const row of catRows) {
    await t.expect(row.label in byCat, 'unexpected category row: ' + row.label);
    await t.expect(leadingNum(row.count) === String(byCat[row.label]), 'category count mismatch for ' + row.label + ': ' + row.count);
  }

  // 4. Top origin rows = topOriginCountries, same order.
  const originRows = await t.page.evaluate(() =>
    Array.from(document.querySelectorAll('#overview-origins .bar-row')).map((r) => ({
      label: r.querySelector('.bar-label').textContent, count: r.querySelector('.bar-count').textContent
    })));
  await t.expect(originRows.length === d.topOriginCountries.length, 'origin rows ' + originRows.length + ' != ' + d.topOriginCountries.length);
  for (let i = 0; i < d.topOriginCountries.length; i++) {
    const c = d.topOriginCountries[i], row = originRows[i];
    if (!row) continue;
    await t.expect(row.label.indexOf(c.country) !== -1, 'origin row ' + i + ' label missing ' + c.country + ': ' + row.label);
    await t.expect(digits(row.count) === String(c.count), 'origin row ' + i + ' count mismatch: ' + row.count + ' vs ' + c.count);
  }

  // 5. Triage table rows = emails, subject/verdict/score match, in order.
  const rows = await t.page.evaluate(() =>
    Array.from(document.querySelectorAll('#overview-triage-body tr[data-email-id]')).map((tr) => ({
      id: tr.getAttribute('data-email-id'),
      subject: tr.children[2].textContent,
      score: tr.querySelector('.score-ring__val').textContent.trim(),
      verdict: tr.querySelector('.badge').textContent.trim()
    })));
  await t.expect(rows.length === emails.length, 'triage rows ' + rows.length + ' != ' + emails.length);
  for (let i = 0; i < emails.length; i++) {
    const e = emails[i], row = rows[i];
    if (!row) continue;
    await t.expect(row.id === e.id, 'row ' + i + ' id mismatch: ' + row.id + ' vs ' + e.id);
    await t.expect(row.subject === e.subject, 'row ' + i + ' subject mismatch: ' + row.subject);
    await t.expect(row.score === String(e.riskScore), 'row ' + i + ' score mismatch: ' + row.score + ' vs ' + e.riskScore);
    await t.expect(row.verdict.toLowerCase() === e.verdict.toLowerCase(), 'row ' + i + ' verdict mismatch: ' + row.verdict + ' vs ' + e.verdict);
  }

  // 6. Clicking the second row selects that email and navigates to analyze.
  const secondId = emails[1].id;
  await t.click('#overview-triage-body tr[data-email-id]:nth-child(2)');
  const state1 = await t.page.evaluate(() => ({ id: window.App.state.selectedEmailId, screen: window.App.state.screen }));
  await t.expect(state1.id === secondId, 'clicking row 2 selected ' + state1.id + ' not ' + secondId);
  await t.expect(state1.screen === 'analyze', 'clicking row 2 did not navigate to analyze, screen=' + state1.screen);
  await t.go('overview');

  // 7. Recent cases + engine health row counts.
  await t.expect((await t.count('#overview-cases .case-row')) === d.recentCases.length, 'recent case row count mismatch');
  await t.expect((await t.count('#overview-engines .engine-row')) === d.engineHealth.length, 'engine health row count mismatch');

  // 8. Selecting a different email marks its triage row aria-selected.
  const otherId = emails[emails.length - 1].id;
  await t.select(otherId);
  const selCount = await t.count('#overview-triage-body tr[data-email-id="' + otherId + '"][aria-selected="true"]');
  await t.expect(selCount === 1, 'row for ' + otherId + ' not marked aria-selected=true after select');
});
