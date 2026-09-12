// Screen test for sections/trace.html — run: node test/trace.test.js
const { run } = require('./harness');

run('trace', async (t) => {
  const { page, data, select, go, text, count, expect, toasts } = t;

  for (const email of data.emails) {
    await select(email.id);
    await go('trace');
    const tag = email.id + ': ';

    // ---- hop stepper rows ----
    const rows = await page.evaluate(() =>
      Array.from(document.querySelectorAll('#screen-trace tr.trace-hop-row')).map((r) => r.innerText)
    );
    await expect(rows.length === email.hops.length, tag + 'hop row count ' + rows.length + ' != ' + email.hops.length);
    for (let i = 0; i < email.hops.length; i++) {
      const h = email.hops[i], row = rows[i] || '';
      await expect(row.indexOf(h.host) >= 0, tag + 'hop ' + i + ' row missing host ' + h.host);
      await expect(row.indexOf(h.ip) >= 0, tag + 'hop ' + i + ' row missing ip ' + h.ip);
      await expect(row.indexOf(h.city) >= 0, tag + 'hop ' + i + ' row missing city ' + h.city);
      await expect(row.indexOf(h.countryCode) >= 0, tag + 'hop ' + i + ' row missing countryCode ' + h.countryCode);
    }

    // ---- map ----
    const map = await page.evaluate((hops) => {
      const svg = document.querySelector('#screen-trace #trace-map');
      const project = window.EFP_MAP.project;
      const byKey = {};
      hops.forEach((h) => { const p = project(h.lat, h.lon, 960, 480); byKey[p.x.toFixed(1) + ':' + p.y.toFixed(1)] = 1; });
      return {
        hasSvg: !!svg,
        basemapPaths: Array.from(svg.querySelectorAll('path')).filter((p) => (p.getAttribute('d') || '').indexOf('Q') < 0).length,
        routePaths: Array.from(svg.querySelectorAll('path')).filter((p) => (p.getAttribute('d') || '').indexOf('Q') >= 0).length,
        markerCircles: svg.querySelectorAll('circle').length,
        clusters: Object.keys(byKey).length,
      };
    }, email.hops);
    await expect(map.hasSvg, tag + 'map svg missing');
    await expect(map.basemapPaths > 0, tag + 'no basemap land/graticule paths');
    // two circles drawn per distinct hop location (halo + marker)
    await expect(map.markerCircles === map.clusters * 2, tag + 'marker circles ' + map.markerCircles + ' != 2x clusters ' + map.clusters);
    await expect(map.clusters >= 1 && map.clusters <= email.hops.length, tag + 'cluster count out of range: ' + map.clusters);
    // an arc is only drawn between distinct locations; co-located hops share one marker, no arc
    if (map.clusters > 1) {
      await expect(map.routePaths > 0, tag + 'expected a route path for >1 distinct hop location');
    }

    // ---- origin card ----
    const originText = await text('#trace-origin-place');
    const ipPillText = await text('#trace-origin-ip-pill');
    const confText = await text('#trace-origin-conf-val');
    await expect((originText || '').indexOf(email.origin.city) >= 0, tag + 'origin place missing city');
    await expect((ipPillText || '').indexOf(email.origin.ip) >= 0, tag + 'origin ip pill missing ip');
    await expect(confText === Math.round(email.origin.confidence * 100) + '%', tag + 'origin confidence text "' + confText + '" wrong');

    // ---- IOC rows ----
    const iocRowCount = await count('#trace-ioc-body .ioc-row');
    if (email.iocs.length) {
      await expect(iocRowCount === email.iocs.length, tag + 'ioc row count ' + iocRowCount + ' != ' + email.iocs.length);
      const iocBodyText = await text('#trace-ioc-body');
      for (const ioc of email.iocs) {
        await expect((iocBodyText || '').indexOf(ioc.value) >= 0, tag + 'ioc value missing: ' + ioc.value);
      }
    } else {
      await expect(iocRowCount === 0, tag + 'expected no ioc rows');
      await expect(count('#trace-ioc-body .trace-empty').then((n) => n === 1), tag + 'expected ioc empty state');
    }

    // ---- related campaigns ----
    const cmpRowCount = await count('#trace-campaigns-body .cmp-row');
    if (email.relatedCampaigns.length) {
      await expect(cmpRowCount === email.relatedCampaigns.length, tag + 'campaign row count ' + cmpRowCount + ' != ' + email.relatedCampaigns.length);
    } else {
      await expect(cmpRowCount === 0, tag + 'expected no campaign rows');
      await expect(count('#trace-campaigns-body .trace-empty').then((n) => n === 1), tag + 'expected campaigns empty state');
    }

    // ---- raw headers ----
    const rawText = await text('#trace-raw-headers');
    const firstLine = email.rawHeaders.split('\n')[0];
    await expect((rawText || '').indexOf(firstLine) >= 0, tag + 'raw headers missing first line');

    // ---- hover highlight ----
    await page.hover('#screen-trace tr.trace-hop-row:first-child');
    await page.waitForTimeout(80);
    const hlDuring = await count('#trace-raw-headers span.hl');
    await expect(hlDuring >= 1, tag + 'hover did not highlight any raw-header line');
    await page.mouse.move(5, 5);
    await page.waitForTimeout(80);
    const hlAfter = await count('#trace-raw-headers span.hl');
    await expect(hlAfter === 0, tag + 'highlight not cleared after mouse left');

    // ---- IOC export toast ----
    if (email.iocs.length) {
      await t.click('#trace-btn-export-ioc-2');
      const msgs = await toasts();
      await expect(msgs.length > 0, tag + 'export ioc did not produce a toast');
    }
  }
  // console errors are auto-checked by run() after this function returns
});
