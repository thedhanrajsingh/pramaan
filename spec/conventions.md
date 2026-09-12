# PRAMAAN — worker contract

Read this file, `spec/tokens.css` (for the class and variable names) and `spec/data.js` (for the
real field names). Build exactly one screen. The head assembles all four sections into a single
HTML Artifact page, so anything that leaks or collides breaks the build.

Product: **PRAMAAN** — email threat detection, geolocation and forensic intelligence console.
Theme is a dark "petrol console": hue-biased blue-green neutrals, cyan accent, brass for
evidence/ledger, and a severity scale (critical / high / medium / low / safe) that is *not* the
accent hue. It should read as an investigator's instrument, not a SaaS dashboard.

## 1. File to write

| screen id   | file                     | title                          |
|-------------|--------------------------|--------------------------------|
| `overview`  | `sections/overview.html` | Threat overview (SOC console)  |
| `analyze`   | `sections/analyze.html`  | Email analysis (verdict sheet) |
| `trace`     | `sections/trace.html`    | Origin trace & attribution     |
| `forensics` | `sections/forensics.html`| Forensic case & evidence chain |

Write **only** your file. No `<!DOCTYPE>`, `<html>`, `<head>`, `<body>`, no `<link>`, no
`<script src>`, no external libraries, no external fonts, no images, no emoji.

## 2. Required wrapper

```html
<section class="screen" id="screen-overview" hidden aria-labelledby="overview-title">
  <div class="screen__head">
    <div>
      <span class="eyebrow">Live · last 14 days</span>
      <h2 class="screen__title" id="overview-title">Threat overview</h2>
    </div>
    <div class="row row--tight"><!-- screen-level actions --></div>
  </div>
  ...
</section>
```

- `hidden` stays in the markup — the shell's `App.go()` owns visibility. Never remove it and
  never set `style.display`.
- Ids: `screen-overview`, `screen-analyze`, `screen-trace`, `screen-forensics`.
- `aria-labelledby` must point at your `<h2>` id, prefixed with your screen id.
- Every `id` you introduce inside the section must start with your screen id
  (`trace-map`, `analyze-signal-body`, …). Ids are global in the assembled page.

## 3. Section-scoped CSS

A section-scoped `<style>` block is allowed, but **every selector must be prefixed with
`#screen-<id>`**:

```html
<style>
#screen-trace .hop-arc{ stroke: var(--accent); stroke-width: 1.25; fill: none; }
#screen-trace .map-wrap{ background: var(--surface-sunk); border: 1px solid var(--border); }
</style>
```

No bare element selectors (`svg{...}`), no `:root`, no `body`, no `@font-face`, no new CSS
variables outside your prefix. Use the tokens: `var(--surface)`, `var(--border)`,
`var(--text-2)`, `var(--accent)`, `var(--sev-critical)` … Never hard-code a hex colour.

## 4. Script pattern (exact)

Your script is parsed **before** the data and the app core, because sections sit inside
`<main>`. So it must not touch `App` or `EFP_DATA` at parse time — only push a registration:

```html
<script>(function(){
  window.__screens = window.__screens || [];
  window.__screens.push(['trace', {
    mount: function (root, ctx) {
      // root  = your <section> element, ctx = App
      // cache nodes here; capture root in a closure variable for onSelect
    },
    onSelect: function (email, ctx) {
      // re-render everything that depends on the selected email
    }
  }]);
})();</script>
```

- `mount(root, ctx)` runs once. `onSelect(email, ctx)` runs immediately after mounting and again
  on every change of the top-bar selector. **`onSelect` does not receive `root`** — store it in
  your IIFE closure during `mount` (e.g. `var el;` then `el = root;`).
- Keep everything inside the IIFE. No `window.*` assignments other than the `__screens` push, no
  globals, no inline `onclick=` attributes.
- Never read `window.EFP_DATA` directly — use `ctx.data`.

### `ctx` (= `window.App`)

| member | meaning |
|---|---|
| `ctx.data.emails` | array of 7 analysed emails (see `spec/data.js`) |
| `ctx.data.dashboard` | `kpis`, `threatsByDay`, `categoryBreakdown`, `topOriginCountries`, `recentCases`, `engineHealth` |
| `ctx.email()` | currently selected email object |
| `ctx.caseFor(emailId)` | matching entry from `dashboard.recentCases`, or `null` |
| `ctx.select(emailId)` | change the global selection (fans out to all screens) |
| `ctx.go('analyze')` | route to another screen |
| `ctx.toast(msg, title)` | bottom-right toast; use it for every fake action |
| `ctx.fmt.escapeHtml(v)` | **required** on every value you interpolate into HTML |
| `ctx.fmt.date(iso)` | `12 Sep 2026, 09:14` |
| `ctx.fmt.time(iso)` | `09:14:22` |
| `ctx.fmt.number(n)` | Indian-grouped integer |
| `ctx.fmt.ms(n)` | `2.14 s` / `412 ms` |
| `ctx.fmt.pct(0.87)` | `87%` |
| `ctx.fmt.severity(score)` | `critical\|high\|medium\|low\|safe` (>=85, >=65, >=40, >=20, else) |
| `ctx.fmt.badgeClass(verdict)` | `badge--critical` / `badge--high` / `badge--safe` / `badge--info` |

`window.EFP_MAP` (`project(lat, lon, w, h) -> {x, y}` and `land` = arrays of `[lat, lon]`) is
available to the trace screen inside `mount`/`onSelect` — never at parse time.

## 5. Shared classes you MUST reuse

`.card` `.card-head` `.card--flush` `.card--sunk` · `.kpi` (`.kpi__label` `.kpi__value`
`.kpi__sub`) · `.badge` + `.badge--critical|high|medium|low|safe|info` (`.badge__dot`) · `.pill`
(`.pill--accent` `.pill--brass`) · `.btn` + `.btn--primary|ghost|danger|sm` · `.table`
(`.table-scroll`, `td.num`, `tr.is-clickable`) · `.mono` · `.eyebrow` · `.score-ring`
(`--ring-val`, `.score-ring--<sev>`, `.score-ring__val`, `.score-ring__cap`, `--sm`/`--lg`) ·
`.stripe` + `.stripe--<sev>` · `.meter` / `.meter__fill--<sev>` · `.grid-2` `.grid-3` `.stack`
`.row` `.row--between` `.grow` · `.muted` `.kbd` `.kv` (`dt`/`dd`) `.hash` `.divider`
`.tooltip-ish` (`data-hint="…"`) · `.dropzone`, `input`, `textarea`, `select`, `pre`.

Do not invent a second button, badge or card style. If you need something new, build it from
tokens inside your `#screen-<id>` prefix.

## 6. Hard rules

1. **Escape everything.** Every data value that reaches `innerHTML` goes through
   `ctx.fmt.escapeHtml()`. Raw headers and body text go into `<pre>` via `textContent`.
2. **Visible at rest.** No `opacity: 0`, no entrance animations that gate content, no
   `setTimeout` before first paint. Transitions on hover/active only; respect the
   `prefers-reduced-motion` block already in the tokens.
3. **Charts are hand-drawn SVG**, laid out to scale from the real numbers (compute `x`/`y` from
   the data; do not eyeball bar heights). Use `var(--sev-*)` for severity series, `var(--accent)`
   for single-series data, `var(--grid-line)` for gridlines, `var(--text-faint)` for axis labels
   (use `<text>` at 10-11px, `font-family: var(--font-mono)`). Give every chart
   `viewBox` + `preserveAspectRatio` so it scales, and wrap wide tables/diagrams in
   `.table-scroll` (or an `overflow-x:auto` container) — the page must never scroll sideways.
4. **Every control does something.** Buttons, toggles, filters, copy actions: either change the
   DOM you own or call `ctx.toast(...)` (and `ctx.select` / `ctx.go` where it makes sense). No
   dead buttons, no `href="#"`.
5. **No lorem, no invented brands.** Every string comes from `spec/data.js` or is a real UI
   label. Numbers in prose must match the data.
6. **Accessibility.** Semantic headings (`h2` per screen, `h3`/`h4` inside cards), real
   `<button type="button">`, `<th scope="col">`, `aria-selected` on a selected table row,
   `aria-live="polite"` for regions you re-render, labels on every form control. Don't remove
   focus outlines.
7. **No `document.write`, no `eval`, no timers left running**, no fetches, no `localStorage`.
8. Target a 1440px-wide console but stay usable at 900px (the shared grid helpers already
   collapse).

## 7. Screen briefs

### `overview` — Threat overview (SOC triage console)
Must have, top to bottom:
1. **KPI strip** — 6 `.kpi` cards from `dashboard.kpis`: analysed today, malicious, suspicious,
   safe, average analysis time (`fmt.ms`), open cases. Severity-coloured values where it applies.
2. **14-day stacked bar chart** (SVG) from `dashboard.threatsByDay`: malicious / suspicious
   stacked with a separate, quieter safe-volume reference (e.g. a thin line or a light band) so
   the 9 Sep and 12 Sep spikes read clearly. Y axis, day labels, and a legend using the severity
   colours.
3. **Category breakdown** from `dashboard.categoryBreakdown` — horizontal `.meter` bars with
   counts (Legitimate dwarfs the rest; either use a log-ish split or show Legitimate separately
   and label it, but do not silently drop it).
4. **Top origin countries** from `dashboard.topOriginCountries` — dense table or bar list with
   country code `.pill` and counts.
5. **Triage table** of all `data.emails`: received time, sender (display name + address, mono),
   subject, category, score (`.score-ring--sm` or a `.meter`), verdict `.badge`. Rows are
   `.is-clickable`: click → `ctx.select(email.id)` then `ctx.go('analyze')`. Mark the current
   row `aria-selected="true"`.
6. **Engine health** list from `dashboard.engineHealth` (status + latency), and a short
   "recent cases" strip from `dashboard.recentCases` with case id, status `.badge`, assignee.

`onSelect`: update the `aria-selected` row in the triage table (and any "currently selected"
caption). Nothing else on this screen depends on the selection.

### `analyze` — Email analysis (verdict sheet)
Must have:
1. **Ingest panel** — `.dropzone` ("Drop .eml / .msg"), a `<textarea>` for pasted raw source, a
   source `<select>` (Upload / Paste / IMAP connector / API), and a **Run analysis** `.btn--primary`
   that walks a short fake staged progress (parser → auth → engines → score) and finishes with a
   toast. Progress must be visible text/bars, not a spinner-only wait.
2. **Verdict header** — `.score-ring--lg` driven by `--ring-val: <riskScore>` and
   `.score-ring--<severity>`, verdict `.badge`, category `.pill`, received time, message id.
3. **Identity card** — From display name, From address, Reply-To, Return-Path (parse from
   `rawHeaders` or state it), To. Flag divergences with a `.stripe--critical`/`.badge--high` and
   a one-line reason.
4. **Auth panel** — three tiles for `auth.spf` / `auth.dkim` / `auth.dmarc`, each with the
   result badge and the `detail` string. For EM-2410 and EM-2409 the details explain why "pass"
   is not exoneration — surface that text, it is the money shot.
5. **Signal table** (the explainability core) — `signals`: name, engine, weight (`.meter`),
   status (`fired` → severity badge, `clear` → `.badge--safe`), evidence in `.mono`. Sort fired
   first, descending weight. Include a total-contribution footer row.
6. **AI explanation** — `aiExplanation` in a `.card.stripe--accent` with an "Explainable verdict"
   eyebrow. Plain paragraph, no bullet-ising.
7. **Body preview + links** — `bodyText` in a `<pre>` (via `textContent`), then for each `links`
   entry: `shown` vs `actual`, the `redirects` chain as arrow-separated steps, and a verdict
   badge. If `links` is empty (EM-2410) say so explicitly: "Zero payload — no URLs, no
   attachments", because that is the point of the BEC sample.
8. **Attachments table** — name, type, truncated sha256 (`.hash`, full value in `title`),
   verdict badge, plus a copy-hash button (toast).
9. **Raw headers** — collapsible `<details>` with a `<pre>` of `rawHeaders` and a copy button.

`onSelect`: re-render items 2-9 entirely from the new email. Reset the ingest panel's progress
state. Never leave a previous email's values on screen.

### `trace` — Origin trace & attribution
Must have:
1. **World map** (SVG, `viewBox="0 0 960 480"` or similar) drawn from `EFP_MAP.land` polygons
   with `EFP_MAP.project`: land as filled paths (`var(--surface-2)` fill,
   `var(--border-strong)` stroke), a faint lat/lon graticule in `var(--grid-line)`, then the
   selected email's `hops` as numbered markers joined in order by curved arcs
   (quadratic `Q` path; arc in `var(--accent)`). Origin hop distinct (larger, `var(--sev-critical)`
   when the verdict is not Safe) and labelled with city + country. Visible at rest — no draw-on
   animation required.
2. **Origin card** — `origin.ip`, city, country, `fmt.pct(confidence)` as a `.meter`, and
   `method` ("first external Received header") stated verbatim, plus the hop-0 `flags` as `.pill`s.
3. **Hop table** — index, host, IP (`.mono`), ASN + org, city/country, timestamp (`fmt.time`),
   delay (`fmt.ms`), TLS, flags. Highlight the first external hop with `.stripe--critical` /
   an "origin" badge and the trusted recipient hops with `.badge--safe`.
4. **Contradiction note** — one short derived line per email where it applies, e.g. "HELO claims
   mgsuniversity.ac.in; observed origin is residential broadband in Istanbul." Derive it from
   hop flags; if nothing contradicts (EM-2406, EM-2405) say the chain is internally consistent.
5. **IOC table** — `iocs`: type `.pill`, value (`.mono`, wrap long values), confidence `.meter`,
   source. Per-row copy button (toast) and an "Export IOC set (CSV)" button (toast). Empty state
   for the legitimate samples: "No indicators — sender is the domain of record."
6. **Related campaigns** — `relatedCampaigns` as cards or rows with similarity `.meter` +
   `fmt.pct`, first seen (`fmt.date`), message count, and a "Pivot to campaign" button (toast).
   Empty state for the safe samples.

`onSelect`: redraw the map, origin card, hop table, contradiction note, IOC table and campaign
list. Hop counts differ per email (3-4), so never assume a fixed number.

### `forensics` — Forensic case & evidence chain
Must have:
1. **Case header** — from `ctx.caseFor(email.id)`: case id, status `.badge`, assignee, opened at
   (`fmt.date`), linked email id and subject. If there is no case (the legitimate samples), show
   an honest empty state with an "Open case" button (toast).
2. **Investigation timeline** — `timeline` as a vertical rail: `fmt.time(t)` in `.mono` on the
   left, event text right, connected by a 1px line in `var(--border)`; each node dotted in
   `var(--brass)`.
3. **Evidence ledger table** — `evidenceLedger`: seq, item, sha256, prevHash, hash (all
   truncated `.hash` with the full value in `title`), timestamp. Chain the rows visually
   (prev → hash). The data is genuinely chained: `entry[n].prevHash === entry[n-1].hash` and
   entry 1's prevHash is 64 zeros.
4. **Verify chain** `.btn--primary` — actually walk the array in JS, compare `prevHash` to the
   previous `hash`, and report the result inline ("7 items · chain intact · genesis verified")
   plus a toast. This must be a real check, not a canned string.
5. **Blockchain anchor panel** — chain head (last `hash`), a plausible anchor line (network
   "Polygon Amoy testnet", txid = the chain head reused as a 0x-prefixed value, block height,
   anchored-at time), and an "Anchor now" button (toast). Label it as notarisation of custody,
   not storage of the email.
6. **Export / action bar** — Export forensic report (PDF), Export STIX 2.1 + CSV IOCs, Push IOCs
   to gateway blocklist, Escalate to CERT-In. All four are `.btn` + `ctx.toast(...)` with a
   specific message naming the case id.
7. **Recent cases table** — `dashboard.recentCases`: case id, linked email, status badge,
   assignee, opened at; rows clickable → `ctx.select(row.emailId)` (stay on this screen).

`onSelect`: re-render the case header, timeline, ledger, verify-result (reset it to "not yet
verified"), anchor panel and the highlighted row in recent cases.

## 8. Self-check before you finish

- [ ] File starts with `<section class="screen" id="screen-<id>" hidden aria-labelledby=…>` and
      ends with `</section>` (plus your `<style>`/`<script>`, both scoped).
- [ ] No reference to `App` or `EFP_DATA` outside `mount`/`onSelect`.
- [ ] All ids prefixed; all selectors prefixed; no globals beyond the `__screens` push.
- [ ] Every interpolated value escaped; `rawHeaders`/`bodyText` set with `textContent`.
- [ ] Switching the top-bar email selector updates everything your screen shows.
- [ ] Works for EM-2406/EM-2405 (no IOCs, no campaigns, no case) without empty holes or errors.
- [ ] Nothing hidden at rest; no external requests; no console errors.
