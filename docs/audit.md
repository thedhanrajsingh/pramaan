# PRAMAAN prototype — Ponytail audit and test report

Date: 13 Sep 2026. Scope: over-engineering and unnecessary complexity only (correctness, security and performance were handled by the build reviewers and the test phase, not by this audit).

## Method

1. **Audit** (ponytail-audit, repo-wide; ponytail-review, per file): seven Opus auditors, one per file group, each grepping every consumer before flagging anything as dead. Findings ranked biggest cut first with the tags `delete:` `stdlib:` `native:` `yagni:` `shrink:`.
2. **Triage** by the head: findings rejected where they would remove a demo feature, change the visual design, or drop a data-contract field a real backend would emit.
3. **Apply**: seven Sonnet workers, one per file, each gated by the headless-Chrome smoke test and, where present, the screen test.
4. **Test phase**: smoke test (boot, every email through every screen, every button, routing, selector, painted background) plus one Playwright screen test per screen asserting the DOM against the live dataset.

## Result

| File | Before | After | Cut | Notes |
|---|---|---|---|---|
| spec/shell.html | 411 | 369 | 42 | no-screens fallback, 1-4 hotkeys, hand-rolled finds, month table, register() validation, replaceState try/catch, JS truncation → CSS ellipsis |
| spec/tokens.css | 434 | 393 | 41 | dead `.tooltip-ish`, `.kbd`, `.right`, `.trunc`, `.card--sunk`, `.table--fixed`, `hr`, duplicated mono rule, restated heading rule |
| spec/data.js | 901 | 894 | 7 | FNV+xorshift fake-digest → 3-line LCG, `'0'.repeat(64)`, two self-referential redirect arrays |
| sections/overview.html | 485 | 451 | 34 | badge if-chains → lookups, tighter axis rounding, scoped flex rules → shared `row`/`grow`, merged duplicate classes, dead guards and ids |
| sections/analyze.html | 606 | 539 | 67 | duplicate sample picker, single-caller helpers inlined, switch → lookup, dead fallbacks for header fields every sample carries |
| sections/trace.html | 666 | 610 | 56 | 33-line Received-block matcher → 9 lines, basemap fallback, private-IP branch, duplicate export button, per-row listeners → delegation, redundant origin rows |
| sections/forensics.html | 506 | 493 | 13 | computeAnchor inlined, redundant genesis check, three rebind loops → delegation, scroll button → anchor link, trunc guards |
| test/smoke.js | 143 | 128 | 15 | now boots through harness.js; dropped report.json, font collection, argv override, double-reported errors |
| assemble.py | 10 | 10 | 0 | unused import removed |
| **Total** | **4162** | **3887** | **275** | |

Net: -275 lines, 0 dependencies removed (none were removable: playwright-core is the test runner, the page itself has none).

## Findings rejected by the head, and why

- **harness.js "dead"** — it is the boot layer for the four screen tests written in the test phase; smoke.js was made to reuse it instead.
- **`@media (max-width:900px)` reflow in the shell** — the published page opens at any width; the rule is 8 lines and earns its place.
- **Lookalike comparison + character diff on Analyze** — in the brief and the most demo-worthy moment on the screen.
- **Six-across KPI row** — the alternative wraps 3+3 and reads worse.
- **`.grid-3` → auto-fit** — changes column counts at wide widths.
- **Custom select chevron → browser default** — the dark theme would get an unmatched UA arrow.
- **Origin object fields on each email** — they mirror what the tracing API would return; the screen reading `hops[0]` instead would couple UI to one derivation.
- **Severity class variants flagged as unused** — they are built dynamically (`'badge--' + sev`); the apply worker re-grepped and kept them.

## Fixes found by the test phase

- `en-GB` date formatting rendered "Sept"; switched to en-US parts reordered to day-month-year so "Sep" stays three letters.
- Clipboard guard on the copy buttons had to stay: `navigator.clipboard` is undefined when the page is opened from a local file.
- Body background line the audit called redundant is what paints the page over the host ground; restored.
- Trace hop table overflowed its card by the flags column; origin badge moved under the host name and the flags column given a min-width instead of a fixed width.

## Test status at publish

| Test | Result |
|---|---|
| test/smoke.js | PASS (4 screens, 7 emails, all buttons, hash routing, selector, painted body) |
| test/overview.test.js | PASS |
| test/analyze.test.js | PASS (7 emails, staged run, action buttons) |
| test/trace.test.js | PASS (7 emails, map, stepper, hover highlight, IOC export) |
| test/forensics.test.js | PASS (7 emails, verify chain, anchor, five exports) |

Run everything:

```
python assemble.py && node test/smoke.js && for t in overview analyze trace forensics; do node test/$t.test.js; done
```
