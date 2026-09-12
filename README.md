# PRAMAAN — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence

Prototype interface for Smart India Hackathon problem statement 26106 (AICTE Cyber Security Cell, theme Blockchain & Cybersecurity).

PRAMAAN (Sanskrit: proof, evidence) takes a suspicious email and answers four questions an investigator actually has: is it fraudulent, exactly why, where was it really injected, and can the evidence be proved later.

This repository contains the working single-page prototype, the solution proposal, a verified resource sheet, and the test suite. The prototype runs on a built-in sample dataset of seven analysed emails; no backend is required.

## Quick start

**Fastest:** open `pramaan.html` in Chrome, Edge or Firefox. No server, no install.

**With a local server** (needed only if your browser blocks clipboard access on `file://` URLs):

```bash
python -m http.server 8765
```

Then open http://localhost:8765/pramaan.html.

Requirements: any modern browser. Python 3 only if you use the server or rebuild the page. Node 18+ only for the tests.

## Who this is for, and how to use it

The console is built for three people. Each has a natural path through the same four screens.

### 1. SOC analyst (institution or bank security desk)

Goal: triage a suspicious email in under a minute and get a block list.

1. **Overview** opens first. Read the KPI strip (analysed today, malicious, suspicious, safe, average analysis time, open cases) and the 14-day chart. A shaded column marks a spike day.
2. Scroll to **Triage queue**. Each row is an analysed email with sender, subject, category, score ring and verdict badge. Click a row: it becomes the email under investigation and you land on Analyze.
3. On **Analyze**, read the verdict block: the score ring, the Malicious / Suspicious / Safe badge and the category. The **AI analyst narrative** is the paragraph you paste into a ticket.
4. Check the three authentication tiles (SPF, DKIM, DMARC). Fail or none is highlighted.
5. The **Signal table** is the explanation. Every point of the score is a row: signal name, engine that fired it, weight, fired or clear, and the evidence string.
6. Under **Body preview & links**, compare the shown link text against the actual destination and the redirect chain.
7. Use the action buttons at the top of the verdict block: **Block sender** and **Report to CERT-In** confirm with a toast; **Trace origin** and **Open case** move you to the next screens.

To analyse a new email: click **Analyse new email** in the top bar. On Analyze, choose the ingest source (paste raw source, upload .eml), paste the "Show original" text from any mail client into the text area, and press **Run analysis**. The staged progress (parse, authenticate, NLP, threat intel, score) then reveals the verdict. In the prototype the verdict shown is that of the currently selected sample.

### 2. CERT or cyber-cell forensic investigator

Goal: attribution and defensible evidence.

1. Pick the email under investigation from the selector in the top bar, or click it in the Overview triage queue.
2. Go to **Trace**. The map draws the injection-to-delivery route. Numbered markers are hops; the red marker is the probable origin.
3. The **Probable origin** card gives IP, city, country, confidence and the method (first external Received header). Read the "what this does not prove" caveat before writing it into a report.
4. The **Hop-by-hop stepper** lists every relay in transfer order: host, IP, ASN and organisation, city, timestamp, delay since the previous hop, TLS, and flags. Anomalies (missing TLS, HELO mismatch, timestamp skew, open relay) are highlighted. Hover a row to highlight its lines in the **Raw Received headers** panel below.
5. The **IOC table** lists domains, URLs, IPs and addresses with confidence and source. **Copy** puts one on the clipboard; **Export IOC set (CSV)** exports the set.
6. **Related campaigns** shows prior clusters that share infrastructure, with a similarity percentage. Pivot to campaign opens that cluster.
7. Go to **Forensics**. The case header shows case id, status, assignee and opened time. The **Investigation timeline** is the typed event log.
8. The **Evidence ledger** lists every artefact with its SHA-256 and chained hash. Press **Verify chain** to walk the chain; the result line reports intact or the first broken sequence number.
9. **Anchor to blockchain** notarises the chain head on a public testnet and shows the transaction id. Only hashes leave the system; the email itself is never written on-chain.
10. Use the **Export & action bar**: PDF report, JSON bundle, STIX 2.1 + CSV IOCs, push IOCs to the gateway blocklist, escalate to CERT-In.

### 3. Institution IT admin

Goal: posture and coverage.

1. **Overview** is the daily view. The **Category breakdown** shows which fraud types are hitting the institution; **Top origin countries** shows where injections come from.
2. **Engine health** in the sidebar and at the bottom of Overview shows each detection engine's status and latency.
3. **Recent cases** shows what is open and who owns it. Case file opens the case on Forensics.
4. Switch the email selector to the two Safe samples (NIC maintenance notice, AICTE handbook) to see what a clean verdict looks like: DMARC aligned, only low-weight signals, low score.

## Sample emails included

| ID | Category | Verdict | Demonstrates |
|---|---|---|---|
| EM-2411 | Credential phishing | Malicious 94 | Lookalike domain aicte-gov.in, SPF fail, redirect chain, credential-harvest page, Amsterdam VPS origin |
| EM-2410 | BEC / CEO fraud | Malicious 88 | Display-name spoof of the Vice-Chancellor, zero payload, wire-transfer intent |
| EM-2409 | Invoice fraud | Suspicious 79 | Bank-detail change request, lookalike vendor TLD, PDF with embedded action |
| EM-2408 | Malware delivery | Malicious 91 | Macro-enabled .xlsm attachment, payload URL in redirect chain, hash IOCs |
| EM-2407 | Lookalike domain | Malicious 85 | Homoglyph domain impersonating the education ministry |
| EM-2406 | Legitimate | Safe 6 | Clean authenticated bulk notice |
| EM-2405 | Legitimate | Safe 18 | Real AICTE mail, DMARC aligned |

## Suggested 3-minute demo

1. Overview: point at the KPIs and the spike day in the chart.
2. Click the AICTE credential-phishing row. Score 94. Read the SPF fail, the DMARC misalignment, and the six-day-old lookalike domain in the signal table. Expose the link: shown as aicte-india.org, actually a .top harvest page after two redirects.
3. Trace: the mail claims Delhi; the first external hop is a VPS in Amsterdam, relayed via Frankfurt, delivered in Mumbai. Confidence 82 percent. Related campaigns show an 87 percent match to a cluster that hit two other universities.
4. Switch the selector to the BEC sample: no link, no attachment, still 88 on intent and identity signals.
5. Forensics: Verify chain, anchor, export the report.

## Project layout

```
pramaan.html            the interface, standalone (open this)
assemble.py             builds pramaan.html from spec/ + sections/
spec/
  blueprint.md          solution blueprint: modules, architecture, stack, MVP scope
  conventions.md        contract each screen was built against
  tokens.css            design tokens and shared component classes
  data.js               sample dataset (7 emails, dashboard, map basemap)
  shell.html            app frame, navigation, App core
sections/
  overview.html         Overview screen
  analyze.html          Analyze screen
  trace.html            Trace and geolocation screen
  forensics.html        Forensics and case screen
docs/
  solution.md           the solution proposal: what can be built, in 14 sections
  resources.md          verified datasets, libraries, APIs, CERT-In reporting links
  audit.md              code audit and test report
test/
  smoke.js              headless-Chrome smoke test
  harness.js            shared boot layer for the screen tests
  *.test.js             one test per screen
```

## Editing and rebuilding

The page is assembled from parts. Edit a file under `spec/` or `sections/`, then rebuild:

```bash
python assemble.py
```

This rewrites `pramaan.html`. Each screen is a `<section>` plus its own script that registers with the App core; see `spec/conventions.md` for the rules a new screen must follow. Sample data lives in `spec/data.js`; add an email object there and it appears in the selector and every screen.

## Running the tests

Requires Node 18+ and Google Chrome installed (the tests drive the installed Chrome headlessly through `playwright-core`).

```bash
cd test && npm install && cd ..
```

```bash
python assemble.py && node test/smoke.js
```

```bash
node test/overview.test.js && node test/analyze.test.js && node test/trace.test.js && node test/forensics.test.js
```

The smoke test boots the page, pushes all seven emails through all four screens, clicks every button, and checks routing, the selector and that no "undefined" or "NaN" leaks into the UI. Each screen test asserts the rendered DOM against the dataset.

## What is real and what is mocked

The interface, navigation, data flow, chart drawing, map projection, hash-chain walk and every screen interaction are real code. The detection engines, geolocation lookups, threat-intel enrichment, sandbox, blockchain transaction and exports are represented by the sample dataset and confirmation toasts. `docs/solution.md` describes the backend that replaces them, and `docs/resources.md` lists the libraries, datasets and APIs to build it with.
