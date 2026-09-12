# PRAMAAN — solution blueprint

SIH PS 26106 · AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
AICTE Cyber Security Cell · Category: Software · Theme: Blockchain & Cybersecurity

## (a) Reading of the problem

The problem is not "detect spam" — filters already do that, as a binary gate with no explanation
and no memory. PS 26106 describes the two failures that happen *after* the filter:

1. **The convincing minority.** Lookalike domains, display-name spoofing, AI-written prose with
   no grammar tells, hidden redirect chains, and BEC mails carrying no link and no attachment.
   These have no signature, so signature systems miss them.
2. **Attribution and investigation.** When an institution does catch a fraudulent mail, it
   cannot answer what an FIR or a CERT-In report asks: which machine injected this message,
   through which relays, in what country, on whose ASN, is this last month's infrastructure, and
   will the evidence survive being challenged.

Three users, three needs from the same analysis:

- **SOC analyst (institution / bank NOC).** Triage speed: a verdict, a reason she can paste into
  a ticket, and a block list (domain, URL, IP, file hash) inside a minute.
- **CERT / cyber-cell forensic investigator.** Attribution and defensibility: the hop chain,
  geo and ASN correlation, campaign linkage, chain of custody, an export that holds up as a
  report annexure.
- **Institution IT admin (AICTE / state university / ministry desk).** Coverage and posture: a
  connector to the real mailbox, weekly counts, which of his domains are being impersonated, and
  a one-click CERT-In package.

## (b) The product

**PRAMAAN** — *Sanskrit: proof, evidence.*

> **Drop in an email and PRAMAAN tells you whether it is fraudulent, exactly why, where on
> earth it was really injected, and hands you tamper-evident evidence for the case file.**

## (c) Modules and pipeline

**1. Ingest.** (i) `.eml` / `.msg` drag-and-drop; (ii) paste raw source — the "Show original"
text every mail client exposes, a zero-friction path for any victim; (iii) IMAP / Gmail OAuth
connector polling a quarantine or `abuse@` mailbox; (iv) `POST /v1/analyse` plus webhooks for
SIEM and gateways. Every ingest is stored as an immutable blob and SHA-256'd on arrival — that
hash is evidence item #1.

**2. Parser.** RFC 5322 header split preserving duplicate and malformed headers (themselves
signals), MIME tree walk, charset and transfer-encoding normalisation, URL extraction from text
+ HTML + `meta refresh` + inline SVG/JS, attachment extraction with type sniffing by magic bytes
rather than extension, and a full `Received:` chain parse into ordered hops with timestamps and
inter-hop delays.

**3. Detection engines** — each emits independent scored signals carrying an evidence string:

- **Authentication.** SPF re-evaluated against the envelope `Return-Path` and the first external
  hop IP, DKIM verification with selector lookup, DMARC policy *and alignment*. The nuance we
  surface: attacker-owned domains frequently pass SPF/DKIM on their *own* domain — alignment
  against the *displayed* brand is what fails.
- **Header anomaly.** `From` vs `Reply-To` vs `Return-Path` divergence, `Message-ID` domain
  mismatch, missing or forged `Received` lines, impossible timestamp ordering, bulk-sender
  `X-Mailer` fingerprints, thread-hijack markers (`In-Reply-To` with no local history).
- **Lookalike / homoglyph domain.** Public-Suffix-List registrable-domain extraction, then
  Damerau–Levenshtein plus visual-skeleton folding (`rn→m`, `l→i`, `0→o`, Cyrillic and
  Devanagari homoglyphs), punycode expansion, keyword-permutation matching (`aicte-gov.in`
  against the real `aicte-india.org`), and RDAP domain age — a six-day-old domain impersonating a
  regulator is near-decisive.
- **Display-name spoofing.** Display name asserts a protected brand or role ("Vice-Chancellor",
  "AICTE", "NIC") while the address domain sits outside that entity's allow-list.
- **URL / redirect chain unwrapping.** Headless follow of shorteners and open redirectors to the
  terminal landing page, screenshot, favicon and DOM similarity against the impersonated brand's
  real login page (credential-harvest detection), IDN check at every hop.
- **Attachment analysis.** SHA-256 and ssdeep, OOXML macro and DDE inspection, PDF
  `/OpenAction` and `/JS` scan, archive recursion, plus CAPE/Cuckoo sandbox hooks for dynamic
  detonation (queued, never blocking the verdict).
- **NLP intent classifier.** Fine-tuned transformer (DeBERTa-v3, IndicBERT for Hinglish-mixed
  corpora) producing multi-label intent: credential request, payment or wire redirection,
  urgency-and-authority pressure, secrecy instruction, invoice change, gift-card ask. This is
  the engine that catches the zero-payload BEC.
- **AI-generated-text signal.** Perplexity and burstiness profile plus a detector head, used
  only as a supporting weight and never decisive alone — honest senders use AI too.
- **Threat-intel enrichment.** VirusTotal, URLhaus, AbuseIPDB, Spamhaus DBL, OpenPhish, and our
  own corpus of prior campaigns.

**4. Explainable risk scoring.** Engines vote; a gradient-boosted meta-model over roughly sixty
features returns 0–100 with per-signal contributions (SHAP-style). The UI never shows a bare
number — it shows which signals fired, their weight, and the evidence substring. Hard rules can
override: DMARC-aligned mail from an allow-listed government domain is capped low.

**5. Hop-by-hop trace.** `Received` chain normalised bottom-up; the **first external hop** is
marked probable origin. Declared `HELO` names are labelled untrusted; only observed IPs feed
geolocation. Per-hop delay exposes relay dwell time and inserted or forged header lines.

**6. Geo / ASN correlation.** MaxMind GeoLite2 City + ASN offline databases as the primary
source (no data leaves the deployment), ipinfo as an online enricher; reverse DNS, hosting-type
classification (residential / mobile / datacentre VPS / Tor exit / bulletproof host), and a
contradiction flag when observed country conflicts with the claimed sender country.

**7. Infrastructure clustering.** Each mail becomes a fingerprint vector — ASN set, HELO and TLS
pattern, registrar and domain-creation window, URL path template, subject and body embeddings,
attachment fuzzy hashes. Nearest-neighbour search over stored cases links it to prior campaigns
with a similarity score. This is how "one phishing mail" becomes "a 41-mail campaign against
three universities".

**8. Forensic case management.** Case ID, assignee, status, linked emails, consolidated IOC set,
analyst notes, action log.

**9. Tamper-evident evidence ledger.** Every artefact (raw `.eml`, parsed headers, each engine
verdict, landing-page screenshot, analyst note) is hashed and appended to a per-case hash chain:
`hash_n = SHA256(prev_hash || sha256(item) || timestamp)`. The chain head is anchored externally
— a Hyperledger Fabric ordering service on-premise, or a Polygon Amoy testnet transaction in the
hackathon build — giving independent timestamp proof that the evidence set was not edited after
the fact. That is the honest use of the blockchain theme: notarising custody, not storing mail
on-chain.

**10. Report export.** PDF/DOCX forensic report (verdict, signals, hops, map, IOCs, ledger with
anchor txid), STIX 2.1 bundle and CSV IOC feed for gateway blocking, and a pre-filled CERT-In
incident-report template.

## (d) Architecture and stack

```
mail clients / abuse@ mailbox / gateway
    | .eml · paste · IMAP-Gmail OAuth · REST
    v
Next.js 14 + React console  -->  FastAPI gateway (JWT, RBAC: analyst / investigator / admin)
                                      |
                                Redis Streams queue
                                      v
                        Celery worker pool — engine fan-out
  parser · auth(SPF/DKIM/DMARC) · header-anomaly · lookalike · URL-unwrap(Playwright)
  attachment+sandbox · NLP transformer (TorchServe) · LightGBM meta-scorer · TI enrichment
                                      |
  Postgres (cases, emails, signals, hops, IOCs, ledger) · pgvector (campaign similarity)
  MinIO/S3 (raw .eml, screenshots) · MaxMind GeoLite2 (local) · ledger anchor client
```

Python 3.11 engines (`dkimpy`, `authres`, `publicsuffix2`, `tldextract`, `maxminddb`), PyTorch +
HuggingFace for the classifier, LightGBM for the meta-scorer, Playwright for redirect
unwrapping, Docker Compose for the whole stack. Offline-first: geo DB, PSL and models ship
locally so a campus deployment works with no egress; threat-intel lookups are opt-in per API key.

## (e) MVP for 36 hours vs full scope

**MVP, demoed end to end:** `.eml` upload + raw paste + seven pre-loaded samples; full parser;
SPF/DKIM/DMARC via libraries; header-anomaly, lookalike/homoglyph, display-name and URL-chain
engines; NLP intent classifier fine-tuned on Nazario + CLAIR phishing + Enron ham plus ~2k
synthetic Indian-context BEC mails; transparent weighted score; hop parse with MaxMind geo and
the world-map trace; campaign similarity over the seeded corpus; case creation; hash-chained
ledger with one testnet anchor; PDF export.

**Full scope:** live IMAP/Graph connectors and inline gateway mode, real sandbox detonation,
RDAP and certificate-transparency monitoring for newly registered lookalikes of *your* domain,
analyst-feedback retraining, multi-tenant onboarding, Indic-language NLP, automated CERT-In
filing, mobile triage app.

## (f) Interface spec — four screens

1. **Overview** — the SOC console. KPI strip (analysed today, malicious, suspicious, safe, mean
   analysis time, open cases); 14-day stacked severity chart; category breakdown; top origin
   countries; engine-health rail; triage table of all seven emails (time, sender, subject,
   category, score, verdict). Clicking a row selects that email globally and routes to Analyze.
2. **Analyze** — the verdict sheet. Ingest panel (drop zone, paste raw source, "Run analysis"
   with staged progress); identity card comparing From / Reply-To / Return-Path with mismatch
   stripes; SPF / DKIM / DMARC panel with detail lines; score ring plus verdict; the **signal
   table** (name, engine, weight, fired or clear, evidence) which is the explainability core;
   the AI explanation in plain investigator language; body preview with the deceptive link
   exposed as shown-vs-actual plus redirect chain; attachment table with hashes; collapsible
   raw-header viewer.
3. **Trace** — attribution. Hand-drawn SVG world map from `EFP_MAP.land` with hop markers, arcs
   in hop order and a marked origin; hop table (index, host, IP, ASN and org, city and country,
   timestamp, delay, TLS, flags); origin card (IP, city, country, confidence, method); IOC table
   with copy actions; related-campaign list with similarity bars.
4. **Forensics** — case and custody. Case header (case ID, status, assignee, opened at);
   investigation timeline; evidence ledger table (seq, item, SHA-256, prev hash, chained hash,
   timestamp) with a verify-chain action that walks the chain and reports intact; blockchain
   anchor panel (chain head, txid, block height, "Anchor now"); action bar — export PDF report,
   export STIX/CSV IOCs, push IOCs to the gateway blocklist, escalate to CERT-In — each
   toast-confirmed; recent-cases table.

## (g) Three-minute demo flow

0:00 **Overview.** "1,284 mails analysed today, 37 malicious, 6 open cases." Point to the spike
three days ago in the 14-day chart.
0:25 **Click the AICTE credential-phishing row → Analyze.** Score 94. "SPF fail, DMARC
unaligned, and the sender domain `aicte-gov.in` is a six-day-old lookalike of the real
`aicte-india.org`." Scroll the signal table: every point of the 94 is accounted for.
1:00 Expose the link — the mail displays `aicte-india.org/verify`; the real destination is a
`.top` credential-harvest page after two redirects.
1:20 **Trace.** "The mail claims Delhi. The first external `Received` hop is a VPS in Amsterdam,
relayed via Frankfurt, delivered to the university MX in Mumbai." The map draws the path;
origin confidence 0.82.
1:50 Related campaigns: 87% similarity to a cluster that hit two other universities — same ASN,
same URL template. One mail just became a campaign.
2:10 **Switch the selector to the BEC sample.** No link, no attachment, passes every filter; NLP
intent is wire-transfer redirection plus authority pressure, display-name spoof of the
Vice-Chancellor, score 88.
2:30 **Forensics.** Verify chain — "8 items, chain intact", anchored at block 54,118,902. Export
the report. "That is what an investigator can actually file."
2:50 Close on the pitch line.

## (h) Why this beats a spam filter

A spam filter answers *deliver or not*, with a probability it will not explain, tuned for the
bulk case, blind to one hand-written mail to one CFO, and it keeps no evidence. PRAMAAN answers
four different questions: **is it fraudulent, why exactly, who and where is behind it, and can I
prove it later.** Concretely: (1) it scores the *relationship* between displayed identity and
cryptographic identity, so an attacker's own perfectly authenticated domain becomes a red flag
rather than a pass; (2) it classifies intent instead of vocabulary, catching zero-payload BEC and
AI-polished prose; (3) it unwraps redirects instead of trusting anchor text; (4) it turns headers
into geolocated infrastructure and clusters it across incidents, converting isolated reports into
campaign attribution; and (5) it emits a hash-chained, externally anchored evidence trail, which
no mail gateway produces. Filters protect the inbox. PRAMAAN closes the case.
