# PRAMAAN — solution proposal
### SIH PS 26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
AICTE Cyber Security Cell · Category: Software · Theme: Blockchain & Cybersecurity

## 1. The gap

Email defence is a binary gate — pass or block, no explanation, no memory, tuned for bulk spam and blind to the convincing minority: lookalike domains, display-name spoofing, AI-written prose with no grammar tells, hidden redirect chains, zero-payload business email compromise. Attackers routinely pass SPF, DKIM and DMARC on infrastructure they own, because each binds a different domain and none binds the identity a reader sees: SPF authorises the connecting IP for the envelope `MAIL FROM` domain, DKIM proves a signature by the `d=` domain it names, and DMARC asks only that one of those identifiers *align* with the `From` header domain. Register a domain, publish the records, and all three pass — for that domain, never for the brand the reader believes sent the mail.

The second failure is downstream: an institution that catches a fraudulent mail cannot answer what a CERT-In report or an FIR asks — which machine injected it, through which relays, in what country, on whose ASN, and whether the evidence survives a challenge. It is left with a spam folder, not a case file.

Three users need three artefacts from one analysis. The **SOC analyst**: a verdict, a pasteable reason, a block list inside a minute. The **cyber-cell investigator**: hop chain, geo and ASN correlation, campaign linkage, custody that holds as an annexure. The **IT admin**: a mailbox connector, posture counts, a CERT-In package.

## 2. What we build

**PRAMAAN** (Sanskrit: proof, evidence) — drop in an email and it tells you whether the mail is fraudulent, exactly why, where on earth it was really injected, and hands you tamper-evident evidence for the case file.

Ten modules (Section 3) surface as four screens:

- **Overview** — SOC console: verdict volumes, 14-day severity trend, category breakdown, top origin countries, engine health, triage table routing into Analyze.
- **Analyze** — verdict sheet: ingest panel, identity-mismatch card, SPF/DKIM/DMARC detail, score ring over the signal table (the explainability core), plain-language explanation, shown-vs-actual links, attachment hashes, raw headers.
- **Trace** — attribution: world map with hop arcs to the marked origin, hop table (ASN, geo, delay, TLS, flags), origin confidence, IOCs, campaign similarity.
- **Forensics** — custody: case timeline, hash-chained ledger, anchor panel, exports.

## 3. How an email flows through the system

1. **Ingest** — `.eml`/`.msg` upload, raw paste of "Show original" text, IMAP/Gmail-OAuth poll of an `abuse@` mailbox, or `POST /v1/analyse`; stored as an immutable blob and SHA-256'd — evidence item #1.
2. **Parse** — RFC 5322 header split keeping duplicate and malformed headers (themselves signals), MIME walk, URL extraction, attachment typing by magic bytes, `Received:` stack into hops.
3. **Detection fan-out** — nine engines score in parallel, each signal carrying its evidence string.
4. **Risk scoring** — meta-model to a 0–100 score with hard-rule overrides.
5. **Hop trace** — outward to the trust boundary; the IP the last trusted relay observed is the probable injection point.
6. **Geo/ASN correlation** — the tenth engine, runnable only once hops exist.
7. **Clustering** — a fingerprint (ASN set, HELO/TLS pattern, domain-creation window, URL template, body embeddings, attachment fuzzy hashes) matched against stored cases via pgvector.
8–10. **Case, ledger, export** — email, IOCs and action log under a Case ID; every artefact hashed into a per-case chain whose head is anchored externally; out come a PDF/DOCX report, STIX 2.1 bundle, CSV IOC feed and pre-filled CERT-In template.

## 4. Detection engines

Each emits scored signals with an evidence string.

| Engine | Technique | Evasion defeated |
|---|---|---|
| Authentication | SPF on envelope `MAIL FROM` + connecting IP; DKIM verify by selector; DMARC alignment with the `From` domain | Own-domain pass: alignment binds a domain, not a display name |
| Header anomaly | From/Reply-To/Return-Path/Message-ID divergence, impossible timestamps, thread-hijack markers | Replies routed away from the claimed sender |
| Lookalike domain | PSL registrable domain, Damerau–Levenshtein + skeleton folding, punycode, RDAP age | Combosquats (`aicte-gov.in` vs `aicte-india.org`), homoglyphs, IDN |
| Display-name spoof | Display name vs brand/role allow-list | Impersonation from an authenticated address |
| URL/redirect unwrap | Headless follow to terminal page, DOM and favicon similarity | Deception behind shorteners and open redirectors |
| Attachment analysis | SHA-256 + ssdeep, macro/DDE, PDF `/OpenAction`, queued sandbox | Droppers a static signature misses |
| NLP intent | DeBERTa-v3, IndicBERT for Hinglish; credential/wire/urgency/secrecy labels | Zero-payload BEC |
| AI-text signal | Perplexity, burstiness, detector head — never decisive alone | Lures that defeat "typo" heuristics |
| Threat intel | VirusTotal, URLhaus, AbuseIPDB, Spamhaus, OpenPhish, own corpus | Reused infrastructure one institution cannot correlate |
| Geo correlation | Observed origin vs claimed country and declared `HELO` | Header claims text analysis cannot test |

## 5. Explainable risk scoring

Every engine emits `{name, engine, weight, status: fired|clear, evidence}`. A LightGBM meta-model over roughly sixty such features returns a 0–100 score with SHAP-style per-signal contributions, and the UI never shows the bare number: the signal table under the score ring lists every signal, its weight and its evidence substring, so a verdict can justify itself to a reviewer who never ran the tool. Hard rules override the model — DMARC-aligned mail from an allow-listed government domain is capped low.

Authentication results are read from the delivery-time `Authentication-Results` header via `authres`. Live re-evaluation — SPF for the `Return-Path` sender against the boundary-observed IP, DKIM against the selector in the signature — is only a cross-check, since records and keys may have changed since delivery; a disagreement is its own signal, not an overwrite.

EM-2411 (94) is led by lookalike domain (22), SPF hard fail (18), DMARC alignment failure (16) and deceptive URL anchor (14). EM-2410 (88) inverts it: `spf=pass`, `dkim=pass`, `dmarc=pass` — all correct, all for `secure-mailbox.icu`, the attacker's own nine-day-old domain in the `From` header. Alignment there says nothing about the impersonated `mgsuniversity.ac.in` or the display name "Dr. Rajeev Menon | Vice-Chancellor", so the top weights become display-name impersonation (24) and wire-transfer intent (22). The score reasons about identity, not protocol compliance.

## 6. Source tracing and geolocation

Each relay *prepends* its own `Received:` line, so the stack reads newest at the top and earliest at the bottom — and only lines written by infrastructure we trust are evidence. Below the trust boundary the sender fabricates freely, so the bottom-most line is the earliest but not the most trustworthy. PRAMAAN reads downward from the recipient's mailstore through trusted hops, stops at the boundary MX, and takes the IP that relay *observed* connecting to it: the **first external hop** (EM-2411: `185.62.190.24`, a Host Sailor VPS in Amsterdam), marked probable injection point, lower lines shown but flagged unverified. Declared `HELO` names are untrusted at any depth — EM-2411's hop 0 announces `aicte-portal-secure` with no matching PTR.

Each observed hop IP resolves against **MaxMind GeoLite2** City and ASN offline (**ipinfo** an optional cross-check), with reverse DNS and hosting-type classification: residential, mobile, VPS, Tor exit, bulletproof host.

**What geolocation can and cannot prove is stated, not hidden.** It shows which network and ASN handled the message, at city level at best — free databases run tens to hundreds of kilometres off, and datacentre and mobile ranges often reflect registration, not location. It never shows a person was there: a VPN exit, a compromised host or a commercial relay all geolocate accurately to a machine that is not the attacker's. **Confidence** (0.82 for EM-2411, 0.74 for EM-2410) reflects hop distance to the trusted MX, hosting-type fit, DNS agreement and ASN abuse history — never a claim about a human. Reports label geo an investigative lead needing subscriber records, not court-grade attribution.

## 7. Forensic intelligence

**Case management** gives a Tier-2 analyst inherited context, not a re-derivation: status, assignee, timeline, consolidated IOCs. **IOC extraction** pulls typed indicators — domain, URL, IPv4, SHA-256, email, bank/IFSC pairs — with confidence and source. **Campaign clustering** turns isolated reports into attribution: EM-2411 matches a 41-mail campaign at 87%. **Exports**: PDF/DOCX report, STIX 2.1 bundle, CSV IOC feed, CERT-In template.

The **evidence ledger** is the forensic spine. Every artefact — raw `.eml`, parsed headers, engine verdicts, screenshot, analyst notes — is hashed on creation into a per-case chain: `hash_n = SHA256(prev_hash || sha256(item) || timestamp)`. Each hash depends on every prior entry, so later editing or reordering breaks it; "verify chain" recomputes the links back to genesis (EM-2411: "8 items, chain intact").

Anchoring that head externally proves something narrow: it existed no later than the block carrying it, so the set cannot be back-dated or silently edited afterwards. It does not attest that the artefacts were genuine or that nothing was dropped before anchoring — hashing at creation and RBAC-logged access carry that. Permissioned Hyperledger Fabric suits a ministry deployment; a public chain (Polygon Amoy testnet here, OpenTimestamps in production) buys independence from us. Either way **only hashes go on-chain, never mail content**: the honest use of the blockchain theme is notarising *custody*.

## 8. Architecture and tech stack

```
mailbox/gateway/client -- .eml · paste · IMAP-OAuth · REST -->
Next.js 14 console --> FastAPI gateway (JWT, RBAC) --> Redis Streams
  --> Celery workers: parser · auth · header-anomaly · lookalike · URL-unwrap
      (Playwright) · attachment+sandbox · NLP (TorchServe) · LightGBM scorer
      · TI enrichment · geo correlation
  --> Postgres+pgvector (cases/signals/hops/IOCs/ledger) · MinIO/S3 (blobs)
      · MaxMind GeoLite2 (local) · anchor client
```

**FastAPI** with JWT and RBAC separates analyst, investigator and admin, so custody records who touched a case. **Redis Streams + Celery** keep engines independent, so a slow sandbox never blocks a verdict. The **Python 3.11** engines lean on mature libraries rather than reinvented protocol code: `dkimpy`, `pyspf`, `authres`, `publicsuffix2`, `tldextract`, `maxminddb`, `mail-parser`. **LightGBM** meta-scores because explainability needs interpretable weights. **Docker Compose** ships the stack on-premise with geo database, PSL and models local.

## 9. Data and training plan

**Corpora.** Malicious: Nazario and the CLAIR fraud corpus plus live feeds (OpenPhish, URLhaus, PhishTank). Benign: Enron for corporate style, SpamAssassin ham and TREC 2007 for real headers. No verified public Indian institutional phishing corpus exists — a gap the pitch names — so the MVP adds ~2,000 synthetic Indian-context mails (AICTE, GST, UPI, university finance).

**Augmentation.** Attackers write AI-polished lures, so the set adds LLM-generated phishing and BEC text in the same intent categories: the classifier learns *intent structure*, not the stylistic tells AI writing erases. The AI-text detector trains as a separate, non-decisive signal — detectors are unreliable on short or edited text, and honest senders use AI too.

**Evaluation.** Per-class precision and recall (malicious recall weighted highest), ROC-AUC and PR-AUC for the meta-scorer, and a tracked false-positive rate on legitimate government mail. Malicious mail is a small minority, so training uses class-weighted loss, not naive oversampling; threat intel refreshes continuously, weights retrain from labelled cases.

## 10. MVP scope vs roadmap

**MVP, demoed end to end:** `.eml` upload, raw paste, seven pre-loaded samples; full RFC 5322/MIME parser; SPF/DKIM/DMARC via `dkimpy`/`pyspf`/`authres`; the header-anomaly, lookalike, display-name, URL-chain and geo-correlation engines; the NLP classifier fine-tuned on Nazario + CLAIR + Enron plus the synthetic set; transparent scoring; hop parse with MaxMind geo and the world-map trace; campaign similarity; case creation; hash-chained ledger with one testnet anchor; PDF export.

**Roadmap:** live IMAP/Graph connectors and inline gateway mode; real sandbox detonation; RDAP and certificate-transparency watch for lookalikes of an institution's own domain; analyst-feedback retraining; multi-tenant onboarding; automated CERT-In filing.

## 11. Security, privacy and ethics

**PII and on-prem.** Analysed mail carries personal data. Raw blobs and extracted entities stay inside the institution's deployment, gated by RBAC. Threat-intel enrichment and online geo lookup are the only outward calls and both are optional, so a campus or PSU bank can run PRAMAAN with zero egress.

**Human in the loop.** PRAMAAN classifies and evidences; it never quarantines mail on its own verdict. Pushing IOCs to a blocklist or escalating to CERT-In is an explicit analyst action.

**False positives.** The Suspicious tier exists for cases like EM-2409, where a lookalike domain and a bank-mandate change appear but the payload could be innocent: the explanation recommends a call to the vendor of record, not a block. Every verdict is analyst-reversible and logged.

## 12. Demo script (3 minutes)

**0:00 Overview.** "1,284 mails analysed today, 37 malicious, 6 open cases." Point to the spike three days ago.
**0:25 AICTE row → Analyze.** Score 94: SPF fail, DMARC unaligned, `aicte-gov.in` a six-day-old lookalike of `aicte-india.org`. Scroll the signal table — every point is accounted for.
**1:00 The link** — shown as `aicte-india.org/approval/verify`, actually a `.top` harvest page after two redirects.
**1:20 Trace.** First external hop a VPS in Amsterdam, relayed via Frankfurt to the MX in Mumbai; confidence 0.82, VPN caveat stated aloud.
**1:50 Related campaigns** — 87% similarity to a cluster on the same ASN.
**2:10 BEC sample.** No link, no attachment, SPF/DKIM/DMARC all pass on the attacker's own domain; wire-transfer intent, Vice-Chancellor display-name spoof, score 88.
**2:30 Forensics.** Verify chain — "8 items, chain intact," anchored at block 54,118,902. Export.
**2:50 Close** on the pitch line.

## 13. Judging alignment

**Innovation** — scores the *relationship* between displayed and cryptographic identity, so a well-authenticated attacker domain reads as a red flag; classifies intent, not vocabulary; anchors custody rather than putting mail on a blockchain.

**Feasibility** — every core engine rests on mature open-source libraries; the MVP is a 36-hour build on seven worked samples.

**Impact and scalability** — each of the three users gets the artefact their workflow already accepts, and Celery fan-out plus the offline-first design runs on one campus or a multi-tenant CERT-In-facing deployment without a rewrite.

## 14. Resources

Every corpus, library, model, API, testnet and reporting standard named above is listed with a verified URL, licence or quota and a usage note in `docs/resources.md`, alongside the five gotchas the build must respect. It is this proposal's sourcing annexure: choices are argued here, provenance and access terms live there.
