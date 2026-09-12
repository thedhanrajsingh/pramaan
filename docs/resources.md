# PRAMAAN Resource Sheet — Verified Links & Notes

Compiled 12 Sep 2026 by a web-research pass; every link was checked for accessibility at that time.

## 1. Email Corpora (Phishing / Benign)

| Name | What it gives | Access/licence | URL | Note for our use |
|---|---|---|---|---|
| Nazario Phishing Corpus | ~4,550+ hand-verified phishing emails, mbox format | Free, research use | [monkey.org mirror via Academic Torrents](https://academictorrents.com/details/a77cda9a9d89a60dbdfbe581adf6e2df9197995a) | Positive-class seed; original monkey.org link is dead, use torrent/archive.org mirror |
| SpamAssassin Public Corpus | ~6,047 msgs (spam + easy/hard ham), raw .eml, bzip2 | Free/Apache | [spamassassin.apache.org/old/publiccorpus](https://spamassassin.apache.org/old/publiccorpus/readme.html) · [HF mirror](https://huggingface.co/datasets/talby/spamassassin) | Clean benign-mail baseline with real headers |
| Enron Email Dataset | ~0.5M internal emails, 422MB tar.gz | Free, CMU release | [cs.cmu.edu/~enron](https://www.cs.cmu.edu/~enron/) | Best source of large-scale legitimate corporate "ham" for intent classifier |
| CLAIR Fraud Email Corpus | 2,500+ "Nigerian"/419 advance-fee scam letters, text | Free, ACL Data/Code Repo | [ACL Wiki](https://aclweb.org/aclwiki/CLAIR_collection_of_fraud_email_(Repository)) · [Kaggle mirror](https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus) | Good for social-engineering / advance-fee scam class |
| TREC 2007 Public Spam Corpus | 75,419 msgs (25,220 ham / 50,199 spam), .tgz 255MB | Free after signed use agreement | [plg.uwaterloo.ca/~gvcormac/treccorpus07](https://plg.uwaterloo.ca/~gvcormac/treccorpus07/about.html) | Time-stamped real mail-server traffic, useful for header/Received-chain forensics |
| Kaggle Combined Phishing Set | Combines Enron+Ling+CEAS+Nazario+Nigerian+SpamAssassin, CSV, ~20K rows | Free, Kaggle terms | [naserabdullahalam/phishing-email-dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) | Fastest path to a balanced train/test set for the MVP demo |
| Indian-context dataset | No dedicated public Indian phishing-email corpus was found and verified | — | — | Synthesize India-specific lures (SBI/UPI/Aadhaar/AICTE-themed) yourselves; cite the absence in the pitch as a gap PRAMAAN fills |

## 2. Lookalike / Domain Intelligence Tools

| Name | What it gives | Access/licence | URL | Note |
|---|---|---|---|---|
| dnstwist | Domain permutation/typosquat fuzzing engine, JSON/CSV output | Free, GPL-3 | [github.com/elceef/dnstwist](https://github.com/elceef/dnstwist) | Run against sender domain to flag typosquats |
| tldextract | Splits URL into subdomain/domain/suffix via Public Suffix List | Free, PyPI (BSD) | [pypi.org/project/tldextract](https://pypi.org/project/tldextract/) | Correct base-domain extraction before comparison |
| confusable-homoglyphs | Detects Unicode homoglyph confusables | Free, PyPI (MIT); low maintenance | [pypi.org/project/confusable-homoglyphs](https://pypi.org/project/confusable-homoglyphs/) | Flags Cyrillic/Greek lookalike chars in sender/display name |
| crt.sh | Certificate Transparency log search, JSON via `?output=json` | Free, no key, no hard rate limit | [crt.sh](https://crt.sh/) | Check if lookalike domain has recently issued certs |

## 3. Email Auth & Parsing (Python)

| Name | What it gives | Access/licence | URL | Note |
|---|---|---|---|---|
| dkimpy | DKIM sign/verify | Free, PyPI (BSD) | [pypi.org/project/dkimpy](https://pypi.org/project/dkimpy/) | Verify DKIM pass/fail per message |
| pyspf | SPF record evaluation | Free, PyPI | [pypi.org/project/pyspf](https://pypi.org/project/pyspf/) | Needs `authres` dependency |
| authres | RFC 7601 Authentication-Results header parsing | Free, PyPI | [pypi.org/project/authres](https://pypi.org/project/authres/) | Parse existing Authentication-Results headers instead of re-checking live |
| checkdmarc | SPF/DMARC record parser + validator, CLI+lib | Free, PyPI | [pypi.org/project/checkdmarc](https://pypi.org/project/checkdmarc/) | One-shot domain auth posture check |
| mail-parser (SpamScope) | RFC-compliant .eml parsing into structured object, forensics-oriented | Free, PyPI (Apache-2.0) | [pypi.org/project/mail-parser](https://pypi.org/project/mail-parser/) | Core parser for headers/body/attachments |
| ssdeep / py-tlsh | Fuzzy/similarity hashing of attachments or bodies | Free, PyPI | [pypi.org/project/ssdeep](https://pypi.org/project/ssdeep/3.2) · [pypi.org/project/py-tlsh](https://pypi.org/project/py-tlsh/) | Cluster near-duplicate phishing campaigns |

## 4. IP Geolocation & ASN

| Name | What it gives | Access/licence | URL | Note |
|---|---|---|---|---|
| MaxMind GeoLite2 | City/Country/ASN MMDB, offline lookups | Free with account + licence key, EULA (must keep updated) | [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup) | Primary offline geolocation DB |
| IPinfo Lite | Country/ASN, unlimited requests with free token | Free (token) | [ipinfo.io/lite](https://ipinfo.io/lite) | Backup/cross-check source |
| ip-api.com | City-level geo, ISP | Free, non-commercial, 45 req/min, HTTP only | [ip-api.com](https://ip-api.com/) | Fine for hackathon demo, not HTTPS |
| RIPEstat | BGP prefix, ASN, historical routing data via REST | Free, no key | [stat.ripe.net](https://stat.ripe.net/) | Good for ASN/route context narrative in reports |
| Team Cymru IP-to-ASN | Bulk IP→ASN/BGP prefix via WHOIS/DNS/HTTPS | Free | [team-cymru.com/ip-asn-mapping](https://www.team-cymru.com/ip-asn-mapping) | Fast bulk enrichment for many IPs in one email chain |
| AbuseIPDB | IP abuse-report reputation score | Free, 1,000 req/day | [abuseipdb.com](https://www.abuseipdb.com/faq.html) | Reputation signal to combine with geo |
| Spamhaus DBL/ZEN | Domain/IP blocklist DNSBL | Free, fair-use policy | [spamhaus.org/blocklists/zen-blocklist](https://www.spamhaus.org/blocklists/zen-blocklist/) | Quick reputation check via DNS query |
| GreyNoise Community API | Classifies scanning/benign internet noise for an IP | Free, ~50 lookups/week | [docs.greynoise.io](https://docs.greynoise.io/docs/using-the-greynoise-community-api) | Filter out mass-scanner false positives |
| Shodan | Open ports/services/banner for an IP | Free tier (limited results/queries) | [shodan.io](https://www.shodan.io/) | Optional infra fingerprint of sending server |

## 5. URL / Attachment Threat Intel

| Name | What it gives | Access/licence | URL | Note |
|---|---|---|---|---|
| VirusTotal API v3 | Multi-engine URL/file scan | Free Public API: 500 req/day, 4/min | [docs.virustotal.com](https://docs.virustotal.com/reference/public-vs-premium-api) | Core verdict source; cache results, mind rate limit |
| URLhaus (abuse.ch) | Malware-distribution URL feed + lookup API | Free, requires Auth-Key from auth.abuse.ch | [urlhaus.abuse.ch/api](https://urlhaus.abuse.ch/api/) | Good malware-URL ground truth |
| OpenPhish | Plain-text active phishing URL feed, refreshed 15 min | Free (basic feed) | [openphish.com/feed.txt](https://openphish.com/feed.txt) | Simple ingestible blocklist |
| PhishTank | Community phishing DB, CSV/JSON/REST | Free | [phishtank.org](https://phishtank.org/) | Cross-check against community-verified phish |
| Google Safe Browsing v4 Lookup API | URL threat-list match, up to 500 URLs/request | Free, non-commercial, default quota (v4 Lookup deprecated in favour of v5) | [developers.google.com/safe-browsing/v4](https://developers.google.com/safe-browsing/v4) | Check v5 migration before finalising |
| CAPE Sandbox | Open-source dynamic malware analysis + config extraction | Free, open source (fork of Cuckoo) | [capev2.readthedocs.io](https://capev2.readthedocs.io/en/latest/introduction/what.html) | Heavier to stand up; only if time permits attachment detonation demo |

## 6. NLP / AI-Text-Detection Models (Hugging Face)

| Name | What it gives | Access/licence | URL | Caveat |
|---|---|---|---|---|
| DeBERTa-v3-base | Strong base encoder for fine-tuning phishing classifier | Free, MIT | [microsoft/deberta-v3-base](https://huggingface.co/microsoft/deberta-v3-base) | Needs fine-tuning on your labelled corpus (see section 1) |
| cybersectony/phishing-email-detection-distilbert | Pre-trained phishing-email classifier | Free, HF hub | [huggingface.co/cybersectony](https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1) | Ready baseline; validate on Indian-lure text before trusting |
| google/muril-base-cased | BERT for 17 Indian languages incl. transliterated (Hinglish) text | Free, Apache-2.0 | [huggingface.co/google/muril-base-cased](https://huggingface.co/google/muril-base-cased) | Best fit for Hindi/Hinglish phishing body text |
| ai4bharat/indic-bert | ALBERT pretrained on 12 Indian languages | Free, MIT | [huggingface.co/ai4bharat/indic-bert](https://huggingface.co/ai4bharat/indic-bert) | Lighter alternative to MuRIL |
| desklib/ai-text-detector-v1.01 | AI-generated-text detector (DeBERTa-v3-large based), strong on RAID benchmark | Free, HF hub | [huggingface.co/desklib/ai-text-detector-v1.01](https://huggingface.co/desklib/ai-text-detector-v1.01) | Detectors are unreliable on short/edited text; treat as one weak signal, not ground truth |

## 7. Blockchain Evidence Anchoring

| Name | What it gives | Access/licence | URL | Cost/setup |
|---|---|---|---|---|
| Polygon Amoy Testnet | EVM testnet (chain ID 80002) to anchor evidence hashes | Free | [chainlist.org/chain/80002](https://chainlist.org/chain/80002) · faucet: [ethglobal.com/faucet/polygon-amoy-80002](https://ethglobal.com/faucet/polygon-amoy-80002) | Free POL from faucet (~0.05/day); write hash to a simple smart contract or as tx calldata |
| Hyperledger Fabric test network | Permissioned ledger sample (2-org Docker Compose network) | Free, open source | [github.com/hyperledger/fabric-samples](https://github.com/hyperledger/fabric-samples) | Heavier setup (Docker, chaincode); better if judges value "permissioned/enterprise" framing |
| OpenTimestamps | Free Bitcoin-anchored timestamp proofs, no account needed | Free, LGPL-3 | [github.com/opentimestamps/opentimestamps-client](https://github.com/opentimestamps/opentimestamps-client) | Simplest fallback: hash → submit to calendar server → proof confirms in a few hours |

## 8. Reporting: STIX/Docs & CERT-In

| Name | What it gives | Access/licence | URL | Note |
|---|---|---|---|---|
| stix2 (OASIS cti-python-stix2) | Python STIX 2.1 object serialisation/validation | Free, BSD, OASIS TC repo | [github.com/oasis-open/cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) | Build the forensic report as a standard STIX bundle |
| python-docx | Generate .docx forensic reports | Free, PyPI (MIT) | [pypi.org/project/python-docx](https://pypi.org/project/python-docx/) | Editable report format for investigators |
| WeasyPrint / ReportLab | HTML→PDF or programmatic PDF report generation | Free, PyPI | [WeasyPrint](https://pypi.org/project/weasyprint/) · [ReportLab](https://pypi.org/project/reportlab/) | WeasyPrint for styled HTML report; ReportLab for charts/tables |
| CERT-In 6-hour Directive (28 Apr 2022) | Mandates reporting of listed cyber incidents (incl. phishing) within 6 hours | Government directive under IT Act s.70B(6) | [CERT-In direction PDF](https://trilegal.com/wp-content/uploads/2022/05/2022-CERT-In-Directions-on-Reporting-Cyber-Incidents-1.pdf) | Reporting via portal [incidents.cert-in.org.in](https://incidents.cert-in.org.in) or email incident@cert-in.org.in; map PRAMAAN's report export to this form |

## 9. Five Gotchas

1. **Received headers read bottom-up, not top-down.** Each relay prepends its own line, so the most trustworthy origin hop is the bottom-most `Received:` line that the sender's infrastructure could not have forged; everything below the first trusted internal gateway is attacker-controllable.
2. **SPF/DKIM "pass" does not mean safe.** A phisher who registers their own lookalike domain gets legitimate SPF/DKIM/DMARC alignment on that domain; authentication proves the domain's policy was followed, not that the domain is trustworthy.
3. **IP geolocation is city-level at best, and often wrong.** Free databases can be off by tens to hundreds of km, especially for mobile carriers and cloud IP ranges; treat geo as investigative context, not court-grade evidence.
4. **VPN, Tor, proxy and cloud-relay exits mask true origin.** A clean-looking IP may be an exit node or SMTP relay (SendGrid, Amazon SES); check ASN and organisation name for known VPN/hosting providers before attributing.
5. **Free threat-intel APIs have tight rate limits.** VirusTotal (500/day), AbuseIPDB (1,000/day), GreyNoise Community (~50/week); cache every lookup and rate-limit demo queries so they do not run dry mid-presentation.
