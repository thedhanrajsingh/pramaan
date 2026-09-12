/* PRAMAAN — mock dataset. Plain script, no modules.
   Exposes: window.EFP_DATA  (emails + dashboard)
            window.EFP_MAP   (equirectangular projection + low-poly land)
   All hashes are deterministic so the evidence chain actually verifies:
   ledger[n].prevHash === ledger[n-1].hash. */
(function () {
  'use strict';

  /* ---- deterministic 64-hex "digest" so demo hashes look real and stay stable ---- */
  function hex64(seed) {
    seed = String(seed);
    var h = 0;
    for (var i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    var o = '';
    while (o.length < 64) o += ('00000000' + (h = (h * 1103515245 + 12345) >>> 0).toString(16)).slice(-8);
    return o.slice(0, 64);
  }
  var GENESIS = '0'.repeat(64);

  /* items: [ [label, isoTimestamp], ... ] */
  function buildLedger(seed, items) {
    var prev = GENESIS;
    return items.map(function (it, i) {
      var sha = hex64(seed + '|item|' + i + '|' + it[0]);
      var hash = hex64(prev + sha + it[1]);
      var rec = { seq: i + 1, item: it[0], sha256: sha, prevHash: prev, hash: hash, at: it[1] };
      prev = hash;
      return rec;
    });
  }

  /* =======================================================================
     EMAILS — 7 analysed samples (newest first)
     ======================================================================= */

  var emails = [];

  /* ---------------------------------------------------------------- EM-2411
     Credential phishing · lookalike domain · SPF fail · redirect chain
     NL VPS origin -> DE relay -> university MX Mumbai                      */
  emails.push({
    id: 'EM-2411',
    receivedAt: '2026-09-12T09:14:22+05:30',
    subject: 'Mandatory: re-verify your AICTE Portal credentials before 15 Sep 2026',
    from: { display: 'AICTE Approval Bureau', address: 'no-reply@aicte-gov.in' },
    replyTo: 'verify.desk@aicte-gov.in',
    to: 'registrar@mgsuniversity.ac.in',
    verdict: 'Malicious',
    riskScore: 94,
    category: 'Credential phishing',
    rawHeaders:
      'Return-Path: <bounce-9241@mailgrid-lite.net>\n' +
      'Delivered-To: registrar@mgsuniversity.ac.in\n' +
      'Received: from mx-store.mgsuniversity.ac.in (mx-store.mgsuniversity.ac.in [103.21.124.22])\n' +
      '        by imap-04.mgsuniversity.ac.in with LMTP id 8fA1JpQk\n' +
      '        for <registrar@mgsuniversity.ac.in>; Sat, 12 Sep 2026 09:14:22 +0530\n' +
      'Received: from smtp-in-3.mgsuniversity.ac.in (smtp-in-3.mgsuniversity.ac.in [103.21.124.14])\n' +
      '        by mx-store.mgsuniversity.ac.in (Postfix) with ESMTPS id 4C1f9K2r\n' +
      '        (TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\n' +
      '        for <registrar@mgsuniversity.ac.in>; Sat, 12 Sep 2026 09:13:41 +0530\n' +
      'Received: from mail.rapidrelay-de.net (mail.rapidrelay-de.net [94.130.11.203])\n' +
      '        by smtp-in-3.mgsuniversity.ac.in (Postfix) with ESMTPS id 2B77aD91\n' +
      '        (TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384)\n' +
      '        for <registrar@mgsuniversity.ac.in>; Sat, 12 Sep 2026 09:12:07 +0530\n' +
      'Received: from aicte-portal-secure (vps-nl-4412.hostmatrix.net [185.62.190.24])\n' +
      '        by mail.rapidrelay-de.net (Exim 4.96) with ESMTPA id 1rQ5xY-0007Kf-2t;\n' +
      '        Sat, 12 Sep 2026 03:41:50 +0000\n' +
      'Message-ID: <20260912034150.9241.aicte-verify@mailgrid-lite.net>\n' +
      'From: "AICTE Approval Bureau" <no-reply@aicte-gov.in>\n' +
      'Reply-To: verify.desk@aicte-gov.in\n' +
      'To: registrar@mgsuniversity.ac.in\n' +
      'Subject: Mandatory: re-verify your AICTE Portal credentials before 15 Sep 2026\n' +
      'Date: Sat, 12 Sep 2026 09:11:02 +0530\n' +
      'X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)\n' +
      'Authentication-Results: smtp-in-3.mgsuniversity.ac.in;\n' +
      '        spf=fail (sender IP is 185.62.190.24) smtp.mailfrom=mailgrid-lite.net;\n' +
      '        dkim=none (message not signed);\n' +
      '        dmarc=fail action=none header.from=aicte-gov.in\n' +
      'MIME-Version: 1.0\n' +
      'Content-Type: multipart/alternative; boundary="=_b41c9ee2"',
    auth: {
      spf: { result: 'fail', detail: 'Envelope mailfrom mailgrid-lite.net does not authorise 185.62.190.24 (-all).' },
      dkim: { result: 'none', detail: 'No DKIM-Signature header present; no selector to verify.' },
      dmarc: { result: 'fail', detail: 'header.from aicte-gov.in has no DMARC record; no aligned SPF or DKIM identifier.' }
    },
    signals: [
      { id: 'SG-01', name: 'Lookalike sender domain', weight: 22, status: 'fired', engine: 'Lookalike/Homoglyph', evidence: 'aicte-gov.in vs legitimate aicte-india.org — keyword permutation "aicte"+"gov", edit distance 6, skeleton match 0.91.' },
      { id: 'SG-02', name: 'SPF hard fail', weight: 18, status: 'fired', engine: 'Authentication', evidence: 'spf=fail; 185.62.190.24 not in any authorised sender network for mailgrid-lite.net.' },
      { id: 'SG-03', name: 'DMARC alignment failure', weight: 16, status: 'fired', engine: 'Authentication', evidence: 'No aligned identifier for header.from=aicte-gov.in; DKIM absent, SPF domain unrelated.' },
      { id: 'SG-04', name: 'Deceptive URL anchor', weight: 14, status: 'fired', engine: 'URL Unwrap', evidence: 'Anchor text "www.aicte-india.org/approval/verify" resolves to aicte-gov.in.verify-portal.top.' },
      { id: 'SG-05', name: 'Credential-harvest landing page', weight: 13, status: 'fired', engine: 'URL Unwrap', evidence: 'Terminal page serves a password form; DOM + favicon similarity 0.91 against the real AICTE login.' },
      { id: 'SG-06', name: 'Newly registered domain', weight: 12, status: 'fired', engine: 'Threat Intel', evidence: 'aicte-gov.in created 2026-09-06 (6 days old), registrar PDR Ltd, WHOIS privacy-protected.' },
      { id: 'SG-07', name: 'NLP intent: credential request under deadline', weight: 11, status: 'fired', engine: 'NLP Intent', evidence: 'Labels: credential_request 0.96, deadline_pressure 0.88, authority_appeal 0.71.' },
      { id: 'SG-08', name: 'Reply-To / Return-Path divergence', weight: 7, status: 'fired', engine: 'Header Anomaly', evidence: 'From aicte-gov.in, Return-Path mailgrid-lite.net, Message-ID domain mailgrid-lite.net — three distinct domains.' },
      { id: 'SG-09', name: 'AI-generated text likelihood', weight: 4, status: 'fired', engine: 'AI-Text', evidence: 'Low burstiness (0.21), uniform sentence length; detector head 0.78. Supporting signal only.' },
      { id: 'SG-10', name: 'Malicious attachment', weight: 0, status: 'clear', engine: 'Attachment', evidence: 'No attachments in this message.' }
    ],
    aiExplanation:
      'This message impersonates the AICTE Approval Bureau but was sent from aicte-gov.in, a six-day-old domain that has no relationship with the genuine aicte-india.org. Authentication corroborates the impersonation: SPF fails for the sending IP and there is no DKIM signature, so nothing in the message cryptographically ties it to AICTE. The visible link claims to point at the AICTE portal, but after two redirects it lands on a credential-harvesting page that is a near-copy of the real login screen. The language asks the registrar to re-enter portal credentials before a three-day deadline, which is the classic pressure pattern for credential theft. Treat any credentials entered after 03:41 UTC on 12 September as compromised and force a reset for the registrar account.',
    bodyText:
      'Dear Registrar,\n\n' +
      'As part of the AICTE Approval Process 2026-27 migration, all institutional portal accounts must be re-verified. Accounts not re-verified before 15 September 2026 will be suspended and pending approval applications will lapse.\n\n' +
      'Re-verify here: https://www.aicte-india.org/approval/verify\n\n' +
      'You will need your portal user ID, password and registered mobile number. Please do not forward this mail.\n\n' +
      'Regards,\n' +
      'Approval Bureau\n' +
      'All India Council for Technical Education\n',
    links: [{
      shown: 'https://www.aicte-india.org/approval/verify',
      actual: 'http://aicte-gov.in.verify-portal.top/login?u=registrar%40mgsuniversity.ac.in',
      redirects: [
        'https://bit.ly/3QxAicteVerify',
        'http://tracking.mailgrid-lite.net/c/r?u=aHR0cDovL2FpY3RlLWdvdi5pbi52ZXJpZnktcG9ydGFsLnRvcA==',
        'http://aicte-gov.in.verify-portal.top/login'
      ],
      verdict: 'Malicious — credential harvesting'
    }],
    attachments: [],
    hops: [
      { index: 0, host: 'vps-nl-4412.hostmatrix.net', ip: '185.62.190.24', asn: 'AS60117', org: 'Host Sailor Ltd', country: 'Netherlands', countryCode: 'NL', city: 'Amsterdam', lat: 52.374, lon: 4.8897, timestamp: '2026-09-12T03:41:50Z', delayMs: 0, tls: 'none', flags: ['first external hop', 'datacentre VPS', 'HELO "aicte-portal-secure" does not match PTR', 'AbuseIPDB confidence 64'] },
      { index: 1, host: 'mail.rapidrelay-de.net', ip: '94.130.11.203', asn: 'AS24940', org: 'Hetzner Online GmbH', country: 'Germany', countryCode: 'DE', city: 'Frankfurt am Main', lat: 50.1109, lon: 8.6821, timestamp: '2026-09-12T03:42:07Z', delayMs: 17000, tls: 'TLSv1.2', flags: ['authenticated submission relay', 'bulk sender', 'seen in 3 prior campaigns'] },
      { index: 2, host: 'smtp-in-3.mgsuniversity.ac.in', ip: '103.21.124.14', asn: 'AS132335', org: 'Sify Technologies Ltd', country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.076, lon: 72.8777, timestamp: '2026-09-12T03:42:07Z', delayMs: 94000, tls: 'TLSv1.2', flags: ['recipient boundary MX', 'trusted'] },
      { index: 3, host: 'mx-store.mgsuniversity.ac.in', ip: '103.21.124.22', asn: 'AS132335', org: 'Sify Technologies Ltd', country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.076, lon: 72.8777, timestamp: '2026-09-12T03:43:41Z', delayMs: 41000, tls: 'TLSv1.3', flags: ['internal delivery', 'trusted'] }
    ],
    origin: { ip: '185.62.190.24', country: 'Netherlands', city: 'Amsterdam', lat: 52.374, lon: 4.8897, confidence: 0.82, method: 'first external Received header' },
    iocs: [
      { type: 'domain', value: 'aicte-gov.in', confidence: 0.97, source: 'PRAMAAN lookalike engine' },
      { type: 'url', value: 'http://aicte-gov.in.verify-portal.top/login', confidence: 0.99, source: 'URLhaus + unwrap' },
      { type: 'url-shortener', value: 'https://bit.ly/3QxAicteVerify', confidence: 0.88, source: 'URL unwrap' },
      { type: 'ipv4', value: '185.62.190.24', confidence: 0.91, source: 'AbuseIPDB' },
      { type: 'ipv4', value: '94.130.11.203', confidence: 0.66, source: 'PRAMAAN corpus' },
      { type: 'email', value: 'verify.desk@aicte-gov.in', confidence: 0.94, source: 'Header parser' }
    ],
    relatedCampaigns: [
      { id: 'CMP-0042', name: 'FakeApproval — AICTE portal credential run', similarity: 0.87, firstSeen: '2026-08-29', count: 41 },
      { id: 'CMP-0031', name: 'HostSailor NL relay cluster', similarity: 0.74, firstSeen: '2026-07-14', count: 118 },
      { id: 'CMP-0066', name: 'verify-portal.top harvest kit', similarity: 0.69, firstSeen: '2026-09-02', count: 23 }
    ],
    timeline: [
      { t: '2026-09-12T03:41:50Z', event: 'Message injected at first external hop 185.62.190.24 (Amsterdam, AS60117).' },
      { t: '2026-09-12T03:43:41Z', event: 'Delivered to registrar@mgsuniversity.ac.in via Sify MX, Mumbai.' },
      { t: '2026-09-12T03:52:10Z', event: 'Reported to abuse@mgsuniversity.ac.in by the registrar office; auto-forwarded to PRAMAAN.' },
      { t: '2026-09-12T03:52:12Z', event: 'Ingested and hashed; analysis pipeline started (10 engines).' },
      { t: '2026-09-12T03:52:14Z', event: 'Analysis complete in 2.31 s — verdict Malicious, score 94.' },
      { t: '2026-09-12T04:05:00Z', event: 'CASE-2026-0188 opened and assigned to A. Nair (Tier-2).' },
      { t: '2026-09-12T04:18:37Z', event: 'IOC set pushed to campus gateway blocklist; registrar credentials force-reset.' }
    ],
    evidenceLedger: buildLedger('EM-2411', [
      ['Raw RFC 5322 message (aicte-verify.eml, 24.8 KB)', '2026-09-12T03:52:12Z'],
      ['Parsed header block + Received chain (4 hops)', '2026-09-12T03:52:12Z'],
      ['Authentication result set (SPF fail / DKIM none / DMARC fail)', '2026-09-12T03:52:13Z'],
      ['Lookalike engine report — aicte-gov.in vs aicte-india.org', '2026-09-12T03:52:13Z'],
      ['Redirect chain capture (3 hops) + terminal URL', '2026-09-12T03:52:14Z'],
      ['Landing page screenshot (verify-portal.top/login, 1280x800 PNG)', '2026-09-12T03:52:14Z'],
      ['GeoIP/ASN enrichment snapshot (MaxMind GeoLite2 2026-09-08)', '2026-09-12T03:52:14Z'],
      ['Analyst note — A. Nair: credentials reset, user confirmed no submission', '2026-09-12T04:21:09Z']
    ])
  });

  /* ---------------------------------------------------------------- EM-2410
     BEC / CEO fraud · display-name spoof · zero payload · urgent wire
     Residential TR origin -> MD bulletproof relay -> MX Mumbai            */
  emails.push({
    id: 'EM-2410',
    receivedAt: '2026-09-12T08:02:11+05:30',
    subject: 'Re: RTGS release before 11:00 AM today — strictly confidential',
    from: { display: 'Dr. Rajeev Menon | Vice-Chancellor', address: 'vc.office.mgsu@secure-mailbox.icu' },
    replyTo: 'vc.rajeev.menon@consultant-desk.info',
    to: 'finance.officer@mgsuniversity.ac.in',
    verdict: 'Malicious',
    riskScore: 88,
    category: 'BEC/CEO fraud',
    rawHeaders:
      'Return-Path: <vc.office.mgsu@secure-mailbox.icu>\n' +
      'Delivered-To: finance.officer@mgsuniversity.ac.in\n' +
      'Received: from smtp-in-3.mgsuniversity.ac.in (smtp-in-3.mgsuniversity.ac.in [103.21.124.14])\n' +
      '        by mx-store.mgsuniversity.ac.in (Postfix) with ESMTPS id 7D2a4M8x\n' +
      '        (TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\n' +
      '        for <finance.officer@mgsuniversity.ac.in>; Sat, 12 Sep 2026 08:02:11 +0530\n' +
      'Received: from mail.secure-mailbox.icu (mail.secure-mailbox.icu [45.133.180.61])\n' +
      '        by smtp-in-3.mgsuniversity.ac.in (Postfix) with ESMTPS id 9E31bC70\n' +
      '        (TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256)\n' +
      '        for <finance.officer@mgsuniversity.ac.in>; Sat, 12 Sep 2026 08:01:38 +0530\n' +
      'Received: from mgsuniversity.ac.in (unknown [88.234.17.9])\n' +
      '        by mail.secure-mailbox.icu (OpenSMTPD) with ESMTPSA id 5f11c204\n' +
      '        auth=yes user=vc.office.mgsu; Sat, 12 Sep 2026 02:29:54 +0000\n' +
      'Message-ID: <CAF9k2Q-vc-office-0912@secure-mailbox.icu>\n' +
      'In-Reply-To: <internal-fin-2026-0908@mgsuniversity.ac.in>\n' +
      'From: "Dr. Rajeev Menon | Vice-Chancellor" <vc.office.mgsu@secure-mailbox.icu>\n' +
      'Reply-To: vc.rajeev.menon@consultant-desk.info\n' +
      'To: finance.officer@mgsuniversity.ac.in\n' +
      'Subject: Re: RTGS release before 11:00 AM today - strictly confidential\n' +
      'Date: Sat, 12 Sep 2026 07:59:41 +0530\n' +
      'X-Mailer: iPhone Mail (21C62)\n' +
      'Authentication-Results: smtp-in-3.mgsuniversity.ac.in;\n' +
      '        spf=pass (sender IP is 45.133.180.61) smtp.mailfrom=secure-mailbox.icu;\n' +
      '        dkim=pass header.d=secure-mailbox.icu header.s=s1;\n' +
      '        dmarc=pass action=none header.from=secure-mailbox.icu\n' +
      'MIME-Version: 1.0\n' +
      'Content-Type: text/plain; charset="utf-8"',
    auth: {
      spf: { result: 'pass', detail: 'secure-mailbox.icu authorises 45.133.180.61 — but that is the attacker\'s own domain, not the university\'s.' },
      dkim: { result: 'pass', detail: 'Valid signature for header.d=secure-mailbox.icu, selector s1. Signs the attacker infrastructure only.' },
      dmarc: { result: 'pass', detail: 'Aligned for secure-mailbox.icu. NOT aligned with the impersonated identity mgsuniversity.ac.in — authentication here proves nothing about the claimed sender.' }
    },
    signals: [
      { id: 'SG-01', name: 'Display-name impersonation of executive', weight: 24, status: 'fired', engine: 'Display-Name Spoof', evidence: 'Display name asserts "Vice-Chancellor" of mgsuniversity.ac.in; address domain secure-mailbox.icu is outside the institution allow-list.' },
      { id: 'SG-02', name: 'NLP intent: payment / wire redirection', weight: 22, status: 'fired', engine: 'NLP Intent', evidence: 'Labels: wire_transfer_request 0.97, new_beneficiary 0.93, invoice_change 0.41. No link or attachment to score.' },
      { id: 'SG-03', name: 'Authority + urgency pressure', weight: 14, status: 'fired', engine: 'NLP Intent', evidence: '"before 11:00 AM", "do not route through the usual approval", "I am in a meeting" — authority_appeal 0.91, urgency 0.95.' },
      { id: 'SG-04', name: 'Secrecy instruction', weight: 9, status: 'fired', engine: 'NLP Intent', evidence: '"strictly confidential", "do not discuss with the finance committee" — secrecy 0.88.' },
      { id: 'SG-05', name: 'Reply-To on unrelated third domain', weight: 10, status: 'fired', engine: 'Header Anomaly', evidence: 'From secure-mailbox.icu, Reply-To consultant-desk.info — replies leave both the institution and the sending domain.' },
      { id: 'SG-06', name: 'Forged thread continuation', weight: 8, status: 'fired', engine: 'Header Anomaly', evidence: 'In-Reply-To references <internal-fin-2026-0908@mgsuniversity.ac.in>, which does not exist in the mailbox — fake "Re:" thread.' },
      { id: 'SG-07', name: 'Newly registered low-reputation TLD', weight: 11, status: 'fired', engine: 'Threat Intel', evidence: 'secure-mailbox.icu created 2026-09-03; .icu abuse rate 0.62 in PRAMAAN corpus.' },
      { id: 'SG-08', name: 'Origin inconsistent with claimed sender', weight: 9, status: 'fired', engine: 'Geo Correlation', evidence: 'HELO claims mgsuniversity.ac.in; first external hop is residential broadband 88.234.17.9 in Istanbul, TR, with no PTR.' },
      { id: 'SG-09', name: 'AI-generated text likelihood', weight: 6, status: 'fired', engine: 'AI-Text', evidence: 'Detector head 0.83; register mismatch against 42 genuine VC mails in the corpus (stylometry distance 0.74).' },
      { id: 'SG-10', name: 'Malicious URL or attachment', weight: 0, status: 'clear', engine: 'URL Unwrap', evidence: 'Zero payload: no URLs, no attachments. Nothing for a signature-based filter to match.' }
    ],
    aiExplanation:
      'This is a business email compromise attempt impersonating the Vice-Chancellor to the finance officer. It is worth noting that SPF, DKIM and DMARC all pass — but they pass for secure-mailbox.icu, a domain the attacker registered nine days ago, and not for mgsuniversity.ac.in, so the green authentication lights mean nothing about the claimed identity. The message carries no link and no attachment at all, which is precisely why gateway filters let it through; the entire attack is language, asking for an RTGS release to a new beneficiary before 11:00 AM while discouraging the normal approval route. The fake "Re:" and In-Reply-To header make it look like an existing thread that the finance officer is expected to recall. No money moved: the officer escalated before release, and the beneficiary account should still be reported to the bank and to the cyber cell.',
    bodyText:
      'Please treat this as confidential.\n\n' +
      'The infrastructure grant tranche has to be released this morning. Kindly process an RTGS of Rs 18,64,000 to the account below before 11:00 AM. Do not route it through the usual approval chain today, I am in back-to-back meetings with the council and cannot sign in person.\n\n' +
      'Beneficiary: Sunrise Infratech Services\n' +
      'A/c: 39218847120\n' +
      'IFSC: UTIB0001432\n' +
      'Branch: Andheri East\n\n' +
      'Confirm by reply once done. Please do not discuss this with the finance committee before the announcement.\n\n' +
      'Regards,\n' +
      'Dr. Rajeev Menon\n' +
      'Vice-Chancellor\n' +
      'Sent from my iPhone\n',
    links: [],
    attachments: [],
    hops: [
      { index: 0, host: '(no PTR record)', ip: '88.234.17.9', asn: 'AS9121', org: 'Turk Telekom', country: 'Turkiye', countryCode: 'TR', city: 'Istanbul', lat: 41.0082, lon: 28.9784, timestamp: '2026-09-12T02:29:54Z', delayMs: 0, tls: 'TLSv1.2', flags: ['first external hop', 'residential broadband', 'HELO claims mgsuniversity.ac.in', 'authenticated as vc.office.mgsu'] },
      { index: 1, host: 'mail.secure-mailbox.icu', ip: '45.133.180.61', asn: 'AS200019', org: 'AlexHost SRL', country: 'Moldova', countryCode: 'MD', city: 'Chisinau', lat: 47.0105, lon: 28.8638, timestamp: '2026-09-12T02:31:38Z', delayMs: 104000, tls: 'TLSv1.2', flags: ['attacker-controlled MTA', 'bulletproof hosting (historic)', 'DKIM signer d=secure-mailbox.icu'] },
      { index: 2, host: 'smtp-in-3.mgsuniversity.ac.in', ip: '103.21.124.14', asn: 'AS132335', org: 'Sify Technologies Ltd', country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.076, lon: 72.8777, timestamp: '2026-09-12T02:32:11Z', delayMs: 33000, tls: 'TLSv1.3', flags: ['recipient boundary MX', 'trusted'] }
    ],
    origin: { ip: '88.234.17.9', country: 'Turkiye', city: 'Istanbul', lat: 41.0082, lon: 28.9784, confidence: 0.74, method: 'first external Received header' },
    iocs: [
      { type: 'domain', value: 'secure-mailbox.icu', confidence: 0.95, source: 'PRAMAAN corpus' },
      { type: 'domain', value: 'consultant-desk.info', confidence: 0.81, source: 'Header parser' },
      { type: 'email', value: 'vc.rajeev.menon@consultant-desk.info', confidence: 0.9, source: 'Header parser' },
      { type: 'ipv4', value: '45.133.180.61', confidence: 0.87, source: 'AbuseIPDB' },
      { type: 'ipv4', value: '88.234.17.9', confidence: 0.58, source: 'GeoIP + AbuseIPDB' },
      { type: 'bank-account', value: 'UTIB0001432 / 39218847120', confidence: 0.99, source: 'NLP entity extraction' }
    ],
    relatedCampaigns: [
      { id: 'CMP-0057', name: 'VC-impersonation wire fraud (higher education)', similarity: 0.79, firstSeen: '2026-06-11', count: 29 },
      { id: 'CMP-0071', name: '.icu executive-spoof mailbox cluster', similarity: 0.72, firstSeen: '2026-08-18', count: 54 }
    ],
    timeline: [
      { t: '2026-09-12T02:29:54Z', event: 'Message injected from residential IP 88.234.17.9 (Istanbul) via authenticated submission.' },
      { t: '2026-09-12T02:32:11Z', event: 'Delivered to finance.officer@mgsuniversity.ac.in — passed gateway filters (no payload).' },
      { t: '2026-09-12T02:41:05Z', event: 'Finance officer telephoned the VC office to confirm; instruction denied.' },
      { t: '2026-09-12T02:44:20Z', event: 'Reported to PRAMAAN; verdict Malicious, score 88 in 1.94 s.' },
      { t: '2026-09-12T03:10:00Z', event: 'CASE-2026-0187 opened; beneficiary account reported to the bank nodal officer.' }
    ],
    evidenceLedger: buildLedger('EM-2410', [
      ['Raw RFC 5322 message (vc-rtgs-request.eml, 9.1 KB)', '2026-09-12T02:44:20Z'],
      ['Parsed header block + Received chain (3 hops)', '2026-09-12T02:44:20Z'],
      ['Authentication result set (SPF pass / DKIM pass / DMARC pass, unaligned)', '2026-09-12T02:44:21Z'],
      ['NLP intent report — wire_transfer_request 0.97', '2026-09-12T02:44:21Z'],
      ['Extracted financial entities (beneficiary, A/c, IFSC)', '2026-09-12T02:44:22Z'],
      ['Telephone verification note — VC office denies instruction', '2026-09-12T03:04:51Z'],
      ['GeoIP/ASN enrichment snapshot (MaxMind GeoLite2 2026-09-08)', '2026-09-12T03:05:02Z']
    ])
  });

  /* ---------------------------------------------------------------- EM-2409
     Invoice fraud against a public-sector bank · lookalike TLD · PDF        */
  emails.push({
    id: 'EM-2409',
    receivedAt: '2026-09-11T17:48:03+05:30',
    subject: 'Revised bank mandate — invoice BNI/2026/1184 (vendor payment)',
    from: { display: 'Accounts — Bharat Nirman Infra Pvt Ltd', address: 'accounts@bharatnirman-infra.co' },
    replyTo: 'accounts.recv@bharatnirman-infra.co',
    to: 'payments.ops@punjabgraminbank.in',
    verdict: 'Suspicious',
    riskScore: 79,
    category: 'Invoice fraud',
    rawHeaders:
      'Return-Path: <accounts@bharatnirman-infra.co>\n' +
      'Delivered-To: payments.ops@punjabgraminbank.in\n' +
      'Received: from mx1.punjabgraminbank.in (mx1.punjabgraminbank.in [14.142.61.38])\n' +
      '        by store-02.punjabgraminbank.in (Postfix) with ESMTPS id 3A90dK14\n' +
      '        (TLSv1.3 cipher=TLS_AES_128_GCM_SHA256)\n' +
      '        for <payments.ops@punjabgraminbank.in>; Fri, 11 Sep 2026 17:48:03 +0530\n' +
      'Received: from relay.mailerq-sg.net (relay.mailerq-sg.net [51.79.140.22])\n' +
      '        by mx1.punjabgraminbank.in (Postfix) with ESMTPS id 1F44cB72\n' +
      '        (TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384)\n' +
      '        for <payments.ops@punjabgraminbank.in>; Fri, 11 Sep 2026 17:46:52 +0530\n' +
      'Received: from vps-sg-1188.ovhcloud-host.net (vps-sg-1188.ovhcloud-host.net [139.99.102.14])\n' +
      '        by relay.mailerq-sg.net (Haraka 3.0.3) with ESMTPSA id d19b7a41;\n' +
      '        Fri, 11 Sep 2026 12:14:07 +0000\n' +
      'Message-ID: <BNI-1184-mandate-0911@bharatnirman-infra.co>\n' +
      'From: "Accounts - Bharat Nirman Infra Pvt Ltd" <accounts@bharatnirman-infra.co>\n' +
      'Reply-To: accounts.recv@bharatnirman-infra.co\n' +
      'To: payments.ops@punjabgraminbank.in\n' +
      'Subject: Revised bank mandate - invoice BNI/2026/1184 (vendor payment)\n' +
      'Date: Fri, 11 Sep 2026 17:44:19 +0530\n' +
      'X-Originating-IP: [139.99.102.14]\n' +
      'Authentication-Results: mx1.punjabgraminbank.in;\n' +
      '        spf=softfail (sender IP is 51.79.140.22) smtp.mailfrom=bharatnirman-infra.co;\n' +
      '        dkim=pass header.d=bharatnirman-infra.co header.s=mq1;\n' +
      '        dmarc=pass action=none header.from=bharatnirman-infra.co\n' +
      'MIME-Version: 1.0\n' +
      'Content-Type: multipart/mixed; boundary="=_9f1a77c3"',
    auth: {
      spf: { result: 'softfail', detail: 'bharatnirman-infra.co publishes ~all; 51.79.140.22 is outside the listed include:_spf.mailerq-sg.net range.' },
      dkim: { result: 'pass', detail: 'Valid signature for header.d=bharatnirman-infra.co, selector mq1 — signed by the sender of record, which is itself a lookalike domain.' },
      dmarc: { result: 'pass', detail: 'Aligned for bharatnirman-infra.co. The genuine vendor domain is bharatnirman-infra.co.in; alignment here does not attest to the real vendor.' }
    },
    signals: [
      { id: 'SG-01', name: 'Lookalike TLD of known vendor', weight: 21, status: 'fired', engine: 'Lookalike/Homoglyph', evidence: 'bharatnirman-infra.co vs vendor of record bharatnirman-infra.co.in — same label, truncated ccTLD (.co / .co.in confusion).' },
      { id: 'SG-02', name: 'Bank-detail change request', weight: 20, status: 'fired', engine: 'NLP Intent', evidence: 'Labels: invoice_change 0.94, new_beneficiary 0.89. References a real open invoice number (BNI/2026/1184).' },
      { id: 'SG-03', name: 'SPF softfail', weight: 9, status: 'fired', engine: 'Authentication', evidence: 'spf=softfail for 51.79.140.22; sending relay not in the domain policy.' },
      { id: 'SG-04', name: 'PDF with embedded action', weight: 12, status: 'fired', engine: 'Attachment', evidence: 'Revised_Bank_Mandate_BNI-1184.pdf contains /OpenAction launching an external URL; no macro, no known malware hash.' },
      { id: 'SG-05', name: 'Deceptive URL anchor', weight: 8, status: 'fired', engine: 'URL Unwrap', evidence: 'Anchor "bharatnirman-infra.co.in/invoices/1184" resolves to bharatnirman-infra.co (no .in).' },
      { id: 'SG-06', name: 'Recently registered domain', weight: 10, status: 'fired', engine: 'Threat Intel', evidence: 'bharatnirman-infra.co created 2026-07-28 (45 days), registrar NameSilo, DNS on the same VPS that injected the mail.' },
      { id: 'SG-07', name: 'Datacentre origin for a vendor mailbox', weight: 7, status: 'fired', engine: 'Geo Correlation', evidence: 'First external hop 139.99.102.14, OVH Singapore VPS; the vendor of record sends from AS55836 in Pune.' },
      { id: 'SG-08', name: 'Display-name impersonation of executive', weight: 0, status: 'clear', engine: 'Display-Name Spoof', evidence: 'Display name matches the address domain; no role or brand impersonation claim.' },
      { id: 'SG-09', name: 'Known malware hash', weight: 0, status: 'clear', engine: 'Threat Intel', evidence: 'Attachment SHA-256 unknown to VirusTotal (0/68) and to the local corpus.' }
    ],
    aiExplanation:
      'A payment-diversion attempt aimed at the bank vendor-payments desk. The sender quotes a genuine open invoice number and asks for the beneficiary mandate to be replaced, which is the standard invoice-fraud pattern and suggests the attacker has seen prior correspondence. The domain is one character class away from the vendor of record: bharatnirman-infra.co instead of bharatnirman-infra.co.in, and DKIM passes only because the attacker signs mail for that lookalike domain. The attached PDF is not malware, but it carries an /OpenAction that opens an external URL when the file is opened. The verdict is Suspicious rather than Malicious because the payload is inert and vendor-domain confusion can occasionally be legitimate; the correct next step is an out-of-band telephone confirmation with the vendor before any mandate change.',
    bodyText:
      'Dear Sir/Madam,\n\n' +
      'Please note that our banking details have changed with effect from this month. Kindly release the pending payment against invoice BNI/2026/1184 (Rs 42,17,500) to the revised account in the attached mandate.\n\n' +
      'Copy of the invoice and revised mandate: bharatnirman-infra.co.in/invoices/1184\n\n' +
      'Our earlier account with the previous bank has been closed, so payments to it will be returned. An early release would be appreciated as the quarter closes on 30 September.\n\n' +
      'Thanks and regards,\n' +
      'Accounts Department\n' +
      'Bharat Nirman Infra Pvt Ltd\n',
    links: [{
      shown: 'bharatnirman-infra.co.in/invoices/1184',
      actual: 'https://bharatnirman-infra.co/invoice/1184?ref=pgb-ops',
      redirects: [],
      verdict: 'Suspicious — lookalike domain, document lure'
    }],
    attachments: [
      { name: 'Revised_Bank_Mandate_BNI-1184.pdf', sha256: hex64('EM-2409|mandate.pdf'), type: 'application/pdf', verdict: 'Suspicious — /OpenAction to external URL' },
      { name: 'Invoice_BNI_2026_1184.pdf', sha256: hex64('EM-2409|invoice.pdf'), type: 'application/pdf', verdict: 'Clean' }
    ],
    hops: [
      { index: 0, host: 'vps-sg-1188.ovhcloud-host.net', ip: '139.99.102.14', asn: 'AS16276', org: 'OVH SAS', country: 'Singapore', countryCode: 'SG', city: 'Singapore', lat: 1.3521, lon: 103.8198, timestamp: '2026-09-11T12:14:07Z', delayMs: 0, tls: 'TLSv1.3', flags: ['first external hop', 'datacentre VPS', 'also hosts authoritative DNS for the sender domain'] },
      { index: 1, host: 'relay.mailerq-sg.net', ip: '51.79.140.22', asn: 'AS16276', org: 'OVH SAS', country: 'Singapore', countryCode: 'SG', city: 'Singapore', lat: 1.3521, lon: 103.8198, timestamp: '2026-09-11T12:16:52Z', delayMs: 165000, tls: 'TLSv1.2', flags: ['commercial SMTP relay', 'same ASN as origin'] },
      { index: 2, host: 'mx1.punjabgraminbank.in', ip: '14.142.61.38', asn: 'AS9498', org: 'Bharti Airtel Ltd', country: 'India', countryCode: 'IN', city: 'Chandigarh', lat: 30.7333, lon: 76.7794, timestamp: '2026-09-11T12:18:03Z', delayMs: 71000, tls: 'TLSv1.2', flags: ['recipient boundary MX', 'trusted'] },
      { index: 3, host: 'store-02.punjabgraminbank.in', ip: '14.142.61.44', asn: 'AS9498', org: 'Bharti Airtel Ltd', country: 'India', countryCode: 'IN', city: 'Chandigarh', lat: 30.7333, lon: 76.7794, timestamp: '2026-09-11T12:18:03Z', delayMs: 4000, tls: 'TLSv1.3', flags: ['internal delivery', 'trusted'] }
    ],
    origin: { ip: '139.99.102.14', country: 'Singapore', city: 'Singapore', lat: 1.3521, lon: 103.8198, confidence: 0.86, method: 'first external Received header' },
    iocs: [
      { type: 'domain', value: 'bharatnirman-infra.co', confidence: 0.92, source: 'PRAMAAN lookalike engine' },
      { type: 'url', value: 'https://bharatnirman-infra.co/invoice/1184', confidence: 0.83, source: 'URL unwrap' },
      { type: 'ipv4', value: '139.99.102.14', confidence: 0.78, source: 'PRAMAAN corpus' },
      { type: 'sha256', value: hex64('EM-2409|mandate.pdf'), confidence: 0.61, source: 'Attachment engine' },
      { type: 'bank-account', value: 'BARB0KHARAR / 19204471182', confidence: 0.97, source: 'NLP entity extraction (attachment)' }
    ],
    relatedCampaigns: [
      { id: 'CMP-0049', name: 'Vendor mandate-change fraud (PSU banks)', similarity: 0.76, firstSeen: '2026-05-22', count: 63 },
      { id: 'CMP-0068', name: 'mailerq-sg.net relay cluster', similarity: 0.58, firstSeen: '2026-08-07', count: 37 }
    ],
    timeline: [
      { t: '2026-09-11T12:14:07Z', event: 'Message injected from OVH Singapore VPS 139.99.102.14.' },
      { t: '2026-09-11T12:18:03Z', event: 'Delivered to payments.ops@punjabgraminbank.in.' },
      { t: '2026-09-11T12:39:44Z', event: 'Flagged by the payments desk (mandate change without a signed request); submitted to PRAMAAN.' },
      { t: '2026-09-11T12:39:47Z', event: 'Analysis complete in 2.68 s — verdict Suspicious, score 79.' },
      { t: '2026-09-11T13:20:00Z', event: 'CASE-2026-0185 opened; vendor called back on the number of record — mandate change denied.' }
    ],
    evidenceLedger: buildLedger('EM-2409', [
      ['Raw RFC 5322 message (bni-mandate.eml, 318 KB)', '2026-09-11T12:39:44Z'],
      ['Parsed header block + Received chain (4 hops)', '2026-09-11T12:39:45Z'],
      ['Authentication result set (SPF softfail / DKIM pass / DMARC pass)', '2026-09-11T12:39:45Z'],
      ['Attachment analysis — Revised_Bank_Mandate_BNI-1184.pdf (/OpenAction)', '2026-09-11T12:39:46Z'],
      ['Lookalike engine report — .co vs .co.in vendor domain', '2026-09-11T12:39:46Z'],
      ['Vendor call-back note — mandate change denied by accounts head', '2026-09-11T13:41:12Z']
    ])
  });

  /* ---------------------------------------------------------------- EM-2408
     Malware delivery · macro attachment · payload redirect · AICTE victim   */
  emails.push({
    id: 'EM-2408',
    receivedAt: '2026-09-11T12:26:44+05:30',
    subject: 'GST notice 2026-27 — action required (ARN summary attached)',
    from: { display: 'GST Compliance Desk', address: 'notice@gst-refund-desk.in' },
    replyTo: 'notice@gst-refund-desk.in',
    to: 'accounts@aicte-india.org',
    verdict: 'Malicious',
    riskScore: 91,
    category: 'Malware delivery',
    rawHeaders:
      'Return-Path: <bounce@gst-refund-desk.in>\n' +
      'Delivered-To: accounts@aicte-india.org\n' +
      'Received: from mx2.aicte-india.org (mx2.aicte-india.org [164.100.158.21])\n' +
      '        by store-01.aicte-india.org (Postfix) with ESMTPS id 6B22nQ08\n' +
      '        (TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\n' +
      '        for <accounts@aicte-india.org>; Fri, 11 Sep 2026 12:26:44 +0530\n' +
      'Received: from smtp.bulkmailz.top (smtp.bulkmailz.top [193.42.33.156])\n' +
      '        by mx2.aicte-india.org (Postfix) with ESMTP id 8C50fR33\n' +
      '        for <accounts@aicte-india.org>; Fri, 11 Sep 2026 12:24:31 +0530\n' +
      'Received: from localhost.localdomain (static-89-37-66-204.rdsnet.ro [89.37.66.204])\n' +
      '        by smtp.bulkmailz.top (Postfix) with ESMTPA id 44d1e9b7;\n' +
      '        Fri, 11 Sep 2026 06:51:12 +0000\n' +
      'Message-ID: <gst-arn-88421-0911@gst-refund-desk.in>\n' +
      'From: "GST Compliance Desk" <notice@gst-refund-desk.in>\n' +
      'To: accounts@aicte-india.org\n' +
      'Subject: GST notice 2026-27 - action required (ARN summary attached)\n' +
      'Date: Fri, 11 Sep 2026 12:20:58 +0530\n' +
      'X-Mailer: Microsoft Outlook 16.0\n' +
      'X-Priority: 1 (Highest)\n' +
      'Authentication-Results: mx2.aicte-india.org;\n' +
      '        spf=fail (sender IP is 193.42.33.156) smtp.mailfrom=gst-refund-desk.in;\n' +
      '        dkim=none (message not signed);\n' +
      '        dmarc=fail action=quarantine header.from=gst-refund-desk.in\n' +
      'MIME-Version: 1.0\n' +
      'Content-Type: multipart/mixed; boundary="=_c7be1102"',
    auth: {
      spf: { result: 'fail', detail: 'gst-refund-desk.in publishes -all listing only 45.61.136.0/24; sending IP 193.42.33.156 is not authorised.' },
      dkim: { result: 'none', detail: 'No DKIM-Signature header present.' },
      dmarc: { result: 'fail', detail: 'p=quarantine, no aligned identifier. The message was accepted because the AICTE gateway policy was in monitor mode for this sender class.' }
    },
    signals: [
      { id: 'SG-01', name: 'Macro-enabled attachment with auto-exec', weight: 26, status: 'fired', engine: 'Attachment', evidence: 'GST_ARN_Summary_Sept2026.xlsm contains Workbook_Open VBA invoking WScript.Shell; VirusTotal 41/68.' },
      { id: 'SG-02', name: 'Payload URL in redirect chain', weight: 18, status: 'fired', engine: 'URL Unwrap', evidence: 'Terminal URL http://45.61.136.9/upd/gst_arn.hta serves an HTA dropper (URLhaus: online, 2026-09-09).' },
      { id: 'SG-03', name: 'SPF hard fail', weight: 15, status: 'fired', engine: 'Authentication', evidence: 'spf=fail; relay 193.42.33.156 (AS44477) is not in the sender policy.' },
      { id: 'SG-04', name: 'DMARC fail under quarantine policy', weight: 12, status: 'fired', engine: 'Authentication', evidence: 'p=quarantine and no aligned identifier — the message should not have been delivered.' },
      { id: 'SG-05', name: 'Government brand impersonation', weight: 13, status: 'fired', engine: 'Display-Name Spoof', evidence: '"GST Compliance Desk" over gst-refund-desk.in; the statutory domain is gst.gov.in.' },
      { id: 'SG-06', name: 'NLP intent: compliance threat + attachment lure', weight: 10, status: 'fired', engine: 'NLP Intent', evidence: 'Labels: authority_appeal 0.93, penalty_threat 0.9, open_attachment_instruction 0.95.' },
      { id: 'SG-07', name: 'Abusive relay infrastructure', weight: 9, status: 'fired', engine: 'Threat Intel', evidence: '193.42.33.156 (AS44477) listed by Spamhaus SBL and seen in 118 prior PRAMAAN samples.' },
      { id: 'SG-08', name: 'Forged X-Mailer fingerprint', weight: 6, status: 'fired', engine: 'Header Anomaly', evidence: 'Claims Outlook 16.0 but MIME boundary format and header order match a Postfix/PHP sender.' },
      { id: 'SG-09', name: 'Lookalike of an existing brand domain', weight: 5, status: 'fired', engine: 'Lookalike/Homoglyph', evidence: 'gst-refund-desk.in shares the "gst" keyword with gst.gov.in; permutation match, not a character-level lookalike.' },
      { id: 'SG-10', name: 'AI-generated text likelihood', weight: 0, status: 'clear', engine: 'AI-Text', evidence: 'Detector head 0.31 — text matches a template reused across 118 corpus samples rather than fresh generation.' }
    ],
    aiExplanation:
      'A malware-delivery mail dressed as a GST compliance notice to the AICTE accounts desk. The attached workbook is macro-enabled and runs on open, and forty-one of sixty-eight antivirus engines already flag its hash, so this is a known payload rather than a novel one. The embedded link adds a second delivery route, ending after one redirect at an HTA dropper hosted on a bare IP address. Authentication is unambiguous: SPF hard-fails and the domain publishes a quarantine policy, which means the gateway should have withheld this message and did not. Isolate the recipient workstation, check for WScript activity after 06:51 UTC on 11 September, and block both the workbook hash and the dropper IP.',
    bodyText:
      'Attention: Accounts Officer,\n\n' +
      'A discrepancy has been recorded against your GSTIN for the period 2026-27. The attached ARN summary must be verified and returned within 72 hours, failing which a penalty under Section 122 will be initiated and the refund claim will be withheld.\n\n' +
      'Open the attached file and enable editing to view the ARN table.\n' +
      'Alternatively: View ARN summary online\n\n' +
      'This is a system-generated notice. Do not reply.\n\n' +
      'GST Compliance Desk\n',
    links: [{
      shown: 'View ARN summary online',
      actual: 'http://45.61.136.9/upd/gst_arn.hta',
      redirects: ['https://drive-doc-viewer.pages.dev/arn?id=88421', 'http://45.61.136.9/upd/gst_arn.hta'],
      verdict: 'Malicious — HTA dropper'
    }],
    attachments: [
      { name: 'GST_ARN_Summary_Sept2026.xlsm', sha256: hex64('EM-2408|arn.xlsm'), type: 'application/vnd.ms-excel.sheet.macroEnabled.12', verdict: 'Malicious — auto-exec macro, VT 41/68' },
      { name: 'gst-header-logo.png', sha256: hex64('EM-2408|logo.png'), type: 'image/png', verdict: 'Clean' }
    ],
    hops: [
      { index: 0, host: 'static-89-37-66-204.rdsnet.ro', ip: '89.37.66.204', asn: 'AS9050', org: 'Telekom Romania Communication SA', country: 'Romania', countryCode: 'RO', city: 'Bucharest', lat: 44.4268, lon: 26.1025, timestamp: '2026-09-11T06:51:12Z', delayMs: 0, tls: 'none', flags: ['first external hop', 'HELO localhost.localdomain', 'likely compromised host'] },
      { index: 1, host: 'smtp.bulkmailz.top', ip: '193.42.33.156', asn: 'AS44477', org: 'Stark Industries Solutions Ltd', country: 'Bulgaria', countryCode: 'BG', city: 'Sofia', lat: 42.6977, lon: 23.3219, timestamp: '2026-09-11T06:54:31Z', delayMs: 199000, tls: 'none', flags: ['Spamhaus SBL listed', 'no opportunistic TLS', 'seen in 118 prior samples'] },
      { index: 2, host: 'mx2.aicte-india.org', ip: '164.100.158.21', asn: 'AS4758', org: 'National Informatics Centre', country: 'India', countryCode: 'IN', city: 'New Delhi', lat: 28.6139, lon: 77.209, timestamp: '2026-09-11T06:56:44Z', delayMs: 133000, tls: 'none', flags: ['recipient boundary MX', 'trusted', 'plaintext SMTP from relay'] }
    ],
    origin: { ip: '89.37.66.204', country: 'Romania', city: 'Bucharest', lat: 44.4268, lon: 26.1025, confidence: 0.71, method: 'first external Received header' },
    iocs: [
      { type: 'sha256', value: hex64('EM-2408|arn.xlsm'), confidence: 0.99, source: 'VirusTotal 41/68' },
      { type: 'url', value: 'http://45.61.136.9/upd/gst_arn.hta', confidence: 0.98, source: 'URLhaus' },
      { type: 'domain', value: 'gst-refund-desk.in', confidence: 0.94, source: 'PRAMAAN corpus' },
      { type: 'domain', value: 'bulkmailz.top', confidence: 0.96, source: 'Spamhaus DBL' },
      { type: 'ipv4', value: '193.42.33.156', confidence: 0.97, source: 'Spamhaus SBL' },
      { type: 'ipv4', value: '89.37.66.204', confidence: 0.54, source: 'GeoIP + corpus' }
    ],
    relatedCampaigns: [
      { id: 'CMP-0038', name: 'GST notice macro-dropper wave', similarity: 0.91, firstSeen: '2026-08-02', count: 118 },
      { id: 'CMP-0031', name: 'HostSailor NL relay cluster', similarity: 0.44, firstSeen: '2026-07-14', count: 118 }
    ],
    timeline: [
      { t: '2026-09-11T06:51:12Z', event: 'Message injected from 89.37.66.204 (Bucharest), HELO localhost.localdomain.' },
      { t: '2026-09-11T06:56:44Z', event: 'Delivered to accounts@aicte-india.org over plaintext SMTP.' },
      { t: '2026-09-11T06:58:02Z', event: 'Gateway sandbox queued the attachment; PRAMAAN verdict Malicious, score 91 in 3.12 s.' },
      { t: '2026-09-11T07:04:30Z', event: 'Message quarantined retroactively; recipient workstation isolated for triage.' },
      { t: '2026-09-11T07:22:15Z', event: 'CASE-2026-0184 opened; hash and dropper IP pushed to the NIC gateway blocklist.' }
    ],
    evidenceLedger: buildLedger('EM-2408', [
      ['Raw RFC 5322 message (gst-arn-notice.eml, 612 KB)', '2026-09-11T06:58:02Z'],
      ['Parsed header block + Received chain (3 hops)', '2026-09-11T06:58:02Z'],
      ['Authentication result set (SPF fail / DKIM none / DMARC fail p=quarantine)', '2026-09-11T06:58:03Z'],
      ['Attachment analysis + VBA dump (GST_ARN_Summary_Sept2026.xlsm)', '2026-09-11T06:58:05Z'],
      ['Sandbox report — process tree EXCEL.EXE -> wscript.exe -> mshta.exe', '2026-09-11T07:01:48Z'],
      ['URLhaus lookup result for 45.61.136.9/upd/gst_arn.hta', '2026-09-11T07:01:52Z'],
      ['Containment note — workstation FIN-PC-14 isolated', '2026-09-11T07:09:26Z']
    ])
  });

  /* ---------------------------------------------------------------- EM-2407
     Lookalike / homoglyph ministry domain · DKIM fail · IN relay hop        */
  emails.push({
    id: 'EM-2407',
    receivedAt: '2026-09-10T15:37:29+05:30',
    subject: 'Directive: submission of AISHE data on the revised portal (immediate)',
    from: { display: 'Ministry of Education, Government of India', address: 'aishe-cell@educatlon-gov.in' },
    replyTo: 'aishe.support@educatlon-gov.in',
    to: 'vc@mgsuniversity.ac.in',
    verdict: 'Malicious',
    riskScore: 85,
    category: 'Lookalike domain',
    rawHeaders:
      'Return-Path: <aishe-cell@educatlon-gov.in>\n' +
      'Delivered-To: vc@mgsuniversity.ac.in\n' +
      'Received: from smtp-in-3.mgsuniversity.ac.in (smtp-in-3.mgsuniversity.ac.in [103.21.124.14])\n' +
      '        by mx-store.mgsuniversity.ac.in (Postfix) with ESMTPS id 5E71pT62\n' +
      '        (TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\n' +
      '        for <vc@mgsuniversity.ac.in>; Thu, 10 Sep 2026 15:37:29 +0530\n' +
      'Received: from vps-in-2214.cloudhostin.net (vps-in-2214.cloudhostin.net [103.148.32.77])\n' +
      '        by smtp-in-3.mgsuniversity.ac.in (Postfix) with ESMTPS id 0A93wV18\n' +
      '        (TLSv1.3 cipher=TLS_AES_128_GCM_SHA256)\n' +
      '        for <vc@mgsuniversity.ac.in>; Thu, 10 Sep 2026 15:36:11 +0530\n' +
      'Received: from aishe-portal.educatlon-gov.in (unknown [43.154.22.61])\n' +
      '        by vps-in-2214.cloudhostin.net (Exim 4.97) with ESMTPSA id 1rPh2K-0003Nm-9c;\n' +
      '        Thu, 10 Sep 2026 10:02:44 +0000\n' +
      'Message-ID: <aishe-directive-2026-0910@educatlon-gov.in>\n' +
      'From: "Ministry of Education, Government of India" <aishe-cell@educatlon-gov.in>\n' +
      'Reply-To: aishe.support@educatlon-gov.in\n' +
      'To: vc@mgsuniversity.ac.in\n' +
      'Subject: Directive: submission of AISHE data on the revised portal (immediate)\n' +
      'Date: Thu, 10 Sep 2026 15:31:07 +0530\n' +
      'DKIM-Signature: v=1; a=rsa-sha256; d=educatlon-gov.in; s=default; c=relaxed/relaxed;\n' +
      '        bh=Qk9HVVNCT0RZSEFTSA==; b=Zm9yZ2VkU2lnbmF0dXJlQm9keUhhc2hNaXNtYXRjaA==\n' +
      'Authentication-Results: smtp-in-3.mgsuniversity.ac.in;\n' +
      '        spf=pass (sender IP is 103.148.32.77) smtp.mailfrom=educatlon-gov.in;\n' +
      '        dkim=fail (body hash did not verify) header.d=educatlon-gov.in;\n' +
      '        dmarc=fail action=none header.from=educatlon-gov.in\n' +
      'MIME-Version: 1.0\n' +
      'Content-Type: text/html; charset="utf-8"',
    auth: {
      spf: { result: 'pass', detail: 'educatlon-gov.in authorises 103.148.32.77 — the attacker-owned domain authorising its own relay.' },
      dkim: { result: 'fail', detail: 'Body hash did not verify for d=educatlon-gov.in, s=default: the body was altered after signing, or the signature was copied from another message.' },
      dmarc: { result: 'fail', detail: 'DKIM failed and SPF is aligned only to educatlon-gov.in, not to the impersonated education.gov.in.' }
    },
    signals: [
      { id: 'SG-01', name: 'Homoglyph sender domain', weight: 25, status: 'fired', engine: 'Lookalike/Homoglyph', evidence: 'educatlon-gov.in vs education.gov.in — "l" substituted for "i"; visual skeleton distance 1, confusable pair (i,l).' },
      { id: 'SG-02', name: 'Government brand impersonation', weight: 16, status: 'fired', engine: 'Display-Name Spoof', evidence: 'Display name "Ministry of Education, Government of India" over a non-gov.in registrable domain.' },
      { id: 'SG-03', name: 'DKIM body-hash failure', weight: 14, status: 'fired', engine: 'Authentication', evidence: 'dkim=fail (bh mismatch) for d=educatlon-gov.in — signature present but invalid.' },
      { id: 'SG-04', name: 'DMARC alignment failure', weight: 12, status: 'fired', engine: 'Authentication', evidence: 'No identifier aligned with the displayed ministry identity.' },
      { id: 'SG-05', name: 'Deceptive URL anchor', weight: 11, status: 'fired', engine: 'URL Unwrap', evidence: 'Anchor "https://aishe.gov.in/aishe/login" points to https://educatlon-gov.in/aishe/login; terminal page requests portal login and institution code.' },
      { id: 'SG-06', name: 'Relay hop inside the victim country', weight: 8, status: 'fired', engine: 'Geo Correlation', evidence: 'Injected from 43.154.22.61 (Hong Kong, AS132203) then relayed through an Indian VPS to look domestic to the MX.' },
      { id: 'SG-07', name: 'NLP intent: authority directive with deadline', weight: 9, status: 'fired', engine: 'NLP Intent', evidence: 'Labels: authority_appeal 0.94, credential_request 0.81, deadline_pressure 0.86.' },
      { id: 'SG-08', name: 'Newly registered domain', weight: 7, status: 'fired', engine: 'Threat Intel', evidence: 'educatlon-gov.in created 2026-08-30 (11 days); certificate issued by a free CA on the same day.' },
      { id: 'SG-09', name: 'Malicious attachment', weight: 0, status: 'clear', engine: 'Attachment', evidence: 'No attachments in this message.' }
    ],
    aiExplanation:
      'This mail impersonates the Ministry of Education using a homoglyph domain: educatlon-gov.in, where a lower-case L stands in for the I in "education". At a glance in a mail client the two are almost indistinguishable, which is the whole point of the attack. The DKIM signature is present but fails on the body hash, meaning the body was changed after signing or the signature was lifted from another message, and DMARC therefore fails against the displayed ministry identity. The message was injected from a Hong Kong host and then relayed through an Indian VPS, a deliberate step to make the last hop look domestic to the university gateway. The link it offers imitates the AISHE portal login and asks for the institution code alongside portal credentials.',
    bodyText:
      'To the Vice-Chancellor,\n\n' +
      'As per the revised AISHE 2026-27 data-capture schedule, all universities must re-submit institutional data on the revised portal. Submission on the old portal will not be counted and non-compliance will be reflected in the ranking framework.\n\n' +
      'Revised portal: https://aishe.gov.in/aishe/login\n\n' +
      'Kindly nominate a nodal officer and complete the submission within 48 hours of receipt of this directive.\n\n' +
      'AISHE Cell\n' +
      'Department of Higher Education\n' +
      'Ministry of Education, Government of India\n',
    links: [{
      shown: 'https://aishe.gov.in/aishe/login',
      actual: 'https://educatlon-gov.in/aishe/login?inst=mgsu',
      redirects: [],
      verdict: 'Malicious — credential harvesting'
    }],
    attachments: [],
    hops: [
      { index: 0, host: '(no PTR record)', ip: '43.154.22.61', asn: 'AS132203', org: 'Tencent Building, Kejizhongyi Avenue', country: 'Hong Kong', countryCode: 'HK', city: 'Hong Kong', lat: 22.3193, lon: 114.1694, timestamp: '2026-09-10T10:02:44Z', delayMs: 0, tls: 'TLSv1.3', flags: ['first external hop', 'cloud tenant', 'HELO aishe-portal.educatlon-gov.in'] },
      { index: 1, host: 'vps-in-2214.cloudhostin.net', ip: '103.148.32.77', asn: 'AS132559', org: 'Cloud Host India Pvt Ltd', country: 'India', countryCode: 'IN', city: 'Chennai', lat: 13.0827, lon: 80.2707, timestamp: '2026-09-10T10:06:11Z', delayMs: 207000, tls: 'TLSv1.3', flags: ['in-country relay (evasion)', 'SPF-authorised for the sender domain', 'hosts the phishing landing page'] },
      { index: 2, host: 'smtp-in-3.mgsuniversity.ac.in', ip: '103.21.124.14', asn: 'AS132335', org: 'Sify Technologies Ltd', country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.076, lon: 72.8777, timestamp: '2026-09-10T10:07:29Z', delayMs: 78000, tls: 'TLSv1.3', flags: ['recipient boundary MX', 'trusted'] }
    ],
    origin: { ip: '43.154.22.61', country: 'Hong Kong', city: 'Hong Kong', lat: 22.3193, lon: 114.1694, confidence: 0.79, method: 'first external Received header' },
    iocs: [
      { type: 'domain', value: 'educatlon-gov.in', confidence: 0.98, source: 'PRAMAAN lookalike engine' },
      { type: 'url', value: 'https://educatlon-gov.in/aishe/login', confidence: 0.96, source: 'URL unwrap + OpenPhish' },
      { type: 'ipv4', value: '43.154.22.61', confidence: 0.72, source: 'GeoIP + corpus' },
      { type: 'ipv4', value: '103.148.32.77', confidence: 0.84, source: 'PRAMAAN corpus' },
      { type: 'email', value: 'aishe.support@educatlon-gov.in', confidence: 0.93, source: 'Header parser' }
    ],
    relatedCampaigns: [
      { id: 'CMP-0042', name: 'FakeApproval — AICTE portal credential run', similarity: 0.68, firstSeen: '2026-08-29', count: 41 },
      { id: 'CMP-0061', name: 'gov.in homoglyph registration cluster', similarity: 0.83, firstSeen: '2026-08-30', count: 17 }
    ],
    timeline: [
      { t: '2026-09-10T10:02:44Z', event: 'Message injected from 43.154.22.61 (Hong Kong, AS132203).' },
      { t: '2026-09-10T10:06:11Z', event: 'Relayed via Indian VPS 103.148.32.77 (Chennai) to appear domestic.' },
      { t: '2026-09-10T10:07:29Z', event: 'Delivered to vc@mgsuniversity.ac.in.' },
      { t: '2026-09-10T10:31:50Z', event: 'Submitted to PRAMAAN by the VC secretariat; verdict Malicious, score 85 in 2.05 s.' },
      { t: '2026-09-10T11:02:00Z', event: 'CASE-2026-0182 opened; homoglyph domain reported to the .in registry and to CERT-In.' }
    ],
    evidenceLedger: buildLedger('EM-2407', [
      ['Raw RFC 5322 message (aishe-directive.eml, 41 KB)', '2026-09-10T10:31:50Z'],
      ['Parsed header block + Received chain (3 hops)', '2026-09-10T10:31:50Z'],
      ['Authentication result set (SPF pass / DKIM fail / DMARC fail)', '2026-09-10T10:31:51Z'],
      ['Homoglyph analysis — educatlon-gov.in vs education.gov.in', '2026-09-10T10:31:51Z'],
      ['Landing page screenshot (educatlon-gov.in/aishe/login)', '2026-09-10T10:31:53Z'],
      ['Registry abuse report submission receipt (.in NIXI)', '2026-09-10T11:14:07Z']
    ])
  });

  /* ---------------------------------------------------------------- EM-2406
     Legitimate · fully aligned NIC service notice                           */
  emails.push({
    id: 'EM-2406',
    receivedAt: '2026-09-10T10:05:12+05:30',
    subject: 'NIC email services: scheduled maintenance, 14 Sep 2026 02:00-04:00 IST',
    from: { display: 'NIC Email Services', address: 'noreply@nic.in' },
    replyTo: 'servicedesk@nic.in',
    to: 'it.admin@aicte-india.org',
    verdict: 'Safe',
    riskScore: 6,
    category: 'Legitimate',
    rawHeaders:
      'Return-Path: <noreply@nic.in>\n' +
      'Delivered-To: it.admin@aicte-india.org\n' +
      'Received: from mx2.aicte-india.org (mx2.aicte-india.org [164.100.158.21])\n' +
      '        by store-01.aicte-india.org (Postfix) with ESMTPS id 2F08hL77\n' +
      '        (TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\n' +
      '        for <it.admin@aicte-india.org>; Thu, 10 Sep 2026 10:05:12 +0530\n' +
      'Received: from mailrelay1.nic.in (mailrelay1.nic.in [164.100.129.14])\n' +
      '        by mx2.aicte-india.org (Postfix) with ESMTPS id 9D13kP41\n' +
      '        (TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\n' +
      '        for <it.admin@aicte-india.org>; Thu, 10 Sep 2026 10:04:48 +0530\n' +
      'Message-ID: <nic-maint-20260914-0001@nic.in>\n' +
      'From: "NIC Email Services" <noreply@nic.in>\n' +
      'Reply-To: servicedesk@nic.in\n' +
      'To: it.admin@aicte-india.org\n' +
      'Subject: NIC email services: scheduled maintenance, 14 Sep 2026 02:00-04:00 IST\n' +
      'Date: Thu, 10 Sep 2026 10:04:31 +0530\n' +
      'DKIM-Signature: v=1; a=rsa-sha256; d=nic.in; s=mail2026; c=relaxed/relaxed;\n' +
      '        bh=Tk9USUZJQ0FUSU9OQk9EWQ==; b=dmFsaWRzaWduYXR1cmVuaWNpbjIwMjZtYWlsMg==\n' +
      'Authentication-Results: mx2.aicte-india.org;\n' +
      '        spf=pass (sender IP is 164.100.129.14) smtp.mailfrom=nic.in;\n' +
      '        dkim=pass header.d=nic.in header.s=mail2026;\n' +
      '        dmarc=pass action=none header.from=nic.in\n' +
      'MIME-Version: 1.0\n' +
      'Content-Type: text/plain; charset="utf-8"',
    auth: {
      spf: { result: 'pass', detail: 'nic.in authorises 164.100.129.14 (include:_spf.nic.in).' },
      dkim: { result: 'pass', detail: 'Valid signature for header.d=nic.in, selector mail2026; body hash verified.' },
      dmarc: { result: 'pass', detail: 'Aligned on both SPF and DKIM with header.from=nic.in; policy p=reject satisfied.' }
    },
    signals: [
      { id: 'SG-01', name: 'SPF / DKIM / DMARC aligned', weight: 0, status: 'clear', engine: 'Authentication', evidence: 'All three pass and align with header.from=nic.in under p=reject.' },
      { id: 'SG-02', name: 'Lookalike sender domain', weight: 0, status: 'clear', engine: 'Lookalike/Homoglyph', evidence: 'nic.in is an allow-listed government domain of record; no confusable neighbour.' },
      { id: 'SG-03', name: 'Display-name impersonation', weight: 0, status: 'clear', engine: 'Display-Name Spoof', evidence: 'Display name and address domain both belong to NIC.' },
      { id: 'SG-04', name: 'Deceptive URL anchor', weight: 0, status: 'clear', engine: 'URL Unwrap', evidence: 'Single URL; anchor text and destination identical, host mail.nic.in, no redirects.' },
      { id: 'SG-05', name: 'Bulk-sender infrastructure', weight: 2, status: 'fired', engine: 'Header Anomaly', evidence: 'noreply mailbox with a bulk notification Message-ID pattern; expected for service notices.' },
      { id: 'SG-06', name: 'NLP intent: credential or payment request', weight: 0, status: 'clear', engine: 'NLP Intent', evidence: 'Labels: informational 0.97. No credential, payment or attachment instruction.' },
      { id: 'SG-07', name: 'Malicious attachment', weight: 0, status: 'clear', engine: 'Attachment', evidence: 'No attachments in this message.' },
      { id: 'SG-08', name: 'AI-generated text likelihood', weight: 4, status: 'fired', engine: 'AI-Text', evidence: 'Detector head 0.55 on a short templated notice — below the 0.75 action threshold, no weight escalation.' }
    ],
    aiExplanation:
      'A routine maintenance notice from NIC to the AICTE IT desk, and it authenticates cleanly: SPF, DKIM and DMARC all pass and all align with nic.in, which publishes a reject policy. The single link points at mail.nic.in with matching anchor text and no redirects, and there are no attachments. Two low-weight signals fired, both benign in context: the message comes from a noreply bulk-notification mailbox, and the templated prose scores moderately on the AI-text detector, which is expected for machine-generated service notices and never acts alone. Both hops stay inside AS4758 in New Delhi, consistent with NIC-hosted infrastructure. No action required.',
    bodyText:
      'Dear User,\n\n' +
      'NIC email services will undergo scheduled maintenance on 14 September 2026 between 02:00 and 04:00 IST. Webmail and IMAP access may be intermittent during this window. No action is required from your side.\n\n' +
      'Service status: https://mail.nic.in/status\n\n' +
      'For assistance, contact the NIC service desk at 1800-111-555.\n\n' +
      'NIC Email Services\n' +
      'National Informatics Centre\n',
    links: [{
      shown: 'https://mail.nic.in/status',
      actual: 'https://mail.nic.in/status',
      redirects: [],
      verdict: 'Benign — anchor matches destination'
    }],
    attachments: [],
    hops: [
      { index: 0, host: 'mailrelay1.nic.in', ip: '164.100.129.14', asn: 'AS4758', org: 'National Informatics Centre', country: 'India', countryCode: 'IN', city: 'New Delhi', lat: 28.6139, lon: 77.209, timestamp: '2026-09-10T04:34:31Z', delayMs: 0, tls: 'TLSv1.3', flags: ['first external hop', 'allow-listed government relay', 'PTR matches HELO'] },
      { index: 1, host: 'mx2.aicte-india.org', ip: '164.100.158.21', asn: 'AS4758', org: 'National Informatics Centre', country: 'India', countryCode: 'IN', city: 'New Delhi', lat: 28.6139, lon: 77.209, timestamp: '2026-09-10T04:34:48Z', delayMs: 17000, tls: 'TLSv1.3', flags: ['recipient boundary MX', 'trusted'] },
      { index: 2, host: 'store-01.aicte-india.org', ip: '164.100.158.30', asn: 'AS4758', org: 'National Informatics Centre', country: 'India', countryCode: 'IN', city: 'New Delhi', lat: 28.6139, lon: 77.209, timestamp: '2026-09-10T04:35:12Z', delayMs: 24000, tls: 'TLSv1.3', flags: ['internal delivery', 'trusted'] }
    ],
    origin: { ip: '164.100.129.14', country: 'India', city: 'New Delhi', lat: 28.6139, lon: 77.209, confidence: 0.94, method: 'first external Received header' },
    iocs: [],
    relatedCampaigns: [],
    timeline: [
      { t: '2026-09-10T04:34:31Z', event: 'Message injected from allow-listed NIC relay 164.100.129.14.' },
      { t: '2026-09-10T04:35:12Z', event: 'Delivered to it.admin@aicte-india.org.' },
      { t: '2026-09-10T04:36:02Z', event: 'Analysed by the IMAP connector sweep; verdict Safe, score 6 in 0.84 s.' }
    ],
    evidenceLedger: buildLedger('EM-2406', [
      ['Raw RFC 5322 message (nic-maintenance.eml, 6.4 KB)', '2026-09-10T04:36:02Z'],
      ['Parsed header block + Received chain (3 hops)', '2026-09-10T04:36:02Z'],
      ['Authentication result set (SPF pass / DKIM pass / DMARC pass, aligned)', '2026-09-10T04:36:03Z'],
      ['Verdict record — Safe, score 6', '2026-09-10T04:36:03Z']
    ])
  });

  /* ---------------------------------------------------------------- EM-2405
     Legitimate but urgency-flavoured · same display name as EM-2411         */
  emails.push({
    id: 'EM-2405',
    receivedAt: '2026-09-09T16:21:40+05:30',
    subject: 'AICTE Approval Process Handbook 2026-27 — last date for deficiency reply is 20 Sep',
    from: { display: 'AICTE Approval Bureau', address: 'approvals@aicte-india.org' },
    replyTo: 'approvals@aicte-india.org',
    to: 'registrar@mgsuniversity.ac.in',
    verdict: 'Safe',
    riskScore: 18,
    category: 'Legitimate',
    rawHeaders:
      'Return-Path: <approvals@aicte-india.org>\n' +
      'Delivered-To: registrar@mgsuniversity.ac.in\n' +
      'Received: from smtp-in-3.mgsuniversity.ac.in (smtp-in-3.mgsuniversity.ac.in [103.21.124.14])\n' +
      '        by mx-store.mgsuniversity.ac.in (Postfix) with ESMTPS id 8A44rJ19\n' +
      '        (TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\n' +
      '        for <registrar@mgsuniversity.ac.in>; Wed, 09 Sep 2026 16:21:40 +0530\n' +
      'Received: from smtp-out-2.aicte-india.org (smtp-out-2.aicte-india.org [164.100.60.15])\n' +
      '        by smtp-in-3.mgsuniversity.ac.in (Postfix) with ESMTPS id 3C90xN55\n' +
      '        (TLSv1.3 cipher=TLS_AES_128_GCM_SHA256)\n' +
      '        for <registrar@mgsuniversity.ac.in>; Wed, 09 Sep 2026 16:20:57 +0530\n' +
      'Message-ID: <aph-2026-27-deficiency-0909@aicte-india.org>\n' +
      'From: "AICTE Approval Bureau" <approvals@aicte-india.org>\n' +
      'To: registrar@mgsuniversity.ac.in\n' +
      'Subject: AICTE Approval Process Handbook 2026-27 - last date for deficiency reply is 20 Sep\n' +
      'Date: Wed, 09 Sep 2026 16:20:22 +0530\n' +
      'DKIM-Signature: v=1; a=rsa-sha256; d=aicte-india.org; s=ai2026; c=relaxed/relaxed;\n' +
      '        bh=QVBIQk9EWUhBU0hWQUxJRA==; b=dmFsaWRzaWduYXR1cmVhaWN0ZWluZGlhb3JnMjAyNg==\n' +
      'Authentication-Results: smtp-in-3.mgsuniversity.ac.in;\n' +
      '        spf=pass (sender IP is 164.100.60.15) smtp.mailfrom=aicte-india.org;\n' +
      '        dkim=pass header.d=aicte-india.org header.s=ai2026;\n' +
      '        dmarc=pass action=none header.from=aicte-india.org\n' +
      'MIME-Version: 1.0\n' +
      'Content-Type: multipart/mixed; boundary="=_41ab7d09"',
    auth: {
      spf: { result: 'pass', detail: 'aicte-india.org authorises 164.100.60.15 (NIC-hosted outbound, include:_spf.nic.in).' },
      dkim: { result: 'pass', detail: 'Valid signature for header.d=aicte-india.org, selector ai2026; body hash verified.' },
      dmarc: { result: 'pass', detail: 'Aligned on SPF and DKIM with header.from=aicte-india.org; policy p=quarantine satisfied.' }
    },
    signals: [
      { id: 'SG-01', name: 'SPF / DKIM / DMARC aligned', weight: 0, status: 'clear', engine: 'Authentication', evidence: 'All three pass and align with the sender of record aicte-india.org.' },
      { id: 'SG-02', name: 'Deadline / urgency language', weight: 6, status: 'fired', engine: 'NLP Intent', evidence: 'Labels: deadline_pressure 0.71, authority_appeal 0.44. Statutory deadline language, no credential or payment ask.' },
      { id: 'SG-03', name: 'Lookalike sender domain', weight: 0, status: 'clear', engine: 'Lookalike/Homoglyph', evidence: 'aicte-india.org is the domain of record; note EM-2411 impersonated this same display name from aicte-gov.in.' },
      { id: 'SG-04', name: 'Display-name impersonation', weight: 0, status: 'clear', engine: 'Display-Name Spoof', evidence: 'Display name "AICTE Approval Bureau" matches an allow-listed address on the AICTE domain.' },
      { id: 'SG-05', name: 'Attachment risk', weight: 3, status: 'fired', engine: 'Attachment', evidence: 'PDF form with an AcroForm and no JavaScript; VirusTotal 0/68, hash known-good from 6 prior circulars.' },
      { id: 'SG-06', name: 'Deceptive URL anchor', weight: 0, status: 'clear', engine: 'URL Unwrap', evidence: 'Anchor matches destination https://www.aicte-india.org/approval-process-handbook; no redirects.' },
      { id: 'SG-07', name: 'Header anomaly', weight: 0, status: 'clear', engine: 'Header Anomaly', evidence: 'From, Return-Path and Message-ID all on aicte-india.org; no Reply-To divergence.' },
      { id: 'SG-08', name: 'AI-generated text likelihood', weight: 5, status: 'fired', engine: 'AI-Text', evidence: 'Detector head 0.61 on formal circular prose; supporting signal only, never decisive.' }
    ],
    aiExplanation:
      'A genuine AICTE circular about the Approval Process Handbook, kept deliberately in the sample set because it looks superficially like the phishing message: the same display name, the same recipient and a hard deadline. The difference is everything that matters. It is sent from aicte-india.org, the domain of record, with SPF, DKIM and DMARC all passing and aligned; the link anchor matches its destination on the same domain; and the attached PDF is a known-good form circulated six times before. Three low-weight signals fired — deadline language, an attachment present, and moderate AI-text score on formal prose — which together reach 18 and stay well inside Safe. This is the false-positive control: urgency alone is not fraud.',
    bodyText:
      'To the Registrar,\n\n' +
      'The Approval Process Handbook 2026-27 has been published on the AICTE web portal. Institutions that have received deficiency observations must submit their replies through the portal on or before 20 September 2026.\n\n' +
      'Handbook and schedule: https://www.aicte-india.org/approval-process-handbook\n\n' +
      'The prescribed deficiency reply format is attached. Queries may be raised through the portal grievance module; please do not reply to this address.\n\n' +
      'Approval Bureau\n' +
      'All India Council for Technical Education\n',
    links: [{
      shown: 'https://www.aicte-india.org/approval-process-handbook',
      actual: 'https://www.aicte-india.org/approval-process-handbook',
      redirects: [],
      verdict: 'Benign — anchor matches destination'
    }],
    attachments: [
      { name: 'APH_2026-27_Deficiency_Reply_Format.pdf', sha256: hex64('EM-2405|aph-format.pdf'), type: 'application/pdf', verdict: 'Clean — known-good hash' }
    ],
    hops: [
      { index: 0, host: 'smtp-out-2.aicte-india.org', ip: '164.100.60.15', asn: 'AS4758', org: 'National Informatics Centre', country: 'India', countryCode: 'IN', city: 'New Delhi', lat: 28.6139, lon: 77.209, timestamp: '2026-09-09T10:50:22Z', delayMs: 0, tls: 'TLSv1.3', flags: ['first external hop', 'allow-listed sender of record', 'PTR matches HELO'] },
      { index: 1, host: 'smtp-in-3.mgsuniversity.ac.in', ip: '103.21.124.14', asn: 'AS132335', org: 'Sify Technologies Ltd', country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.076, lon: 72.8777, timestamp: '2026-09-09T10:50:57Z', delayMs: 35000, tls: 'TLSv1.3', flags: ['recipient boundary MX', 'trusted'] },
      { index: 2, host: 'mx-store.mgsuniversity.ac.in', ip: '103.21.124.22', asn: 'AS132335', org: 'Sify Technologies Ltd', country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.076, lon: 72.8777, timestamp: '2026-09-09T10:51:40Z', delayMs: 43000, tls: 'TLSv1.3', flags: ['internal delivery', 'trusted'] }
    ],
    origin: { ip: '164.100.60.15', country: 'India', city: 'New Delhi', lat: 28.6139, lon: 77.209, confidence: 0.93, method: 'first external Received header' },
    iocs: [],
    relatedCampaigns: [],
    timeline: [
      { t: '2026-09-09T10:50:22Z', event: 'Message injected from the AICTE outbound relay 164.100.60.15 (NIC, New Delhi).' },
      { t: '2026-09-09T10:51:40Z', event: 'Delivered to registrar@mgsuniversity.ac.in.' },
      { t: '2026-09-09T10:53:11Z', event: 'Analysed by the IMAP connector sweep; verdict Safe, score 18 in 1.12 s.' },
      { t: '2026-09-12T04:09:40Z', event: 'Retained as the comparison baseline for CASE-2026-0188 (same display name, different domain).' }
    ],
    evidenceLedger: buildLedger('EM-2405', [
      ['Raw RFC 5322 message (aicte-handbook-circular.eml, 214 KB)', '2026-09-09T10:53:11Z'],
      ['Parsed header block + Received chain (3 hops)', '2026-09-09T10:53:11Z'],
      ['Authentication result set (SPF pass / DKIM pass / DMARC pass, aligned)', '2026-09-09T10:53:12Z'],
      ['Attachment analysis — APH_2026-27_Deficiency_Reply_Format.pdf (clean)', '2026-09-09T10:53:13Z'],
      ['Baseline comparison record linked to CASE-2026-0188', '2026-09-12T04:09:40Z']
    ])
  });

  /* =======================================================================
     DASHBOARD
     ======================================================================= */

  var dashboard = {
    kpis: {
      analysedToday: 1284,
      malicious: 37,
      suspicious: 112,
      safe: 1135,
      avgAnalysisMs: 2140,
      casesOpen: 6
    },
    threatsByDay: [
      { day: '30 Aug', malicious: 4, suspicious: 9, safe: 786 },
      { day: '31 Aug', malicious: 6, suspicious: 14, safe: 1042 },
      { day: '01 Sep', malicious: 5, suspicious: 11, safe: 1128 },
      { day: '02 Sep', malicious: 8, suspicious: 18, safe: 1190 },
      { day: '03 Sep', malicious: 7, suspicious: 16, safe: 1164 },
      { day: '04 Sep', malicious: 11, suspicious: 21, safe: 1207 },
      { day: '05 Sep', malicious: 6, suspicious: 13, safe: 902 },
      { day: '06 Sep', malicious: 3, suspicious: 7, safe: 611 },
      { day: '07 Sep', malicious: 9, suspicious: 19, safe: 1243 },
      { day: '08 Sep', malicious: 14, suspicious: 26, safe: 1281 },
      { day: '09 Sep', malicious: 31, suspicious: 58, safe: 1304 },
      { day: '10 Sep', malicious: 22, suspicious: 44, safe: 1266 },
      { day: '11 Sep', malicious: 18, suspicious: 39, safe: 1298 },
      { day: '12 Sep', malicious: 37, suspicious: 112, safe: 1135 }
    ],
    categoryBreakdown: [
      { category: 'Credential phishing', count: 46 },
      { category: 'Lookalike domain', count: 31 },
      { category: 'BEC/CEO fraud', count: 19 },
      { category: 'Invoice fraud', count: 24 },
      { category: 'Malware delivery', count: 15 },
      { category: 'Legitimate', count: 1149 }
    ],
    topOriginCountries: [
      { countryCode: 'NL', country: 'Netherlands', count: 34 },
      { countryCode: 'IN', country: 'India', count: 29 },
      { countryCode: 'RO', country: 'Romania', count: 21 },
      { countryCode: 'SG', country: 'Singapore', count: 17 },
      { countryCode: 'TR', country: 'Turkiye', count: 14 },
      { countryCode: 'HK', country: 'Hong Kong', count: 12 },
      { countryCode: 'BG', country: 'Bulgaria', count: 9 },
      { countryCode: 'US', country: 'United States', count: 8 }
    ],
    recentCases: [
      { caseId: 'CASE-2026-0188', emailId: 'EM-2411', status: 'Open', assignee: 'A. Nair (Tier-2 SOC)', openedAt: '2026-09-12T04:05:00Z' },
      { caseId: 'CASE-2026-0187', emailId: 'EM-2410', status: 'Open', assignee: 'S. Iyer (Fraud desk)', openedAt: '2026-09-12T03:10:00Z' },
      { caseId: 'CASE-2026-0185', emailId: 'EM-2409', status: 'Awaiting vendor', assignee: 'R. Bhatt (Bank CISO office)', openedAt: '2026-09-11T13:20:00Z' },
      { caseId: 'CASE-2026-0184', emailId: 'EM-2408', status: 'Containment', assignee: 'K. Deshmukh (IR)', openedAt: '2026-09-11T07:22:15Z' },
      { caseId: 'CASE-2026-0182', emailId: 'EM-2407', status: 'Reported to CERT-In', assignee: 'A. Nair (Tier-2 SOC)', openedAt: '2026-09-10T11:02:00Z' },
      { caseId: 'CASE-2026-0179', emailId: 'EM-2411', status: 'Closed', assignee: 'M. Farooqui (Cyber cell liaison)', openedAt: '2026-09-08T09:41:00Z' }
    ],
    engineHealth: [
      { engine: 'Header parser', status: 'operational', latencyMs: 38 },
      { engine: 'Authentication (SPF/DKIM/DMARC)', status: 'operational', latencyMs: 214 },
      { engine: 'Lookalike/Homoglyph', status: 'operational', latencyMs: 96 },
      { engine: 'Display-Name Spoof', status: 'operational', latencyMs: 22 },
      { engine: 'URL Unwrap (headless)', status: 'degraded', latencyMs: 1840 },
      { engine: 'Attachment + sandbox', status: 'queue backlog', latencyMs: 4120 },
      { engine: 'NLP Intent (DeBERTa-v3)', status: 'operational', latencyMs: 412 },
      { engine: 'AI-Text detector', status: 'operational', latencyMs: 268 },
      { engine: 'Geo/ASN correlation', status: 'operational', latencyMs: 74 },
      { engine: 'Threat Intel enrichment', status: 'operational', latencyMs: 626 },
      { engine: 'Evidence ledger + anchor', status: 'operational', latencyMs: 158 }
    ]
  };

  window.EFP_DATA = { emails: emails, dashboard: dashboard };

  /* =======================================================================
     EFP_MAP — equirectangular projection + hand-approximated low-poly land
     Polygons are arrays of [lat, lon] pairs.
     ======================================================================= */

  window.EFP_MAP = {
    project: function (lat, lon, width, height) {
      return {
        x: (Number(lon) + 180) / 360 * width,
        y: (90 - Number(lat)) / 180 * height
      };
    },
    land: [
      /* Africa */
      [[37, 10], [33, 22], [31, 32], [22, 37], [12, 43], [11, 51], [2, 46], [-5, 39],
       [-16, 40], [-26, 33], [-34, 26], [-34, 19], [-23, 14], [-17, 12], [-6, 12],
       [4, 9], [6, 3], [5, -4], [10, -13], [15, -17], [21, -17], [28, -12], [33, -6],
       [36, -2], [37, 10]],
      /* Eurasia */
      [[36, -9], [43, -9], [48, -5], [51, 2], [58, 5], [62, 5], [71, 28], [69, 33],
       [68, 44], [73, 55], [76, 69], [73, 80], [76, 100], [73, 113], [71, 130],
       [70, 160], [66, 180], [60, 163], [54, 142], [43, 132], [39, 122], [31, 122],
       [23, 117], [21, 109], [10, 107], [9, 100], [16, 95], [22, 89], [16, 80],
       [8, 78], [15, 73], [23, 69], [25, 57], [29, 48], [30, 32], [36, 36],
       [41, 29], [40, 20], [38, 16], [44, 12], [43, 5], [38, 0], [36, -9]],
      /* North America */
      [[70, -165], [71, -156], [70, -140], [68, -128], [68, -110], [67, -95], [64, -78],
       [60, -64], [52, -56], [47, -53], [45, -62], [41, -70], [35, -76], [30, -81],
       [25, -80], [30, -89], [26, -97], [19, -96], [16, -95], [19, -105], [23, -110],
       [28, -114], [34, -120], [40, -124], [48, -125], [55, -133], [59, -140],
       [60, -148], [58, -157], [63, -166], [66, -162], [70, -165]],
      /* South America */
      [[12, -72], [11, -64], [8, -60], [5, -52], [0, -50], [-5, -35], [-13, -39],
       [-23, -41], [-30, -50], [-35, -54], [-40, -62], [-50, -68], [-55, -68],
       [-52, -73], [-45, -74], [-37, -73], [-30, -71], [-23, -70], [-18, -70],
       [-12, -77], [-5, -81], [2, -79], [8, -77], [12, -72]],
      /* Australia */
      [[-11, 131], [-12, 137], [-16, 146], [-20, 149], [-25, 153], [-32, 153],
       [-38, 146], [-38, 141], [-35, 137], [-32, 134], [-34, 124], [-34, 115],
       [-26, 113], [-20, 119], [-14, 127], [-11, 131]],
      /* British Isles + Scandinavian tail for silhouette recognition */
      [[58, -5], [57, -2], [54, 0], [51, 1], [50, -5], [53, -5], [55, -6], [58, -5]]
    ]
  };
})();
