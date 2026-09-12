import pathlib
HEAD = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRAMAAN: AI Email Threat Detection, Geolocation and Forensic Intelligence</title>
<meta name="description" content="Open-source console that scores a suspicious email, explains every signal, traces the Received chain to a geolocated origin, and produces a hash-chained, blockchain-anchored evidence ledger. Prototype for Smart India Hackathon problem 26106.">
<meta name="keywords" content="email threat detection, phishing detection, business email compromise, email forensics, email header analysis, IP geolocation, lookalike domain, SPF DKIM DMARC, evidence chain, blockchain anchoring, CERT-In, Smart India Hackathon, AICTE">
<meta name="robots" content="index,follow"><link rel="canonical" href="https://brandmagis.me/pramaan/">
<meta property="og:type" content="website"><meta property="og:title" content="PRAMAAN: AI Email Threat Detection, Geolocation and Forensic Intelligence">
<meta property="og:description" content="Score a suspicious email, see exactly why, trace where it was injected, and export tamper-evident evidence. Open-source prototype, runs in the browser.">
<meta property="og:url" content="https://brandmagis.me/pramaan/"><meta property="og:image" content="https://brandmagis.me/pramaan/docs/social-preview.png">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="PRAMAAN: AI Email Threat Detection and Forensic Intelligence">
<meta name="twitter:description" content="Explainable phishing and BEC detection with hop-by-hop origin tracing and a blockchain-anchored evidence ledger."><meta name="twitter:image" content="https://brandmagis.me/pramaan/docs/social-preview.png">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"PRAMAAN","applicationCategory":"SecurityApplication","operatingSystem":"Web browser","url":"https://brandmagis.me/pramaan/","codeRepository":"https://github.com/thedhanrajsingh/pramaan","license":"https://opensource.org/licenses/MIT","description":"AI-powered email threat detection, geolocation and forensic intelligence platform prototype.","offers":{"@type":"Offer","price":"0","priceCurrency":"INR"}}</script>
</head><body style="margin:0">"""
root = pathlib.Path(__file__).parent
shell = (root/'spec'/'shell.html').read_text(encoding='utf-8')
tokens = (root/'spec'/'tokens.css').read_text(encoding='utf-8')
data = (root/'spec'/'data.js').read_text(encoding='utf-8')
sections = ''.join((root/'sections'/f'{s}.html').read_text(encoding='utf-8') + '\n' for s in ['overview','analyze','trace','forensics'])
assert '/*TOKENS*/' in shell and '<!--SECTIONS-->' in shell and '//DATA' in shell, 'shell markers missing'
out = shell.replace('/*TOKENS*/', tokens, 1).replace('<!--SECTIONS-->', sections, 1).replace('//DATA', data, 1)
(root/'index.html').write_text(HEAD + out + '</body></html>', encoding='utf-8')
print('index.html bytes:', len(out.encode('utf-8')))
