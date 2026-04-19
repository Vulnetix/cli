---
title: "VNX-NODE-028 – Missing Content-Security-Policy header"
description: "Detects Node.js HTTP response header calls that do not include a Content-Security-Policy header, leaving browsers without a defense-in-depth control against XSS."
---

## Overview

This rule detects calls to `res.writeHead()`, `res.setHeader()`, and `res.header()` (the Express alias) in JavaScript files where no `Content-Security-Policy`, `X-Content-Security-Policy`, or `X-WebKit-CSP` header is being set. Content Security Policy is a browser-enforced allowlist that restricts the origins from which scripts, styles, images, and other resources may be loaded. Without a CSP header, the browser applies no origin restrictions on resource loading, providing no secondary defence if XSS is achieved.

CSP does not prevent XSS from occurring — it is a defense-in-depth control that limits the impact of XSS that does occur. A strict CSP that prohibits inline scripts and restricts script sources to trusted domains prevents the most common post-XSS actions (data exfiltration, credential harvesting) by blocking the injected script from making outbound requests or loading attacker-controlled resources. This vulnerability is classified as CWE-693 (Protection Mechanism Failure).

**Severity:** Medium | **CWE:** [CWE-693 – Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) | **OWASP:** [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | **CAPEC:** [CAPEC-63 – Cross-Site Scripting (XSS)](https://capec.mitre.org/data/definitions/63.html)

## Why This Matters

Modern browser security models rely on security headers as a key layer of defense. The absence of a CSP means that if any XSS vulnerability exists elsewhere in the application (or in a third-party script), the attacker's injected code operates with unrestricted capabilities: it can load arbitrary external scripts, exfiltrate data to any domain, inject UI elements, or redirect the page. CSP reports (via `report-uri` or `report-to`) also provide runtime visibility into XSS attempts, which is lost without the header.

Regulators and security auditors (PCI-DSS, SOC 2 assessors) increasingly flag missing security headers as findings. Bug bounty programs typically accept missing CSP on sensitive pages as a valid low-to-medium severity report. Implementing CSP is a high-leverage control that pays dividends across all XSS vectors simultaneously.

## What Gets Flagged

```javascript
// FLAGGED: writeHead with no CSP header
res.writeHead(200, {
  'Content-Type': 'text/html',
  'X-Frame-Options': 'DENY',
});

// FLAGGED: setHeader call loop with no CSP set
res.setHeader('Content-Type', 'text/html');
res.setHeader('Cache-Control', 'no-store');

// FLAGGED: Express res.header without CSP
app.get('/', (req, res) => {
  res.header('X-Powered-By', 'MyApp');
  res.send(html);
});
```

## Remediation

1. Use the [helmet](https://helmetjs.github.io/) middleware for Express, which sets a conservative CSP and other security headers by default with a single `app.use(helmet())` call.
2. If helmet is not suitable, set a CSP manually via `res.setHeader('Content-Security-Policy', '...')` with a policy appropriate to your application's resource requirements.
3. Start with a report-only policy (`Content-Security-Policy-Report-Only`) to identify violations before enforcing, then tighten to enforcement mode.
4. Avoid `unsafe-inline` and `unsafe-eval` in script-src; instead use nonces or hashes for inline scripts.

```javascript
// SAFE: helmet applies a strong CSP and other security headers
const helmet = require('helmet');
const express = require('express');
const app = express();

app.use(helmet());

// SAFE: manual CSP header for custom policies
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'nonce-{RANDOM}'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  );
  next();
});
```

## References

- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [MDN Web Docs — Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [helmet.js — Node.js security middleware](https://helmetjs.github.io/)
- [CSP Evaluator — Google](https://csp-evaluator.withgoogle.com/)
- [PortSwigger Web Security Academy — Content Security Policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
