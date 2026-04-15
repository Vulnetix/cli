---
title: "VNX-NODE-004 – Express App Without Helmet"
description: "Detects Express applications that do not use helmet middleware, leaving them without critical HTTP security headers such as CSP, HSTS, and X-Frame-Options."
---

## Overview

This rule detects Express applications — identified by the presence of `express()` in a file — that do not import or apply the `helmet` middleware. Helmet sets a collection of HTTP response headers that instruct browsers to enforce security policies: Content Security Policy, HTTP Strict Transport Security, X-Frame-Options, X-Content-Type-Options, and others. Without these headers, browsers apply permissive defaults that enable clickjacking, MIME-type sniffing attacks, cross-site scripting amplification, and protocol downgrade attacks. This maps to CWE-693 (Protection Mechanism Failure).

**Severity:** Medium | **CWE:** [CWE-693 – Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Why This Matters

HTTP security headers are a browser-enforced second line of defence. If an attacker finds an XSS vector in your application, a strong Content Security Policy can prevent injected scripts from loading external payloads or exfiltrating data. Without `X-Frame-Options` or the frame-ancestors CSP directive, your login page can be embedded in an invisible iframe on an attacker's site and used to steal clicks or credentials (clickjacking). Without `Strict-Transport-Security`, a network-level attacker can downgrade HTTPS connections to HTTP on the first visit. Without `X-Content-Type-Options: nosniff`, a browser may execute a file uploaded as an image if it detects executable content — a classic polyglot attack.

These are all issues that bypass server-side controls entirely; they are enforced — or not — by the browser. Helmet provides all of them in a single, well-maintained package with sensible defaults that you can tighten incrementally.

## What Gets Flagged

The rule flags any source file that calls `express()` but does not reference the string `helmet` anywhere in the same file.

```javascript
// FLAGGED: Express app with no helmet
const express = require('express');
const app = express();

app.use(express.json());

app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
```

## Remediation

1. **Install helmet:**

   ```bash
   npm install helmet
   ```

2. **Apply it as the first middleware**, before any route definitions, so the headers are set on every response:

   ```javascript
   // SAFE: helmet applied to all routes
   const express = require('express');
   const helmet = require('helmet');

   const app = express();

   app.use(helmet()); // sets all default headers

   app.use(express.json());
   app.get('/', (req, res) => res.send('Hello'));
   app.listen(3000);
   ```

   The default `helmet()` call sets these headers:
   - `Content-Security-Policy` — restricts script, style, and resource origins
   - `Strict-Transport-Security` — enforces HTTPS for future visits
   - `X-Frame-Options: SAMEORIGIN` — prevents clickjacking
   - `X-Content-Type-Options: nosniff` — prevents MIME sniffing
   - `Referrer-Policy: no-referrer` — limits referrer leakage
   - `X-DNS-Prefetch-Control: off` — prevents DNS prefetching data leakage
   - `X-Download-Options: noopen` — IE-specific protection
   - `X-Permitted-Cross-Domain-Policies: none` — blocks Adobe Flash/Acrobat

3. **Tighten the Content Security Policy for your application.** The default CSP is strict but may break inline scripts or third-party resources you rely on. Configure it explicitly rather than disabling it:

   ```javascript
   // SAFE: customised CSP that permits your CDN and disables inline scripts
   app.use(
     helmet({
       contentSecurityPolicy: {
         directives: {
           defaultSrc: ["'self'"],
           scriptSrc: ["'self'", 'https://cdn.example.com'],
           styleSrc: ["'self'", "'unsafe-inline'"],
           imgSrc: ["'self'", 'data:', 'https:'],
         },
       },
     })
   );
   ```

4. **Add `helmet` to your ESLint config as a required import** using a custom rule or the `eslint-plugin-security` package, so any new Express file that omits it fails the linter immediately.

## References

- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [helmet npm package documentation](https://helmetjs.github.io/)
- [MDN – HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP Node.js Security Cheat Sheet – Use Helmet.js](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html#use-helmet)
- [Content Security Policy Quick Reference](https://content-security-policy.com/)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
