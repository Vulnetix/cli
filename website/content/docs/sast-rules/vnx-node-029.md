---
title: "VNX-NODE-029 – Missing HttpOnly flag on cookie"
description: "Detects Express cookie() or res.cookie() calls that do not set the httpOnly option, exposing cookies to JavaScript access and session hijacking via XSS."
---

## Overview

This rule detects calls to `cookie()` or `res.cookie()` in JavaScript files where the `httpOnly` option is absent or explicitly set to `false`. The `HttpOnly` flag instructs browsers to deny JavaScript access to a cookie via `document.cookie`. Without it, any XSS vulnerability in the application — or in a third-party script loaded by the page — can read session and authentication cookies and relay them to an attacker-controlled server, enabling complete session hijacking. This is classified as CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag).

Session tokens are the most valuable target of XSS attacks: a stolen session token provides the attacker with the victim's authenticated identity without requiring their password. The `HttpOnly` flag is one of the simplest and most effective mitigations for this attack path. It does not prevent all XSS impacts, but it specifically and reliably removes the ability to steal cookies via `document.cookie`, significantly raising the cost of a successful XSS exploitation.

**Severity:** Medium | **CWE:** [CWE-1004 – Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html) | **OWASP:** [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | **CAPEC:** [CAPEC-63 – Cross-Site Scripting (XSS)](https://capec.mitre.org/data/definitions/63.html)

## Why This Matters

Session hijacking via XSS-based cookie theft is one of the most impactful and easily executed web attacks. Once an attacker has a valid session token, they can impersonate the victim for as long as the session remains active — bypassing MFA, accessing sensitive account data, and performing actions on the victim's behalf. The attack requires no interaction beyond a successful XSS payload, which can be delivered via a crafted link, an injected ad, or a compromised third-party script.

The `HttpOnly` flag has been supported by all major browsers since Internet Explorer 6, making it a zero-cost, universally compatible mitigation. Its absence is flagged as a finding in penetration tests, bug bounty programs, and compliance audits (PCI-DSS requirement 6.4). It should be set on all cookies that do not require client-side JavaScript access — which, for session and authentication cookies, is always the case.

## What Gets Flagged

```javascript
// FLAGGED: session cookie set without httpOnly
res.cookie('sessionId', token, {
  secure: true,
  sameSite: 'strict',
});

// FLAGGED: no options object at all
res.cookie('auth', jwt);

// FLAGGED: httpOnly explicitly false
res.cookie('userId', userId, { httpOnly: false, secure: true });
```

## Remediation

1. Add `{ httpOnly: true }` to all `res.cookie()` calls. This single flag eliminates JavaScript access to the cookie.
2. Combine `httpOnly` with `secure: true` (HTTPS-only transmission) and `sameSite: 'strict'` or `'lax'` (CSRF mitigation) to form a complete cookie security configuration.
3. Use the `cookie-session` or `express-session` middleware with `httpOnly: true` in the session options object so that all session cookies are consistently secured.
4. Review whether any cookies genuinely need to be JavaScript-accessible — for most authentication and session cookies, they do not.

```javascript
// SAFE: session cookie with full security flags
res.cookie('sessionId', token, {
  httpOnly: true,   // not accessible via document.cookie
  secure: true,     // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 3600000,  // 1 hour in ms
  path: '/',
});

// SAFE: express-session with httpOnly enabled
const session = require('express-session');
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000,
  },
  resave: false,
  saveUninitialized: false,
}));
```

## References

- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [MDN Web Docs — Set-Cookie: HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Testing for Cookies Attributes](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
- [Express.js — res.cookie()](https://expressjs.com/en/api.html#res.cookie)
- [PortSwigger Web Security Academy — Stealing cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)
