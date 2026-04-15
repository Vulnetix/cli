---
title: "VNX-NODE-025 – Insecure express-session or cookie-session configuration"
description: "Detects express-session or cookie-session configured with secure:false or httpOnly:false cookie flags, which allow session tokens to be transmitted over HTTP or accessed by client-side JavaScript."
---

## Overview

This rule detects `express-session` and `cookie-session` middleware configurations that weaken session cookie security by setting `secure: false`, `httpOnly: false`, or `resave: true`. These settings control how browsers transmit and expose session cookies and represent the first line of defence against session hijacking attacks.

The `secure` flag instructs browsers to transmit the cookie only over HTTPS connections. When it is absent or set to `false`, the session cookie is sent with every HTTP request, including over unencrypted connections on coffee shop Wi-Fi, corporate proxies, or any network where traffic is intercepted. The `httpOnly` flag prevents JavaScript running in the page from reading the cookie via `document.cookie`, which limits the damage from XSS attacks — without it, a single reflected or stored XSS vulnerability gives an attacker immediate access to the victim's session token.

The `resave: true` flag, while not a direct security vulnerability, causes unnecessary session writes that increase session store load and can create race conditions in concurrent request scenarios.

**Severity:** Medium | **CWE:** [CWE-614 – Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

## Why This Matters

Session token theft is one of the most common and impactful attack outcomes. An attacker who obtains a valid session token can impersonate the authenticated user for the lifetime of the session without knowing their password. Session tokens are high-value targets for both passive network sniffing and active XSS exploitation.

HTTP-only networks are more common than developers expect — developer laptops on internal networks, staging environments, HTTP→HTTPS redirects that fire after a cookie is already set, and load balancers that terminate TLS before the Node.js process. Without `secure: true`, session cookies leak in all of these scenarios.

The combination of `secure: false` and `httpOnly: false` is particularly dangerous: it allows both network interception and JavaScript theft, meaning a single vulnerability anywhere in the application can compromise every authenticated session.

## What Gets Flagged

```javascript
// FLAGGED: secure:false — cookie transmitted over plain HTTP
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: false, httpOnly: true },
}));

// FLAGGED: httpOnly:false — cookie readable by JavaScript
app.use(cookieSession({
  name: 'session',
  keys: [process.env.COOKIE_KEY],
  cookie: { httpOnly: false },
}));

// FLAGGED (low): resave:true causes unnecessary session writes
app.use(session({ secret: 'abc', resave: true, saveUninitialized: false }));
```

## Remediation

1. **Set `cookie.secure: true`** and ensure the application is only accessible over HTTPS in production. Use an environment variable to conditionally allow `false` in local development.

2. **Set `cookie.httpOnly: true`** (this is the default in `express-session` but should be set explicitly for clarity).

3. **Set `cookie.sameSite: 'strict'` or `'lax'`** to mitigate CSRF attacks using the session cookie.

4. **Set `resave: false`** and `saveUninitialized: false` to reduce session store writes and avoid race conditions.

```javascript
// SAFE: secure session configuration
const session = require('express-session');

app.use(session({
  secret:            process.env.SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production', // HTTPS only in prod
    httpOnly: true,    // not accessible via document.cookie
    sameSite: 'strict', // CSRF mitigation
    maxAge:   3600000,  // 1 hour
  },
}));
```

## References

- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](https://capec.mitre.org/data/definitions/60.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [express-session npm documentation](https://www.npmjs.com/package/express-session)
- [MDN Web Docs – Set-Cookie: Secure](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure)
