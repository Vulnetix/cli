---
title: "VNX-NODE-008 – Node.js Open Redirect"
description: "Detects user input from req.query, req.params, or req.body passed directly to res.redirect(), enabling phishing attacks via open redirect."
---

## Overview

This rule detects Express route handlers where user-supplied request data (`req.query`, `req.params`, `req.body`, `request.query`) is passed directly to `res.redirect()` without validation. An open redirect allows an attacker to craft a URL on your trusted domain that redirects the victim to an arbitrary external site. This is CWE-601 (URL Redirection to Untrusted Site — Open Redirect).

**Severity:** Medium | **CWE:** [CWE-601 – URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html)

## Why This Matters

Open redirects are highly effective phishing enablers. An attacker constructs a link like `https://your-trusted-app.com/login?next=https://evil.com/phish` and sends it to targets. Because the link hostname is your legitimate domain, email security filters, link previews, and users familiar with your brand are all more likely to trust it. The victim clicks, lands briefly on your server, and is immediately bounced to the attacker's convincing replica of your login page. Credentials entered there go directly to the attacker.

Open redirects are also used as a redirect step in OAuth flows. An attacker who can control the redirect target may be able to capture OAuth authorization codes or access tokens by pointing the redirect to an attacker-controlled page that logs the query string.

## What Gets Flagged

The rule matches lines containing `res.redirect(req.query`, `res.redirect(req.params`, `res.redirect(req.body`, `res.redirect(request.query`, or `redirect(req.query`.

```javascript
// FLAGGED: redirect destination from query parameter
app.get('/login', (req, res) => {
  // ... authenticate user ...
  res.redirect(req.query.next);
});

// FLAGGED: redirect from route param
app.get('/go/:url', (req, res) => {
  res.redirect(req.params.url);
});
```

An attacker sends `GET /login?next=https://evil.com` and the server complies.

## Remediation

1. **Validate the redirect target against an explicit allowlist of permitted paths or domains.** For internal redirects, accept only relative paths that start with `/`:

   ```javascript
   // SAFE: only allow relative paths — prevents off-site redirect
   app.get('/login', (req, res) => {
     const next = req.query.next;
     const safeNext =
       next && next.startsWith('/') && !next.startsWith('//')
         ? next
         : '/dashboard';
     res.redirect(safeNext);
   });
   ```

2. **For redirects that must go to external domains, maintain an explicit allowlist:**

   ```javascript
   // SAFE: allowlist of permitted redirect domains
   const ALLOWED_REDIRECT_HOSTS = new Set([
     'app.example.com',
     'account.example.com',
   ]);

   function safeRedirect(res, target) {
     try {
       const url = new URL(target);
       if (!ALLOWED_REDIRECT_HOSTS.has(url.hostname)) {
         return res.redirect('/dashboard');
       }
       res.redirect(target);
     } catch {
       res.redirect('/dashboard');
     }
   }

   app.get('/oauth/callback', (req, res) => {
     safeRedirect(res, req.query.redirect_uri);
   });
   ```

3. **Use `new URL()` for robust URL parsing.** Avoid trying to validate URLs with regular expressions — they are easy to bypass with encodings, Unicode characters, or scheme variations. The `URL` constructor correctly normalises the input before you inspect `hostname`.

4. **Replace user-supplied redirect targets with server-side session state.** Store the intended destination in the session before redirecting to authentication, then read it from the session after login — the user never controls the redirect URL:

   ```javascript
   // SAFE: destination stored in session, not URL parameter
   app.get('/protected', (req, res) => {
     req.session.returnTo = req.originalUrl;
     res.redirect('/login');
   });

   app.post('/login', (req, res) => {
     // ... authenticate ...
     const dest = req.session.returnTo || '/dashboard';
     delete req.session.returnTo;
     res.redirect(dest);
   });
   ```

## References

- [CWE-601: URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html)
- [CAPEC-194: Fake the Source of Data](https://capec.mitre.org/data/definitions/194.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Node.js URL API – new URL()](https://nodejs.org/api/url.html#new-urlinput-base)
- [MITRE ATT&CK T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)
