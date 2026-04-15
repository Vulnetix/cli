---
title: "VNX-SEC-024 – OAuth Token Stored in localStorage"
description: "Detect JavaScript/TypeScript code that stores OAuth access tokens, refresh tokens, or ID tokens in localStorage, which is vulnerable to XSS-based theft."
---

## Overview

This rule detects JavaScript and TypeScript code that stores authentication tokens (access tokens, refresh tokens, ID tokens) in the browser's `localStorage`. While `localStorage` is convenient, it is accessible to **any** JavaScript running on the page — including scripts injected via Cross-Site Scripting (XSS) attacks. A single XSS vulnerability anywhere in your application or its third-party dependencies allows an attacker to exfiltrate all tokens stored in `localStorage`.

**Severity:** Medium | **CWE:** [CWE-922 – Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

## Why This Matters

Storing OAuth tokens in `localStorage` creates a direct path from XSS to account takeover:

- **XSS is common.** The OWASP Top 10 consistently lists XSS as one of the most prevalent web vulnerabilities. Third-party scripts (analytics, ads, chat widgets) expand the attack surface
- **localStorage has no access controls.** Any JavaScript on the origin can read `localStorage` — there is no same-origin sub-domain isolation, no expiry, and no `httpOnly` equivalent
- **Token theft is silent.** Unlike session cookies, `localStorage` reads produce no browser warnings, no network requests to intercept, and no server-side logs
- **Refresh tokens are especially dangerous.** If a refresh token is stolen, the attacker can mint new access tokens indefinitely, surviving even password changes
- **Regulatory implications.** GDPR, SOC 2, and PCI DSS all require appropriate protection of authentication credentials; `localStorage` does not meet this bar

## What Gets Flagged

```javascript
// Flagged: access token stored in localStorage
localStorage.setItem("access_token", response.data.access_token);

// Flagged: refresh token in localStorage
localStorage.setItem("refresh_token", tokens.refresh_token);

// Flagged: ID token in localStorage
localStorage.setItem("id_token", oidcResponse.id_token);

// Flagged: generic "token" key
localStorage.setItem("token", jwt);

// Flagged: auth_token key
localStorage.setItem("auth_token", authResult.token);
```

The rule skips `.lock`, `.sum`, `.min.js`, and `.min.css` files.

## Remediation

1. **Use `httpOnly` secure cookies for token storage.** Cookies with `httpOnly` and `Secure` flags cannot be read by JavaScript, eliminating the XSS token theft vector entirely:

   ```javascript
   // Server-side (Express.js example)
   res.cookie("access_token", token, {
     httpOnly: true,   // Not accessible via JavaScript
     secure: true,     // Only sent over HTTPS
     sameSite: "Lax",  // CSRF protection
     maxAge: 900000,   // 15 minutes
     path: "/",
   });
   ```

2. **Implement a Backend-for-Frontend (BFF) pattern.** Keep tokens entirely on the server side. The browser gets a session cookie; the BFF proxies API calls with the real token:

   ```
   Browser  ──cookie──>  BFF Server  ──bearer token──>  API
   ```

   This is the approach recommended by the OAuth 2.0 for Browser-Based Apps specification (RFC draft).

3. **If you must store tokens client-side, use `sessionStorage` with short-lived tokens.** `sessionStorage` is cleared when the tab closes, reducing the exposure window:

   ```javascript
   // Better than localStorage (but still vulnerable to XSS within the tab session)
   sessionStorage.setItem("access_token", shortLivedToken);
   ```

4. **Use in-memory storage for the most sensitive tokens.** Store tokens in a JavaScript closure or module-scoped variable — they survive page navigation via SPA routing but are cleared on refresh:

   ```javascript
   // auth.js module
   let accessToken = null;

   export function setToken(token) { accessToken = token; }
   export function getToken() { return accessToken; }
   // Token is never persisted to disk, never accessible via devtools Storage tab
   ```

5. **Implement Content Security Policy (CSP) to reduce XSS risk.** Even with proper token storage, CSP provides defense in depth:

   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
   ```

## References

- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
- [OWASP HTML5 Security Cheat Sheet – Local Storage](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CAPEC-60: Reusing Session IDs](https://capec.mitre.org/data/definitions/60.html)
- [MITRE ATT&CK T1539 – Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [OAuth 2.0 for Browser-Based Apps (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- [Auth0: Token Storage Best Practices](https://auth0.com/docs/secure/security-guidance/data-security/token-storage)
- [OWASP ASVS V3 – Session Management](https://owasp.org/www-project-application-security-verification-standard/)
