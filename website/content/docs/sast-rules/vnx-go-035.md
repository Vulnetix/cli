---
title: "VNX-GO-035 – Missing HttpOnly flag on cookie"
description: "Detect Go http.Cookie struct literals where HttpOnly is not set to true, leaving session cookies accessible to JavaScript and vulnerable to cross-site scripting theft."
---

## Overview

This rule flags any `http.Cookie` struct literal in Go source code that does not explicitly set `HttpOnly: true`. The `HttpOnly` attribute instructs browsers to withhold the cookie from JavaScript's `document.cookie` API. Without it, any cross-site scripting (XSS) vulnerability — however minor — can be escalated by an attacker to steal session tokens, authentication cookies, or any other sensitive value stored in cookies. This is mapped to [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html).

The flag has been supported by every major browser since 2009 and carries no functional cost for server-side session management. Its absence is almost always an oversight rather than a deliberate decision, making it a high-signal, low-noise indicator of a security gap.

**Severity:** Medium | **CWE:** [CWE-1004 – Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html) | **OWASP:** [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

## Why This Matters

Cross-site scripting remains one of the most prevalent vulnerabilities in web applications. When an attacker can execute arbitrary JavaScript in a victim's browser context — whether via a stored, reflected, or DOM-based XSS — the first action is typically to exfiltrate `document.cookie`. A session cookie without `HttpOnly` is directly readable, allowing the attacker to replay the cookie from another machine and hijack the session without ever obtaining the user's password.

This pattern is actively exploited in the wild. Browser extensions, injected third-party scripts, and supply-chain compromises of JavaScript dependencies can all read non-`HttpOnly` cookies silently. The `HttpOnly` flag does not prevent all XSS damage, but it eliminates the most common and most immediately impactful consequence: session hijacking. Even applications that believe they have no XSS vulnerabilities benefit from defence-in-depth, because new XSS vectors are regularly discovered in frameworks and libraries. CAPEC-63 (Simple Script Injection) describes the attack pattern this flag directly mitigates.

## What Gets Flagged

The rule fires on any `http.Cookie{...}` literal that lacks `HttpOnly: true`, including cookies used for session identifiers, CSRF tokens stored in cookies, and authentication tokens.

```go
// FLAGGED: HttpOnly not set — cookie is readable by JavaScript
func setSessionCookie(w http.ResponseWriter, sessionID string) {
    cookie := &http.Cookie{
        Name:   "session",
        Value:  sessionID,
        Path:   "/",
        Secure: true,
        // HttpOnly omitted — accessible to document.cookie
    }
    http.SetCookie(w, cookie)
}

// FLAGGED: explicit false is equally flagged
func setAuthCookie(w http.ResponseWriter, token string) {
    http.SetCookie(w, &http.Cookie{
        Name:     "auth_token",
        Value:    token,
        HttpOnly: false,
    })
}
```

```go
// SAFE: HttpOnly explicitly enabled
func setSessionCookie(w http.ResponseWriter, sessionID string) {
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    sessionID,
        Path:     "/",
        Secure:   true,
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
    })
}
```

## Remediation

1. **Set `HttpOnly: true` on every cookie that does not need to be read by JavaScript.** The vast majority of session and authentication cookies have no legitimate client-side JavaScript access requirement.

   ```go
   // SAFE: complete, hardened cookie configuration
   func issueSessionCookie(w http.ResponseWriter, id string, expires time.Time) {
       http.SetCookie(w, &http.Cookie{
           Name:     "session_id",
           Value:    id,
           Path:     "/",
           Expires:  expires,
           Secure:   true,   // HTTPS only
           HttpOnly: true,   // not accessible via document.cookie
           SameSite: http.SameSiteStrictMode,
       })
   }
   ```

2. **Audit all cookie creation sites**, including middleware, authentication libraries, and third-party integrations that may set cookies on your behalf. Centralize cookie creation through a single helper function so the flags are always applied consistently.

3. **Apply `Secure: true` alongside `HttpOnly: true`** to additionally prevent the cookie from being transmitted over unencrypted HTTP connections. Both flags together constitute the baseline for sensitive cookies.

## References

- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP HttpOnly](https://owasp.org/www-community/HttpOnly)
- [CAPEC-63: Simple Script Injection](https://capec.mitre.org/data/definitions/63.html)
- [MITRE ATT&CK T1059.007 – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [Go net/http Cookie documentation](https://pkg.go.dev/net/http#Cookie)
