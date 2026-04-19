---
title: "VNX-GO-030 – Missing Secure flag on cookie"
description: "Detects http.Cookie creation without the Secure attribute set to true, which allows session cookies to be transmitted over unencrypted HTTP connections."
---

## Overview

This rule flags Go code that creates an `http.Cookie` struct without setting `Secure: true`. The `Secure` attribute instructs browsers to transmit the cookie only over HTTPS connections. Without it, any cookie — including session tokens, authentication tokens, and CSRF tokens — can be intercepted in plaintext by a network attacker performing a passive eavesdrop or an active man-in-the-middle attack. This maps to [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html).

This is particularly dangerous for session management. Even if your application enforces HTTPS at the server level, a cookie without the `Secure` flag can be exposed the moment a user's browser makes any HTTP request to your domain — for example, by following a link to `http://` rather than `https://`. Mixed-content scenarios and HTTP-to-HTTPS redirect chains are common in real deployments and create a reliable interception window.

**Severity:** Medium | **CWE:** [CWE-614 – Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

The `Secure` flag is a defense-in-depth control that operates at the browser level: the browser itself refuses to send the cookie over unencrypted channels regardless of the application's redirect logic. Omitting it means the protection depends entirely on every HTTP request always redirecting to HTTPS, every link in the application using `https://`, and no intermediary ever downgrading the connection — assumptions that frequently fail in practice.

Passive interception on open Wi-Fi networks, HTTP downgrade attacks such as SSLstrip, and DNS-based interception can all expose session cookies that lack the `Secure` attribute. OWASP explicitly requires the `Secure` flag on all sensitive cookies in its Session Management Cheat Sheet, and CAPEC-63 (Simple Script Injection) documents cookie theft as a standard attack goal achievable when this flag is absent.

## What Gets Flagged

The rule flags `http.Cookie` struct literals where the `Secure` field is absent or explicitly set to `false`:

```go
// FLAGGED: Secure field not set (defaults to false)
cookie := &http.Cookie{
    Name:     "session_id",
    Value:    sessionToken,
    HttpOnly: true,
    Path:     "/",
}
http.SetCookie(w, cookie)

// FLAGGED: Secure explicitly disabled
http.SetCookie(w, &http.Cookie{
    Name:     "auth_token",
    Value:    token,
    Secure:   false,
    HttpOnly: true,
})
```

## Remediation

1. **Always set `Secure: true`** on cookies that carry session or authentication data:
   ```go
   // SAFE: Secure flag set
   cookie := &http.Cookie{
       Name:     "session_id",
       Value:    sessionToken,
       HttpOnly: true,
       Secure:   true,
       SameSite: http.SameSiteLaxMode,
       Path:     "/",
       MaxAge:   3600,
   }
   http.SetCookie(w, cookie)
   ```

2. **Set `HttpOnly: true` at the same time** to prevent JavaScript access, and configure `SameSite` to reduce CSRF exposure:
   ```go
   // SAFE: all recommended security attributes present
   func setSessionCookie(w http.ResponseWriter, token string) {
       http.SetCookie(w, &http.Cookie{
           Name:     "session",
           Value:    token,
           Path:     "/",
           MaxAge:   int(24 * time.Hour / time.Second),
           HttpOnly: true,
           Secure:   true,
           SameSite: http.SameSiteStrictMode,
       })
   }
   ```

3. **Use a helper function** that enforces secure defaults so individual call sites cannot accidentally omit the `Secure` flag:
   ```go
   // SAFE: centralized cookie factory enforces Secure
   func newSecureCookie(name, value string, maxAge int) *http.Cookie {
       return &http.Cookie{
           Name:     name,
           Value:    value,
           Path:     "/",
           MaxAge:   maxAge,
           HttpOnly: true,
           Secure:   true,
           SameSite: http.SameSiteLaxMode,
       }
   }
   ```

## References

- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Top 10 A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Go net/http – Cookie](https://pkg.go.dev/net/http#Cookie)
- [MDN – Set-Cookie: Secure](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure)
- [CAPEC-63: Simple Script Injection](https://capec.mitre.org/data/definitions/63.html)
