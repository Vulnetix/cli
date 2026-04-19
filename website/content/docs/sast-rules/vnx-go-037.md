---
title: "VNX-GO-037 – Missing security headers in HTTP response"
description: "Detect Go HTTP handlers that write responses via WriteHeader, Header().Set, or http.ResponseWriter without setting essential browser security headers such as X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy."
---

## Overview

This rule flags Go HTTP handler functions that interact with `http.ResponseWriter` — by calling `WriteHeader`, `Header().Set`, `w.Write`, or `w.Header()` — without setting one or more of the following critical security headers: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Strict-Transport-Security`, or `Content-Security-Policy`. These headers instruct browsers to enforce security policies that cannot be applied server-side, and their absence exposes users to a class of attacks that are entirely preventable at zero functional cost. This maps to [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html).

The rule targets handlers that appear to produce HTML or API responses — indicated by `Content-Type: text/html` or generic response writing — where the absence of these headers is most impactful.

**Severity:** Medium | **CWE:** [CWE-693 – Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) | **OWASP:** [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

## Why This Matters

Browser security headers form a second line of defence against injection and UI-redressing attacks. `X-Frame-Options: DENY` or the `frame-ancestors` CSP directive prevents clickjacking, where an attacker overlays an invisible iframe of a legitimate site onto a malicious page to capture clicks and credential entry. `X-Content-Type-Options: nosniff` prevents MIME-type confusion attacks where a browser might execute an uploaded image as JavaScript. `Strict-Transport-Security` (HSTS) ensures that once a user visits your site over HTTPS, all subsequent requests are automatically upgraded, closing a downgrade-attack window even if the user types `http://` in their browser.

`Content-Security-Policy` is the most powerful of these headers, allowing you to declare which sources of scripts, styles, fonts, and frames are legitimate — effectively eliminating entire categories of XSS and data-exfiltration attacks even when an injection vulnerability exists in the application. Many large-scale security incidents could have had their impact significantly reduced if a restrictive CSP had been in place. These headers cost nothing to serve and provide substantial depth-in-defence value.

## What Gets Flagged

The rule fires on handler functions that write HTTP responses without a security header middleware or explicit header-setting calls.

```go
// FLAGGED: handler writes HTML response with no security headers
func homeHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    // No X-Frame-Options, X-Content-Type-Options, or CSP set
    fmt.Fprintf(w, "<html><body>Welcome</body></html>")
}

// FLAGGED: API handler missing security headers
func apiHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status":"ok"}`))
}
```

```go
// SAFE: security headers applied via middleware wrapping all handlers
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        next.ServeHTTP(w, r)
    })
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", homeHandler)
    http.ListenAndServe(":8080", securityHeaders(mux))
}
```

## Remediation

1. **Apply security headers in a single middleware** rather than in each handler. This ensures consistent coverage and makes it impossible to accidentally omit them from a new endpoint.

   ```go
   // SAFE: reusable security header middleware
   func SecurityHeadersMiddleware(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           h := w.Header()
           h.Set("X-Frame-Options", "DENY")
           h.Set("X-Content-Type-Options", "nosniff")
           h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
           h.Set("Content-Security-Policy",
               "default-src 'self'; script-src 'self'; object-src 'none'")
           h.Set("Referrer-Policy", "no-referrer")
           h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
           next.ServeHTTP(w, r)
       })
   }
   ```

2. **Use the `github.com/unrolled/secure` library** for production Go applications. It provides a battle-tested, configurable middleware for all major security headers and handles edge cases such as development vs production HSTS configuration.

3. **Validate headers are present in integration tests** using `httptest.ResponseRecorder` to assert on the headers returned by your handler chain.

## References

- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [CAPEC-63: Simple Script Injection](https://capec.mitre.org/data/definitions/63.html)
- [MDN Web Docs – Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [MDN Web Docs – Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
