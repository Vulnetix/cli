---
title: "VNX-GO-037 – Missing security headers in HTTP response"
description: "Detects Go web applications that serve HTML pages, templates or static files while no production Go file sets browser security headers directly or through middleware. Reported once per file."
---

## Overview

This rule flags Go web applications that serve pages to browsers (an html/template `Execute` into the response writer, a `text/html` Content-Type, gin/echo `c.HTML`, fiber `c.Render`, `http.FileServer`/`http.ServeFile`, or markup written with `fmt.Fprint(w, "<...")`) while no production Go file sets `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy` or the Cross-Origin policies. These headers instruct browsers to enforce protections that cannot be applied server-side. This maps to [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html).

The rule reports once per file, at the first line that serves a page, and only in a project that declares `func main` (a library or framework that only provides a renderer does not choose its users' headers). It stays silent when any non-test Go file in the project mentions a security header or a security-headers middleware (`unrolled/secure`, `gin-contrib/secure`, `middleware.Secure`), because a header set in middleware protects handlers in every other file. JSON and status-only responses, test servers and mocks are not reported.

**Severity:** Medium | **CWE:** [CWE-693 – Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) | **OWASP:** [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

## Why This Matters

Browser security headers form a second line of defence against injection and UI-redressing attacks. `X-Frame-Options: DENY` or the `frame-ancestors` CSP directive prevents clickjacking, where an attacker overlays an invisible iframe of a legitimate site onto a malicious page to capture clicks and credential entry. `X-Content-Type-Options: nosniff` prevents MIME-type confusion attacks where a browser might execute an uploaded image as JavaScript. `Strict-Transport-Security` (HSTS) ensures that once a user visits your site over HTTPS, all subsequent requests are automatically upgraded, closing a downgrade-attack window even if the user types `http://` in their browser.

`Content-Security-Policy` is the most powerful of these headers, allowing you to declare which sources of scripts, styles, fonts, and frames are legitimate — effectively eliminating entire categories of XSS and data-exfiltration attacks even when an injection vulnerability exists in the application. Many large-scale security incidents could have had their impact significantly reduced if a restrictive CSP had been in place. These headers cost nothing to serve and provide substantial depth-in-defence value.

## What Gets Flagged

In a project with a `func main`, the first line of each file that serves a browser-rendered page, when no production Go file sets a security header or uses a security-headers middleware:

```go
// FLAGGED: template rendered into the response
if err := tmpl.ExecuteTemplate(w, name, data); err != nil {

// FLAGGED: gin / fiber pages and static files
c.HTML(http.StatusOK, "index.tmpl", gin.H{"title": "Home"})
return http.StripPrefix("/static/", http.FileServer(http.Dir("public")))
app.Static("/", "./public")

// FLAGGED: markup written directly
fmt.Fprintf(w, "<html><body>Hello %s</body></html>", name(r))
```

Not flagged: JSON and status-only responses, a project where any file mentions `X-Frame-Options`, `Content-Security-Policy` (and the other headers) or uses `gin-contrib/secure`, `unrolled/secure` or `middleware.Secure`, libraries without a `main` (a renderer does not choose its users' headers), test servers, comments and strings.

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
