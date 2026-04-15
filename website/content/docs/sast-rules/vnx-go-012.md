---
title: "VNX-GO-012 – Go HTTP Response Header Injection (CRLF)"
description: "Detect Go code that passes user-controlled query or form input directly into HTTP response headers, enabling CRLF injection and response splitting attacks."
---

## Overview

This rule flags Go code where `w.Header().Set()` or `w.Header().Add()` receives a value sourced from `r.URL.Query().Get()` or `r.FormValue()` on the same line. If an attacker includes carriage return and line feed characters (`\r\n`) in the input, they can inject additional HTTP headers or split the response entirely, leading to cache poisoning, cross-site scripting, or session fixation. This maps to [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html).

**Severity:** Medium | **CWE:** [CWE-113 – Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)

## Why This Matters

HTTP header injection is a foundational web security vulnerability. By injecting `\r\n` into a response header value, an attacker can add arbitrary headers (e.g., `Set-Cookie` for session fixation), inject a blank line followed by a malicious HTML body (response splitting for reflected XSS), or poison shared caches (CDN or reverse proxy) with attacker-controlled content. Go's `net/http` package validates header values starting from Go 1.22 and silently drops headers containing `\r` or `\n`, but earlier versions are vulnerable and the code pattern itself signals a design flaw.

## What Gets Flagged

```go
// FLAGGED: user input directly in response header
func handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Language", r.URL.Query().Get("lang"))
}
```

## Remediation

1. **Validate and sanitize header values.** Strip or reject input containing `\r`, `\n`, or non-printable characters:

```go
// SAFE: sanitized header value
func isValidHeaderValue(s string) bool {
    for _, c := range s {
        if c == '\r' || c == '\n' || c < 0x20 {
            return false
        }
    }
    return true
}

func handler(w http.ResponseWriter, r *http.Request) {
    lang := r.URL.Query().Get("lang")
    if !isValidHeaderValue(lang) {
        http.Error(w, "invalid parameter", http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Language", lang)
}
```

2. **Use an allowlist for expected values:**

```go
// SAFE: allowlist validation
var validLanguages = map[string]bool{"en": true, "fr": true, "de": true}

func handler(w http.ResponseWriter, r *http.Request) {
    lang := r.URL.Query().Get("lang")
    if !validLanguages[lang] {
        lang = "en"
    }
    w.Header().Set("Content-Language", lang)
}
```

3. **Upgrade to Go 1.22+** where the standard library rejects headers containing CRLF characters.

## References

- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
- [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
- [CAPEC-86: XSS Through HTTP Headers](https://capec.mitre.org/data/definitions/86.html)
