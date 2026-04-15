---
title: "VNX-GO-012 – Go HTTP Response Header Injection (CRLF)"
description: "Detect Go code that passes user-controlled query or form input directly into HTTP response headers, enabling CRLF injection and response splitting attacks."
---

## Overview

This rule flags Go code where `w.Header().Set()` or `w.Header().Add()` receives a value sourced from `r.URL.Query().Get()` or `r.FormValue()` on the same line. If an attacker includes carriage return and line feed characters (`\r\n`) in the input, they can inject additional HTTP headers or split the response entirely, leading to cache poisoning, cross-site scripting, or session fixation. This maps to [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html).

**Severity:** Medium | **CWE:** [CWE-113 – Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html) | **OWASP ASVS:** [V5.2 – Sanitization and Sandboxing](https://owasp.org/www-project-application-security-verification-standard/)

> **Go idiom note:** Validating user input before placing it into response headers is expected Go practice but is NOT enforced by the standard library in Go versions before 1.22. Go 1.22+ added runtime validation that panics on CRLF in header values, but earlier versions silently write the injected content. The secure approach — allowlisting or sanitising header values — is NOT the default: it must be implemented explicitly.

## Why This Matters

HTTP header injection is a foundational web security vulnerability. By injecting `\r\n` into a response header value, an attacker can add arbitrary headers (e.g., `Set-Cookie` for session fixation), inject a blank line followed by a malicious HTML body (response splitting for reflected XSS), or poison shared caches (CDN or reverse proxy) with attacker-controlled content.

OWASP ASVS v4.0 requirement **V5.2.1** requires that all untrusted HTML input is sanitised. Requirement **V14.4.1** requires that HTTP response headers do not include sensitive information or enable injection attacks. CAPEC-86 documents the specific technique of injecting malicious content through HTTP headers. MITRE ATT&CK T1059 (Command and Scripting Interpreter) covers the code execution potential of injected content in split responses.

`go vet` does not detect this pattern. [staticcheck](https://staticcheck.dev/) does not have a dedicated check for header CRLF injection. This rule provides detection that neither standard toolchain nor common linters cover.

## What Gets Flagged

The rule fires when `w.Header().Set()` or `w.Header().Add()` appears on the same line as `r.URL.Query().Get()` or `r.FormValue()`.

```go
// FLAGGED: user input directly in response header
func handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Language", r.URL.Query().Get("lang"))
}

// FLAGGED: form value in custom header
func handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("X-Request-Id", r.FormValue("requestId"))
}
```

## Remediation

1. **Use an allowlist for expected header values.** This is the strongest defence and the idiomatic Go approach for bounded sets of valid values such as language codes, content types, or region codes:

```go
// SAFE: allowlist validation — only known-safe values are ever written to the header
var validLanguages = map[string]bool{"en": true, "fr": true, "de": true, "es": true}

func handler(w http.ResponseWriter, r *http.Request) {
    lang := r.URL.Query().Get("lang")
    if !validLanguages[lang] {
        lang = "en" // safe default
    }
    w.Header().Set("Content-Language", lang)
}
```

2. **Validate and sanitize header values** when the set of valid values is not bounded. Strip or reject input containing `\r`, `\n`, or non-printable characters:

```go
// SAFE: sanitize before writing to header
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

3. **Upgrade to Go 1.22+** where the standard library panics if a header value contains CRLF characters, providing a runtime safety net. However, relying solely on runtime panics is not a substitute for input validation — a panic in a production handler causes a 500 response and log noise, and may itself be used as a denial-of-service vector.

```go
// Go 1.22+: the runtime will panic if lang contains \r or \n
// This is a last-resort safety net, not a primary control
w.Header().Set("Content-Language", lang)
```

4. **For redirect URLs**, use `http.Redirect()` rather than manually setting `Location` headers, as it applies its own sanitisation.

## References

- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
- [OWASP Application Security Verification Standard v4.0 – V5.2 Sanitization](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
- [Go 1.22 release notes – header validation](https://go.dev/doc/go1.22)
- [staticcheck – available checks](https://staticcheck.dev/docs/checks/)
- [CAPEC-86: XSS Through HTTP Headers](https://capec.mitre.org/data/definitions/86.html)
