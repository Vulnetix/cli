---
title: "VNX-GO-012 – Go HTTP Response Header Set from a Request Parameter"
description: "Detect Go code that writes a query, form or route parameter into an HTTP response header (net/http, gin, echo, fiber, fasthttp), inline or through a variable, without neutralising or constraining it."
---

## Overview

This rule flags Go code where a response header is set from a query, form or route parameter, inline or through a variable, with no neutralising step. If an attacker includes carriage return and line feed characters (`\r\n`) in the input, they can inject additional HTTP headers or split the response entirely, leading to cache poisoning, cross-site scripting, or session fixation. This maps to [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html).

**Severity:** Medium | **CWE:** [CWE-113 – Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html) | **OWASP ASVS:** [V5.2 – Sanitization and Sandboxing](https://owasp.org/www-project-application-security-verification-standard/)

> **Go idiom note:** `net/http` replaces CR and LF in header values with spaces when it writes a response, so on servers built on it (net/http, gin, echo, chi, gorilla) the attacker cannot add headers or split the response. What remains is that the attacker chooses the content of the header: a `Location`, a `Content-Disposition` filename, a `Content-Language`. Servers that write header values without that replacement can be split. Allow-listing or encoding header values must be done explicitly either way.

## Why This Matters

HTTP header injection is a foundational web security vulnerability. By injecting `\r\n` into a response header value, an attacker can add arbitrary headers (e.g., `Set-Cookie` for session fixation), inject a blank line followed by a malicious HTML body (response splitting for reflected XSS), or poison shared caches (CDN or reverse proxy) with attacker-controlled content.

OWASP ASVS v4.0 requirement **V5.2.1** requires that all untrusted HTML input is sanitised. Requirement **V14.4.1** requires that HTTP response headers do not include sensitive information or enable injection attacks. CAPEC-86 documents the specific technique of injecting malicious content through HTTP headers. MITRE ATT&CK T1059 (Command and Scripting Interpreter) covers the code execution potential of injected content in split responses.

`go vet` does not detect this pattern. [staticcheck](https://staticcheck.dev/) does not have a dedicated check for header CRLF injection. This rule provides detection that neither standard toolchain nor common linters cover.

## What Gets Flagged

The rule reports a response-header write (`w.Header().Set/Add`, `w.Header()[k] = ...`, gin `c.Header`, echo `c.Response().Header().Set`, fiber `c.Set`/`c.Append`, fasthttp `ctx.Response.Header.Set/Add`) whose value is a query, form or route parameter (`r.URL.Query().Get`, `q.Get`/`q[k]` on `q := r.URL.Query()`, `FormValue`, `PostFormValue`, `Form.Get`, `mux.Vars`, `chi.URLParam`, `r.PathValue`, gin/echo/fiber `Query`/`Param`/`QueryParam`, fasthttp `QueryArgs().Peek`), inline or through a variable assigned from one in the same function.

```go
func Localised(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Language", r.URL.Query().Get("lang")) // FLAGGED
}

func Download(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    w.Header().Set("Content-Disposition", "attachment; filename="+name) // FLAGGED
}

func AfterLogin(w http.ResponseWriter, r *http.Request) {
    next := r.FormValue("next")
    if len(next) == 0 { // a length check does not neutralise the value
        next = "/home"
    }
    w.Header().Set("Location", next) // FLAGGED
}
```

Not reported: a value passed through `url.QueryEscape`/`PathEscape`, `url.Parse` (it rejects control characters), a parse that validates it (`uuid.Parse`, `netip.Parse*`, `time.Parse`, `mail.ParseAddress`), `strconv`, `mime.FormatMediaType`, `%q` formatting, a CR/LF replacer or a `strings.ContainsAny(v, "\r\n")` guard, an allow-list map lookup or `switch`; values derived through `len()`, a `mime` function or a hash; constant or server-derived values; a value echoed from the request's own headers (a client can only change its own response); headers on outbound requests; gin's `c.Set` (a context value, not a header); comments and strings.

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

3. **Do not rely on the server to neutralise the value.** `net/http` turns CR and LF into spaces when it writes headers, which stops response splitting but still sends the attacker's text as the header's content. Other servers may not do even that. Validate the value against what the header may hold.

```go
// net/http writes "en\r\nSet-Cookie: x=y" as "en  Set-Cookie: x=y":
// no new header, but still not a language tag.
w.Header().Set("Content-Language", lang)
```

4. **For redirect URLs**, use `http.Redirect()` rather than manually setting `Location` headers, as it applies its own sanitisation.

## References

- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
- [OWASP Application Security Verification Standard v4.0 – V5.2 Sanitization](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
- [staticcheck – available checks](https://staticcheck.dev/docs/checks/)
- [CAPEC-86: XSS Through HTTP Headers](https://capec.mitre.org/data/definitions/86.html)
