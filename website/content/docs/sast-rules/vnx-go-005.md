---
title: "VNX-GO-005 – Go Open Redirect"
description: "Reports http.Redirect, gin/echo/fiber Redirect and hand-written Location headers whose destination starts with a request value, directly, through a variable, or behind a prefix that does not pin the host (\"//\", \"https://\", a bare \"/\"). Fixed hosts or paths, validated destinations and configuration values are not reported."
---

## Overview

This rule detects Go HTTP handlers where values from `r.URL.Query()`, `r.FormValue()`, or `r.URL.Path` are passed directly as the URL argument to `http.Redirect`. Without validation, an attacker can supply an arbitrary URL that points to a malicious site, causing your server to issue a redirect response that sends the victim's browser to that destination. This maps to [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html).

**Severity:** Medium | **CWE:** [CWE-601 – URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Why This Matters

Open redirects are exploited almost exclusively in phishing attacks (MITRE ATT&CK T1566). An attacker crafts a link like `https://yourtrustedsite.com/login?next=https://attacker.example/steal-creds` and shares it with targets. The victim's browser first touches your legitimate domain — satisfying link-preview trust checks, email security scanners, and the victim's own recognition of your brand — then immediately redirects to the attacker's page. The attacker's page can be a pixel-perfect clone of your login form. Victims who notice the initial domain are reassured, while the redirect destination is the one that captures their credentials. This technique is also used to bypass OAuth `redirect_uri` checks in systems that allow redirects through trusted domains.

## What Gets Flagged

The rule fires when the destination of `http.Redirect`, gin/echo `c.Redirect(code, url)`, fiber `c.Redirect(url)` or a `Location` header starts with a request value (`r.Referer()`, `r.Header.Get`, `r.URL.Query().Get`, `r.FormValue`, gin `c.Query`, echo `c.QueryParam`, `mux.Vars`, `chi.URLParam`, `r.PathValue`...). The value may be inline, in a variable assigned from it a few lines up, or behind a prefix that leaves the host open (`"//"+v`, `"https://"+v`, `"/"+v`). It does not fire for a fixed path or host (`"/items?id="+v`), a destination checked in between (`url.Parse` with a host test, `strings.HasPrefix` that also rejects `//`, an allowlist, `isLocalURL`), the request's own `r.URL.Path`, or configuration values. A bare `strings.HasPrefix(next, "/")` or a `url.Parse` whose result is never tested is not a check and is still reported: `//evil.example` passes the first and parses under the second.

```go
// FLAGGED: user-supplied "next" parameter redirected without validation
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // ... authenticate user ...
    next := r.URL.Query().Get("next")
    http.Redirect(w, r, next, http.StatusFound)
    // Attacker sends: /login?next=https://evil.example/fake-login
}
```

```go
// FLAGGED: form value used directly in redirect
func afterPaymentHandler(w http.ResponseWriter, r *http.Request) {
    returnURL := r.FormValue("return_url")
    http.Redirect(w, r, returnURL, http.StatusSeeOther)
}
```

## Remediation

1. **Validate the redirect target against an allowlist of permitted paths.** The simplest and most robust approach is to only allow redirects to paths within your own application — reject any URL that has a host component or that starts with `//`.

```go
import (
    "net/http"
    "net/url"
    "strings"
)

// SAFE: only allow relative paths within the same origin
func safeRedirect(w http.ResponseWriter, r *http.Request, target string, code int) {
    parsed, err := url.Parse(target)
    if err != nil || parsed.Host != "" || parsed.Scheme != "" || !strings.HasPrefix(target, "/") {
        http.Redirect(w, r, "/", code)
        return
    }
    http.Redirect(w, r, parsed.Path, code)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    next := r.URL.Query().Get("next")
    safeRedirect(w, r, next, http.StatusFound)
}
```

2. **Use an allowlist for external redirects.** If your application legitimately redirects to a fixed set of external domains (e.g., partner sites or OAuth providers), maintain an explicit allowlist and check the parsed hostname:

```go
var allowedHosts = map[string]bool{
    "partner.example.com": true,
    "auth.example.com":    true,
}

func validateRedirectURL(target string) (string, bool) {
    u, err := url.Parse(target)
    if err != nil {
        return "/", false
    }
    if u.Host != "" && !allowedHosts[u.Host] {
        return "/", false
    }
    return target, true
}
```

3. **Never embed the redirect destination in the URL when the destination is predictable.** If after login you always redirect to the user's dashboard, hard-code that path instead of reading it from the request.

## References

- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [Go net/url package documentation](https://pkg.go.dev/net/url)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
- [CAPEC-194: Fake the Source of Data](https://capec.mitre.org/data/definitions/194.html)
- [MITRE ATT&CK T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)
