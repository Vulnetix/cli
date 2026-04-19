---
title: "VNX-GO-034 – OAuth redirect URI without validation against allowlist"
description: "Detect Go HTTP handlers that pass user-controlled redirect URI values directly to http.Redirect without validating against an explicit allowlist, enabling open redirect attacks in OAuth flows."
---

## Overview

This rule flags Go code where `http.Redirect` or a `Redirect` call receives a redirect destination sourced from user-supplied input — `r.FormValue`, `r.URL.Query().Get`, `r.PostFormValue`, or `r.Header.Get` — without a preceding check against an allowlist, allowed list, or validity function such as `isAllowed`, `isValid`, `allowlist`, or `validRedirects`. OAuth 2.0 authorization endpoints are a high-value target because they are designed to redirect the browser; an attacker who can control the destination can silently redirect authorization codes or tokens to their own server.

This maps to [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) and is catalogued under CAPEC-610 (Cellular Traffic Intercept) in its broader redirect-abuse context.

**Severity:** Medium | **CWE:** [CWE-601 – URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) | **OWASP:** [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

## Why This Matters

Open redirects in OAuth flows are particularly dangerous because the authorization server is explicitly trusted to issue redirects as part of the protocol. An attacker who discovers an unvalidated `redirect_uri` parameter can craft a malicious authorization URL. When a legitimate user clicks it, the authorization code is sent to the attacker's server. The attacker can then exchange that code for access tokens, gaining full access to the victim's account without ever seeing their password.

Beyond OAuth, unvalidated redirects undermine phishing defenses. Users are trained to verify the initial domain before clicking, but a redirect from a trusted domain to a malicious one circumvents that check. Security teams and WAF rules that block external links from reaching sensitive applications are also bypassed because the initial request originates from a legitimate host. This technique is referenced in MITRE ATT&CK T1046 under network service scanning and lateral movement via trusted channels.

## What Gets Flagged

The rule fires when `http.Redirect` or `Redirect(` receives a value derived from request input with no allowlist guard visible on the same or immediately preceding lines.

```go
// FLAGGED: redirect destination taken directly from query parameter
func oauthCallback(w http.ResponseWriter, r *http.Request) {
    redirectURI := r.URL.Query().Get("redirect_uri")
    // No allowlist check — attacker controls the destination
    http.Redirect(w, r, redirectURI, http.StatusFound)
}

// FLAGGED: post form value forwarded without validation
func loginRedirect(w http.ResponseWriter, r *http.Request) {
    next := r.PostFormValue("next")
    http.Redirect(w, r, next, http.StatusSeeOther)
}
```

```go
// SAFE: redirect URI validated against an explicit allowlist
var allowedRedirects = map[string]bool{
    "https://app.example.com/callback": true,
    "https://beta.example.com/callback": true,
}

func oauthCallback(w http.ResponseWriter, r *http.Request) {
    redirectURI := r.URL.Query().Get("redirect_uri")
    if !allowedRedirects[redirectURI] {
        http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
        return
    }
    http.Redirect(w, r, redirectURI, http.StatusFound)
}
```

## Remediation

1. **Maintain a server-side allowlist of permitted redirect URIs** and reject any value not present in it. Never rely on client-supplied values being safe.

   ```go
   var validRedirects = map[string]struct{}{
       "https://app.example.com/oauth/callback": {},
       "https://mobile.example.com/callback":    {},
   }

   func isAllowed(uri string) bool {
       _, ok := validRedirects[uri]
       return ok
   }

   func handleOAuthRedirect(w http.ResponseWriter, r *http.Request) {
       redirectURI := r.FormValue("redirect_uri")
       if !isAllowed(redirectURI) {
           http.Error(w, "redirect_uri not permitted", http.StatusBadRequest)
           return
       }
       http.Redirect(w, r, redirectURI, http.StatusFound)
   }
   ```

2. **Register redirect URIs at client registration time** and look them up by client ID rather than accepting them from the request at all. The OAuth 2.0 specification (RFC 6749 §3.1.2) requires exact URI matching for confidential clients.

3. **For relative redirects** (same-origin only), parse the URI and confirm `Host` is empty and the scheme is absent before issuing the redirect.

   ```go
   import "net/url"

   func isSameOrigin(raw string) bool {
       u, err := url.Parse(raw)
       if err != nil || u.Host != "" || u.Scheme != "" {
           return false
       }
       return true
   }
   ```

## References

- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [RFC 6749 – The OAuth 2.0 Authorization Framework §3.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2)
- [CAPEC-610: Cellular Traffic Intercept](https://capec.mitre.org/data/definitions/610.html)
- [MITRE ATT&CK T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [Go net/url package documentation](https://pkg.go.dev/net/url)
