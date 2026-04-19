---
title: "VNX-GO-025 – Potential open redirect via HTTP redirect"
description: "Detects HTTP redirects that use user-controlled input without validation, which can lead to open redirect vulnerabilities."
---

## Overview

This rule flags instances where HTTP redirect functions (like `http.Redirect`) use user-controlled input to determine the redirect destination without proper validation. This pattern can lead to open redirect vulnerabilities where attackers can redirect users to malicious websites.

This maps to [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html).

**Severity:** Medium | **CWE:** [CWE-601 – URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) | **OWASP ASVS:** [V4.1.2 – Redirect Validation](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

Open redirect vulnerabilities occur when an application accepts user-controlled input to determine the destination of a redirect without proper validation. Attackers can craft URLs that appear to link to a trusted site but actually redirect victims to malicious sites for phishing, malware distribution, or credential theft.

These vulnerabilities are often overlooked but can be highly effective in social engineering attacks because the initial URL appears legitimate.

## What Gets Flagged

The rule flags HTTP redirect functions that use request parameters, form data, headers, or context values as the redirect destination:

```go
// FLAGGED: Redirect using form data without validation
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // ... authentication logic ...
    redirectURL := r.FormValue("redirect")
    http.Redirect(w, r, redirectURL, http.StatusFound) // User-controlled redirect
}

// FLAGGED: Redirect using query parameters
func oauthCallback(w http.ResponseWriter, r *http.Request) {
    state := r.URL.Query().Get("state")
    redirectURL := fmt.Sprintf("/app?state=%s", state)
    http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect) // Potential open redirect
}

// FLAGGED: Redirect using header values
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    target := r.Header.Get("X-Redirect-URL")
    http.Redirect(w, r, target, http.StatusSeeOther) // User-controlled redirect
}

// FLAGGED: Redirect using context values
func apiHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) {
    redirectURL := ctx.Value("redirectURL").(string)
    http.Redirect(w, r, redirectURL, http.StatusFound) // From context
}
```

## Remediation

1. **Validate redirect URLs against an allowlist:** Only allow redirects to trusted domains or paths:
   ```go
   // SAFE: Validate against allowlist
   func loginHandler(w http.ResponseWriter, r *http.Request) {
       redirectURL := r.FormValue("redirect")
       if isAllowedRedirectURL(redirectURL) {
           http.Redirect(w, r, redirectURL, http.StatusFound)
           return
       }
       // Default to safe location
       http.Redirect(w, r, "/", http.StatusFound)
   }
   
   func isAllowedRedirectURL(url string) bool {
       // Parse URL and check host against allowed domains
       u, err := url.Parse(url)
       if err != nil {
           return false
       }
       allowed := map[string]bool{
           "example.com": true,
           "www.example.com": true,
       }
       return allowed[u.Host] && u.IsAbs() // Only absolute URLs to allowed domains
   }
   ```

2. **Use relative paths for internal redirects:** When redirecting within your own site:
   ```go
   // SAFE: Use relative paths that you control
   func handler(w http.ResponseWriter, r *http.Request) {
       // Validate it's a relative path without dangerous elements
       redirectPath := r.FormValue("redirect")
       if strings.HasPrefix(redirectPath, "/") && 
          !strings.Contains(redirectPath, "..") &&
          !strings.Contains(redirectPath, "//") {
           http.Redirect(w, r, redirectPath, http.StatusFound)
           return
       }
       http.Error(w, "Invalid redirect path", http.StatusBadRequest)
   }
   ```

3. **Implement redirect validation middleware:** Create reusable validation logic:
   ```go
   // SAFE: Middleware for redirect validation
   func redirectValidator(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           if r.URL.Path == "/redirect" {
               target := r.URL.Query().Get("url")
               if !isSafeRedirectTarget(target) {
                   http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
                   return
               }
           }
           next.ServeHTTP(w, r)
       })
   }
   ```

4. **Use URL parsing and validation:** Always parse and validate URLs properly:
   ```go
   // SAFE: Proper URL validation
   func isSafeRedirectTarget(input string) bool {
       if input == "" {
           return false
       }
       
       // Prevent protocol-relative URLs that could be dangerous
       if strings.HasPrefix(input, "//") {
           return false
       }
       
       u, err := url.Parse(input)
       if err != nil {
           return false
       }
       
       // Allow only relative paths or known safe absolute URLs
       if !u.IsAbs() {
           // Relative path - additional validation
           return strings.HasPrefix(u.Path, "/") && 
                  !strings.Contains(u.Path, "..")
       }
       
       // Absolute URL - check against allowlist
       allowedHosts := map[string]bool{
           "example.com": true,
           "trusted-partner.com": true,
       }
       return allowedHosts[u.Hostname()]
   }
   ```

## References

- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Application Security Verification Standard v4.0 – V4.1.2 Redirect Validation](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Open Redirect Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Open_Redirect_Cheat_Sheet.html)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
- [Go net/url package documentation](https://pkg.go.dev/net/url)