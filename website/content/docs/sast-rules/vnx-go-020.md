---
title: "VNX-GO-020 – Use of template.HTML with potential user input"
description: "Detects usage of template.HTML function that may mark user input as safe, potentially leading to Cross-Site Scripting (XSS) vulnerabilities."
---

## Overview

This rule flags instances where `template.HTML` is used to mark a string as safe HTML without proper validation or sanitization. When user-controlled data is passed to `template.HTML`, it can lead to Cross-Site Scripting (XSS) vulnerabilities because the HTML template engine will treat the input as safe and render it directly without escaping.

This maps to [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html).

**Severity:** Medium | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) | **OWASP ASVS:** [V1.2.1 – Output Encoding for HTTP Responses](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

The `template.HTML` function in Go's `html/template` package tells the template engine that the provided string is safe HTML and should not be escaped. When this function is used with user-controlled input (such as form data, URL parameters, or HTTP headers), an attacker can inject malicious JavaScript that will execute in victims' browsers.

XSS vulnerabilities can lead to session hijacking, credential theft, defacement, or malware distribution. The vulnerability is particularly dangerous because it exploits the trust users have in a legitimate website.

## What Gets Flagged

The rule flags any usage of `template.HTML` in Go source files, regardless of the input source. While some uses may be safe (e.g., hardcoded strings), the rule errs on the side of caution since determining whether input is truly trusted requires complex data flow analysis.

```go
// FLAGGED: template.HTML used with request data
func handler(w http.ResponseWriter, r *http.Request) {
    userInput := r.URL.Query().Get("comment")
    tmpl, _ := template.New("page").Parse("<div>{{.}}</div>")
    tmpl.Execute(w, template.HTML(userInput)) // User input marked as safe
}

// FLAGGED: template.HTML used with form data
func profileHandler(w http.ResponseWriter, r *http.Request) {
    bio := r.FormValue("bio")
    tmpl.Execute(w, template.HTML(bio))
}
```

## Remediation

1. **Avoid using template.HTML with untrusted input:** Instead, let the template engine automatically escape your data by passing it directly:
   ```go
   // SAFE: Let template engine escape the input
   tmpl.Execute(w, userInput) // Will be HTML-escaped automatically
   ```

2. **Sanitize input before marking as safe:** If you must allow certain HTML tags, use a proper HTML sanitization library:
   ```go
   import "github.com/microcosm-cc/bluemonday"
   
   // SAFE: Sanitize before marking as HTML
   sanitizer := bluemonday.UGCPolicy()
   safeHTML := template.HTML(sanitizer.Sanitize(userInput))
   ```

3. **Use template functions for specific needs:** Rather than bypassing the safety mechanisms entirely, create custom template functions:
   ```go
   func safeLink(url string) template.URL {
       // Validate and sanitize URL here
       return template.URL(url)
   }
   // Then in template: <a href="{{.Link | safeLink}}">Click</a>
   ```

4. **Consider the context:** Remember that different contexts require different escaping (HTML vs JavaScript vs CSS vs URL). The `html/template` package handles HTML context automatically when you don't use `template.HTML`.

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Application Security Verification Standard v4.0 – V1.2.1 Output Encoding for HTTP Responses](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Go html/template package documentation](https://pkg.go.dev/html/template)
- [Bluemonday HTML Sanitizer](https://github.com/microcosm-cc/bluemonday)