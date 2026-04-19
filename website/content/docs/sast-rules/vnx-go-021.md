---
title: "VNX-GO-021 – Potential XSS via fmt.Fprintf with HTML tags"
description: "Detects usage of fmt.Fprintf to output HTML tags combined with variables, which can lead to Cross-Site Scripting (XSS) if variables contain user-controlled data."
---

## Overview

This rule flags instances where `fmt.Fprintf` is used to output HTML tags along with variables that may contain user-controlled input. This pattern can lead to Cross-Site Scripting (XSS) vulnerabilities because the variables are not properly escaped before being included in HTML output.

This maps to [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html).

**Severity:** Medium | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) | **OWASP ASVS:** [V1.2.1 – Output Encoding for HTTP Responses](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

When using `fmt.Fprintf` to generate HTML responses, developers must ensure that any user-controlled data is properly escaped before being included in the output. Failure to escape user input allows attackers to inject malicious JavaScript that will execute in victims' browsers.

XSS vulnerabilities can lead to session hijacking, credential theft, defacement, or malware distribution. This is particularly dangerous in web applications that display user-generated content.

## What Gets Flagged

The rule flags any usage of `fmt.Fprintf` that contains HTML tags (both opening `<` and closing `>`) in Go source files.

```go
// FLAGGED: fmt.Fprintf with HTML tags and user input
func handler(w http.ResponseWriter, r *http.Request) {
    userInput := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<h1>Hello %s</h1>", userInput) // User input not escaped
}

// FLAGGED: fmt.Fprintf with HTML tags
func listItems(w http.ResponseWriter, items []string) {
    fmt.Fprintf(w, "<ul>")
    for _, item := range items {
        fmt.Fprintf(w, "<li>%s</li>", item) // Potential XSS if item is user-controlled
    }
    fmt.Fprintf(w, "</ul>")
}
```

## Remediation

1. **Use html/template package:** The safest way to generate HTML in Go is to use the `html/template` package, which automatically escapes data:
   ```go
   // SAFE: Use html/template for automatic escaping
   tmpl, _ := template.New("page").Parse("<h1>{{.}}</h1>")
   tmpl.Execute(w, userInput) // Automatically HTML-escaped
   ```

2. **Manually escape HTML:** If you must use fmt.Fprintf, escape user input using template.HTMLEscapeString:
   ```go
   // SAFE: Manually escape HTML
   import "html/template"
   
   func handler(w http.ResponseWriter, r *http.Request) {
       userInput := r.URL.Query().Get("name")
       escaped := template.HTMLEscapeString(userInput)
       fmt.Fprintf(w, "<h1>Hello %s</h1>", escaped)
   }
   ```

3. **Use template.FuncMap for custom functions:** Create safe helper functions for common HTML generation patterns:
   ```go
   // SAFE: Custom template function
   func safeURL(u string) template.URL {
       // Validate URL here
       return template.URL(u)
   }
   ```

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Application Security Verification Standard v4.0 – V1.2.1 Output Encoding for HTTP Responses](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Go html/template package documentation](https://pkg.go.dev/html/template)
- [Go fmt package documentation](https://pkg.go.dev/fmt)