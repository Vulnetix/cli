---
title: "VNX-GO-024 – Missing input validation on HTTP request parameters"
description: "Detects direct usage of HTTP request parameters without apparent validation, which can lead to injection and business logic bypass vulnerabilities."
---

## Overview

This rule flags instances where HTTP request parameters (from form data, query strings, headers, or context values) are used directly without apparent validation or sanitization. This pattern can lead to various security vulnerabilities including injection attacks, bypass of business logic, and other input validation issues.

This maps to [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html).

**Severity:** Medium | **CWE:** [CWE-20 – Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) | **OWASP ASVS:** [V5.2 – Input Validation](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

HTTP request parameters are controlled by users and can contain malicious input. When applications use this input directly without validation, attackers can inject malicious payloads that exploit vulnerabilities in downstream systems (databases, command shells, etc.) or bypass intended business logic.

Common attacks that result from missing input validation include SQL injection, command injection, cross-site scripting (XSS), path traversal, and business logic bypass.

## What Gets Flagged

The rule flags direct usage of common HTTP request parameter extraction methods in Go source files:

```go
// FLAGGED: Direct use of form data without validation
func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")
    // Used directly in database query or authentication
    authenticate(username, password) // Potential SQL injection
}

// FLAGGED: Direct use of query parameters
func searchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    // Used directly in search or command execution
    exec.Command("grep", query).Run() // Potential command injection
}

// FLAGGED: Direct use of header values
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    target := r.Header.Get("X-Target-URL")
    // Used directly in HTTP request
    http.Get(target) // Potential SSRF or open redirect
}

// FLAGGED: Direct use of context values
func apiHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) {
    userID := ctx.Value("userID")
    // Used directly in database access
    db.Query("SELECT * FROM orders WHERE user_id = ?", userID)
}
```

## Remediation

1. **Validate all input:** Implement validation for all HTTP request parameters based on expected format, type, and business rules:
   ```go
   // SAFE: Validate input before use
   func searchHandler(w http.ResponseWriter, r *http.Request) {
       query := r.URL.Query().Get("q")
       if !isValidSearchQuery(query) {
           http.Error(w, "Invalid search query", http.StatusBadRequest)
           return
       }
       // Now safe to use
       results := searchDatabase(query)
   }
   
   func isValidSearchQuery(s string) bool {
       // Implement validation logic: length, allowed characters, etc.
       return len(s) <= 100 && !containsDangerousChars(s)
   }
   ```

2. **Use allowlists where possible:** For inputs with known valid values:
   ```go
   // SAFE: Use allowlist for known values
   func sortHandler(w http.ResponseWriter, r *http.Request) {
       sortBy := r.URL.Query().Get("sort")
       allowed := map[string]bool{
           "name": true, "date": true, "price": true,
       }
       if !allowed[sortBy] {
           sortBy = "name" // Default safe value
       }
       // Now safe to use
   }
   ```

3. **Sanitize when appropriate:** For inputs that need to allow a range of values:
   ```go
   // SAFE: Sanitize input for specific contexts
   func redirectHandler(w http.ResponseWriter, r *http.Request) {
       url := r.URL.Query().Get("url")
       if isSafeURL(url) { // Validate it's a safe, allowed URL
           http.Redirect(w, r, url, http.StatusFound)
           return
       }
       http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
   }
   ```

4. **Use context validation:** For context values, ensure they're properly set and validated:
   ```go
   // SAFE: Validate context values
   func apiHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) {
       userIDVal := ctx.Value("userID")
       if userIDVal == nil {
           http.Error(w, "Unauthorized", http.StatusUnauthorized)
           return
       }
       userID, ok := userIDVal.(string)
       if !ok || !isValidUUID(userID) {
           http.Error(w, "Invalid user ID", http.StatusBadRequest)
           return
       }
       // Now safe to use
   }
   ```

## References

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Application Security Verification Standard v4.0 – V5.2 Input Validation](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Go net/http package documentation](https://pkg.go.dev/net/http)