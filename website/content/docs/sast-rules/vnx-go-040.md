---
title: "VNX-GO-040 – Logging of sensitive data"
description: "Detect Go code that passes sensitive values such as passwords, secrets, tokens, or credentials directly to log output functions, which persists plaintext secrets in log files, SIEM systems, and log aggregation pipelines."
---

## Overview

This rule flags calls to standard library and popular logging package functions — `log.Print`, `log.Println`, `log.Printf`, `log.Fatal`, `log.Fatalf`, and their equivalents in `logrus`, `zap`, `zerolog`, and generic `logger.` invocations — where the arguments or format string include sensitive identifiers such as `password`, `passwd`, `secret`, `key`, `token`, `auth`, `credential`, `ssn`, `credit`, `card`, or `cvv`. Logging sensitive data exposes it to anyone with access to the log infrastructure, which typically includes far more people and systems than those authorised to handle the underlying credentials. This maps to [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html).

Sensitive data in logs is a persistent, silent risk: unlike a live API response, log data accumulates in files, is shipped to centralised aggregation platforms, archived to cold storage, and often retained for months or years.

**Severity:** High | **CWE:** [CWE-532 – Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) | **OWASP:** [A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)

## Why This Matters

Log infrastructure is rarely treated with the same security controls as credential storage systems. Log files are often world-readable on servers, replicated to insecure backup destinations, forwarded to cloud SIEM platforms with less granular access control, and visible to support engineers, DevOps personnel, and external contractors. A single `log.Printf("user %s authenticated with password %s", user, password)` statement can expose that password to dozens of people and systems that have no business need to see it.

Beyond internal exposure, compliance frameworks including PCI-DSS (Requirement 3), HIPAA (§164.312), GDPR (Article 32), and SOC 2 (CC6.1) explicitly prohibit logging authentication credentials, payment card data, and other sensitive personal information. A log file containing passwords or card numbers can constitute a reportable data breach. Attackers who compromise a logging pipeline or SIEM gain access to an aggregated, searchable archive of credentials across all users and time periods — a far more valuable target than a single account compromise.

## What Gets Flagged

The rule fires when a logging call's arguments contain variable names or string literals matching sensitive data patterns.

```go
// FLAGGED: password logged in error path
func authenticate(username, password string) error {
    user, err := db.FindUser(username)
    if err != nil {
        log.Printf("authentication failed for %s with password %s", username, password)
        return err
    }
    return nil
}

// FLAGGED: API token included in logrus debug output
func fetchData(token string) {
    logrus.Debugf("fetching data with auth token: %s", token)
    // ...
}

// FLAGGED: credit card number logged on error
func processPayment(cardNumber, cvv string) {
    log.Println("payment failed for card", cardNumber, "cvv", cvv)
}
```

```go
// SAFE: log the event without the sensitive value
func authenticate(username, password string) error {
    user, err := db.FindUser(username)
    if err != nil {
        // Log that authentication failed, not what the password was
        log.Printf("authentication failed for user %q: %v", username, err)
        return err
    }
    return nil
}

// SAFE: log a redacted placeholder or masked value
func fetchData(token string) {
    logrus.WithField("token_prefix", token[:8]+"****").Debug("fetching data")
}
```

## Remediation

1. **Never log the value of sensitive fields.** Log the event (authentication failure, token validation error) with enough context to diagnose problems (username, request ID, error type) but without the secret itself.

   ```go
   // SAFE: structured log with no sensitive value exposed
   func handleLogin(w http.ResponseWriter, r *http.Request) {
       username := r.FormValue("username")
       password := r.FormValue("password") // only used for auth check, never logged

       if err := auth.Verify(username, password); err != nil {
           log.Printf("login failed: user=%q reason=%v", username, err)
           http.Error(w, "invalid credentials", http.StatusUnauthorized)
           return
       }
       log.Printf("login success: user=%q", username)
   }
   ```

2. **Implement a redacting logger wrapper** that scrubs known-sensitive fields before writing log entries. This provides a safety net for cases where sensitive data is accidentally included in a struct that gets logged.

   ```go
   // SAFE: mask sensitive fields in log output
   func maskSecret(s string) string {
       if len(s) <= 4 {
           return "****"
       }
       return s[:4] + strings.Repeat("*", len(s)-4)
   }
   ```

3. **Use structured logging** (e.g. `zap`, `zerolog`, `slog`) with field-level redaction rules. Structured loggers make it easier to audit exactly which fields are logged and to apply redaction at the sink level.

4. **Scan log output in CI** using tools like `truffleHog` or `gitleaks` run against captured test logs to catch accidental credential logging before it reaches production.

## References

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Top 10 A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [CAPEC-63: Simple Script Injection](https://capec.mitre.org/data/definitions/63.html)
- [PCI-DSS Requirement 3 – Protect Stored Account Data](https://www.pcisecuritystandards.org/document_library/)
- [Go log/slog package documentation](https://pkg.go.dev/log/slog)
- [go.uber.org/zap documentation](https://pkg.go.dev/go.uber.org/zap)
