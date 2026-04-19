---
title: "VNX-GO-029 – Hardcoded weak or default password"
description: "Detects password, passwd, or similar credential variables assigned common weak or default string values such as 'admin', 'password', or '123456'."
---

## Overview

This rule flags Go source code where variables with names like `password`, `passwd`, `pass`, or `pwd` are assigned well-known weak or default string values such as `"admin"`, `"password"`, `"123456"`, `"secret"`, or similar. Hardcoded credentials — whether used as defaults in configuration, embedded in initialization code, or left over from development — are a direct path to unauthorized access and are trivially found by static analysis, binary inspection, or simple string searches. This maps to [CWE-798: Use of Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html).

Default and hardcoded passwords are among the most frequently exploited weaknesses in deployed software. IoT devices, network appliances, and web applications with factory-default credentials have been the root cause of major botnets and infrastructure attacks. Even when intended only for development, such credentials frequently survive into production environments through misconfigured deployments or operator error.

**Severity:** High | **CWE:** [CWE-798 – Use of Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html) | **OWASP:** [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

## Why This Matters

Attackers routinely scan for services using default credentials as one of the first steps in reconnaissance. Tools like Shodan, Masscan, and Metasploit modules automate this at internet scale. A single default password left in a deployed service can grant full administrative access without any exploitation of other vulnerabilities. MITRE ATT&CK technique T1078.003 (Valid Accounts: Local Accounts) covers the use of default or hardcoded credentials to gain initial access.

Beyond active exploitation, hardcoded credentials embedded in source code become a persistent liability: they are often committed to public repositories, included in packaged binaries, and copied between projects. Rotating them typically requires a code change and redeployment, meaning they persist in production for far longer than dynamically managed secrets.

## What Gets Flagged

The rule flags assignments of common weak passwords to credential-named variables:

```go
// FLAGGED: default password hardcoded in initialization
var password = "admin"

// FLAGGED: weak password in struct literal
cfg := Config{
    Username: "admin",
    Passwd:   "password",
}

// FLAGGED: classic default in function
func newDBConnection() *sql.DB {
    pass := "123456"
    dsn := fmt.Sprintf("user:root password:%s@tcp(localhost)/app", pass)
    db, _ := sql.Open("mysql", dsn)
    return db
}
```

## Remediation

1. **Load credentials from environment variables** at runtime, never at compile time:
   ```go
   // SAFE: read from environment
   import "os"

   func getDBPassword() string {
       pw := os.Getenv("DB_PASSWORD")
       if pw == "" {
           panic("DB_PASSWORD environment variable is not set")
       }
       return pw
   }
   ```

2. **Use a secrets manager** such as HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager for production deployments:
   ```go
   // SAFE: retrieve from secrets manager at startup
   func loadSecrets(ctx context.Context, client *secretmanager.Client) (string, error) {
       name := "projects/my-project/secrets/db-password/versions/latest"
       result, err := client.AccessSecretVersion(ctx,
           &secretmanagerpb.AccessSecretVersionRequest{Name: name})
       if err != nil {
           return "", err
       }
       return string(result.Payload.Data), nil
   }
   ```

3. **For tests and local development**, use randomly generated credentials created at setup time — never check in real or weak passwords:
   ```go
   // SAFE: generate a random password for test setup
   import (
       "crypto/rand"
       "encoding/base64"
   )

   func randomPassword(n int) string {
       b := make([]byte, n)
       rand.Read(b)
       return base64.URLEncoding.EncodeToString(b)[:n]
   }
   ```

4. **Audit your repository history.** If a weak credential was ever committed, rotate it immediately and consider the affected system fully compromised. Use tools like `git-secrets` or `truffleHog` to prevent future commits containing credentials.

## References

- [CWE-798: Use of Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Top 10 A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Testing Guide – Testing for Default Credentials](https://owasp.org/www-project-web-security-testing-guide/)
- [CAPEC-256: SOAP Array Blowup](https://capec.mitre.org/data/definitions/256.html)
- [MITRE ATT&CK T1078.003 – Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [NIST SP 800-63B – Memorized Secret Authenticators](https://pages.nist.gov/800-63-3/sp800-63b.html)
