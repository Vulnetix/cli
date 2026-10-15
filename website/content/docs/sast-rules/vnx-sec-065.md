---
title: "VNX-SEC-065 – HTTP Basic Authentication Header"
description: "Detects literal HTTP Basic credentials: a \"Basic <base64>\" header value that decodes to a real user:password pair."
---

## Overview

This rule reports the string `Basic <base64>` (an `Authorization` header in a `.http` file, a `curl -H` argument, a headers dict or object, a `Header.Set` call, a constant, or the two-argument .NET `new AuthenticationHeaderValue("Basic", "...")`) when the base64 decodes to a printable `user:password` pair with a non-empty password. The decoded password is never printed.

It does not report headers built from variables (`"Basic " + token`, f-strings, `${VAR}`, `$(...)`), text that does not decode to a credential (`Basic authentication`, `Basic realm`), default or placeholder pairs (`admin:password`, `user:pass`, a password equal to the user), comment lines, Markdown/reStructuredText/AsciiDoc, and test, fixture, vendored and generated files.

## What Gets Flagged

```python
HEADERS = {"Authorization": "Basic c3ZjLWRlcGxveTpUcTh2TDJtWnA5V3g="}   # svc-deploy:Tq8vL2mZp9Wx
```

```go
req.Header.Set("Authorization", "Basic c3ZjLWRlcGxveTpUcTh2TDJtWnA5V3g=")
```

Not flagged:

```python
headers = {"Authorization": "Basic " + token}
DEFAULT = {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}   # admin:password
```

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded http basic authentication header values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
