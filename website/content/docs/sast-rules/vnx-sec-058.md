---
title: "VNX-SEC-058 – Notion API Token"
description: "Reports a hard-coded Notion integration token (ntn_ + 11 digits + 35 alphanumerics, or a legacy secret_ token in a file that names Notion), but not bare prefixes, placeholders or tokens read from the environment."
---

## Overview

This rule reports a Notion integration token written into a file: the current format `ntn_` + 11 digits + 35 alphanumerics anywhere, and the legacy internal-integration format `secret_` + 43 alphanumerics only when the file mentions Notion, because `secret_` alone is too common a prefix. Each token must stand alone and have enough entropy to be real. The snippet is redacted.

It does not report bare prefixes in a prefix check, placeholder or low-entropy bodies, `secret_` identifiers in files unrelated to Notion, tokens read from the environment, or test, fixture and vendored paths.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## What Gets Flagged

```javascript
// FLAGGED: token passed to the SDK
const notion = new Client({ auth: "ntn_<11 digits><35 alphanumerics>" });
```

```python
# FLAGGED: legacy internal-integration secret in a Notion client
notion = Client(auth="secret_<43 alphanumerics>")
```

```typescript
// NOT FLAGGED: read from the environment
export const notion = new Client({ auth: process.env.NOTION_TOKEN });
```

## Why This Matters

Hardcoded notion api token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
