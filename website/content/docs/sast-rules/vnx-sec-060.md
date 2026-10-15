---
title: "VNX-SEC-060 – Airtable Personal Access Token"
description: "Reports a hard-coded Airtable personal access token (pat + 14 alphanumerics + . + 64 hex) or a legacy key-prefixed API key when Airtable is named on that line or up to three code lines above it, but not placeholders, ordinary key-prefixed identifiers or tokens read from the environment."
---

## Overview

This rule reports an Airtable credential written into a file: a personal access token (`pat` + 14 alphanumerics + `.` + 64 hex) anywhere, and a legacy API key (`key` + 14 alphanumerics) only when Airtable (`airtable`, `AIRTABLE_API_KEY`, `Airrecord`) is named on that line or up to three code lines above it, because `key` followed by letters is an ordinary identifier. Each must stand alone and have enough entropy to be real. The snippet is redacted.

It does not report placeholder or low-entropy bodies, `key`-prefixed names on lines without Airtable context, tokens read from the environment, or test, fixture and vendored paths.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## What Gets Flagged

```python
# FLAGGED: personal access token passed to pyairtable
api = Api('pat<14 alphanumerics>.<64 hex>')
```

```ruby
# FLAGGED: legacy API key on an Airrecord line
Airrecord.api_key = "key<14 alphanumerics>"
```

```python
# NOT FLAGGED: an ordinary identifier that starts with "key"
cache_key = "keyAbc123Def456Gh"
```

## Why This Matters

Hardcoded airtable personal access token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
