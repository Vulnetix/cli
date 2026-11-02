---
title: "VNX-SEC-059 – Linear API Key"
description: "Reports a hard-coded Linear personal API key (lin_api_ + 40 alphanumerics) or OAuth access token (lin_oauth_ + 64 hex), but not bare prefixes, placeholders, lookalike identifiers or keys read from the environment."
---

## Overview

This rule reports a Linear credential written into a file: a personal API key (`lin_api_` + 40 alphanumerics) or an OAuth access token (`lin_oauth_` + 64 hex), standing alone rather than inside a longer identifier and with enough entropy to be real. The snippet is redacted.

It does not report bare prefixes in a prefix check, placeholder bodies (`xxxx`, `YOUR_KEY_HERE`), identifiers that merely begin `lin_api_`, keys read from the environment, or test, fixture and vendored paths.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## What Gets Flagged

```typescript
// FLAGGED: API key passed to the SDK
export const linear = new LinearClient({ apiKey: "lin_api_<40 alphanumerics>" });
```

```yaml
# FLAGGED: OAuth token in a workflow
env:
  LINEAR_TOKEN: lin_oauth_<64 hex>
```

```typescript
// NOT FLAGGED: read from the environment
export const linear = new LinearClient({ apiKey: process.env.LINEAR_API_KEY });
```

## Why This Matters

Hardcoded linear api key values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
