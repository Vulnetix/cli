---
title: "VNX-SEC-070 – 1Password Secret Key / Service Account"
description: "Detects 1Password service account tokens (ops_eyJ...) and account Secret Keys (A3-XXXXXX-...) in any file."
---

## Overview

This rule reports a 1Password service account token (`ops_eyJ` followed by at least 50 base64url characters, the value `OP_SERVICE_ACCOUNT_TOKEN` holds) or an account Secret Key (`A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, and the older `A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX` layout, with both letters and digits) in any file. The credential is masked in the snippet.

It does not report the bare `ops_eyJ` prefix in token checks, truncated examples (`ops_eyJ...`), CI secret references (`${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}`), `A3-` strings of another layout or with an all-digit body (paper sizes, SKUs, batch numbers), placeholder runs, and generated, vendored and test-suffixed files.

## What Gets Flagged

```sh
OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ<base64 JSON>
```

```yaml
secret_key: A3-<6>-<6>-<5>-<5>-<5>-<5>
```

Not flagged:

```yaml
env:
  OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded 1password secret key / service account values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
