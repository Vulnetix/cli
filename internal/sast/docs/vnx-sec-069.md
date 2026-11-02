---
title: "VNX-SEC-069 – age Secret Key"
description: "Detects age identities (AGE-SECRET-KEY-1 or the post-quantum AGE-SECRET-KEY-PQ-1, followed by 58 Bech32 characters) in any file."
---

## Overview

This rule reports an age secret key, `AGE-SECRET-KEY-1` (X25519) or `AGE-SECRET-KEY-PQ-1` (the post-quantum hybrid identity of age 1.3) followed by exactly 58 Bech32 characters, in any file: key files, `.env` files, CI variables, `SOPS_AGE_KEY` settings, and comments (a key in a comment is still leaked). The key is masked in the snippet.

It does not report public recipients (`age1...`), the bare `AGE-SECRET-KEY-1` prefix used in format checks, plugin identities (`AGE-PLUGIN-YUBIKEY-1...`, which name a hardware key rather than hold one), keys of the wrong length or alphabet, placeholder runs (`AGE-SECRET-KEY-1XXXX...`), and generated, vendored and test-suffixed files.

## What Gets Flagged

```sh
SOPS_AGE_KEY=AGE-SECRET-KEY-1<58 Bech32 characters>
```

Not flagged:

```yaml
creation_rules:
  - age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded age secret key values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
