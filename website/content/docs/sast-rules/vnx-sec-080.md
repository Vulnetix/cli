---
title: "VNX-SEC-080 – GitHub OAuth / App / Refresh Token"
description: "Reports a whole GitHub OAuth (gho_), App user-to-server (ghu_), installation (ghs_) or refresh (ghr_) token in any file, excluding classic and fine-grained PATs, prefix lists, truncated tokens, placeholders and test files."
---

## Overview

This rule reports a GitHub OAuth access token (`gho_`), GitHub App user-to-server token (`ghu_`), App installation token (`ghs_`) or refresh token (`ghr_`, 36 or 76 characters), quoted, assigned, in an `Authorization` header or inside a clone URL. The token is redacted in the finding's snippet.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded github oauth / app / refresh token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## What Gets Flagged

```bash
# FLAGGED: installation token inside a clone URL
git clone https://x-access-token:ghs_<36 characters>@github.com/acme/infra.git
```

```jsonc
// FLAGGED: refresh token committed with a session file
{ "refresh_token": "ghr_<76 characters>" }
```

Not flagged:

- Classic `ghp_` and fine-grained `github_pat_` tokens (VNX-SEC-004 and VNX-SEC-079 report them).
- Prefix lists and regular expressions (`"gho_", "ghs_"`), truncated tokens (`ghs_16C7e42F...` from the GitHub documentation is 32 characters) and placeholders (`gho_xxxx...`).
- Environment references (`os.environ["GITHUB_TOKEN"]`).
- Test, fixture, vendored and generated files.

VNX-SEC-004 also reports these tokens as part of its wider set.

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
