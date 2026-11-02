---
title: "VNX-SEC-078 – Doppler API Token"
description: "Reports a whole Doppler personal token (dp.pt. and 43 characters) in any file, excluding service, CLI and service-account tokens, placeholders, truncated tokens, environment references and test files."
---

## Overview

This rule reports a Doppler personal token, `dp.pt.` followed by 43 mixed-case alphanumeric characters, quoted, assigned (`DOPPLER_TOKEN=...`), passed to `doppler --token` or sent in an `Authorization` header. The token is redacted in the finding's snippet.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded doppler api token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## What Gets Flagged

```bash
# FLAGGED
doppler run --token dp.pt.<43 characters> --project billing --config prd -- ./server
```

```yaml
# FLAGGED: workflow env
env:
  DOPPLER_TOKEN: "dp.pt.<43 characters>"
```

Not flagged:

- Service, CLI, service-account and audit tokens (`dp.st.`, `dp.ct.`, `dp.sa.`, `dp.audit.`), which VNX-SEC-1022 to VNX-SEC-1025 report.
- The bare prefix in a check (`token.startswith("dp.pt.")`), truncated tokens and placeholders (`dp.pt.xxxx...`).
- Environment references (`os.environ["DOPPLER_TOKEN"]`).
- Test, fixture, vendored and generated files.

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
