---
title: "VNX-SEC-046 – Square Access Token"
description: "Reports Square access tokens (EAAA plus 56-64 characters, or legacy sq0atp- OAuth tokens) standing alone in files; EAAA inside base64 blobs is not reported."
---

## Overview

This rule reports a Square access token: a production or sandbox access token (`EAAA` followed by 56 to 64 base64url characters) or a legacy OAuth access token (`sq0atp-` followed by 22 to 43 characters), standing alone rather than inside a longer base64 run. `EAAA` inside an embedded image, font or certificate, placeholders (`EAAAxxxx...`, `sq0atp-REPLACE...`), low-entropy values, environment lookups and test, fixture and vendored paths are not reported, and the snippet is redacted.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded square access token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- gitleaks `square-access-token`
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
