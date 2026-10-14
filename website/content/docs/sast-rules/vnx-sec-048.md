---
title: "VNX-SEC-048 – OpenAI Project / Service / Admin Key"
description: "Reports OpenAI project, service-account and admin keys (sk-proj-, sk-svcacct-, sk-admin- with a body of 40+ characters) written into files."
---

## Overview

This rule reports an OpenAI project, service-account or admin key: `sk-proj-`, `sk-svcacct-` or `sk-admin-` followed by at least 40 base64url characters, not inside a longer identifier (`task-proj-...`, `desk-admin-...`). Truncated keys (`sk-proj-...`, `sk-proj-Ab3dEf`), placeholders (`sk-proj-xxxx...`, `sk-proj-your-key-...`), low-entropy values, environment lookups and test, fixture and vendored paths are not reported, and the snippet is redacted. Classic `sk-...T3BlbkFJ...` keys are VNX-SEC-251.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded openai project / service / admin key values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- gitleaks `openai-api-key`
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
