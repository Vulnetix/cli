---
title: "VNX-SEC-066 – HTTP Bearer Authentication Header"
description: "Detects literal HTTP Bearer tokens: a \"Bearer <token>\" value of 20+ high-entropy characters written into code, scripts or request files."
---

## Overview

This rule reports the string `Bearer <token>` (an `Authorization` header in a `.http` file or YAML, a `curl -H` argument, a headers dict or object, a `Header.Set` call, a template literal, a constant, or the two-argument .NET `new AuthenticationHeaderValue("Bearer", "...")`) when the token is at least 20 characters, contains a digit or is a JWT, and has high entropy. The token is masked in the snippet.

It does not report headers built from variables (`"Bearer " + token`, `${TOKEN}`, `$(gcloud auth print-access-token)`, `{{ .Values.token }}`), low-entropy or placeholder values (`invalid_token_format`, `YOUR_ACCESS_TOKEN`, the jwt.io sample token), comment lines, Markdown/reStructuredText/AsciiDoc, and test, fixture, vendored and generated files.

## What Gets Flagged

```sh
curl -s -H 'Authorization: Bearer <40 random characters>' https://ci.acme-corp.io/api/v4/trigger
```

```python
session.headers.update({"Authorization": "Bearer <32 random characters>"})
```

Not flagged:

```sh
curl -H "Authorization: Bearer ${GITLAB_TOKEN}" https://gitlab.acme-corp.io/api/v4/projects
```

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded http bearer authentication header values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
