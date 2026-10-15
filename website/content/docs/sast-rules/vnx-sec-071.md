---
title: "VNX-SEC-071 – GitLab Session Cookie"
description: "Detects captured GitLab session cookie values (_gitlab_session with a 32-hex session id) in any file."
---

## Overview

This rule reports `_gitlab_session` followed by `=` (a `Cookie` header, `document.cookie`, a curl argument) by a quoted or symbol key and `:`/`=`/`=>` (a cookies dict, hash or object), by a call argument pair (`cookies.set("_gitlab_session", "...")`) or by a tab (Netscape `cookies.txt`); or a cookie object whose `"name"` is `_gitlab_session` with its `"value"` on the same line or up to 12 lines below, as browser cookie exports write it; and then a 32-character lowercase hexadecimal session id. The value is masked in the snippet.

It does not report the cookie name on its own (Rails `session_store key: "_gitlab_session"`), a value read from a variable or the environment, placeholder values (all zeros, `xxxx...`), and generated, vendored and test-suffixed files.

## What Gets Flagged

```sh
curl -s -H "Cookie: _gitlab_session=<32 hex>" https://gitlab.acme-corp.io/api/v4/projects
```

```python
cookies = {"_gitlab_session": "<32 hex>"}
```

Not flagged:

```python
cookies = {"_gitlab_session": os.environ["GITLAB_SESSION"]}
```

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded gitlab session cookie values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
