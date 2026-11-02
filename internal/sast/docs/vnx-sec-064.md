---
title: "VNX-SEC-064 – Redis Connection String with Credentials"
description: "Reports a Redis connection URL (redis://, rediss://, including the empty-user redis://:password@host form) that embeds a literal password, but not interpolated or default passwords, localhost servers, documentation or example files."
---

## Overview

This rule reports a Redis connection URL that embeds a literal password: `redis://` or `rediss://user:password@host`, including the empty-user form `redis://:password@host` used by AUTH-only servers, in code, config, `.env` and compose files. The password is masked in the snippet.

It does not report a password that is interpolated or templated (`${VAR}`, `$VAR`, `{{ }}`, `%s`, `<password>`, f-string or template-literal fields, concatenation), a default or placeholder word (`password`, `redis`, `default`, `changeme`, the user name itself), a server on localhost or a documentation host (`example.com`, `*.test`, a bare `host` or `hostname`), 127.0.0.1 or ::1, URLs without a password, Markdown/reStructuredText/AsciiDoc and `*.example`/`*.sample`/`*.template` files, or test, fixture, vendored and generated files. VNX-SEC-008 and VNX-SEC-577 report the same URLs.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## What Gets Flagged

```python
# FLAGGED: redis-py URL with a literal password
r = redis.from_url("redis://worker:<password>@10.0.5.9:6379/2")
```

```yaml
# FLAGGED: TLS URL with an AUTH-only password (empty user)
production:
  url: rediss://:<password>@cache.acme.internal:6380/0
```

```python
# NOT FLAGGED: interpolated password
REDIS_URL = f"redis://:{REDIS_PASSWORD}@redis:6379/0"
```

## Why This Matters

Hardcoded redis connection string with credentials values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
