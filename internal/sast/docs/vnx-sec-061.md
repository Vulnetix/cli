---
title: "VNX-SEC-061 – PostgreSQL Connection String with Credentials"
description: "Reports a PostgreSQL connection URL (postgres://, postgresql+driver://, jdbc:postgresql) that embeds a literal password, but not interpolated or default passwords, localhost servers, documentation or example files."
---

## Overview

This rule reports a PostgreSQL connection URL that embeds a literal password: `postgres://` or `postgresql://user:password@host`, with an optional driver suffix (`postgresql+psycopg2`, `postgresql+asyncpg`) or `jdbc:` prefix, and a `jdbc:postgresql` URL carrying a `password=` parameter, in code, config, `.env` and compose files. The password is masked in the snippet.

It does not report a password that is interpolated or templated (`${VAR}`, `$VAR`, `{{ }}`, `%s`, `<password>`, f-string or template-literal fields, concatenation), a default or placeholder word (`password`, `postgres`, `changeme`, the user name itself), a server on localhost or a documentation host (`example.com`, `*.test`, a bare `host` or `hostname`), 127.0.0.1 or ::1, URLs without a password, Markdown/reStructuredText/AsciiDoc and `*.example`/`*.sample`/`*.template` files, or test, fixture, vendored and generated files. VNX-SEC-008 reports the same URLs for every database scheme.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## What Gets Flagged

```python
# FLAGGED: SQLAlchemy URL with a literal password
engine = create_engine("postgresql+psycopg2://reporting:<password>@pg.acme.internal/analytics")
```

```properties
# FLAGGED: JDBC URL with a password parameter
spring.datasource.url=jdbc:postgresql://pg.acme.internal:5432/shop?user=shop&password=<password>
```

```python
# NOT FLAGGED: the password comes from the environment
DATABASE_URL = f"postgresql://{os.environ['PGUSER']}:{os.environ['PGPASSWORD']}@db:5432/app"
```

## Why This Matters

Hardcoded postgresql connection string with credentials values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
