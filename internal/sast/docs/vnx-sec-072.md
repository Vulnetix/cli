---
title: "VNX-SEC-072 – Generic High-Entropy API Key / Secret"
description: "Detects high-entropy literals (20+ characters, letters and digits) assigned to a name that ends in a credential word such as api_key, secret, token or password."
---

## Overview

This rule reports a literal assigned to a name that ends in a credential word (`api_key`/`apiKey`, `secret`, `secret_key`, `client_secret`, `token`, `access_token`, `password`, `passwd`, `credentials`, `creds`, `private_key`, `access_key`): an assignment, constant, object or JSON key, keyword argument, typed declaration (Go `string`, TypeScript `: string`, Kotlin/Swift `: String`, Rust `: &str`) or XML setting (`<add key="PaymentApiKey" value="..."/>`, Android `<string name="maps_api_key">`) whose quoted value (or unquoted value in `.env`, YAML, `.properties`, `.ini`, `.conf` and `.cfg` files) is at least 20 token characters, mixes letters and digits, and has Shannon entropy of at least 3.5. The value is masked in the snippet.

It does not report values read from the environment or configuration, names that only contain a credential word (`TOKEN_URL`, `passwordField`, `secretName`, `tokenizer`, `nextPageToken`), comparisons, placeholders and low-entropy values (`YOUR_API_KEY...`, `0000...`, `changeme`, word phrases), dotted identifiers, lowercase word lists, `sha256-` integrity hashes, lowercase secret-store paths (`projects/p/secrets/db-password/versions/3`), comment lines, prose and HTML files, `examples/`, `samples/`, `demo/` and `docs/` directories, and test, fixture, vendored and generated files.

## What Gets Flagged

```python
API_KEY = "<40 random letters and digits>"
```

```yaml
service:
  api_key: <40 random letters and digits>
```

Not flagged:

```python
API_KEY = os.environ["API_KEY"]
TOKEN_URL = "https://auth.acme-corp.io/oauth2/v3/token"
```

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded generic high-entropy api key / secret values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
