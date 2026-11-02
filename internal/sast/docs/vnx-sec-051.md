---
title: "VNX-SEC-051 – RubyGems API Token"
description: "Reports a RubyGems.org API key (rubygems_ + exactly 48 hex characters) in any file; bare prefixes, longer identifiers, placeholders and CI secret references are not reported."
---

## Overview

This rule reports a RubyGems.org API key, `rubygems_` followed by exactly 48 lower-case hex characters as a whole token, wherever it appears: `~/.gem/credentials`, `GEM_HOST_API_KEY` in a workflow, a Rakefile or a shell script. Not reported: the bare prefix, shorter or longer hex runs, placeholder bodies, `${{ secrets.X }}` references, and test, fixture or vendored paths.

### What Gets Flagged

```yaml
:rubygems_api_key: rubygems_<48 hex characters>
```

```yaml
env:
  GEM_HOST_API_KEY: "rubygems_<48 hex characters>"
```

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded rubygems api token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- gitleaks `rubygems-api-token`
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
