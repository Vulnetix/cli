---
title: "VNX-SEC-052 – Artifactory / JFrog API Key"
description: "Reports a JFrog Artifactory API key (AKCp + 69 alphanumerics) or reference token (cmVmd + 59 alphanumerics) as a whole token in any file; lookalikes inside longer base64 runs and placeholders are not reported."
---

## Overview

This rule reports a JFrog Artifactory credential as a whole token: a legacy API key (`AKCp` followed by 69 letters and digits) or a reference/access token (`cmVmd` followed by 59 letters and digits). Typical places are `.npmrc`, `gradle.properties`, an `X-JFrog-Art-Api` header or a Bearer header. The prefix inside a longer alphanumeric run (base64 data), shorter lookalikes, placeholder bodies, environment references and test paths are not reported.

### What Gets Flagged

```ini
//acme.jfrog.io/artifactory/api/npm/npm-virtual/:_password=AKCp<69 characters>
```

```python
TOKEN = "cmVmdGtuOjAx<52 characters>"
```

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded artifactory / jfrog api key values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- gitleaks `artifactory-api-key`, `artifactory-reference-token`
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
