---
title: "VNX-SEC-057 – Grafana API / Service Account Token"
description: "Reports a hard-coded Grafana service account token (glsa_), Grafana Cloud access policy token (glc_eyJ...) or legacy Grafana API key (eyJrIjoi...), but not bare prefixes, placeholders, ordinary JWTs or tokens read from the environment."
---

## Overview

This rule reports a Grafana credential written into a file: a service account token (`glsa_` + 32 alphanumerics + `_` + 8 hex), a Grafana Cloud access policy token (`glc_` followed by its base64 JSON body, `glc_eyJ...`), or a legacy Grafana API key (the base64 of `{"k":"`, `eyJrIjoi...`, 70+ characters). Each token must stand alone rather than sit inside a longer identifier, and must have enough entropy to be real. The snippet is redacted.

It does not report bare prefixes in a prefix check, placeholder bodies (`xxxx`, `0000`, `YOUR_TOKEN`), ordinary JWTs (`eyJhbGci...`), tokens read from the environment, or test, fixture and vendored paths.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## What Gets Flagged

```go
// FLAGGED: service account token in a client config
return gapi.New("https://grafana.acme.internal", gapi.Config{
	APIKey: "glsa_<32 alphanumerics>_<8 hex>",
})
```

```hcl
# FLAGGED: Grafana Cloud access policy token in Terraform
cloud_access_policy_token = "glc_eyJ<base64 body>=="
```

```python
# NOT FLAGGED: read from the environment
token = os.environ["GRAFANA_SA_TOKEN"]
```

## Why This Matters

Hardcoded grafana api / service account token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

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
