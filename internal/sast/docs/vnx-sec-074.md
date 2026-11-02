---
title: "VNX-SEC-074 – Kubernetes Secret Manifest with Credentials"
description: "Reports each credential entry with a literal value in the data: or stringData: block of a committed Kubernetes Secret manifest, excluding templated, referenced, SOPS-encrypted, empty and placeholder values and other kinds such as SealedSecret."
---

## Overview

This rule reads every YAML document whose top-level `kind` is `Secret` (multi-document files included) and reports each entry in its `data:` or `stringData:` block whose key names a credential (password, token, secret, key, auth, credentials, connection string, `.dockerconfigjson`) and whose value is a literal. Base64 in `data:` is an encoding, not encryption.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded kubernetes secret manifest with credentials values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## What Gets Flagged

```yaml
# FLAGGED: the password and API key entries
apiVersion: v1
kind: Secret
metadata:
  name: billing-api
type: Opaque
data:
  username: YmlsbGluZw==        # not a credential key, not flagged
  password: Ums5eVcyczlMcTd6
  stripe-api-key: c2stbGl2ZS1iaWxsaW5nLTQ4Mjk3MzE1OTA=
```

Not flagged:

- Helm and other templated values (`{{ .Values.db.password | b64enc }}`), `${VAR}` and `$(VAR)` references, `<placeholder>` values and empty strings.
- Default or placeholder words (`password`, `changeme`, `admin`, `xxxx...`), including their base64 encodings.
- SOPS-encrypted values (`ENC[AES256_GCM,data:...]`), release-pipeline token substitutions (`#{DbPassword}#`, `__API_TOKEN__`, `%%TOKEN%%`) and argocd-vault-plugin `<path:...>` references.
- `SealedSecret`, `ExternalSecret`, `ConfigMap` and other kinds, and `secretKeyRef` references.
- Test, fixture and testdata files.

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
