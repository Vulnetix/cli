---
title: "VNX-SEC-037 – HashiCorp Vault Token"
description: "Reports a HashiCorp Vault token: a standalone hvs. service token (24 or more base62 characters, so root and namespaced tokens are included), an hvb. batch token (138 to 300 characters), or a legacy s. service token (24 characters) only where it is assigned to a Vault token setting (VAULT_TOKEN=, vault_token:, X-Vault-Token:, token = inside a vault block). A bare s.-prefixed word, placeholders and test or fixture paths are not reported."
---

## Overview

This rule detects HashiCorp Vault tokens in three formats:
- `hvb.<138-300 chars>`: batch token
- `hvs.<24+ chars>`: service token (root tokens are the short form)
- `s.<24 chars>`: legacy service token, reported only where it is assigned to a Vault token setting

Vault tokens grant the ability to read every secret the token's policy allows, which often includes database credentials, API keys, and signing keys for downstream services.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Vault token is the keys to the kingdom for whatever secrets Vault is managing. Unlike cloud-issued tokens, Vault policies are entirely under your control — a token with `database/creds/read` grants the ability to issue short-lived database credentials on demand, which can then be used to exfiltrate the entire database.

## What Gets Flagged

Flagged:

```bash
VAULT_TOKEN=hvs.<24+ characters>                     # service or root token
export VAULT_TOKEN=s.<24 characters>                 # legacy token, in a Vault setting
curl -H "X-Vault-Token: s.<24 characters>" ...
```

```yaml
vault:
  token: hvb.<138-300 characters>                    # batch token
```

Not flagged: an `s.` word outside a Vault token setting (`s.abcdefghijklmnopqrstuvwx` in JavaScript), `os.environ["VAULT_TOKEN"]`, `hvs.xxxx…` placeholders, and test or fixture files.

## Remediation

1. **Revoke the token in Vault** with `vault token revoke <token>` or via the UI.
2. **Audit the token's accessor in the Vault audit log** to see what secrets were read.
3. **Rotate every secret the token's policy allowed**, since the attacker may have already read them.
4. **Use short-lived tokens** (Kubernetes auth, AWS IAM, GCP IAM) with a 1-hour TTL instead of long-lived ones.
5. **Purge from git history** with `git filter-repo`.

## References

- [Vault Tokens](https://developer.hashicorp.com/vault/docs/concepts/tokens)
- [Vault Audit Devices](https://developer.hashicorp.com/vault/docs/audit)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `vault-batch-token`, `vault-service-token`](https://github.com/gitleaks/gitleaks)
- [truffleHog HashiCorp Vault detector](https://github.com/trufflesecurity/trufflehog)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
