---
title: "VNX-SEC-037 – HashiCorp Vault Token"
description: "Detects HashiCorp Vault batch tokens (hvb.), service tokens (hvs.), and legacy s. tokens hardcoded in source code."
---

## Overview

This rule detects HashiCorp Vault tokens in three formats:
- `hvb.<138-300 chars>` — batch token
- `hvs.<90-120 chars>` — service token
- `s.<24 chars>` — legacy service token

Vault tokens grant the ability to read every secret the token's policy allows, which often includes database credentials, API keys, and signing keys for downstream services.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Vault token is the keys to the kingdom for whatever secrets Vault is managing. Unlike cloud-issued tokens, Vault policies are entirely under your control — a token with `database/creds/read` grants the ability to issue short-lived database credentials on demand, which can then be used to exfiltrate the entire database.

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
