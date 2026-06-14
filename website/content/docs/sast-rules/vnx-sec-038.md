---
title: "VNX-SEC-038 – HashiCorp Terraform Cloud Token"
description: "Detects HashiCorp Terraform Cloud API tokens (atlasv1 format) hardcoded in source code."
---

## Overview

This rule detects Terraform Cloud API tokens matching `<14 chars>.atlasv1.<60-70 chars>`. Terraform Cloud tokens grant the ability to trigger runs that can alter production infrastructure, modify variable values, and read state files (which may contain plaintext secrets for downstream resources).

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked TFC token can trigger a speculative apply that destroys production infrastructure. The attacker can also modify workspace variables (which often contain database credentials) and read state, which frequently contains unredacted secret values.

## Remediation

1. **Revoke the token in the Terraform Cloud user settings** → Tokens.
2. **Audit runs in the TFC activity feed** to confirm no malicious applies occurred.
3. **Use OIDC federation** to issue short-lived TFC tokens from your CI provider without a long-lived secret.
4. **Purge from git history** with `git filter-repo`.

## References

- [Terraform Cloud API Tokens](https://developer.hashicorp.com/terraform/cloud-docs/api-docs#authentication)
- [Terraform Cloud Dynamic Credentials](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `hashicorp-tf-api-token`](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
