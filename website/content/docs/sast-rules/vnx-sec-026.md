---
title: "VNX-SEC-026 – DigitalOcean Personal Access Token Hardcoded"
description: "Detect DigitalOcean personal access tokens (dop_v1_ prefix) hardcoded in source code, which provide full API access to Droplets, databases, and Kubernetes clusters in the associated account."
---

## Overview

This rule flags source files that contain a string matching the DigitalOcean personal access token format: the prefix `dop_v1_` followed by exactly 64 hexadecimal characters. DigitalOcean personal access tokens authenticate requests to the DigitalOcean API with the full permissions of the account that generated them. There is no built-in scope limitation on personal access tokens — they can create and destroy Droplets, manage DNS records, access databases, and control Kubernetes clusters.

A token hardcoded in source code is exposed to everyone who can access the repository: all contributors, CI/CD systems, any third-party GitHub Apps with read access, and any future attacker who compromises the repository or its clones. Because the token is tied to the account rather than to a specific resource, exposure can lead to complete account takeover.

This rule corresponds to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

DigitalOcean infrastructure — Droplets, managed databases, Spaces object storage, App Platform deployments — often forms the backbone of production applications. A personal access token with full API scope allows an attacker to enumerate and access all of these resources, exfiltrate data from managed databases, delete or replace running Droplets, exfiltrate files from Spaces buckets, and spin up additional infrastructure at the account owner's expense for cryptocurrency mining or other malicious purposes.

Personal access tokens are particularly sensitive because DigitalOcean's API does not support fine-grained scopes for these tokens. An attacker who obtains any personal access token immediately has the same capabilities as the account owner for API operations. This makes accidental exposure far more damaging than with services that support scoped tokens.

Because git history is permanent until actively rewritten, a token committed even briefly remains accessible to anyone with historical access to the repository. Automated secret scanning by malicious actors frequently targets public repositories within minutes of a push.

## What Gets Flagged

The rule matches any file (excluding lock files, checksums, and minified assets) containing a string that matches `dop_v1_` followed by 64 hexadecimal characters.

```bash
# FLAGGED: DigitalOcean token hardcoded in a deployment script
DIGITALOCEAN_TOKEN=dop_v1_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2

# FLAGGED: token in application configuration
do_token = "dop_v1_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

## Remediation

1. **Revoke the token immediately.** Go to [cloud.digitalocean.com/account/api/tokens](https://cloud.digitalocean.com/account/api/tokens), find the exposed token, and delete it. Generate a new token only after the old one is revoked.

2. **Store the new token as an environment variable or in a secrets manager.** Never commit credentials to source control:

```bash
# SAFE: load token from environment variable
export DIGITALOCEAN_TOKEN="$(vault kv get -field=token secret/digitalocean)"
doctl auth init --access-token "$DIGITALOCEAN_TOKEN"
```

3. **Use CI/CD secret storage for automated workflows.** GitHub Actions, GitLab CI, and similar platforms provide encrypted secret storage. Reference secrets by name in workflow files rather than embedding values:

```yaml
# SAFE: GitHub Actions secret reference
- name: Deploy to DigitalOcean
  env:
    DIGITALOCEAN_TOKEN: ${{ secrets.DIGITALOCEAN_TOKEN }}
  run: doctl apps create --spec app.yaml
```

4. **Purge the token from git history** using `git filter-repo` or BFG Repo-Cleaner, then force-push all branches and rotate the credential.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [DigitalOcean API – Managing personal access tokens](https://docs.digitalocean.com/reference/api/create-personal-access-token/)
- [DigitalOcean security best practices](https://docs.digitalocean.com/support/how-to-protect-your-digitalocean-account/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub Actions – Encrypted secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
