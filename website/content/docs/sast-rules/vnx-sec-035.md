---
title: "VNX-SEC-035 – DigitalOcean Personal Access Token"
description: "Detects DigitalOcean personal access tokens (dop_v1_) and OAuth tokens (doo_v1_) hardcoded in source code."
---

## Overview

This rule detects DigitalOcean personal access tokens (`dop_v1_<64 hex>`) and OAuth tokens (`doo_v1_<64 hex>`) hardcoded in source files. These tokens grant full API access to the user's DigitalOcean account, including the ability to create and destroy droplets, modify load balancers, and read state databases.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

DigitalOcean tokens are commonly leaked via `.env` files committed to GitHub. The compromise pattern is well-documented: bots scan for `dop_v1_` / `doo_v1_` prefixes, validate the token, and immediately spin up cryptomining droplets billed to the victim.

## What Gets Flagged

```bash
# FLAGGED
export DIGITALOCEAN_TOKEN="dop_v1_EXAMPLE_REDACTED"
doctl auth init
```

## Remediation

1. **Revoke the token in the DigitalOcean control panel** → API → Tokens/Revoke.
2. **Replace with an OAuth application** where possible, or a scoped token with read-only access.
3. **Store new tokens in a secrets manager** (Doppler, Vault, AWS SSM, GitHub Actions secrets).
4. **Audit Droplet, Volume, and Snapshot creation events** in the DigitalOcean activity log.
5. **Purge from git history** with `git filter-repo` and re-scan.

## References

- [DigitalOcean API Tokens](https://docs.digitalocean.com/reference/api/digitalocean/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `digitalocean-pat`](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
