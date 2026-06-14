---
title: "VNX-SEC-036 – Heroku API Key"
description: "Detects Heroku API keys (HRKU-AA prefix) hardcoded in source code."
---

## Overview

This rule detects Heroku API keys (v2 format) matching the `HRKU-AA[0-9a-zA-Z_-]{58}` pattern. Heroku API keys grant full account access including the ability to deploy applications, modify add-ons (e.g. Postgres, Redis), and read environment variables containing credentials.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Heroku API key is sufficient to push a malicious build to a production app, attach to the production database, and exfiltrate customer data. Because Heroku's git push deploy model is git-based, the attacker can deploy without re-authentication if they have a key with `deploy` scope.

## What Remediation

1. **Regenerate the API key** in the Heroku account settings.
2. **Use platform API OAuth tokens** for CI instead of long-lived API keys.
3. **Store the new key in Heroku Config Vars** or an external secrets manager.
4. **Audit recent deploys** in the Heroku activity log.
5. **Purge from git history** with `git filter-repo` and re-scan.

## References

- [Heroku API Authentication](https://devcenter.heroku.com/articles/authentication)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `heroku-api-key-v2`](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
