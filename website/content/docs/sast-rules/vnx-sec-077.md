---
title: "VNX-SEC-077 – Mapbox Access Token"
description: "Reports a whole Mapbox public access token (pk.eyJ... with its signature) in any file, excluding secret sk. tokens, placeholders, environment references, minified and test files."
---

## Overview

This rule reports a Mapbox public access token: `pk.`, its base64url payload (`eyJ...`), a dot and a 22-character signature, quoted, assigned to `mapboxgl.accessToken`, in a tile URL (`?access_token=pk...`) or in a `.env` file. Public tokens are meant for browser code, so the finding asks you to confirm the token is URL- and scope-restricted, and to rotate it if it is not.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded mapbox access token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## What Gets Flagged

```javascript
// FLAGGED
mapboxgl.accessToken = 'pk.eyJ<payload>.<22-character signature>';
```

```python
# FLAGGED: token in a tile URL
TILE_URL = "https://api.mapbox.com/styles/v1/mapbox/streets-v12/tiles/{z}/{x}/{y}?access_token=pk.eyJ<payload>.<signature>"
```

Not flagged:

- Secret `sk.` tokens, which VNX-SEC-904 reports.
- Environment references (`import.meta.env.VITE_MAPBOX_TOKEN`) and the bare `pk.eyJ` prefix.
- Placeholder, truncated or low-entropy tokens.
- Test, fixture, vendored, minified and generated files.

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
