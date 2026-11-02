---
title: "VNX-SEC-050 – Google Gemini / Vertex AI / PaLM API Key"
description: "Reports a Google API key (AIza + 35 characters) on or within eight lines of a Gemini, PaLM, Vertex AI or Google GenAI SDK reference; Firebase web config keys and AIza keys with no generative-AI context are left to the generic GCP key rules."
---

## Overview

This rule reports a Google API key (`AIza` followed by 35 characters) used for the generative AI APIs. The key must be on a line, or within eight lines of one, that names Gemini, PaLM, Vertex AI, the `generativelanguage.googleapis.com` endpoint, or a Google GenAI SDK (`google.generativeai`, `google-genai`, `@google/generative-ai`, `generative-ai-go`). AIza keys without that context (Maps, Firebase web config, generic GCP keys) are covered by VNX-SEC-005 and VNX-SEC-170. Keys read from the environment, placeholder bodies and test paths are not reported.

### What Gets Flagged

```python
import google.generativeai as genai
genai.configure(api_key="AIza<35 characters>")
```

```sh
GEMINI_API_KEY=AIza<35 characters>
```

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded google gemini / vertex ai / palm api key values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- gitleaks `gcp-api-key`
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
