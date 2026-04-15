---
title: "VNX-JWT-001 – JWT Signature Verification Disabled"
description: "JWT decode is called with signature verification disabled or the 'none' algorithm permitted, allowing any forged token to be accepted."
---

## Overview

JWT decode is called with `verify_signature=False`, `verify=False`, or the `none` algorithm is included in the permitted algorithms list. This completely disables cryptographic authentication of tokens, allowing an attacker to forge arbitrary tokens with any payload — including elevated privilege claims — and have them accepted as valid.

**Severity:** Critical | **CWE:** [CWE-347 – Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

## Why This Matters

JWT authentication relies entirely on signature verification. Disabling it means any JSON payload base64-encoded and passed as a token will be accepted. An attacker can craft a token claiming to be any user or any role, forge admin claims, or bypass multi-factor authentication entirely. The `none` algorithm vulnerability (CVE-2015-9235 and related CVEs) has been exploited in production systems and remains a common misconfiguration.

## What Gets Flagged

```python
# FLAGGED: verify_signature=False bypasses all signature checks
payload = jwt.decode(token, options={"verify_signature": False})

# FLAGGED: none algorithm allows unsigned tokens
payload = jwt.decode(token, secret, algorithms=["HS256", "none"])

# FLAGGED: verify=False in older PyJWT versions
payload = jwt.decode(token, secret, verify=False)
```

## Remediation

1. Always verify signatures — remove `verify_signature=False` from all production code.
2. Explicitly specify allowed algorithms and exclude `none`.
3. Use a restricted algorithms list matching your key type.

```python
# SAFE: explicit algorithm list, signature verified
payload = jwt.decode(
    token,
    secret_key,
    algorithms=["HS256"]  # only allow expected algorithm
)
```

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [Auth0 – Critical Vulnerabilities in JSON Web Token Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [OWASP – JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
