---
title: "VNX-1025 – Improper Comparison of User-Supplied Input"
description: "Detects equality comparison operators in Go, Node.js, and Python that may indicate non-constant-time comparisons of security-sensitive values such as tokens, passwords, or MACs."
---

## Overview

VNX-1025 is an auto-generated broad-pattern rule that searches for equality comparison operators (`==` in Go and Python, `===` in Node.js) across source files. The rule is associated with [CWE-1025: Comparison Using Wrong Factors](https://cwe.mitre.org/data/definitions/1025.html), which covers situations where comparisons are made using factors that do not accurately represent the intended condition — for example, comparing a cryptographic token with a standard equality operator that short-circuits on the first differing byte.

Standard equality operators are not timing-safe. When used to compare secrets such as HMAC signatures, session tokens, or password hashes, they are vulnerable to timing side-channel attacks: an attacker who can make many requests can measure response times to progressively guess the correct value byte by byte.

This rule has a very high false-positive rate because `==` is used in virtually all programs. Findings must be reviewed in context to determine whether the comparison involves security-sensitive data.

**Severity:** Medium | **CWE:** [CWE-1025 – Comparison Using Wrong Factors](https://cwe.mitre.org/data/definitions/1025.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

Timing attacks against string comparison have been exploited in real production systems, including HMAC verification bypasses in web frameworks. An attacker who can submit controlled input and observe response times with sufficient precision can recover a secret token without ever seeing it directly, turning an authentication bypass into a matter of statistical analysis over a large number of requests.

Fixing this class of vulnerability requires replacing standard equality with a constant-time comparison function for every location where security-sensitive secrets are compared, not just the obvious authentication paths.

## What Gets Flagged

The rule scans Go, Node.js, and Python files for equality operator usage:

```python
# FLAGGED: non-constant-time token comparison
if user_token == expected_token:
    grant_access()
```

```go
// FLAGGED: direct string equality on HMAC
if receivedMAC == computedMAC {
    process(request)
}
```

```javascript
// FLAGGED: strict equality on API key
if (req.headers['x-api-key'] === process.env.API_KEY) {
    next();
}
```

## Remediation

1. Replace secret comparisons with constant-time equivalents:
   - **Go**: `crypto/subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1`
   - **Python**: `hmac.compare_digest(a, b)`
   - **Node.js**: `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`
2. Never compare raw password strings — always compare derived hashes using the KDF library's built-in verification function (e.g., `bcrypt.CheckPasswordHash`).
3. Limit the scope of findings by suppressing confirmed-safe comparisons with a `// vulnetix-ignore: VNX-1025` comment after review.

## References

- [CWE-1025: Comparison Using Wrong Factors](https://cwe.mitre.org/data/definitions/1025.html)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [OWASP Testing Guide – Testing for Timing Attacks](https://owasp.org/www-project-web-security-testing-guide/)
- [Go crypto/subtle package](https://pkg.go.dev/crypto/subtle)
- [Python hmac.compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)
