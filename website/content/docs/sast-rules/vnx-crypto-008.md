---
title: "VNX-CRYPTO-008 – Timing Attack via Direct Comparison of Secrets"
description: "Detects direct == or === comparison of HMAC digests, hashes, tokens, or signatures, which leaks timing information that allows attackers to incrementally reconstruct the expected value."
---

## Overview

This rule detects cases where HMAC digests, hash values, authentication tokens, or signatures are compared using standard equality operators (`==` in Python, `===` in JavaScript). Standard string comparison is not constant-time: it returns early as soon as it finds the first mismatching character. This timing difference — nanoseconds per character — is measurable over a network and allows an attacker to mount a timing side-channel attack, gradually discovering the expected value one character at a time. This maps to CWE-208 (Observable Timing Discrepancy).

**Severity:** Medium | **CWE:** [CWE-208 – Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)

## Why This Matters

Timing attacks sound theoretical but are practical against web services. By sending thousands of requests where a token differs in one position and measuring average response times, an attacker can statistically determine whether each character of the submitted value matches the expected value. For webhook signature verification (where HMAC-SHA256 is compared to a submitted header), this could allow an attacker to forge signatures without the secret key.

GitHub, Stripe, Slack, and virtually every other webhook provider explicitly documents "use constant-time comparison" in their security recommendations precisely because this attack works. The attack is easier when the attacker controls part of the input (e.g., submitting a webhook with a known partial signature) and has high-resolution timing access (on-premises or low-latency cloud), but timing information also leaks through TCP retransmissions and other network artefacts at larger scale.

## What Gets Flagged

```python
# FLAGGED: direct == comparison of HMAC digest
if hmac_digest == request_signature:
    process_webhook()
```

```python
# FLAGGED: token comparison with ==
if token == stored_token:
    authenticate_user()
```

```javascript
// FLAGGED: === comparison of hash values
if (hash === expectedHash) {
  verifyWebhook();
}
```

## Remediation

1. **Python: use `hmac.compare_digest()` for all secret comparisons:**

   ```python
   # SAFE: constant-time comparison
   import hmac

   def verify_webhook(payload: bytes, received_sig: str, secret: str) -> bool:
       expected = hmac.new(secret.encode(), payload, "sha256").hexdigest()
       return hmac.compare_digest(expected, received_sig)
   ```

2. **Node.js: use `crypto.timingSafeEqual()` for all secret comparisons:**

   ```javascript
   // SAFE: constant-time comparison in Node.js
   const crypto = require('crypto');

   function verifyWebhook(payload, receivedSig, secret) {
     const expected = crypto
       .createHmac('sha256', secret)
       .update(payload)
       .digest('hex');
     const expectedBuf = Buffer.from(expected);
     const receivedBuf = Buffer.from(receivedSig);
     if (expectedBuf.length !== receivedBuf.length) return false;
     return crypto.timingSafeEqual(expectedBuf, receivedBuf);
   }
   ```

3. **Java: use `MessageDigest.isEqual()` (Java 7+):**

   ```java
   // SAFE: constant-time comparison in Java
   import java.security.MessageDigest;
   boolean verified = MessageDigest.isEqual(expectedBytes, receivedBytes);
   ```

4. **Apply constant-time comparison to all secret material**: webhook signatures, CSRF tokens, API keys, session tokens, and password reset tokens — any value where a timing oracle would reveal useful information.

## References

- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [OWASP – Testing for Timing Attacks](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing)
- [Python `hmac.compare_digest` documentation](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)
- [Node.js `crypto.timingSafeEqual` documentation](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b)
- [CAPEC-462: Cross-Channel Guessing](https://capec.mitre.org/data/definitions/462.html)
