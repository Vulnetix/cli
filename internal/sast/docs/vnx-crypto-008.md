---
title: "VNX-CRYPTO-008 – Timing Attack via Direct Comparison of Secrets"
description: "Reports a MAC, signature, digest or secret token checked with ordinary equality (==, !=, ===, !==, Java equals/Arrays.equals, Go bytes.Equal) in Python, Node.js, Go, Java, PHP and Ruby, any equality on a line that computes an HMAC, and a hand-written byte loop with an early return in MAC or signature code, when the comparison verifies a supplied value (a request input, a handler parameter, a verify-named function or a value hashed just above). Comparisons where neither side is supplied, presence checks, constants, lexer token kinds, hash-named values and constant-time APIs are not reported."
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
# FLAGGED: token comparison with == in a function that checks it
def check_token(token, stored_token):
    if token == stored_token:
        authenticate_user()
```

```javascript
// FLAGGED: an HMAC computed and compared with ===
if (crypto.createHmac('sha256', secret).update(body).digest('hex') === req.get('X-Signature')) {
  verifyWebhook();
}
```

```go
// FLAGGED: Go string equality on a signature
return sig == expected
```

```go
// FLAGGED: a byte loop that returns at the first difference, in HMAC code
for i := range expected {
	if expected[i] != supplied[i] {
		return false
	}
}
```

```php
// FLAGGED: PHP CSRF token compared with !==
if ($user_token !== $session_token) { die('CSRF token is incorrect'); }
```

### Only where a supplied value is checked

A timing attack needs one operand the attacker supplies and the other a value the code holds. An equality comparison is therefore reported only when something on or around the line says it verifies a supplied value:

- one side is computed by an HMAC, hash or signing call (`hmac.new`, `createHmac`, `hash_hmac`, `doFinal`, `mac.Sum`, `md5(...)`, `hexdigest`) on the same line or one of the five lines above;
- the enclosing function is named for verifying: `verify`, `validate`, `valid`, `check`, `authenticate`;
- an operand is read from a request (`req`, `request`, `params`, `headers`, `cookies`, `body`, `$_POST`, `r.Header`) or is named for what was supplied or what it is checked against (`provided`, `supplied`, `received`, `given`, `incoming`, `submitted`, `candidate`, `user_`, `client_`, `header`, `input`, `got`, `expected`, `computed`, `calculated`);
- an operand was assigned from a request on one of the 30 lines above (`tok := r.Header.Get(...)`, `token = request.POST.get(...)`, `$token = $_GET['token']`);
- an operand is a parameter of a request handler (`@RequestParam`, `@RequestHeader`, `@PostMapping`, `HttpServletRequest`, `http.ResponseWriter`).

These are not reported, because neither side is supplied by a caller:

```go
// two documents' content digests
if from.Source.Digest == to.Source.Digest { ... }
// a cache dropping its own entry only if it is still the one it issued
if t := cache[key]; t != nil && t.Token == tok { ... }
// change detection on a refreshed credential
if tok.RefreshToken != login.RefreshToken { ... }
// a credential compared with a published constant
return creds.APIKey == CommunityAPIKey
```

The byte-loop form (`expected[i] != supplied[i]` with an early return) keeps its own context test: code whose file name, function, class or doc comment names a MAC, signature, digest or secret.

Not flagged: presence checks against an empty string, `null`, `None`, `nil`, a boolean or a number; comparisons with an ALL_CAPS constant or after `typeof` (lexer token kinds); `.length`, `.type` and size comparisons; names that only contain `hash` (`geometryHash`, `location.hash`); lines already using `hmac.compare_digest`, `crypto.timingSafeEqual`, `hmac.Equal`, `hash_equals`, `secure_compare` or `MessageDigest.isEqual`; comments, strings and test files.

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
