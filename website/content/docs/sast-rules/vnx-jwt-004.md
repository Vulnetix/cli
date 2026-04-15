---
title: "VNX-JWT-004 – JWT Algorithm Explicitly Set to 'none'"
description: "Detects JWT encode or decode calls that use the 'none' algorithm, which disables cryptographic signing and allows any party to forge valid tokens."
---

## Overview

This rule detects JWT operations — `jwt.encode()` in Python, `jwt.sign()` in Node.js, or `algorithms=['none']` in decode/verify calls — that explicitly specify the `none` algorithm. The `none` algorithm is defined in RFC 7519 as an unsecured JWT: the signature section of the token is empty and no cryptographic verification is performed. Any party who holds such a token (or manufactures one from scratch) can present it as valid. Libraries that accept `none` as a permitted algorithm during verification allow an attacker to forge arbitrary token payloads and be accepted as authenticated. This maps to CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

The `none` algorithm was originally included in the JWT specification to support use cases where JWTs are transmitted over already-authenticated channels and a signature would be redundant. In practice, its inclusion in production authentication flows is almost always a mistake or a deliberate attack. Several high-profile CVEs have been filed against JWT libraries that accepted `none` by default or allowed it to be specified in the token header.

**Severity:** Critical | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

The `none` algorithm attack on JWTs is well documented: an attacker takes a valid token, decodes the header (which is just base64), changes the `alg` field to `"none"`, re-encodes, and strips the signature. A vulnerable library accepts this token as valid because it sees `alg: none` and skips signature verification. This allows complete authentication bypass and identity spoofing.

CAPEC-196 (Session Credential Falsification through Forging) and MITRE ATT&CK T1550.001 (Use Alternate Authentication Material: Application Access Token) document this attack. It requires only a base64 decoder and text editor — no cryptographic knowledge or computation. Any production system that accepts `none`-algorithm tokens effectively has no authentication at all.

The fix is straightforward: always specify a strong algorithm explicitly and never include `none` in the list of accepted algorithms.

## What Gets Flagged

```python
# FLAGGED: jwt.encode with algorithm='none'
token = jwt.encode({"sub": user_id}, key, algorithm="none")

# FLAGGED: jwt.decode accepting 'none' as the only algorithm
payload = jwt.decode(token, key, algorithms=["none"])
```

```javascript
// FLAGGED: jwt.sign with algorithm: 'none'
const token = jwt.sign({ sub: userId }, secret, { algorithm: "none" });

// FLAGGED: jwt.verify with algorithm set to 'none'
const payload = jwt.verify(token, secret, { algorithm: "none" });
```

## Remediation

1. **Replace `"none"` with a strong signing algorithm.** Use `HS256` for symmetric (shared secret) use cases, `RS256` or `ES256` for asymmetric (public/private key) use cases.

   ```python
   # SAFE: strong symmetric algorithm
   import jwt

   token = jwt.encode({"sub": user_id, "exp": expiry}, SECRET_KEY, algorithm="HS256")

   # SAFE: decode specifies only strong algorithms
   payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
   ```

   ```javascript
   // SAFE: strong algorithm in sign and verify
   const token = jwt.sign({ sub: userId }, secretKey, {
     algorithm: "HS256",
     expiresIn: "1h",
   });

   const payload = jwt.verify(token, secretKey, { algorithms: ["HS256"] });
   ```

2. **For asymmetric tokens (RS256, ES256)**, keep the private key out of the codebase and load it from a secrets manager or environment variable at runtime.

   ```javascript
   // SAFE: RS256 with externally loaded private key
   const privateKey = process.env.JWT_PRIVATE_KEY;
   const token = jwt.sign({ sub: userId }, privateKey, { algorithm: "RS256" });
   ```

3. **Explicitly exclude `"none"` from the `algorithms` list** in decode/verify calls even if not using it, to ensure the library cannot be tricked by a forged header.

   ```python
   # SAFE: whitelist only specific algorithms, never include 'none'
   ALLOWED_ALGORITHMS = ["HS256", "HS384"]
   payload = jwt.decode(token, SECRET_KEY, algorithms=ALLOWED_ALGORITHMS)
   ```

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CAPEC-196: Session Credential Falsification through Forging](https://capec.mitre.org/data/definitions/196.html)
- [MITRE ATT&CK T1550.001 – Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [RFC 7519 – JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [jwt.io – JWT introduction and algorithm overview](https://jwt.io/introduction)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Auth0 – Critical vulnerabilities in JWT libraries (the 'none' attack)](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
