---
title: "VNX-SEC-015 – JWT Algorithm None Attack"
description: "Detects JWT configurations that allow the 'none' algorithm, which completely disables signature verification and allows arbitrary token forgery."
---

## Overview

This rule detects JWT library configurations that accept or specify `algorithm='none'` (or equivalent), including library-specific constants like `Algorithm.NONE` and `SignatureAlgorithm.NONE`. When a JWT is configured with the `none` algorithm, the signature section of the token is omitted or set to an empty string, and if the library accepts this, it verifies the token without checking any signature. This means an attacker can craft a token with arbitrary claims — any user ID, any role, any permission — and the application will accept it as valid.

**Severity:** Critical | **CWE:** [CWE-345 – Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html), [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

The JWT `none` algorithm attack is one of the most severe authentication bypasses in web application security. It was first widely publicized as CVE-2015-9235 (PyJWT) and affects many JWT libraries that do not explicitly reject the `none` algorithm. The attack works as follows:

1. The attacker takes any valid JWT (or even creates one from scratch)
2. They decode the header and change `"alg": "HS256"` to `"alg": "none"`
3. They modify the payload to claim any identity or privileges
4. They construct a token with an empty signature (or no signature)
5. The vulnerable server accepts the token and grants the claimed access

This is not a theoretical vulnerability — it has been exploited in real applications and widely used CTF challenges. The root cause is library code that treats `none` as a valid algorithm rather than explicitly rejecting it, or application code that passes `algorithms=["none"]` when decoding.

## What Gets Flagged

```python
# FLAGGED: PyJWT — explicitly accepting none algorithm
import jwt

decoded = jwt.decode(token, options={"verify_signature": False})
# OR
decoded = jwt.decode(token, algorithms=["none"])
```

```java
// FLAGGED: jjwt (Java) — using NONE algorithm
import io.jsonwebtoken.SignatureAlgorithm;

String jwt = Jwts.builder()
    .setSubject("admin")
    .signWith(SignatureAlgorithm.NONE)
    .compact();
```

```javascript
// FLAGGED: jsonwebtoken (Node.js)
const decoded = jwt.verify(token, '', { algorithms: ['none'] });
```

```python
# FLAGGED: setting alg to none in token header
header = {"alg": "none", "typ": "JWT"}
```

## Remediation

1. **Explicitly specify an allowlist of accepted algorithms** — never include `none` in the list:

```python
# SAFE: PyJWT — explicit algorithm allowlist
import jwt
import os

SECRET_KEY = os.environ['JWT_SECRET']

# For HMAC-signed tokens
decoded = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=["HS256"]  # explicit allowlist, never "none"
)

# For RSA-signed tokens (e.g., from an identity provider)
PUBLIC_KEY = os.environ['JWT_PUBLIC_KEY']
decoded = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=["RS256"]  # asymmetric — no shared secret needed
)
```

```javascript
// SAFE: Node.js jsonwebtoken — explicit algorithm
const jwt = require('jsonwebtoken');

const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'],  // explicit — never 'none'
});
```

```java
// SAFE: jjwt — explicit algorithm with key
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;

Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
Claims claims = Jwts.parserBuilder()
    .setSigningKey(key)
    .build()
    .parseClaimsJws(token)  // rejects none algorithm automatically
    .getBody();
```

2. **Prefer asymmetric algorithms (RS256, ES256) over symmetric (HS256)** for tokens issued to external parties. With asymmetric algorithms, only you can sign (using the private key) but anyone can verify (using the public key) — there is no shared secret to leak.

3. **Update JWT libraries to current versions.** PyJWT 2.x, jsonwebtoken 9.x, and jjwt 0.11+ all reject `none` by default. Check your library's changelog to confirm your version handles this correctly.

4. **Never use `options={"verify_signature": False}`** in PyJWT for any token that grants privileges. This is appropriate only for debugging or decoding tokens you already trust.

5. **Validate all JWT claims** after signature verification: check `exp` (expiration), `iss` (issuer), and `aud` (audience) to prevent token reuse across different services or after expiration.

## References

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CVE-2015-9235: PyJWT none algorithm vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- [OWASP: JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Auth0: Critical vulnerabilities in JWT libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [jwt.io: Debugger and algorithm information](https://jwt.io/)
- [MITRE ATT&CK T1550.001 – Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [CAPEC-115: Authentication Bypass](https://capec.mitre.org/data/definitions/115.html)
