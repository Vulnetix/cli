---
title: "VNX-JWT-001 – JWT Signature Verification Disabled"
description: "JWT decode is called with signature verification disabled, or the 'none' algorithm is permitted in the allowed-algorithms list, allowing any forged or tampered token to be accepted as valid."
---

## Overview

JWT decode is called with `verify_signature=False`, `verify=False`, or the `"none"` algorithm is included in the permitted algorithms list. This completely disables cryptographic authentication of tokens, allowing an attacker to forge arbitrary tokens with any payload — including elevated privilege claims — and have them accepted as valid without any key material.

**Severity:** Critical | **CWE:** [CWE-347 – Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) | **CAPEC:** [CAPEC-196 – Session Credential Falsification through Forging](https://capec.mitre.org/data/definitions/196.html)

**OWASP ASVS v4:** [3.5.3](https://asvs.dev/v4.0.3/V3-Session-management/) – Stateless session tokens must use digital signatures and other countermeasures to protect against null cipher and key substitution attacks.

## Why This Matters

JWT authentication relies entirely on signature verification. The signature is a cryptographic proof that the token was issued by a party holding the signing key and that its contents have not been altered. Disabling verification means any JSON payload — base64url-encoded and passed as a token — will be accepted regardless of its source or content.

### The `alg:none` Attack

The `none` algorithm attack is one of the oldest and best-documented JWT vulnerabilities, originally disclosed in 2015 and covered by CVE-2015-9235 and multiple related CVEs. The steps require no cryptographic knowledge:

1. Obtain any valid JWT (including one issued to your own low-privilege account).
2. Base64url-decode the header (no key required — this is public data).
3. Change `"alg"` from `"HS256"` (or any signing algorithm) to `"none"`.
4. Modify the payload to claim any identity, role, or permission you want.
5. Re-encode header and payload, append an empty signature section (a trailing dot), and submit.

A vulnerable library that includes `"none"` in its accepted algorithms list will skip signature validation entirely and accept the forged token as authentic.

### Algorithm Confusion Attack

A more sophisticated attack targets services that use asymmetric algorithms (RS256, ES256). If the verify call accepts both RS256 and HS256:

1. Obtain the server's RSA **public key** — often exposed at a `/.well-known/jwks.json` endpoint.
2. Forge a token signed with **HS256** using the **public key bytes as the HMAC secret**.
3. Submit the token with `"alg": "HS256"` in the header.

A vulnerable library that calls a single algorithm-agnostic `verify()` without checking the expected algorithm will use the public key as the HMAC secret, confirm the HMAC signature, and accept the forged token. The defence is always specifying the exact expected algorithm server-side and never trusting the `alg` field from the token header.

### Library Defaults

| Library | `"none"` accepted by default? |
|---|---|
| **PyJWT** (Python) | No. Since v2.0, `algorithms` is a required parameter. `"none"` must be explicitly listed to be permitted. |
| **jsonwebtoken** (Node.js) | **v8.x and earlier: yes** — omitting the `algorithms` option could result in `"none"` being accepted. **v9.0.0+: no** — `"none"` was removed from default behaviour. Upgrade immediately if on v8. |
| **jose** (Node.js) | No. Algorithm is always required at verification time; `"none"` is never implicitly accepted. |
| **java-jwt** (Java/Auth0) | No. `Algorithm` is a mandatory, typed constructor parameter. There is no `Algorithm.NONE` constant; you must explicitly construct a signing algorithm. |
| **golang-jwt** (Go) | No. `alg=none` is rejected unless the caller explicitly passes `jwt.UnsafeAllowNoneSignatureType` as the key — a deliberately conspicuous opt-in. |

## What Gets Flagged

```python
# FLAGGED: verify_signature=False bypasses all signature checks (PyJWT)
payload = jwt.decode(token, options={"verify_signature": False})

# FLAGGED: verify=False in older PyJWT API
payload = jwt.decode(token, secret, verify=False)

# FLAGGED: 'none' included in the allowed algorithms list
payload = jwt.decode(token, secret, algorithms=["HS256", "none"])
```

```javascript
// FLAGGED: algorithms list contains 'none' (jsonwebtoken <=8.x)
const payload = jwt.verify(token, secret, { algorithms: ["HS256", "none"] });
```

## Remediation

### Python (PyJWT)

Always specify a concrete algorithm list that excludes `"none"`. For symmetric secrets:

```python
import jwt
import os

SECRET_KEY = os.environ["JWT_SECRET"]

# SAFE: explicit algorithm whitelist — signature is always verified
payload = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=["HS256"],
)
```

For asymmetric keys (RS256 or ES256), pass the PEM public key and specify the exact algorithm:

```python
import jwt

with open("public.pem") as f:
    PUBLIC_KEY = f.read()

# SAFE: RS256 only — algorithm confusion attack is not possible
payload = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=["RS256"],  # never mix asymmetric and symmetric algorithms here
)
```

### Node.js (jsonwebtoken v9+)

```javascript
const jwt = require("jsonwebtoken");

// SAFE: explicit algorithm list, 'none' is absent
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"],
});
```

### Java (Auth0 java-jwt)

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

// Algorithm.HMAC256() enforces HMAC-SHA256 — 'none' cannot be constructed
Algorithm algorithm = Algorithm.HMAC256(System.getenv("JWT_SECRET"));
DecodedJWT verified = JWT.require(algorithm)
    .build()
    .verify(token);
```

### Go (golang-jwt/jwt v5)

```go
import (
    "fmt"
    "os"
    "github.com/golang-jwt/jwt/v5"
)

secretKey := []byte(os.Getenv("JWT_SECRET"))

// WithValidMethods rejects any algorithm not in the explicit list
token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return secretKey, nil
}, jwt.WithValidMethods([]string{"HS256"}))
if err != nil {
    // token is invalid or signature failed
}
```

### Key rules

1. Never include `"none"` in any algorithms list — in encode or decode calls.
2. Always specify the exact expected algorithm server-side — never read `alg` from the token header to decide which algorithm to use for verification.
3. Do not mix asymmetric (RS256, ES256) and symmetric (HS256) algorithms in the same verify call — this enables algorithm confusion attacks.
4. If you are running `jsonwebtoken` v8 or earlier, upgrade to v9+ immediately.

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CAPEC-196: Session Credential Falsification through Forging](https://capec.mitre.org/data/definitions/196.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP ASVS v4 V3.5.3 – Stateless Token Protections](https://asvs.dev/v4.0.3/V3-Session-management/)
- [RFC 7519 §6 – Unsecured JWTs (alg:none)](https://www.rfc-editor.org/rfc/rfc7519#section-6)
- [Auth0 – Critical Vulnerabilities in JSON Web Token Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [PortSwigger Web Security Academy – Algorithm Confusion Attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [jwt.io – JWT Introduction](https://jwt.io/introduction)
- [MITRE ATT&CK T1550.001 – Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
