---
title: "VNX-JWT-005 – Sensitive Credential Data Stored in JWT Payload"
description: "A password, password hash, secret, API key, SSN or card number is put into JWT claims: in the payload of jwt.sign / SignJWT, jwt.encode, JWT.encode, JWT::encode or jwt.NewWithClaims, in a payload variable built just above, in a jjwt .claim() / Auth0 .withClaim(), or as a json-tagged field of a Go struct embedding jwt.RegisteredClaims."
---

## Overview

This rule detects sensitive keys (`password`, `passwordHash`, `secret`, `client_secret`, `api_key`, `ssn`, `credit_card`, `card_number`, `cvv` and spellings of them) placed into a token: in the payload literal of jsonwebtoken `jwt.sign()` or jose `new SignJWT()` (including the `{ password }` shorthand), PyJWT `jwt.encode()`, ruby-jwt `JWT.encode()`, firebase/php-jwt `JWT::encode()` and golang-jwt `jwt.NewWithClaims()`; in a payload variable defined or extended (`payload["password"] = ...`) within 20 lines above the call; in a jjwt `.claim("password", ...)` or Auth0 `.withClaim(...)`; and as a json-tagged field of a Go claims struct that embeds `jwt.RegisteredClaims`. Lookalike keys (`passwordChangedAt`, `hasPassword`), login forms and request bodies that never reach a token are not reported; signing a whole user record is not detected. JWT payloads are base64url-encoded JSON objects — they are not encrypted. Anyone who holds a JWT token can decode the payload without any key material by simply base64-decoding the second segment of the token. Storing passwords, secrets, API keys, or other sensitive credentials in a JWT claim means those credentials are visible to any party that receives the token: the user's browser, any intermediary proxy, log aggregators, and any system that inspects the Authorization header. This maps to CWE-522 (Insufficiently Protected Credentials).

JWT tokens are often stored in browser local storage, cookies, or mobile app storage. They are transmitted in HTTP headers, logged by access log systems, and stored in analytics pipelines. A token containing a password field leaks that password to every system that processes the request, potentially for the full lifetime of the token.

**Severity:** High | **CWE:** [CWE-522 – Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

## Why This Matters

JWT tokens are bearer tokens: possession equals identity. They are deliberately designed to be passed around, cached, and inspected. A password embedded in a JWT claim is therefore effectively a cleartext credential that travels with every authenticated request. If an attacker can read any log line, any HTTP access log entry, or any network capture that contains the Authorization header, they obtain the user's password without needing to crack anything.

CAPEC-37 (Retrieve Embedded Sensitive Data) and MITRE ATT&CK T1552 (Unsecured Credentials) document the exploitation pattern. The impact is amplified if the password is reused across services — which is common for credentials stored in systems where developers believed the JWT was opaque — because a single token exposure compromises multiple accounts.

JWT payloads should contain only non-sensitive identifiers: user IDs, roles, session IDs, and expiry claims. If additional claims are required for authorisation, they should be limited to data that is safe to be visible to the token holder and any infrastructure that processes requests.

## What Gets Flagged

```python
# FLAGGED: password stored in JWT payload
payload = {
    "sub": user.id,
    "password": user.password_hash,  # visible to anyone with the token
}
token = jwt.encode(payload, SECRET, algorithm="HS256")
```

```javascript
// FLAGGED: jwt.sign payload contains 'password' field
const token = jwt.sign(
  { sub: userId, password: req.body.password },
  secretKey,
  { expiresIn: "1h" }
);
```

```java
// FLAGGED
.claim("password", user.getPassword())
```

```go
// FLAGGED: a claims struct carrying the password
type Claims struct {
	Password string `json:"password"`
	jwt.RegisteredClaims
}
```

## Remediation

1. **Remove all sensitive credential fields from JWT payloads.** Store only non-sensitive identifiers such as user IDs, roles, and expiry timestamps.

   ```python
   # SAFE: payload contains only non-sensitive identifiers
   import jwt
   from datetime import datetime, timedelta

   payload = {
       "sub": str(user.id),
       "role": user.role,
       "exp": datetime.utcnow() + timedelta(hours=1),
   }
   token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
   ```

   ```javascript
   // SAFE: no sensitive fields in the JWT payload
   const token = jwt.sign(
     { sub: userId, role: user.role },
     secretKey,
     { expiresIn: "1h" }
   );
   ```

2. **If you need to pass sensitive data alongside a JWT**, use a server-side session store keyed by the JWT's subject claim (`sub`) and look up the sensitive data server-side on each request rather than embedding it in the token.

3. **If you genuinely need to protect sensitive claims in a token**, use a JWE (JSON Web Encryption) token rather than a JWS (JSON Web Signature) token. JWE encrypts the payload so it is not readable without the decryption key. Most JWT libraries support JWE alongside JWS.

## References

- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CAPEC-37: Retrieve Embedded Sensitive Data](https://capec.mitre.org/data/definitions/37.html)
- [MITRE ATT&CK T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [RFC 7519 – JSON Web Token (JWT), Section 4: JWT Claims](https://datatracker.ietf.org/doc/html/rfc7519#section-4)
- [RFC 7516 – JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
- [jwt.io – JWT introduction](https://jwt.io/introduction)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
