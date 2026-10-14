---
title: "VNX-JWT-006 – JWT Missing Audience or Issuer Verification"
description: "Audience or issuer validation is switched off (verify_aud/verify_iss False in Python, ValidateAudience/ValidateIssuer = false in C#), or a token is verified against an identity provider's shared JWKS with no audience check in the file (jsonwebtoken, jose, express-jwt, Auth0 java-jwt, golang-jwt)."
---

## Overview

This rule detects two concrete shapes. First, audience or issuer validation switched off explicitly: PyJWT/python-jose `options={"verify_aud": False}` or `{"verify_iss": False}`, and .NET `TokenValidationParameters` with `ValidateAudience = false` or `ValidateIssuer = false`. Second, a token verified against an identity provider's shared key set with no audience check anywhere in the file: jsonwebtoken `jwt.verify()`, jose `jwtVerify()` and express-jwt in a file using jwks-rsa or `createRemoteJWKSet`, Auth0 `JWT.require()` in a file using a `JwkProvider`, and golang-jwt `jwt.Parse()` with a keyfunc/JWKS key set and no `jwt.WithAudience`. Verification with a private shared secret and no audience is not reported (the key itself binds the token to this service, and PyJWT already rejects an `aud` claim it was not told to expect). Without audience and issuer checks, a JWT that was legitimately issued for one service can be presented to a different service that shares the same signing key, and that second service will accept it as valid. This is a token cross-service replay attack. This maps to CWE-287 (Improper Authentication).

The JWT specification defines the `aud` (audience) claim to identify the recipients that the JWT is intended for, and the `iss` (issuer) claim to identify the principal that issued the JWT. Verifying both claims ensures that a token can only be used with the service it was issued for, by the issuer you trust. Libraries do not verify these claims by default — explicit options must be passed to each decode or verify call.

**Severity:** Medium | **CWE:** [CWE-287 – Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

## Why This Matters

In a microservices architecture or multi-application environment, multiple services may share a signing key — for convenience or because tokens are issued by a central identity provider. Without audience verification, a JWT issued for the `payments-service` with a payload like `{ "sub": "user123", "role": "admin" }` can be presented to the `admin-console` service. If both services share a key and neither verifies `aud`, the admin console accepts the token and grants admin access.

CAPEC-196 (Session Credential Falsification through Forging) and MITRE ATT&CK T1550.001 (Use Alternate Authentication Material: Application Access Token) document the token replay pattern. This attack requires no cryptographic capability — the attacker simply presents a valid token to an unintended service. It is particularly easy to exploit when the attacker has a legitimate account on one low-privilege service and uses their valid token against a higher-privilege service.

Issuer verification prevents a third-party identity provider — or a compromised internal service — from issuing tokens that a victim service accepts. Together, audience and issuer verification bind tokens to their intended context.

## What Gets Flagged

```python
# FLAGGED: audience verification switched off
return jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
```

```csharp
// FLAGGED
ValidateIssuer = false,
ValidateAudience = false,
```

```javascript
// FLAGGED: key from the provider's JWKS, no audience anywhere in the file
const client = jwksClient({ jwksUri: 'https://tenant.example.com/.well-known/jwks.json' });
jwt.verify(token, getKey, { algorithms: ['RS256'], issuer: 'https://tenant.example.com/' }, cb);
```

```go
// FLAGGED: JWKS keyfunc without jwt.WithAudience
return jwt.Parse(raw, jwks.Keyfunc, jwt.WithIssuer("https://idp.example.com/"))
```

Not flagged: `audience="orders-api"`, `ValidateAudience = true`, an options object carrying `audience`, `.withAudience(...)`, `jwt.WithAudience(...)`, and `jwt.verify(token, process.env.SESSION_KEY)` with a private shared secret.

## Remediation

1. **Always pass `audience` and `issuer` parameters to `jwt.decode()`** in Python.

   ```python
   # SAFE: audience and issuer verified on every decode
   import jwt

   payload = jwt.decode(
       token,
       SECRET_KEY,
       algorithms=["HS256"],
       audience="payments-service",
       issuer="https://auth.example.com",
   )
   ```

2. **Pass `audience` and `issuer` in the options object to `jwt.verify()`** in Node.js.

   ```javascript
   // SAFE: audience and issuer verified on every verify call
   const payload = jwt.verify(token, secretKey, {
     algorithms: ["HS256"],
     audience: "payments-service",
     issuer: "https://auth.example.com",
   });
   ```

3. **Define expected audience and issuer values as application constants** rather than inline strings, so they can be audited and are not silently empty in any deployment environment.

   ```javascript
   // SAFE: constants ensure the values are always explicitly defined
   const JWT_AUDIENCE = process.env.JWT_AUDIENCE;
   const JWT_ISSUER = process.env.JWT_ISSUER;

   if (!JWT_AUDIENCE || !JWT_ISSUER) {
     throw new Error("JWT_AUDIENCE and JWT_ISSUER must be configured");
   }

   const payload = jwt.verify(token, secretKey, {
     algorithms: ["RS256"],
     audience: JWT_AUDIENCE,
     issuer: JWT_ISSUER,
   });
   ```

## References

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CAPEC-196: Session Credential Falsification through Forging](https://capec.mitre.org/data/definitions/196.html)
- [MITRE ATT&CK T1550.001 – Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [RFC 7519 – JSON Web Token (JWT), Section 4.1: Registered Claim Names](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)
- [jwt.io – JWT introduction and claims](https://jwt.io/introduction)
- [OWASP JWT Security Cheat Sheet – Validate all claims](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PyJWT documentation – Audience and issuer verification](https://pyjwt.readthedocs.io/en/stable/usage.html#audience-claim)
