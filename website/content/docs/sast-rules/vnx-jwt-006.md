---
title: "VNX-JWT-006 – JWT Missing Audience or Issuer Verification"
description: "Detects jwt.decode() and jwt.verify() calls that do not specify audience or issuer claim verification, allowing tokens issued for one service to be replayed against another."
---

## Overview

This rule detects `jwt.decode()` calls (Python) and `jwt.verify()` calls (Node.js) that do not include `audience`, `issuer`, `aud`, or `iss` verification options. Without audience and issuer checks, a JWT that was legitimately issued for one service can be presented to a different service that shares the same signing key, and that second service will accept it as valid. This is a token cross-service replay attack. This maps to CWE-287 (Improper Authentication).

The JWT specification defines the `aud` (audience) claim to identify the recipients that the JWT is intended for, and the `iss` (issuer) claim to identify the principal that issued the JWT. Verifying both claims ensures that a token can only be used with the service it was issued for, by the issuer you trust. Libraries do not verify these claims by default — explicit options must be passed to each decode or verify call.

**Severity:** Medium | **CWE:** [CWE-287 – Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

## Why This Matters

In a microservices architecture or multi-application environment, multiple services may share a signing key — for convenience or because tokens are issued by a central identity provider. Without audience verification, a JWT issued for the `payments-service` with a payload like `{ "sub": "user123", "role": "admin" }` can be presented to the `admin-console` service. If both services share a key and neither verifies `aud`, the admin console accepts the token and grants admin access.

CAPEC-196 (Session Credential Falsification through Forging) and MITRE ATT&CK T1550.001 (Use Alternate Authentication Material: Application Access Token) document the token replay pattern. This attack requires no cryptographic capability — the attacker simply presents a valid token to an unintended service. It is particularly easy to exploit when the attacker has a legitimate account on one low-privilege service and uses their valid token against a higher-privilege service.

Issuer verification prevents a third-party identity provider — or a compromised internal service — from issuing tokens that a victim service accepts. Together, audience and issuer verification bind tokens to their intended context.

## What Gets Flagged

```python
# FLAGGED: jwt.decode without audience or issuer verification
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
# A token issued for "service-a" is accepted by "service-b"
```

```javascript
// FLAGGED: jwt.verify without audience or issuer options
const payload = jwt.verify(token, secretKey);

// FLAGGED: jwt.verify with options object but no audience/issuer
const payload = jwt.verify(token, secretKey, { algorithms: ["HS256"] });
```

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
