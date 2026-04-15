---
title: "VNX-JWT-003 – JWT Signing with Hardcoded Secret"
description: "Detects jwt.sign() or jwt.encode() using a hardcoded string literal as the signing secret, allowing anyone with source code access to forge valid tokens."
---

## Overview

This rule detects `jwt.sign()` and `jwt.encode()` calls where the signing secret is a hardcoded string literal passed directly as an argument, as well as variable assignments like `JWT_SECRET = "some-literal-string"` that are not loaded from the environment. A hardcoded secret committed to version control gives every developer, contractor, or attacker who accesses your code the ability to mint valid JWTs with any claims they choose. This maps to CWE-798 (Use of Hard-coded Credentials).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

The JWT signing secret is the root of trust for your authentication system. Anyone who knows the secret can forge tokens for any user, any role, or any permission scope your application uses. If this secret is in your git history, it is accessible to every past and future person with repository access — including former employees, contractors, and anyone who finds a leaked backup.

Unlike a database password that grants access to one service, a leaked JWT signing secret is a skeleton key for your entire application's authentication layer. An attacker can create a token for your highest-privileged admin account, set a far-future expiration, and silently maintain access indefinitely while performing any action the admin role permits.

## What Gets Flagged

```javascript
// FLAGGED: secret hardcoded as second argument to jwt.sign()
const token = jwt.sign({ userId: user.id }, "my-super-secret-jwt-key-12345");
```

```python
# FLAGGED: secret hardcoded in jwt.encode()
token = jwt.encode({"sub": user_id}, "hardcoded-secret-key-value", algorithm="HS256")
```

```javascript
// FLAGGED: JWT secret variable assigned a string literal
const JWT_SECRET = "production-jwt-secret-do-not-share";
```

## Remediation

1. **Load the signing secret from an environment variable** in all environments, including local development:

   ```javascript
   // SAFE: secret from environment
   const token = jwt.sign(
     { userId: user.id, role: user.role },
     process.env.JWT_SECRET,
     { expiresIn: '15m' }
   );
   ```

   ```python
   # SAFE: secret from environment
   import os
   import jwt
   token = jwt.encode({"sub": user_id, "exp": exp}, os.environ["JWT_SECRET"], algorithm="HS256")
   ```

2. **For stronger guarantees, switch to RS256 or ES256 with asymmetric keys.** The private key signs tokens; the public key verifies them. You can share the public key widely without risk, and rotation only requires updating the private key and publishing a new public key via JWKS.

3. **Generate a strong secret if you must use HS256.** Use at least 256 bits of random entropy:

   ```bash
   openssl rand -hex 64
   ```

4. **Rotate the exposed secret immediately.** If the secret was ever hardcoded and committed, assume it is compromised and generate a new one. Plan for a brief period where both old and new secrets are accepted (if your library supports it) to avoid invalidating all existing sessions simultaneously.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 7518 – JSON Web Algorithms – HS256 Key Requirements](https://www.rfc-editor.org/rfc/rfc7518#section-3.2)
- [Auth0 – JWT Signing Algorithms](https://auth0.com/blog/json-web-token-signing-algorithms-overview/)
- [MITRE ATT&CK T1552.001 – Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
