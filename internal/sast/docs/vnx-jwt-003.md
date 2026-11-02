---
title: "VNX-JWT-003 – JWT Signing with Hardcoded Secret"
description: "A JWT signing or verification key is a string literal: passed straight to jwt.sign/verify, express-jwt, jwt.encode/decode, JWT.encode/decode, JWT::encode, new Key(), jjwt signWith/setSigningKey, Algorithm.HMAC256, SignedString([]byte(...)) or SymmetricSecurityKey, assigned to a variable used as the key, or assigned to a JWT-named setting in code, .properties or YAML."
---

## Overview

This rule detects a JWT key written into the source: a literal passed directly as the key to jsonwebtoken `jwt.sign()`/`jwt.verify()`, express-jwt `{ secret }`, PyJWT `jwt.encode()`/`jwt.decode()`, ruby-jwt, firebase/php-jwt (`JWT::encode`, `new Key(...)`), jjwt `signWith`/`setSigningKey`, Auth0 `Algorithm.HMAC256/384/512`, `Keys.hmacShaKeyFor`, golang-jwt `SignedString([]byte("..."))` and .NET `new SymmetricSecurityKey(Encoding.UTF8.GetBytes("..."))`; a variable assigned a literal in the same file and then passed as the key; and a JWT-named setting (`JWT_SECRET`, `JWT_SECRET_KEY`, `jwtSecret`, `jwtKey`, `app.config["JWT_SECRET_KEY"]`, `jwt.secret=` in `.properties`, `jwt_secret:` in YAML) assigned a literal. Keys read from the environment or configuration, placeholders (`changeme`, `<...>`, `${...}`), non-secret settings such as `JWT_ALGORITHM`, and test files are not reported. A hardcoded secret committed to version control gives every developer, contractor, or attacker who accesses your code the ability to mint valid JWTs with any claims they choose. This maps to CWE-798 (Use of Hard-coded Credentials).

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

// FLAGGED: the assignment, because signingKey is then used as the key
const signingKey = 'kZ8#dev-signing-key';
jwt.sign({ sub: user.id }, signingKey, { expiresIn: '15m' });
```

```java
// FLAGGED
.signWith(SignatureAlgorithm.HS512, "victory-key")
private final Algorithm algorithm = Algorithm.HMAC256("auth0-hmac-key");
```

```go
// FLAGGED
return t.SignedString([]byte("inline-secret"))
```

Not flagged: `process.env.JWT_SECRET`, `os.environ["JWT_SECRET"]`, `@Value("${jwt.secret}")`, `config["Jwt:Key"]`, `JWT_SECRET_KEY = "changeme"`, `jwt_secret: ${JWT_SECRET}` and literals in test files.

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
