---
title: "VNX-JWT-002 – JWT Token Signed Without Expiration"
description: "Detects jwt.sign() or jwt.encode() calls missing an expiration claim, producing tokens that remain valid indefinitely and cannot be invalidated after compromise."
---

## Overview

This rule detects `jwt.sign()` (Node.js/jsonwebtoken) and `jwt.encode()` (Python/PyJWT) calls where no `expiresIn` option or `exp` claim is present. A JWT without expiration is valid forever — from the moment it is issued until the signing secret is rotated or the token is explicitly blocklisted (which requires server-side state, defeating much of the purpose of JWTs). This maps to CWE-613 (Insufficient Session Expiration).

**Severity:** Medium | **CWE:** [CWE-613 – Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

## Why This Matters

JWTs are commonly used as stateless session tokens — the server does not store them, so there is no built-in revocation mechanism. This is by design, but it places extra importance on short lifetimes. If a token without expiration is leaked from a user's device, a log file, a network capture, or a third-party service, the attacker has a permanent credential.

A sliding session attack exploits this directly: an attacker who steals one token can replay it months or years later, long after the legitimate user has changed their password. Because JWTs are stateless, a password change does not invalidate previously issued tokens unless the application explicitly tracks and rejects them. Short-lived access tokens (15 minutes to 1 hour) combined with a refresh token pattern are the standard mitigation: the refresh token is stored securely and exchanged for new access tokens, and can be revoked server-side if needed.

## What Gets Flagged

```javascript
// FLAGGED: jwt.sign() without expiresIn
const token = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_SECRET);
```

```python
# FLAGGED: jwt.encode() without exp claim
token = jwt.encode({"sub": user_id, "role": "admin"}, SECRET_KEY, algorithm="HS256")
```

## Remediation

1. **Add `expiresIn` to all `jwt.sign()` calls.** Use short durations for access tokens:

   ```javascript
   // SAFE: 15-minute access token
   const accessToken = jwt.sign(
     { userId: user.id, role: user.role },
     process.env.JWT_SECRET,
     { expiresIn: '15m' }
   );
   ```

2. **Add an `exp` claim to Python `jwt.encode()` calls:**

   ```python
   # SAFE: token expires in 15 minutes
   from datetime import datetime, timedelta, timezone
   import jwt

   payload = {
       "sub": str(user_id),
       "role": user.role,
       "iat": datetime.now(timezone.utc),
       "exp": datetime.now(timezone.utc) + timedelta(minutes=15)
   }
   token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
   ```

3. **Implement a refresh token pattern** for sessions that need to last longer than the access token lifetime. Issue a short-lived access token (15 minutes) and a longer-lived refresh token (7–30 days) stored in an httpOnly cookie. The refresh token can be revoked server-side in a blocklist or by rotating the stored token hash.

4. **Choose token lifetimes based on sensitivity.** High-value operations (payment, admin actions) warrant shorter-lived tokens. Adjust based on your threat model.

## References

- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- [RFC 7519 – JSON Web Token – Section 4.1.4 exp Claim](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Auth0 – Refresh Tokens: When to Use Them and How They Interact with JWTs](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
- [MITRE ATT&CK T1550.001 – Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
