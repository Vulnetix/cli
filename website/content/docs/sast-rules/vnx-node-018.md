---
title: "VNX-NODE-018 – JWT Decoded Without Signature Verification"
description: "Detects use of jwt.decode() instead of jwt.verify(), and JWT configurations that accept the 'none' algorithm, both of which allow forged tokens to be accepted as valid."
---

## Overview

This rule detects two distinct but related patterns in JSON Web Token handling: using `jwt.decode()` where `jwt.verify()` is required, and configuring the `jsonwebtoken` library to accept the `none` algorithm in the accepted algorithms list. Both patterns result in the same critical outcome: the token's signature is not verified, so any token — including a completely fabricated one — will be accepted as valid.

`jwt.decode()` from the `jsonwebtoken` library is a utility function that base64-decodes the token payload and returns the claims without performing any cryptographic validation. It does not check the signature, the `exp` (expiry) claim, the `iss` (issuer) claim, or the `aud` (audience) claim. Code that uses `jwt.decode()` to make authorization decisions is functionally equivalent to having no token authentication at all — any user can craft a token claiming to be an administrator.

The `none` algorithm attack is a separate vector: some JWT libraries honour the algorithm field in the token header. If the application lists `"none"` as an acceptable algorithm, an attacker removes the signature from a valid token, changes the header algorithm to `"none"`, and submits the modified token. The library accepts it because there is nothing to verify.

**Severity:** High | **CWE:** [CWE-347 – Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

## Why This Matters

JWT is the dominant authentication mechanism in modern Node.js APIs, and authentication bypass is one of the highest-severity vulnerability classes. When token verification is absent, every protected endpoint in the application is accessible to any caller who knows the expected token structure. Attackers escalate privileges by setting `"role": "admin"` in the payload, impersonate arbitrary users by setting `"sub"` to any user ID, and bypass multi-factor authentication by crafting tokens that assert the second factor was completed.

The `jwt.decode()` mistake is particularly common because the function name sounds authoritative — developers assume that if decoding succeeds, the token is valid. API documentation and tutorials do not always clearly distinguish between `decode` (inspection only) and `verify` (cryptographic validation). The error is extremely easy to introduce during rapid development and can persist unnoticed because the application continues to function normally with legitimate tokens.

Bug bounty programmes regularly receive high-severity reports for `jwt.decode()` misuse. Because the bypass requires no special tools or prior access, it is reliably exploitable by any attacker who can observe a valid token (e.g., from browser developer tools or a network proxy).

## What Gets Flagged

```javascript
// FLAGGED: jwt.decode() does not verify the signature
const decoded = jwt.decode(req.headers.authorization.split(' ')[1]);
if (decoded.role === 'admin') {
  return res.json({ admin: true });
}

// FLAGGED: JWT configured to accept 'none' algorithm
const payload = jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });

// FLAGGED: accepting none allows signature stripping
app.use((req, res, next) => {
  const token = req.headers['x-auth-token'];
  const user = jwt.decode(token); // no verification at all
  req.user = user;
  next();
});
```

## Remediation

1. **Always use `jwt.verify()` with the signing secret or public key.** Pass the exact algorithm(s) you expect to prevent algorithm confusion attacks.

2. **Never include `"none"` in the accepted algorithms list.**

3. **Validate the decoded claims** (expiry, issuer, audience) either via `jwt.verify()` options or manually after verification.

4. **Treat `jwt.decode()` as a debugging tool only** — it should never appear in authentication or authorization code paths.

```javascript
// SAFE: verify signature with explicit algorithm and secret from env
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET; // loaded at startup, never hardcoded

app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],    // explicit allowlist — never 'none'
      issuer: 'https://yourapp.com',
      audience: 'api',
    });
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// SAFE: using jsonwebtoken verify with RS256 (asymmetric)
const publicKey = fs.readFileSync('./keys/public.pem');
const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CAPEC-196: Session Credential Falsification through Forging](https://capec.mitre.org/data/definitions/196.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [jsonwebtoken npm package — verify() documentation](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback)
- [Auth0: Critical vulnerabilities in JWT libraries (algorithm confusion)](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
