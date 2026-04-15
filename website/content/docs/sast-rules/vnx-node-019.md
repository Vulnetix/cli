---
title: "VNX-NODE-019 – Hardcoded JWT or Session Secret"
description: "Detects hardcoded string literals used as JWT signing secrets, session secrets, or HMAC keys instead of environment variables or a secrets manager."
---

## Overview

This rule flags hardcoded string literals passed as cryptographic secrets to `jwt.sign()`, `jwt.verify()`, `express-session`'s `secret:` configuration option, or `crypto.createHmac()`. A hardcoded secret is one embedded directly in source code as a quoted string rather than loaded at runtime from an environment variable (`process.env.SECRET_NAME`) or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).

The rule matches `jwt.sign(payload, 'literal-string')` and `jwt.verify(token, 'literal-string')`, `secret: 'literal-string'` in any session or cookie configuration, and `crypto.createHmac('sha256', 'literal-key')`. It excludes lines that reference `process.env` (a variable load) and comment lines.

Hardcoded secrets are functionally equivalent to no secret at all for anyone with read access to the repository. Every JWT the application signs with a known secret can be forged, every session can be hijacked, and every HMAC can be replicated by an attacker who has recovered the key from source code.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Source code is rarely as private as developers assume. It may be checked in to a shared Git repository, present in build artefacts, included in Docker images, visible to CI/CD pipeline runners, or accessible to any employee with repository read access. Once a secret appears in a commit, it is permanently recorded in Git history even if subsequently removed — any clone made before the removal retains the secret.

For JWT secrets, compromise means an attacker can sign arbitrary tokens asserting any identity or role. For session secrets, it means session cookies can be forged, bypassing authentication entirely. For HMAC keys, it breaks the integrity guarantee of any MAC-protected data.

Real-world incidents: hardcoded secrets in public GitHub repositories are continuously harvested by automated scanners. The GitGuardian 2024 report found hardcoded secrets in one in ten public commits. Internal repositories are not immune — insider threats, accidental repository visibility changes, and repository exposure during security incidents all create paths to secret discovery.

## What Gets Flagged

```javascript
// FLAGGED: hardcoded string literal as JWT signing secret
const token = jwt.sign({ userId: user.id }, 'my-secret-key');

// FLAGGED: hardcoded secret in jwt.verify
const payload = jwt.verify(token, 'supersecret123');

// FLAGGED: hardcoded session secret in express-session
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
}));

// FLAGGED: hardcoded HMAC key
const hmac = crypto.createHmac('sha256', 'static-key');
```

## Remediation

1. **Load all secrets from environment variables** using `process.env`. Validate that the variable is set at application startup so the app fails fast rather than running with a missing secret.

2. **For production deployments**, use a secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Doppler) and inject secrets as environment variables at runtime.

3. **Rotate any secret that has already appeared in source code.** Even a brief window of exposure requires rotation because Git history is permanent.

4. **Use a `.env` file locally with `dotenv`**, ensuring `.env` is in `.gitignore` and never committed.

```javascript
// SAFE: load secrets from environment at startup
const JWT_SECRET = process.env.JWT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!JWT_SECRET || !SESSION_SECRET) {
  console.error('Required secrets not set in environment');
  process.exit(1);
}

// SAFE: use environment variable for JWT signing
const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
  algorithm: 'HS256',
  expiresIn: '1h',
  issuer: 'https://yourapp.com',
});

// SAFE: use environment variable for express-session
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: 'strict' },
}));

// SAFE: use environment variable for HMAC
const hmac = crypto.createHmac('sha256', process.env.HMAC_KEY);
hmac.update(data);
const digest = hmac.digest('hex');
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
- [OWASP Node.js Security Cheat Sheet – Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [dotenv npm package](https://github.com/motdotla/dotenv)
- [jsonwebtoken npm — best practices](https://github.com/auth0/node-jsonwebtoken#readme)
