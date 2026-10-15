---
title: "VNX-SEC-011 – Hardcoded JWT Token"
description: "Detects a signed JSON Web Token that decodes (JSON header and payload, alg other than none, not expired) in any file outside tests and prose; the jwt.io sample token, Supabase anon keys and the Supabase local demo keys are not reported."
---

## Overview

This rule detects signed JSON Web Tokens: three base64url segments whose header and payload decode to JSON objects, whose header names a signing algorithm other than `none`, and whose `exp` claim (if any) is still in the future. Tokens in test, spec, fixture and mock paths, in Markdown and other prose files, the public jwt.io sample token (`sub` 1234567890, John Doe), and Supabase anon keys (`role: anon`, public by design) are not reported. JWTs are Base64url-encoded tokens with three dot-separated parts: a header (starts with `eyJ`), a payload, and a signature. They are widely used for authentication and session management. Hardcoding a JWT in source code exposes the token and all its claims — including user identity, roles, and permissions — in version history where it may remain accessible indefinitely.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A critical misconception about JWTs is that they are encrypted — most are not. The header and payload are merely Base64url-encoded, meaning anyone who intercepts or finds the token can decode it to read its contents without any key. Run `echo 'eyJ...' | base64 -d` (with appropriate padding) to decode a JWT payload and see its claims. Only JWE (JSON Web Encryption) tokens provide confidentiality; standard JWS (signed) tokens do not.

This means a hardcoded JWT in source code exposes user identity claims, roles, email addresses, and any other data in the payload to anyone who can read the code. If the token is long-lived (some JWTs have very long or no expiration), it can be used to impersonate the user or service it represents until the signing key is rotated.

Hardcoded JWTs commonly appear in test fixtures, where developers create tokens for specific roles or permissions. Even test-environment tokens should not be committed if the signing secret or service is shared with production.

## What Gets Flagged

```python
# FLAGGED: a long-lived service token committed as a default
SERVICE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvcnQtd29ya2VyIiwicm9sZSI6InNlcnZpY2UifQ.<signature>"
```

```javascript
// FLAGGED: hardcoded token in config
const DEFAULT_AUTH_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...';
```

## Remediation

1. **Invalidate the token.** If your application supports JWT revocation (via a blocklist or by rotating the signing key), invalidate the exposed token immediately. If the token has no expiration (`exp` claim), the only safe option is rotating the signing key, which invalidates all tokens signed with it.

2. **Remove from source code.** JWTs for testing should be generated programmatically in tests, not hardcoded:

```python
# SAFE: generate a fresh test token at test time — never hardcode
import os
import jwt
import time

def generate_test_token(user_id: str, role: str) -> str:
    secret = os.environ['JWT_SECRET']
    payload = {
        'sub': user_id,
        'role': role,
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600,  # 1 hour
    }
    return jwt.encode(payload, secret, algorithm='HS256')
```

3. **Decode the exposed token** to understand what was leaked. Use `jwt.io` or:

```bash
echo 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx' | \
  python3 -c "import sys,base64,json; parts=sys.stdin.read().strip().split('.'); print(json.dumps(json.loads(base64.urlsafe_b64decode(parts[1]+'==')), indent=2))"
```

4. **Use short expiration times on all tokens.** JWTs should have an `exp` claim with a short lifetime (minutes to hours, not days or weeks). Use refresh tokens for long-lived sessions — these can be revoked individually unlike JWTs.

5. **Load signing secrets from environment variables** and never hardcode them:

```python
# SAFE: load JWT signing secret from environment
import os
import jwt

SECRET_KEY = os.environ['JWT_SECRET_KEY']

def create_token(user_id: str) -> str:
    return jwt.encode({'sub': user_id, 'exp': ...}, SECRET_KEY, algorithm='HS256')

def verify_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
```

6. **Scan git history** for any committed tokens:

```bash
gitleaks detect --source . --verbose
# JWTs always start with eyJ so this catches all of them
git log --all -p | grep -o 'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [JWT.io: JSON Web Token introduction](https://jwt.io/introduction)
- [OWASP: JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 7519: JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
