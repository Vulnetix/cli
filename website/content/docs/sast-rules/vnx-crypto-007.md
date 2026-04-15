---
title: "VNX-CRYPTO-007 – Weak Password Hashing (Insufficient Iterations or Missing KDF)"
description: "Detects passwords hashed with MD5, SHA-1, SHA-256, or similar general-purpose algorithms instead of a proper key derivation function, making stored passwords recoverable through brute-force or rainbow-table attacks."
---

## Overview

This rule detects password hashing operations using general-purpose cryptographic hash functions: MD5, SHA-1, or SHA-256 applied directly to passwords in Python (`hashlib`), Java (`MessageDigest`), and Node.js (`crypto.createHash`). General-purpose hash functions are designed to be fast — which is the opposite of what you want for password hashing. A GPU can compute billions of MD5 or SHA-256 hashes per second, making a database of hashed passwords recoverable in hours or days. This maps to CWE-916 (Use of Password Hash With Insufficient Computational Effort).

**Severity:** High | **CWE:** [CWE-916 – Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

## Why This Matters

When attackers breach a database containing password hashes, the speed of cracking depends almost entirely on the hashing algorithm used. An MD5 hash of `password123` can be reversed in milliseconds using precomputed rainbow tables. SHA-256 without a salt fares little better. Even with per-user salts, MD5 and SHA-1 remain orders of magnitude too fast — modern GPU clusters crack salted SHA-256 passwords at rates exceeding 10 billion hashes per second.

The impact is not limited to users who reuse passwords. Cracked passwords reveal patterns: users who use `CompanyName2024!` in one place often use similar patterns elsewhere. A breach of your password database can become a starting point for credential stuffing attacks against every other service your users touch. The OWASP Password Storage Cheat Sheet is explicit: use bcrypt, scrypt, or Argon2id for all new password storage.

## What Gets Flagged

```python
# FLAGGED: SHA-256 applied directly to password
import hashlib
hashed = hashlib.sha256(password.encode()).hexdigest()
```

```java
// FLAGGED: MD5 for password hashing in Java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());
```

```javascript
// FLAGGED: SHA-1 applied to password in Node.js
const hash = crypto.createHash('sha1').update(password).digest('hex');
```

## Remediation

1. **Use bcrypt for most applications.** The cost factor lets you tune computational expense upward as hardware improves:

   ```python
   # SAFE: bcrypt with cost factor 12
   import bcrypt
   hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

   # Verification
   bcrypt.checkpw(password.encode('utf-8'), hashed)
   ```

   ```javascript
   // SAFE: bcrypt in Node.js
   const bcrypt = require('bcrypt');
   const SALT_ROUNDS = 12;
   const hash = await bcrypt.hash(password, SALT_ROUNDS);

   // Verification (constant-time comparison built in)
   const match = await bcrypt.compare(password, hash);
   ```

2. **Use Argon2id for new projects.** It is the winner of the Password Hashing Competition and is recommended by OWASP as the first choice:

   ```python
   # SAFE: Argon2id
   from argon2 import PasswordHasher
   ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=1)
   hash = ph.hash(password)
   ph.verify(hash, password)
   ```

3. **Migrate existing MD5/SHA hashes.** On each successful login with the old hash, rehash with bcrypt/Argon2id and store the new hash. After a grace period, invalidate all accounts that still have the old hash format.

4. **Never use raw hash output for password comparison** — always use the library's built-in comparison function, which incorporates constant-time comparison (see VNX-CRYPTO-008).

## References

- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B – Memorized Secret Verifiers](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5)
- [bcrypt package (Python)](https://pypi.org/project/bcrypt/)
- [argon2-cffi package (Python)](https://pypi.org/project/argon2-cffi/)
- [MITRE ATT&CK T1110.002 – Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
