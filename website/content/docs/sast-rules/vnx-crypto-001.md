---
title: "VNX-CRYPTO-001 – MD5 Usage Detected"
description: "Detects use of the MD5 hash algorithm across Python, Node.js, Go, Java, Ruby, and PHP, flagging code that relies on a cryptographically broken hash function."
---

## Overview

This rule detects invocations of the MD5 hashing algorithm across six languages (Python, Node.js, Go, Java, Ruby, and PHP). MD5 produces a 128-bit digest and was widely used for integrity checks and password storage, but it is now definitively broken for any security purpose. Collisions can be generated in seconds on commodity hardware, and rainbow tables covering billions of MD5 digests are freely available. This maps directly to CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

**Severity:** Medium | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

The most damaging consequence of MD5 is in password storage: if your database is breached and passwords are stored as plain MD5 hashes, attackers can reverse the majority of them in minutes using precomputed tables or GPU-accelerated cracking. Large-scale breaches at LinkedIn (2012), RockYou (2009), and Adobe (2013) all involved weak hashing schemes similar to MD5, resulting in hundreds of millions of account takeovers.

For file integrity and digital signatures, the SHAttered and Flame malware attacks demonstrated that MD5 collisions can be exploited to forge certificate signatures and code-signing payloads. Even when MD5 is used "only for checksums," an attacker controlling the data source can produce two different files with the same MD5 digest, negating the integrity guarantee entirely. CAPEC-97 (Cryptanalysis) covers this attack class.

## What Gets Flagged

The rule matches language-specific MD5 invocation patterns in source files:

```python
# FLAGGED: Python hashlib MD5
import hashlib
digest = hashlib.md5(data).hexdigest()
```

```javascript
// FLAGGED: Node.js crypto MD5
const hash = crypto.createHash('md5').update(data).digest('hex');
```

```java
// FLAGGED: Java MessageDigest MD5
MessageDigest md = MessageDigest.getInstance("MD5");
```

```go
// FLAGGED: Go md5 package
import "crypto/md5"
hash := md5.Sum(data)
```

## Remediation

1. **Replace MD5 with SHA-256 or SHA-3 for general-purpose hashing.** SHA-256 is NIST-approved, hardware-accelerated on all modern CPUs, and has no known practical collisions. Use SHA-3 (Keccak) for new systems where a distinct algorithm family is preferred.

   ```python
   # SAFE: SHA-256 for integrity checks
   import hashlib
   digest = hashlib.sha256(data).hexdigest()
   ```

   ```javascript
   // SAFE: SHA-256 in Node.js
   const hash = crypto.createHash('sha256').update(data).digest('hex');
   ```

2. **For password hashing, use a purpose-built KDF.** Never use a bare hash (MD5, SHA-256, or even SHA-3) to store passwords. Use bcrypt, Argon2id, or scrypt, which are designed to be computationally expensive and salted.

   ```python
   # SAFE: Argon2id for password hashing (argon2-cffi library)
   from argon2 import PasswordHasher
   ph = PasswordHasher()
   hash = ph.hash(password)
   ```

3. **Migrate existing MD5 hashes.** If you have a database of MD5-hashed passwords, implement a migration path: on next successful login, re-hash the password with the new KDF and replace the stored value.

4. **For file checksums in a trust boundary you do not control, use SHA-256 or SHA-512.** Many package managers and artifact stores provide SHA-256 checksums; verify them rather than computing your own MD5.

5. **Audit non-security uses.** Some teams use MD5 as a fast non-cryptographic hash (e.g., cache keys, ETags). This is technically acceptable if there is no security dependency, but consider a purpose-built non-cryptographic hash (xxHash, MurmurHash3) to avoid confusion and future security reviews flagging the usage.

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
- [NIST SP 800-131A Rev 2 – Transitioning the Use of Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 6151 – Updated Security Considerations for MD5](https://www.rfc-editor.org/rfc/rfc6151)
- [SHAttered – MD5/SHA-1 Collision Attack](https://shattered.io/)
