---
title: "VNX-GO-028 – Use of weak cryptographic hash for password hashing"
description: "Detects use of MD5 or SHA-1 for password hashing, which are cryptographically broken algorithms unsuitable for storing credentials."
---

## Overview

This rule flags code that uses `crypto/md5` or `crypto/sha1` — via `md5.New`, `sha1.New`, `md5.Sum`, or `sha1.Sum` — in proximity to variables named `password`, `passwd`, or similar. MD5 and SHA-1 are general-purpose hash functions designed for speed, not for password storage. They can be reversed using precomputed rainbow tables or brute-forced at billions of hashes per second on commodity GPU hardware, making any password database hashed with them trivially crackable. This maps to [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html).

Password hashing is a fundamentally different problem from data integrity hashing. A good password hashing algorithm is deliberately slow and incorporates a per-user salt to defeat precomputation attacks. MD5 and SHA-1 have neither of these properties and have additionally been shown to have serious collision vulnerabilities, making them unsuitable for any security-sensitive purpose.

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

Real-world breaches consistently demonstrate the danger of weak password hashing. When databases using MD5 or SHA-1 are leaked, attackers can crack the majority of passwords within hours using GPU-accelerated tools like Hashcat. Even salted MD5/SHA-1 hashes provide only marginal additional protection because the underlying compute cost remains negligible. LinkedIn's 2012 breach (117 million unsalted SHA-1 hashes) and Adobe's 2013 breach (3DES-ECB encrypted passwords) are well-known examples of weak credential storage leading to mass account compromise.

OWASP explicitly lists MD5 and SHA-1 as prohibited for password storage in its Password Storage Cheat Sheet, and NIST SP 800-63B prohibits the use of non-adaptive hashing for passwords. The correct algorithms — bcrypt, scrypt, and Argon2 — are available in the `golang.org/x/crypto` package and require only a few lines of code to use correctly.

## What Gets Flagged

The rule flags MD5 or SHA-1 usage that appears alongside password-related variables or context:

```go
// FLAGGED: MD5 used to hash a password
import "crypto/md5"

func hashPassword(password string) string {
    hash := md5.Sum([]byte(password))
    return hex.EncodeToString(hash[:])
}

// FLAGGED: SHA-1 hasher created near password variable
import "crypto/sha1"

func storeUser(passwd string) {
    h := sha1.New()
    h.Write([]byte(passwd))
    storedHash := hex.EncodeToString(h.Sum(nil))
    saveToDatabase(storedHash)
}
```

## Remediation

1. **Use bcrypt** for the vast majority of applications — it is battle-tested, widely supported, and has a tunable cost factor:
   ```go
   // SAFE: bcrypt with default cost
   import "golang.org/x/crypto/bcrypt"

   func hashPassword(password string) (string, error) {
       bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
       return string(bytes), err
   }

   func checkPasswordHash(password, hash string) bool {
       err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
       return err == nil
   }
   ```

2. **Use Argon2id** when higher memory-hardness is required (recommended by OWASP for new systems):
   ```go
   // SAFE: Argon2id with OWASP-recommended parameters
   import (
       "crypto/rand"
       "golang.org/x/crypto/argon2"
   )

   func hashPasswordArgon2(password string) ([]byte, []byte, error) {
       salt := make([]byte, 16)
       if _, err := rand.Read(salt); err != nil {
           return nil, nil, err
       }
       hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
       return hash, salt, nil
   }
   ```

3. **Never use MD5 or SHA-1 for any new security-sensitive purpose.** If you need a fast content hash for non-credential data, use SHA-256 or SHA-3. If you are migrating an existing system, re-hash passwords on next login using a strong algorithm.

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Top 10 A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [NIST SP 800-63B – Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
- [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2)
- [CAPEC-32: XSS via HTTP Query Strings](https://capec.mitre.org/data/definitions/32.html)
