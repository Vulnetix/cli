---
title: "VNX-KOTLIN-005 – Kotlin MD5 or SHA-1 Used as Cryptographic Hash"
description: "Detects MessageDigest.getInstance() calls with MD5 or SHA-1 in Kotlin, both of which are cryptographically broken and should be replaced with SHA-256 or stronger algorithms."
---

## Overview

MD5 and SHA-1 are legacy hash algorithms that are no longer considered cryptographically secure. MD5 has known practical collision attacks — two different inputs that produce the same hash — which have been demonstrated in real-world certificate forgery. SHA-1 was theoretically broken in 2005 and practically broken by Google's SHAttered attack in 2017, which produced the first real SHA-1 collision. Using either algorithm for security-sensitive purposes (digital signatures, certificate fingerprints, data integrity verification, or password hashing) provides a false sense of security. This is CWE-328 (Use of Weak Hash).

This rule flags two patterns in Kotlin files: `MessageDigest.getInstance("MD5")`, `MessageDigest.getInstance("SHA-1")`, and `MessageDigest.getInstance("SHA1")` calls, and Apache Commons `DigestUtils` MD5 or SHA-1 helper methods (`md5`, `md5Hex`, `getMd5Digest`, `sha1`, `sha1Hex`). Both the standard JDK API and the Commons wrapper are covered.

The appropriate replacement depends on the use case: SHA-256 or SHA-3 for general integrity verification and checksums, and bcrypt, scrypt, or Argon2 for password hashing (which requires a slow, memory-hard function, not a general-purpose hash).

**Severity:** Medium | **CWE:** [CWE-328 – Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)

## Why This Matters

The consequences of using a broken hash algorithm vary by use case but are consistently serious. For digital signatures and certificate validation, SHA-1 collisions enable attackers to forge trusted documents or certificates. The SHAttered attack demonstrated that two PDFs with identical SHA-1 hashes but different contents could be constructed, enabling document fraud in any system that uses SHA-1 for integrity verification.

For password storage, MD5 and SHA-1 are catastrophically unsuitable: they are fast hash functions, and purpose-built GPU cracking tools can evaluate billions of MD5 or SHA-1 hashes per second. A leaked MD5 password hash database can be cracked for common passwords in seconds using pre-computed rainbow tables. Every major password database breach in recent history has demonstrated this — LinkedIn (2012), RockYou, Adobe — all involved fast hash functions that were trivially reversed.

In Android and Kotlin applications, MD5 is frequently used for file checksums or cache keys where the full cryptographic implications are not considered. Even non-security-sensitive uses of MD5 can be problematic if the context later evolves to include security-sensitive data.

## What Gets Flagged

```kotlin
// FLAGGED: MD5 via JDK MessageDigest
val digest = MessageDigest.getInstance("MD5")
val hash = digest.digest(data)

// FLAGGED: SHA-1 via JDK MessageDigest
val digest = MessageDigest.getInstance("SHA-1")

// FLAGGED: MD5 via Apache Commons DigestUtils
val hex = DigestUtils.md5Hex(inputStream)

// FLAGGED: SHA-1 via Apache Commons DigestUtils
val hash = DigestUtils.sha1Hex(content)
```

## Remediation

1. **Use SHA-256 or SHA-3 for general-purpose integrity hashing.** Both are standardised by NIST and widely supported across all platforms.

2. **Use bcrypt, scrypt, or Argon2 for password hashing.** Never use a general-purpose hash function for passwords, regardless of whether it is a strong algorithm.

3. **Replace Apache Commons `DigestUtils.md5Hex()`** with `DigestUtils.sha256Hex()` for the simplest migration path.

4. **If MD5 is used for non-security purposes** (e.g., a cache sharding key or a legacy compatibility checksum), document the non-security intent clearly and ensure the value never migrates to a security context.

```kotlin
// SAFE: SHA-256 for integrity verification
val digest = MessageDigest.getInstance("SHA-256")
val hash = digest.digest(fileBytes)
val hexHash = hash.joinToString("") { "%02x".format(it) }

// SAFE: Apache Commons SHA-256
val hex = DigestUtils.sha256Hex(inputStream)

// SAFE: Argon2 for password hashing (using Spring Security's encoder)
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
val encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
val hash = encoder.encode(rawPassword)
val matches = encoder.matches(rawPassword, hash)
```

## References

- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Android Developer Security Guide: Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [Google SHAttered: SHA-1 Collision Attack](https://shattered.io/)
- [NIST Policy on Hash Functions](https://csrc.nist.gov/projects/hash-functions)
