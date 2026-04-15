---
title: "VNX-CS-009 – C# Use of Weak Cryptographic Algorithm (MD5, SHA1, DES, RC2, 3DES)"
description: "Detects instantiation of broken or weak cryptographic algorithm classes in C# including MD5, SHA-1, DES, RC2, and TripleDES, which should not be used for security-sensitive operations such as password hashing, message authentication, or data encryption."
---

## Overview

This rule flags C# files (`.cs`) where any of the following classes are instantiated with `new AlgoName()` or created via `AlgoName.Create()`: `MD5`, `SHA1`, `SHA1Managed`, `DES`, `DESCryptoServiceProvider`, `RC2`, `RC2CryptoServiceProvider`, `TripleDES`, `TripleDESCryptoServiceProvider`, and `MD5CryptoServiceProvider`. These classes are available in `System.Security.Cryptography` and represent algorithms that are considered cryptographically broken or insufficiently strong for modern security requirements.

MD5 and SHA-1 are hash functions with known collision attacks — two different inputs can be crafted to produce the same hash output. MD5 collisions can be computed in seconds on modern hardware, and chosen-prefix collisions (where the attacker can choose the beginning of both inputs) are practical. SHA-1 suffered its first practical chosen-prefix collision in 2020. Using these algorithms for integrity verification allows attackers to substitute malicious data without changing the hash value.

DES has a 56-bit key, which is exhaustively searchable in hours using modern hardware. RC2 is similarly weak. TripleDES provides a maximum of 112 bits of effective security and is far slower than AES, making it an inferior choice in every respect.

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

The practical break of MD5 has had real security consequences. The Flame malware (2012) used an MD5 collision attack to forge a valid Microsoft code-signing certificate, allowing it to appear as legitimately signed Windows Update software. This allowed the malware to spread within networks that trusted Microsoft's signing infrastructure. SHA-1 TLS certificates were deprecated by all major browsers by 2017 precisely because chosen-prefix collisions make certificate forgery practical.

For password storage, MD5 and SHA-1 are catastrophically weak — they are fast hash functions designed for speed, and modern GPUs can compute billions of MD5 or SHA-1 hashes per second, reducing the time to crack a password database from years to hours or minutes even with salted hashes. Password hashing must use purpose-built slow KDFs: PBKDF2, bcrypt, scrypt, or Argon2.

In .NET, these algorithms are still available for legacy interoperability reasons, but they carry `[Obsolete]` attributes in newer framework versions and should not be used in new code for any security-relevant purpose. CAPEC-97 (Cryptanalysis of Cellular Phone Communication) and ATT&CK T1600 both relate to this class of cryptographic weakness.

## What Gets Flagged

```csharp
// FLAGGED: MD5 used for password or data hashing
var md5 = new MD5CryptoServiceProvider();
byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));

// FLAGGED: SHA1 used for HMAC or integrity check
using var sha1 = SHA1.Create();
byte[] checksum = sha1.ComputeHash(fileBytes);

// FLAGGED: DES encryption
using var des = new DESCryptoServiceProvider();
des.Key = desKey;
```

## Remediation

1. For hashing data integrity (files, documents, non-password data): use SHA-256 (`SHA256.Create()`) or SHA-3 (`SHA3_256.Create()` in .NET 8+).
2. For password hashing: use `Rfc2898DeriveBytes` (PBKDF2 with SHA-256) with at least 310,000 iterations, or use a third-party library providing bcrypt or Argon2.
3. For symmetric encryption: replace DES/3DES/RC2 with AES using GCM mode (`AesGcm` class, .NET 3.0+) for authenticated encryption.
4. For HMAC: use `HMACSHA256` or `HMACSHA512` instead of `HMACMD5` or `HMACSHA1`.

```csharp
// SAFE: SHA-256 for data integrity
using var sha256 = SHA256.Create();
byte[] hash = sha256.ComputeHash(fileBytes);

// SAFE: PBKDF2 with SHA-256 for password hashing
using var pbkdf2 = new Rfc2898DeriveBytes(
    password,
    salt: RandomNumberGenerator.GetBytes(32),
    iterations: 310_000,
    hashAlgorithm: HashAlgorithmName.SHA256);
byte[] passwordHash = pbkdf2.GetBytes(32);

// SAFE: AES-GCM for authenticated encryption
byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
```

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP – Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Microsoft Docs – .NET Cryptography Model](https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
- [NIST SP 800-131A – Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
