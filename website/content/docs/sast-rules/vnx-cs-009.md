---
title: "VNX-CS-009 – C# Use of Weak Cryptographic Algorithm (MD5, SHA-1, DES, 3DES, RC2, RC4)"
description: "Reports C# code that creates or invokes MD5, SHA-1, DES, 3DES, RC2, RC4, MD4/MD2 or PBKDF1 through the .NET or BouncyCastle crypto APIs, including SHA-1/MD5 signatures and algorithms requested by name. HMAC, RSA-OAEP, PBKDF2, protocol-fixed hashes (WebSocket, Gravatar, ETag, Content-MD5), analyzer-suppressed code, comments, strings and test projects are not reported."
---

## Overview

This rule reports a line of C# (`.cs`) that creates or calls a broken or deprecated cryptographic primitive. It matches the API call, not the algorithm's name, so an enum member `DigestKind.MD5`, a property called `SHA1`, `OrderByDescending` or a log message naming `MD5.Create()` is not a finding. What it reports:

- **Hashes:** `MD5.Create()`, `SHA1.Create()`, the one-shot `MD5.HashData()`, `SHA1.HashData()`, `HashDataAsync()` and `TryHashData()` (also fully qualified, split across two lines, or through a `using Alias = System.Security.Cryptography.MD5;` alias), and the classes `MD5CryptoServiceProvider`, `MD5Cng`, `SHA1Managed`, `SHA1CryptoServiceProvider` and `SHA1Cng` (`new X()`, `new X { ... }`, `X x = new();`).
- **Ciphers:** `DES.Create()`, `TripleDES.Create()`, `RC2.Create()` and `DESCryptoServiceProvider`, `TripleDESCryptoServiceProvider`, `TripleDESCng`, `RC2CryptoServiceProvider`.
- **By name:** `HashAlgorithm.Create("MD5")`, `SymmetricAlgorithm.Create("TripleDES")`, `CryptoConfig.CreateFromName("SHA1")`, `CryptoConfig.MapNameToOID("SHA1")` and `formatter.SetHashAlgorithm("SHA1")`.
- **Hashing and signing with a weak `HashAlgorithmName`:** `IncrementalHash.CreateHash(HashAlgorithmName.MD5)`, `CryptographicOperations.HashData(HashAlgorithmName.MD5, ...)`, `SignData`/`SignHash`/`VerifyData`/`VerifyHash` and `new CertificateRequest(...)` with `HashAlgorithmName.SHA1` or `MD5`, also when the argument sits on its own line of a multi-line call. An XML signature whose `SignatureMethod` or `DigestMethod` is set to `SignedXml.XmlDsigRSASHA1Url`, `XmlDsigDSAUrl` or `XmlDsigSHA1Url`.
- **PBKDF1:** `new PasswordDeriveBytes(...)`.
- **BouncyCastle:** `MD5Digest`, `MD4Digest`, `MD2Digest`, `Sha1Digest`, `DesEngine`, `DesEdeEngine`, `RC2Engine`, `RC4Engine`, and `DigestUtilities.GetDigest("MD5")`, `CipherUtilities.GetCipher("DES/CBC/...")`, `SignerUtilities.GetSigner("SHA1withRSA")`.

Deliberately not reported:

- HMAC constructions (`HMACSHA1`, `HMACMD5`, `IncrementalHash.CreateHMAC`). HMAC does not depend on collision resistance, and TOTP and several webhook schemes fix HMAC-SHA1.
- RSA-OAEP with SHA-1 (`RSAEncryptionPadding.OaepSHA1`) and PBKDF2 (`Rfc2898DeriveBytes`), whatever its hash.
- A `HashAlgorithmName.SHA1` that is compared, mapped in a `switch` or rejected rather than used.
- A hash whose surrounding code shows a protocol-fixed, non-security use: the WebSocket `Sec-WebSocket-Accept` key (RFC 6455), Gravatar URLs, ETags, Content-MD5 / `ContentHash`, and name-based GUIDs.
- Code under an explicit analyzer suppression: `#pragma warning disable CA5350`, `CA5351` or `CA5373` (until the matching `restore`), or a `[SuppressMessage(..., "CA5351...")]` on the member.
- Comments, string literals, and test projects (`tests/`, `*.Tests/`, `*.UnitTests/`, `*Tests.cs`).
- ECB mode and an algorithm chosen at run time from a variable (`HashAlgorithm.Create(name)`) are outside this rule.

MD5 and SHA-1 are hash functions with known collision attacks. MD5 collisions can be computed in seconds on modern hardware, and chosen-prefix collisions are practical; SHA-1 suffered its first practical chosen-prefix collision in 2020. Using either for integrity or signatures lets an attacker substitute data without changing the digest.

DES has a 56-bit key, which is exhaustively searchable in hours. RC2 and RC4 are similarly weak. TripleDES offers at most 112 bits of security, has a 64-bit block (Sweet32), is deprecated by NIST, and is slower than AES.

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

The practical break of MD5 has had real security consequences. The Flame malware (2012) used an MD5 collision attack to forge a valid Microsoft code-signing certificate, allowing it to appear as legitimately signed Windows Update software. This allowed the malware to spread within networks that trusted Microsoft's signing infrastructure. SHA-1 TLS certificates were deprecated by all major browsers by 2017 precisely because chosen-prefix collisions make certificate forgery practical.

For password storage, MD5 and SHA-1 are catastrophically weak: they are fast hash functions designed for speed, and modern GPUs compute billions of MD5 or SHA-1 hashes per second, reducing the time to crack a password database from years to hours even with salted hashes. Password hashing must use purpose-built slow KDFs: PBKDF2, bcrypt, scrypt, or Argon2.

In .NET these algorithms remain available for legacy interoperability, and the .NET analyzers CA5350 and CA5351 flag them. The `*CryptoServiceProvider` and `*Managed` classes are obsolete (SYSLIB0021) in current .NET. CAPEC-97 (Cryptanalysis) and ATT&CK T1600 both relate to this class of cryptographic weakness.

## What Gets Flagged

```csharp
// FLAGGED: MD5 for a password hash
using var md5 = MD5.Create();
var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(salt + password));

// FLAGGED: one-shot SHA-1
return SHA1.HashData(Encoding.UTF8.GetBytes(token));

// FLAGGED: DES and 3DES
using var des = new DESCryptoServiceProvider();
var tdes = new TripleDESCryptoServiceProvider { Key = key, Mode = CipherMode.CBC };

// FLAGGED: algorithm requested by name
return (HashAlgorithm)CryptoConfig.CreateFromName("SHA1");

// FLAGGED: SHA-1 signature
return _rsa.SignData(payload, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

// NOT FLAGGED: HMAC-SHA1 for TOTP, SHA-1 fixed by the WebSocket protocol
using var hmac = new HMACSHA1(secret);
var accept = SHA1.HashData(Encoding.ASCII.GetBytes(clientKey + WebSocketGuid));
```

## Remediation

1. For hashing data integrity (files, documents, non-password data): use SHA-256 (`SHA256.Create()`) or SHA-3 (`SHA3_256.Create()` in .NET 8+).
2. For password hashing: use `Rfc2898DeriveBytes` (PBKDF2 with SHA-256) with at least 310,000 iterations, or use a third-party library providing bcrypt or Argon2.
3. For symmetric encryption: replace DES/3DES/RC2/RC4 with AES using GCM mode (`AesGcm` class, .NET Core 3.0+) for authenticated encryption.
4. For signatures and certificates: pass `HashAlgorithmName.SHA256` or stronger to `SignData`, `VerifyData` and `CertificateRequest`, and use `SignedXml.XmlDsigRSASHA256Url` / `XmlDsigSHA256Url` for XML signatures.
5. For new MAC designs prefer `HMACSHA256` or `HMACSHA512`. HMAC-SHA1 is not reported, since it remains acceptable where a protocol such as TOTP fixes it.

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
