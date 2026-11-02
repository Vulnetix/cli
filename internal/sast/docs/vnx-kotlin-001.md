---
title: "VNX-KOTLIN-001 – Kotlin ECB Cipher Mode"
description: "Detects Kotlin Cipher.getInstance() calls that select ECB mode for any block cipher (AES, DES, DESede, Blowfish and others): an X/ECB transformation, a bare block-cipher name whose provider default is ECB, a template or concatenation with ECB in the mode position, or a constant holding one of those. RSA/ECB is not reported."
---

## Overview

Electronic Codebook (ECB) is the simplest block cipher mode of operation, but it is cryptographically broken for almost all practical purposes. When `Cipher.getInstance("AES/ECB/PKCS5Padding")` or any variant containing ECB is used in Kotlin code, each 16-byte block of plaintext is encrypted independently using the same key. Identical plaintext blocks always produce identical ciphertext blocks, meaning that data patterns — repeated values, block-aligned fields, or headers — are preserved in the ciphertext and are directly observable to anyone who intercepts it. This is CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

This rule reads the first argument of every `Cipher.getInstance()` call in a `.kt` or `.kts` file (also across a line break) and reports it when it selects ECB for a block cipher: an `X/ECB/...` transformation, a bare block-cipher name such as `"AES"`, `"DES"`, `"DESede"` or `KeyProperties.KEY_ALGORITHM_AES` (which the provider completes as ECB), a string template or concatenation with ECB in the mode position, or a constant anywhere in the file whose literal value is one of those. `RSA/ECB/...` (RSA's mode name, not block ECB), GCM, CBC and CTR, ChaCha20, `KeyGenerator`/`SecretKeySpec`, transformations passed in as parameters, ECB in a comment or an unrelated string, and Java files are not reported. AES-ECB is also reported, in Java and Kotlin, by VNX-ANDROID-007.

Beyond pattern leakage, ECB provides no authentication or integrity protection. An attacker who can intercept and modify ciphertext can cut, paste, and rearrange cipher blocks to alter the decrypted output without knowing the key — a block-manipulation attack that can corrupt data or forge messages.

**Secure behavior is NOT the Kotlin or Android default.** Calling `Cipher.getInstance("AES")` without a full transformation string causes the JCE provider to fall back to `AES/ECB/PKCS5Padding` on many Android versions. Specifying a safe mode (`AES/GCM/NoPadding`) explicitly is required — there is no safe default to rely on.

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

The canonical demonstration of ECB's weakness is the "ECB penguin": an image of Tux the Linux mascot encrypted with AES/ECB still clearly shows the penguin's outline in the ciphertext because the structure of the image is preserved. The same effect applies to any structured data: database records with fixed-width fields, protocol messages with repeated headers, or any plaintext with recognisable patterns.

In practical attacks, ECB-encrypted session tokens or authentication cookies can be subjected to block-cutting attacks. If a cookie contains a block-aligned field representing the user's privilege level, an attacker can copy the corresponding ciphertext block from a known admin account's cookie into their own, escalating privileges without ever knowing the encryption key.

Android applications in particular have historically used `Cipher.getInstance("AES")` without specifying a mode, and the JCE provider defaults to `AES/ECB/PKCS5Padding` on some platforms. This implicit ECB use is caught by the same rule.

OWASP Mobile Application Security Verification Standard (MASVS) requires under MASVS-CRYPTO-1 that apps must not use cryptographic protocols or algorithms considered deprecated for security purposes. ECB mode fails this control. Android's `KeyProperties` class provides named constants (`BLOCK_MODE_GCM`, `BLOCK_MODE_CBC`) to make safe choices explicit.

## What Gets Flagged

```kotlin
// FLAGGED: explicit ECB with any block cipher
val aes = Cipher.getInstance("AES/ECB/PKCS5Padding")
val des = Cipher.getInstance("DESede/ECB/NoPadding", "BC")

// FLAGGED: no mode named, so the provider default (ECB) applies
val legacy = Cipher.getInstance("Blowfish")

// FLAGGED: ECB through a template or a constant
val c = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_ECB}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")
val d = Cipher.getInstance(TRANSFORMATION) // const val TRANSFORMATION = "AES/ECB/PKCS5Padding"
```

Not flagged: `Cipher.getInstance("AES/GCM/NoPadding")`, `Cipher.getInstance("RSA/ECB/OAEPPadding")`, or `Cipher.getInstance(transformation)` with a parameter.

## Remediation

1. **Use AES/GCM/NoPadding for authenticated encryption.** GCM provides both confidentiality and integrity with a single key, producing an authentication tag that detects tampering. Always generate a fresh random 12-byte IV for each encryption operation and prepend it to the ciphertext.

2. **Use AES/CBC/PKCS7Padding if authenticated encryption is not possible.** CBC with a random IV avoids pattern leakage but requires a separate MAC (HMAC-SHA256) for integrity protection.

3. **Never reuse IVs.** IV reuse with GCM is catastrophic (breaks both confidentiality and the authentication guarantee). Use `SecureRandom` to generate each IV.

```kotlin
// SAFE: AES-GCM authenticated encryption
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

val keyGen = KeyGenerator.getInstance("AES")
keyGen.init(256)
val key = keyGen.generateKey()

val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
val ciphertext = cipher.doFinal(plaintext)
// Store iv + ciphertext together; iv is not secret
```

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Android Developer Security Guide: Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [Kotlin Security Best Practices](https://kotlinlang.org/docs/security.html)
- [NIST SP 800-38D: GCM Recommendation](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
