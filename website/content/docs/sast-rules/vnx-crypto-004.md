---
title: "VNX-CRYPTO-004 – Broken or Obsolete Cipher"
description: "Detects use of DES, 3DES, RC4, and Blowfish — cryptographically broken or deprecated symmetric ciphers — across Python, Node.js, Go, Java, Ruby, and PHP."
---

## Overview

This rule detects usage of symmetric ciphers that are known to be cryptographically broken or officially deprecated: DES (56-bit key, exhaustively brute-forced in 1998), Triple-DES/3DES (Sweet32 birthday attack), RC4 (statistical biases, BEAST/CRIME variants), and Blowfish (64-bit block size, Sweet32 vulnerability). All of these algorithms have been replaced by AES, and their continued use creates exploitable weaknesses in data confidentiality. This maps to CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

**DES** has an effective key length of 56 bits, which was broken by the EFF's "Deep Crack" hardware in under 23 hours in 1998. Any modern attacker with cloud access can brute-force DES-encrypted data in minutes.

**3DES (Triple DES)** was designed as a stopgap with an effective security of 112 bits, which was acceptable until the 2016 Sweet32 attack: because 3DES uses a 64-bit block size, roughly 32 GB of data encrypted under the same key creates a birthday collision that leaks plaintext XOR values. NIST deprecated 3DES in 2017 and disallowed it after 2023.

**RC4** is a stream cipher with well-documented statistical biases. The first few bytes of the keystream are predictable, and the RC4-based BEAST and CRIME TLS attacks demonstrated plaintext recovery of session cookies in real-world web browsers. TLS 1.3 removed RC4 entirely.

**Blowfish**, like 3DES, uses a 64-bit block size and is vulnerable to Sweet32. It was a reasonable choice in the 1990s but has no place in new code.

## What Gets Flagged

The rule matches cipher names and API calls across all supported languages:

```python
# FLAGGED: PyCryptodome DES
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_CBC)
```

```java
// FLAGGED: Java 3DES cipher
Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

// FLAGGED: Java RC4
Cipher rc4 = Cipher.getInstance("RC4");
```

```go
// FLAGGED: Go DES
import "crypto/des"
block, _ := des.NewCipher(key)

// FLAGGED: Go RC4
import "crypto/rc4"
cipher, _ := rc4.NewCipher(key)
```

```javascript
// FLAGGED: Node.js DES-CBC
const cipher = crypto.createCipheriv('des-cbc', key, iv);
```

## Remediation

1. **Replace all usages with AES-256-GCM.** AES-GCM is the NIST-recommended default for symmetric authenticated encryption. It is hardware-accelerated, has a 128-bit block size (no Sweet32 risk), and provides both confidentiality and integrity.

   ```python
   # SAFE: AES-256-GCM with authenticated encryption
   import os
   from Crypto.Cipher import AES
   key = os.urandom(32)   # 256-bit
   nonce = os.urandom(12) # 96-bit nonce
   cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
   ciphertext, tag = cipher.encrypt_and_digest(plaintext)
   ```

   ```java
   // SAFE: AES-256-GCM in Java
   KeyGenerator keyGen = KeyGenerator.getInstance("AES");
   keyGen.init(256, new SecureRandom());
   SecretKey key = keyGen.generateKey();
   Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
   ```

2. **For stream cipher use cases, use ChaCha20-Poly1305.** ChaCha20-Poly1305 is an IETF-standardized AEAD cipher (RFC 8439) that performs well on devices without AES hardware acceleration (e.g., older ARM microcontrollers).

   ```go
   // SAFE: Go ChaCha20-Poly1305
   import "golang.org/x/crypto/chacha20poly1305"
   aead, _ := chacha20poly1305.New(key)
   nonce := make([]byte, aead.NonceSize())
   io.ReadFull(rand.Reader, nonce)
   ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
   ```

3. **Remove weak ciphers from TLS configurations.** If these cipher names appear in TLS configuration files, remove them and ensure only TLS 1.2+ with AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) are permitted.

4. **Migrate stored data.** If you have data encrypted with DES, 3DES, or RC4, plan a migration: decrypt with the old key and re-encrypt with AES-GCM. Prioritize sensitive data (PII, credentials, payment data) first.

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
- [NIST SP 800-131A Rev 2 – Deprecation of 3DES](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [Sweet32: Birthday Attacks on 64-bit Block Ciphers in TLS and OpenPGP](https://sweet32.info/)
- [RFC 7465 – Prohibiting RC4 Cipher Suites in TLS](https://www.rfc-editor.org/rfc/rfc7465)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
