---
title: "VNX-CRYPTO-003 – AES in ECB Mode"
description: "Reports block ciphers set up in ECB mode in Python, Node.js, Go, Java, Ruby and PHP: MODE_ECB, modes.ECB(), '*-ecb' cipher names, Java '*/ECB/*' or bare \"AES\", \"DES\", \"DESede\" or \"Blowfish\" transformations (literal, variable or getProperty default), NewECBEncrypter and hand-written per-block Encrypt loops. Other modes, RSA/ECB/* and AES key-wrap transformations, guards against ECB, single-block operations, overridden property defaults, comments and test vectors are not reported."
---

## Overview

This rule detects AES encryption configured to use ECB (Electronic Codebook) mode across multiple languages. ECB is the simplest block cipher mode: each 16-byte plaintext block is encrypted independently with the same key, producing a deterministic ciphertext for every distinct plaintext block. This means identical plaintext blocks always produce identical ciphertext blocks, making ECB semantically insecure and unsuitable for encrypting any structured or repetitive data. The vulnerability maps to CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

The canonical demonstration of ECB's weakness is the "ECB penguin": encrypting a bitmap image of Tux the Linux mascot with AES-ECB produces a ciphertext that still clearly shows the outline of the penguin, because large uniform-color regions produce repeating ciphertext blocks. This visual example captures the deeper problem: any structured data — database rows, credit card numbers, JSON payloads with fixed keys — leaks statistical patterns even when "encrypted."

In practice, an attacker observing ECB-encrypted ciphertext can determine which blocks of plaintext are equal without knowing the key. For protocols that encrypt tokens or session data, this enables a block rearrangement attack: the attacker can swap ciphertext blocks to alter decrypted content in predictable ways (a form of chosen-ciphertext attack). ECB-encrypted storage has been identified as a contributing weakness in several payment system compromises.

## What Gets Flagged

The rule reports cipher constructions that select ECB mode, by name or by default:

```python
# FLAGGED: PyCryptodome AES-ECB
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
```

```java
// FLAGGED: Java JCE AES/ECB
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

```javascript
// FLAGGED: Node.js forge AES-ECB
const cipher = forge.cipher.createCipher('AES-ECB', key);
```

```go
// FLAGGED: Go ECB written by hand, one block at a time
for i := 0; i < len(plaintext); i += bs {
	block.Encrypt(out[i:i+bs], plaintext[i:i+bs])
}
```

```php
// FLAGGED: PHP openssl with an ECB method
$e = openssl_encrypt($plaintext, 'aes-128-ecb', $key, OPENSSL_RAW_DATA);
```

Not flagged: GCM, CBC, CTR and other modes; `RSA/ECB/...` (RSA has no block mode), `AESWrap` and `AES/KW/NoPadding`; a comparison against `MODE_ECB` (a guard); `KeyGenerator`/`SecretKeySpec` with `"AES"`; a single-block `Encrypt` outside a loop (CMAC subkeys, key wrapping); a Java `getProperty` default that the project's own `.properties` overrides with a non-ECB transformation; a bare name joined to a mode (`Cipher.getInstance("AES" + "/GCM/NoPadding")`), which is not the provider default; comments, strings, documentation and test files.

Java ECB is reported by this rule once. [VNX-1240](../vnx-1240/) leaves every Java call this rule reports to it, and reports only the Java forms this rule does not: a mode concatenated onto the algorithm (`alg + "/ECB/PKCS5Padding"`), a `getOrDefault` default, and ECB in test sources.

## Remediation

1. **Use AES-GCM (Galois/Counter Mode) for authenticated encryption.** AES-GCM is the NIST-recommended default. It provides both confidentiality and integrity (via authentication tag), requires a unique 12-byte nonce per encryption, and is hardware-accelerated via AES-NI on x86 and ARM.

   ```python
   # SAFE: AES-GCM with random nonce
   import os
   from Crypto.Cipher import AES
   key = os.urandom(32)          # 256-bit key
   nonce = os.urandom(12)        # 96-bit nonce — never reuse with same key
   cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
   ciphertext, tag = cipher.encrypt_and_digest(plaintext)
   # Store: nonce + tag + ciphertext
   ```

   ```java
   // SAFE: AES-GCM in Java
   byte[] nonce = new byte[12];
   new SecureRandom().nextBytes(nonce);
   Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
   cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
   byte[] ciphertext = cipher.doFinal(plaintext);
   ```

2. **If you need unauthenticated encryption (rare), use AES-CTR.** CTR mode turns a block cipher into a stream cipher and does not leak patterns. However, it provides no integrity guarantee — pair it with HMAC-SHA256 (encrypt-then-MAC).

3. **Generate a fresh, random nonce/IV for every encryption operation.** Never reuse a nonce with the same key in GCM mode — nonce reuse in GCM completely breaks confidentiality and exposes the authentication key.

4. **Rotate to an AEAD construction.** For new systems, consider the `cryptography` library's `Fernet` (Python), `libsodium`/`NaCl` `secretbox`, or Go's `golang.org/x/crypto/chacha20poly1305`, which bundle secure defaults and make misuse harder.

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
- [NIST SP 800-38A – Block Cipher Modes of Operation](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [NIST SP 800-38D – GCM Recommendation](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [OWASP Cryptographic Storage Cheat Sheet – Cipher Modes](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes)
- [The ECB Penguin – Visual demonstration of ECB weakness](https://words.filippo.io/the-ecb-penguin/)
