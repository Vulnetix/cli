---
title: "VNX-CRYPTO-010 – Hardcoded IV, Nonce, or Salt in Cryptographic Operation"
description: "Detects hardcoded or zero-filled initialization vectors, nonces, and salts assigned to variables named iv, nonce, or salt across multiple languages, which destroys the security properties of stream ciphers, AEAD schemes, and key derivation functions."
---

## Overview

This rule scans across Python, JavaScript, TypeScript, Go, Java, C, C++, and Rust source files for two related patterns. The first pattern matches variable assignments where the variable is named `iv`, `nonce`, `initialization_vector`, or `init_vector` and the right-hand side is a byte-string literal, a byte array constructor, or a raw byte sequence. The second pattern matches any of `iv`, `nonce`, or `salt` variables whose values are zero-filled via patterns like `b'\x00' * 16`, `bytes.fromhex("000000")`, or `[0] * 16`. Lock files, checksum files, and minified JavaScript are excluded.

The IV (initialization vector), nonce, and salt all serve the same essential purpose: they introduce uniqueness and unpredictability into cryptographic operations so that encrypting the same plaintext twice with the same key produces different ciphertext, and so that deriving a key from the same password twice produces a different derived key. When these values are hardcoded or zeroed, this uniqueness property is entirely eliminated.

**Severity:** High | **CWE:** [CWE-329 – Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

## Why This Matters

The consequences of a static IV or nonce depend on the cipher mode, but all of them are severe. For stream ciphers and counter modes (CTR, GCM, ChaCha20-Poly1305), reusing the same nonce with the same key is catastrophic: two ciphertexts encrypted with the same key and nonce can be XORed together to cancel the keystream, immediately recovering the XOR of the two plaintexts without any knowledge of the key. This is called a "two-time pad" attack and requires only two captured ciphertexts.

Real-world examples of nonce reuse vulnerabilities include WPA2's KRACK attack (CVE-2017-13077), where a reinstallation attack forced nonce reuse in the TKIP and CCMP cipher suites, and the PlayStation 3's ECDSA key recovery, where Sony used a constant "random" nonce in their firmware signing, allowing the private key to be computed from two signatures. These are not theoretical: attackers with network or file access to encrypted data can recover plaintext or keys when nonce reuse occurs.

For KDFs like PBKDF2, bcrypt, and Argon2, a hardcoded or zero salt means all passwords are hashed with the same salt. This allows precomputed rainbow tables to be built for the specific salt value, eliminating the performance cost that KDFs are designed to impose on attackers. This is covered by CWE-760 and maps to CAPEC-112 and ATT&CK T1600.

## What Gets Flagged

```python
# FLAGGED: hardcoded IV byte string
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
cipher = AES.new(key, AES.MODE_CBC, iv)

# FLAGGED: zero-filled nonce pattern
nonce = b'\x00' * 12
aesgcm.encrypt(nonce, plaintext, None)
```

```javascript
// FLAGGED: hardcoded IV array
const iv = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, data);
```

```go
// FLAGGED: zero-initialized nonce
var nonce [12]byte  // zero IV — do not use
gcm.Seal(nil, nonce[:], plaintext, nil)
```

## Remediation

1. Generate a fresh random IV/nonce for every encryption operation using a cryptographically secure random source. Prepend or store the IV alongside the ciphertext — it is not secret, only unique.
2. For salts in password hashing, let the KDF library generate the salt automatically; most modern libraries (bcrypt, Argon2) handle this internally.
3. For GCM and ChaCha20-Poly1305, the nonce must never be reused with the same key. Use a counter or random nonce, and retire the key before the nonce space is exhausted.

```python
# SAFE: random IV generated per-encryption
import os
from Crypto.Cipher import AES

key = os.urandom(32)
iv = os.urandom(16)           # fresh random IV every time
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
# Store iv alongside ciphertext for decryption

# SAFE: random nonce for GCM
nonce = os.urandom(12)        # 96-bit nonce for GCM
aesgcm = AESGCM(key)
ct = aesgcm.encrypt(nonce, plaintext, None)
```

```go
// SAFE: random nonce filled from crypto/rand
import "crypto/rand"
nonce := make([]byte, gcm.NonceSize())
if _, err := rand.Read(nonce); err != nil {
    return nil, err
}
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
```

## References

- [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
- [CWE-760: Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)
- [OWASP – Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-38D – Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 5116 – An Interface and Algorithms for Authenticated Encryption (nonce requirements)](https://www.rfc-editor.org/rfc/rfc5116)
