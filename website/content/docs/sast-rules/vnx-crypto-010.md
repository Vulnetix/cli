---
title: "VNX-CRYPTO-010 – Hardcoded IV, Nonce, or Salt in Cryptographic Operation"
description: "Detects a constant IV, nonce or salt (a string or byte literal, a literal byte array, or a zero-filled buffer) passed to a cipher, AEAD or password KDF call in Python, JavaScript/TypeScript, Go, Java/Kotlin, C/C++/Objective-C, Rust, C#, PHP and Ruby, directly or through a variable assigned that constant. Random, ciphertext-derived and in-place-filled IVs are not reported."
---

## Overview

This rule reports a constant used as the IV, nonce or salt argument of a cipher, AEAD or password-KDF call. A constant is a string or byte literal, a literal byte array (`{0x00, 0x01, ...}`, `[]byte{...}`, `byteArrayOf(...)`), a literal wrapped in a conversion (`"...".getBytes()`, `Buffer.from("...", "hex")`, `bytes.fromhex("...")`, `CryptoJS.enc.Utf8.parse("...")`), or a zero-filled buffer (`bytes(16)`, `Buffer.alloc(16)`, `new Uint8Array(12)`, `make([]byte, n)`, `var nonce [12]byte`, `new byte[16]`, `ByteArray(16)`, `[0u8; 12]`, `memset(iv, 0, ...)`). It is reported on the call line when it is written in the call, and on the assignment when a variable carries it: the variable's nearest assignment above the call is the constant, and nothing fills it in between.

The calls are: Python pycryptodome `AES/DES/Blowfish.new`, cryptography `modes.CBC/CTR/GCM/CFB/OFB/XTS`, `AESGCM`/`AESCCM`/`ChaCha20Poly1305` `encrypt`/`decrypt`, the `iv=`/`nonce=`/`salt=` keywords of those and of `PBKDF2HMAC`/`Scrypt`, `hashlib.pbkdf2_hmac`, `PBKDF2`/`scrypt`, argon2 `hash_secret`, `bcrypt.hashpw`; Node `createCipheriv`/`createDecipheriv`, `pbkdf2(Sync)`/`scrypt(Sync)`, WebCrypto and CryptoJS `iv:`/`salt:` parameters, `CryptoJS.PBKDF2`; Go `cipher.NewCBCEncrypter`/`NewCBCDecrypter`/`NewCTR`/`NewOFB`/`NewCFB*`, AEAD `Seal`/`Open`, `secretbox`/`box` `Seal`/`Open`, `pbkdf2`/`scrypt`/`argon2` `Key`; Java and Kotlin `IvParameterSpec`, `GCMParameterSpec`, `PBEKeySpec`, `PBEParameterSpec`, `ChaCha20ParameterSpec`, `BCrypt.hashpw`; C, C++ and Objective-C `EVP_EncryptInit`/`DecryptInit`/`CipherInit` (and `_ex`), `AES_cbc_encrypt` and friends, `PKCS5_PBKDF2_HMAC`, `mbedtls_aes_crypt_cbc`, `mbedtls_gcm_crypt_and_tag`, `crypto_secretbox_easy`, `CCCrypt`; Rust `Nonce::from_slice`, ring `Nonce::assume_unique_for_key`, CBC/CTR/CFB/OFB `::new` and `new_from_slices`, `pbkdf2_hmac`, `pbkdf2::derive` and Argon2 `hash_password_into`; C# `Rfc2898DeriveBytes` (constructor and `Pbkdf2`), `CreateEncryptor`/`CreateDecryptor(key, iv)`, the `.IV` property and `AesGcm`/`AesCcm`/`ChaCha20Poly1305` `Encrypt`/`Decrypt`; PHP `openssl_encrypt`/`openssl_decrypt`, `hash_pbkdf2`, `openssl_pbkdf2` and the libsodium `sodium_crypto_secretbox`, `sodium_crypto_aead_*` and `sodium_crypto_pwhash` calls; Ruby `cipher.iv =`, `OpenSSL::PKCS5.pbkdf2_hmac` and `OpenSSL::KDF` `salt:`.

Not reported: values from a CSPRNG, read from the ciphertext, or filled in place before use (`rand.Read`, `io.ReadFull`, `randomFillSync`, `getRandomValues`, `nextBytes`, `RAND_bytes`, `fill_bytes`); values from configuration objects (`config.iv`) or from function parameters with no constant assignment in the file; HKDF salts (RFC 5869 allows a constant one); `NULL` IVs; calls in comments, docstrings and string literals; and test files, where known-answer vectors use fixed IVs by design. Flows through more than one variable, through helper functions or across files are not followed.

The IV (initialization vector), nonce, and salt all serve the same essential purpose: they introduce uniqueness and unpredictability into cryptographic operations so that encrypting the same plaintext twice with the same key produces different ciphertext, and so that deriving a key from the same password twice produces a different derived key. When these values are hardcoded or zeroed, this uniqueness property is entirely eliminated.

**Severity:** High | **CWE:** [CWE-329 – Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

## Why This Matters

The consequences of a static IV or nonce depend on the cipher mode, but all of them are severe. For stream ciphers and counter modes (CTR, GCM, ChaCha20-Poly1305), reusing the same nonce with the same key is catastrophic: two ciphertexts encrypted with the same key and nonce can be XORed together to cancel the keystream, immediately recovering the XOR of the two plaintexts without any knowledge of the key. This is called a "two-time pad" attack and requires only two captured ciphertexts.

Real-world examples of nonce reuse vulnerabilities include WPA2's KRACK attack (CVE-2017-13077), where a reinstallation attack forced nonce reuse in the TKIP and CCMP cipher suites, and the PlayStation 3's ECDSA key recovery, where Sony used a constant "random" nonce in their firmware signing, allowing the private key to be computed from two signatures. These are not theoretical: attackers with network or file access to encrypted data can recover plaintext or keys when nonce reuse occurs.

For KDFs like PBKDF2, bcrypt, and Argon2, a hardcoded or zero salt means all passwords are hashed with the same salt. This allows precomputed rainbow tables to be built for the specific salt value, eliminating the performance cost that KDFs are designed to impose on attackers. This is covered by CWE-760 and maps to CAPEC-112 and ATT&CK T1600.

## What Gets Flagged

```python
# FLAGGED: a literal IV and a literal PBKDF2 salt
cipher = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")
return hashlib.pbkdf2_hmac('sha1', pin.encode(), b'pinsalt', 1000)

# FLAGGED (on the assignment): a zero nonce reaching the cipher
nonce = bytes(12)
return ChaCha20.new(key=key, nonce=nonce).encrypt(data)
```

```javascript
// FLAGGED: a zero IV, and a constant reaching createCipheriv
const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));
const IV = Buffer.from("00112233445566778899aabbccddeeff", "hex");
crypto.createCipheriv("aes-256-gcm", key, IV);
```

```go
// FLAGGED: a zero nonce; a literal IV
var nonce [12]byte
gcm.Seal(nil, nonce[:], plaintext, nil)
mode := cipher.NewCBCEncrypter(block, []byte("1234567890123456"))
```

```java
// FLAGGED: a zero IV in the call; a constant salt field
cipher.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(new byte[16]));
private static final byte[] SALT = "acme-salt-value".getBytes(StandardCharsets.UTF_8);
```

```c
// FLAGGED: a literal IV and salt
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, (const unsigned char *)"0123456789012345");
PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), (const unsigned char *)"saltsalt", 8, 100000, EVP_sha256(), 32, out);
```

```rust
// FLAGGED: a fixed nonce
let nonce = Nonce::from_slice(b"unique nonce");
```

```csharp
// FLAGGED: a constant salt field; a zero IV
private static readonly byte[] Salt = Encoding.ASCII.GetBytes("pepper-2019-v1");
aes.IV = new byte[16];
```

```php
// FLAGGED: a literal IV and a literal salt
openssl_encrypt($plain, 'aes-256-cbc', self::KEY, 0, '1234567890123456');
hash_pbkdf2('sha256', $pw, 'site-wide-salt', 100000, 64);
```

```javascript
// NOT FLAGGED: random, filled in place, or read from the payload
const iv = crypto.randomBytes(16);
const buf = Buffer.alloc(16); crypto.randomFillSync(buf);
crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(parts[0], 'hex'));
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
