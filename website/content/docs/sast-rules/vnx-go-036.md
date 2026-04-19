---
title: "VNX-GO-036 – Use of ECB block mode"
description: "Detect Go cryptographic code that implements or references Electronic Codebook (ECB) block cipher mode, which leaks data patterns and must not be used to protect sensitive data."
---

## Overview

This rule flags Go code that implements ECB (Electronic Codebook) block cipher mode — typically identified by `NewECBEncrypter`, `NewECBDecrypter`, `ECB`, or manual block-at-a-time encryption using `aes.NewCipher` with `block.BlockSize()` loops that process each block independently with no IV or nonce chaining. ECB mode encrypts each plaintext block independently with the same key, which means identical plaintext blocks always produce identical ciphertext blocks. This makes ECB mode structurally unable to conceal data patterns regardless of the underlying cipher's strength. This is mapped to [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html).

Go's standard library deliberately omits ECB mode from `crypto/cipher` — its absence is intentional. When developers implement ECB themselves or import a third-party package that exposes it, this rule raises a finding.

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

The canonical demonstration of ECB's weakness is the "ECB penguin": encrypting the Tux Linux mascot image with ECB-AES produces output where the penguin's outline remains clearly visible because regions of uniform colour map to uniform ciphertext blocks. The same structural leak occurs with any structured or partially-predictable plaintext — encrypted database records, JSON payloads, filesystem blocks, and network packets all contain repeated or predictable patterns that ECB makes visible.

In practice, an adversary with access to ECB-encrypted ciphertexts can perform chosen-plaintext attacks to recover plaintext by observing when ciphertext blocks repeat, use statistical analysis to fingerprint content even without decryption, and detect when two records share common prefix or suffix values — leaking business-sensitive relationships. These attacks require no knowledge of the key and succeed even against AES-256 in ECB mode, demonstrating that algorithm strength is irrelevant when the mode is fundamentally broken. CAPEC-32 (XSS via HTTP Request Headers) and broader cryptanalysis patterns both rely on this structural weakness.

## What Gets Flagged

The rule fires on ECB mode references and on manual block-at-a-time patterns that replicate ECB semantics.

```go
// FLAGGED: manual ECB implementation — each block encrypted independently
func ecbEncrypt(key, plaintext []byte) []byte {
    block, _ := aes.NewCipher(key)
    bs := block.BlockSize()
    ciphertext := make([]byte, len(plaintext))
    for i := 0; i < len(plaintext); i += bs {
        // No IV, no chaining — this is ECB mode
        block.Encrypt(ciphertext[i:i+bs], plaintext[i:i+bs])
    }
    return ciphertext
}

// FLAGGED: third-party ECB wrapper
import ecb "github.com/example/ecb-mode"

func encryptData(key, data []byte) []byte {
    block, _ := aes.NewCipher(key)
    enc := ecb.NewECBEncrypter(block)
    out := make([]byte, len(data))
    enc.CryptBlocks(out, data)
    return out
}
```

```go
// SAFE: AES-GCM with authenticated encryption and nonce
func encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
```

## Remediation

1. **Replace ECB mode with AES-GCM.** AES-GCM provides authenticated encryption (confidentiality and integrity), randomised ciphertext via a nonce, and is hardware-accelerated on all modern CPUs.

   ```go
   import (
       "crypto/aes"
       "crypto/cipher"
       "crypto/rand"
       "io"
   )

   // SAFE: AES-256-GCM — no pattern leakage, built-in integrity check
   func encrypt(key, plaintext, additionalData []byte) ([]byte, error) {
       block, err := aes.NewCipher(key) // key must be 16, 24, or 32 bytes
       if err != nil {
           return nil, err
       }
       gcm, err := cipher.NewGCM(block)
       if err != nil {
           return nil, err
       }
       nonce := make([]byte, gcm.NonceSize())
       if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
           return nil, err
       }
       // additionalData is authenticated but not encrypted (optional)
       return gcm.Seal(nonce, nonce, plaintext, additionalData), nil
   }
   ```

2. **Use AES-CTR when streaming encryption is required** and you handle authentication separately with HMAC-SHA256. AES-CTR is not ECB: it XORs plaintext with a keystream derived from an incrementing counter and a nonce.

3. **Consider `golang.org/x/crypto/chacha20poly1305`** for environments without AES hardware acceleration. ChaCha20-Poly1305 provides equivalent security with excellent software performance.

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-38A – Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [CAPEC-32: XSS via HTTP Request Headers](https://capec.mitre.org/data/definitions/32.html)
- [Go crypto/cipher package documentation](https://pkg.go.dev/crypto/cipher)
- [The ECB Penguin – Visual demonstration of ECB weakness](https://words.filippo.io/the-ecb-penguin/)
