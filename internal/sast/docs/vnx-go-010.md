---
title: "VNX-GO-010 – Go Weak Cipher Usage"
description: "Detect Go code that constructs DES, Triple DES, RC4, Blowfish, CAST5, TEA or XTEA ciphers, or enables RC4/3DES TLS cipher suites or 3DES/arcfour SSH ciphers, which are broken or deprecated for protecting data."
---

## Overview

This rule flags Go code that calls `des.NewCipher`, `des.NewTripleDESCipher`, `rc4.NewCipher` or one of the deprecated `golang.org/x/crypto` 64-bit-block ciphers, or lists an RC4/3DES suite in `tls.Config.CipherSuites` or a 3DES/arcfour cipher in an `x/crypto/ssh` `Ciphers` list. DES has a 56-bit effective key length that can be brute-forced in hours with commodity hardware. Triple DES (3DES) was deprecated by NIST in 2017 and is prohibited after 2023 due to the Sweet32 birthday attack. RC4 has serious statistical biases that can leak plaintext, especially in protocols where the same key is reused. Any data encrypted with these algorithms must be treated as potentially exposed. This maps to [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html).

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

Cryptographic algorithm selection is a long-lived decision — data encrypted today may need to remain confidential for years. DES was broken publicly in 1999 with a $250,000 machine that cracked it in 22 hours; modern GPUs and cloud computing make this dramatically cheaper. Triple DES provides only 112 bits of effective security rather than 168, and the Sweet32 attack allows plaintext recovery from long-lived sessions using the same key. RC4 was deprecated by the IETF in RFC 7465 (prohibited in TLS) after practical attacks were demonstrated against it in real-world protocols including WEP (Wi-Fi) and SSL. Attackers can decrypt data at rest, intercept and decrypt communications, or forge ciphertexts protected by these algorithms. MITRE ATT&CK T1600 covers weakening cryptography as a technique used to facilitate further compromise.

## What Gets Flagged

The rule reports the line that constructs a weak cipher: `des.NewCipher`, `des.NewTripleDESCipher`, `rc4.NewCipher`, and the deprecated 64-bit-block ciphers from `golang.org/x/crypto` (`blowfish`, `cast5`, `tea`, `xtea`). A constructor passed as a value (a table of selectable ciphers) counts, and an aliased import is resolved. It also reports an RC4 or 3DES TLS suite (`tls.TLS_*_RC4_128_*`, `tls.TLS_*_3DES_EDE_CBC_*`) placed in a `tls.Config` `CipherSuites` list, and a legacy SSH cipher (`"3des-cbc"`, `"arcfour"`, `"arcfour128"`, `"arcfour256"`) placed in an `x/crypto/ssh` `Ciphers` list, which re-enables a cipher the package leaves off by default. The list can be written inline or held in a variable the field is set from.

```go
import legacydes "crypto/des"

func wrapKey(kek []byte) (cipher.Block, error) {
    return legacydes.NewTripleDESCipher(kek) // FLAGGED: 3DES
}

var blockCiphers = map[string]func([]byte) (cipher.Block, error){
    "aes":  aes.NewCipher,
    "3des": des.NewTripleDESCipher, // FLAGGED: still selectable
}

cfg := &tls.Config{
    CipherSuites: []uint16{
        tls.TLS_RSA_WITH_RC4_128_SHA, // FLAGGED
    },
}

sshCfg.Ciphers = append(sshCfg.Ciphers, "aes128-ctr", "3des-cbc") // FLAGGED
```

Not reported: the import on its own, constants such as `des.BlockSize` and `des.KeySizeError`, `blowfish.NewSaltedCipher` (the bcrypt key schedule, a password-hashing primitive), a TLS suite or SSH cipher named in a deny-list or a comparison, comments and string literals, and test files (known-answer tests protect no data).

## Remediation

1. **Replace DES, 3DES, and RC4 with AES-GCM.** AES-256-GCM is the recommended symmetric encryption algorithm. It provides 256-bit security, authenticated encryption (integrity protection built in), and is hardware-accelerated on virtually all modern CPUs.

```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
)

// SAFE: AES-256-GCM with authenticated encryption
func encrypt(key, plaintext []byte) ([]byte, error) {
    if len(key) != 32 {
        return nil, fmt.Errorf("key must be 32 bytes for AES-256")
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    // Nonce is prepended to the ciphertext for storage/transmission
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}
```

2. **Generate keys with `crypto/rand`.** Never derive AES keys from weak sources. Use `crypto/rand` to generate 32-byte (256-bit) keys.

```go
func newAESKey() ([]byte, error) {
    key := make([]byte, 32)
    _, err := rand.Read(key)
    return key, err
}
```

3. **Re-encrypt data at rest that was protected with weak ciphers.** If existing data was encrypted with DES, 3DES, or RC4, decrypt it with the old key and re-encrypt with AES-GCM as part of a planned migration. Treat all data encrypted with weak ciphers as potentially compromised.

4. **Use `golang.org/x/crypto/chacha20poly1305` as an alternative.** For environments where AES hardware acceleration is not available (some embedded or edge deployments), ChaCha20-Poly1305 provides equivalent security with good software performance.

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-131A Rev 2 – Transitioning the Use of Cryptographic Algorithms](https://doi.org/10.6028/NIST.SP.800-131Ar2)
- [Go crypto/aes package documentation](https://pkg.go.dev/crypto/aes)
- [Go crypto/cipher package documentation](https://pkg.go.dev/crypto/cipher)
- [RFC 7465 – Prohibiting RC4 Cipher Suites](https://datatracker.ietf.org/doc/html/rfc7465)
- [CAPEC-97: Cryptanalysis of Cellular Phone Communication](https://capec.mitre.org/data/definitions/97.html)
- [MITRE ATT&CK T1600 – Weaken Encryption](https://attack.mitre.org/techniques/T1600/)
