---
title: "VNX-PHP-019 – PHP insecure cipher mode (AES-CBC)"
description: "Detects openssl_encrypt() or openssl_decrypt() called with an AES-CBC cipher mode, which is unauthenticated and vulnerable to padding oracle and bit-flipping attacks."
---

## Overview

This rule detects calls to PHP's `openssl_encrypt()` or `openssl_decrypt()` that specify an AES-CBC cipher mode (`aes-128-cbc`, `aes-192-cbc`, or `aes-256-cbc`). It also flags standalone string literals containing these cipher names, which may indicate cipher configuration values. AES-CBC provides confidentiality but not integrity or authenticity — it does not prevent an attacker from modifying the ciphertext and having those modifications silently reflected in the decrypted plaintext.

Cipher Block Chaining (CBC) mode encrypts each plaintext block by XORing it with the previous ciphertext block before encryption. This creates a dependency between blocks, but it also means that flipping bits in a ciphertext block produces predictable, targeted changes in the decrypted output of the following block. An attacker with a decryption oracle — a service that decrypts ciphertext and returns whether the padding is valid — can decrypt any CBC-encrypted message byte by byte without knowing the key, through the padding oracle attack.

Authenticated Encryption with Associated Data (AEAD) modes such as AES-GCM combine encryption and a Message Authentication Code (MAC) in a single operation, making any ciphertext modification detectable before decryption. Using AES-GCM instead of AES-CBC eliminates both padding oracle attacks and bit-flipping.

**Severity:** Medium | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

Padding oracle attacks have been exploited in practice against a wide range of systems, including ASP.NET ViewState (POET), Oracle PeopleSoft, and numerous custom implementations that used CBC mode with PKCS#7 padding and exposed error information through timing differences or distinct error messages. The attack requires only that the application behave differently for valid versus invalid padding — a property that is difficult to eliminate in CBC-based systems.

Bit-flipping attacks against CBC are relevant wherever encrypted data influences application logic. An attacker who can modify encrypted session tokens, authentication cookies, or encrypted database fields by flipping bits in the ciphertext can alter decrypted values without knowing the key. Common targets include role fields, user ID fields, and boolean flags embedded in encrypted payloads.

Switching to AES-GCM eliminates both attack classes and is supported natively by PHP's OpenSSL extension with no additional dependencies.

## What Gets Flagged

```php
// FLAGGED: AES-CBC used with openssl_encrypt()
$ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, 0, $iv);

// FLAGGED: AES-CBC cipher string as configuration value
$cipher = 'aes-128-cbc';
$encrypted = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $iv);
```

## Remediation

1. **Replace AES-CBC with AES-256-GCM**, which provides authenticated encryption. The `openssl_encrypt()` function supports GCM and returns an authentication tag via the `$tag` parameter.

2. **Verify the authentication tag before decrypting** — reject any message where the tag does not match.

3. **Never reuse an IV (nonce) with the same key in GCM mode** — use `random_bytes(12)` to generate a fresh 96-bit nonce for every encryption operation.

4. **Prepend the IV/nonce to the ciphertext** for storage or transmission so it is available for decryption.

```php
<?php
// SAFE: AES-256-GCM — authenticated encryption, no padding oracle risk
function encrypt(string $plaintext, string $key): string {
    $nonce      = random_bytes(12); // 96-bit nonce for GCM
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag,         // authentication tag output
        '',           // additional authenticated data
        16            // tag length in bytes
    );
    // Store nonce + tag + ciphertext together
    return base64_encode($nonce . $tag . $ciphertext);
}

function decrypt(string $encoded, string $key): string {
    $data       = base64_decode($encoded);
    $nonce      = substr($data, 0, 12);
    $tag        = substr($data, 12, 16);
    $ciphertext = substr($data, 28);

    $plaintext = openssl_decrypt(
        $ciphertext, 'aes-256-gcm', $key,
        OPENSSL_RAW_DATA, $nonce, $tag
    );

    if ($plaintext === false) {
        throw new RuntimeException('Decryption failed: authentication tag mismatch');
    }
    return $plaintext;
}
```

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CAPEC-97: Cryptanalysis of Cellular Phone Communication](https://capec.mitre.org/data/definitions/97.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – openssl_encrypt()](https://www.php.net/manual/en/function.openssl-encrypt.php)
- [NIST SP 800-38D – GCM Mode Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
