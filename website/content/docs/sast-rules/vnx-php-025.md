---
title: "VNX-PHP-025 – PHP deprecated mcrypt encryption functions"
description: "Detects use of the mcrypt extension functions (mcrypt_encrypt, mcrypt_decrypt, etc.), which were deprecated in PHP 7.1 and removed in PHP 7.2 due to their insecure cipher implementations and unmaintained codebase."
---

## Overview

This rule detects calls to functions from PHP's `mcrypt` extension: `mcrypt_encrypt()`, `mcrypt_decrypt()`, `mcrypt_cbc()`, `mcrypt_cfb()`, `mcrypt_ecb()`, `mcrypt_ofb()`, `mcrypt_create_iv()`, `mcrypt_generic()`, `mdecrypt_generic()`, and related module management functions. The mcrypt extension was deprecated in PHP 7.1 and removed in PHP 7.2. Any codebase still using these functions is either running on an outdated PHP version with known security vulnerabilities or will fail to function on a current PHP installation.

The mcrypt library itself (libmcrypt) has been unmaintained since 2003. It implements a collection of cipher algorithms including DES, Triple-DES, Blowfish, and older stream ciphers, many of which are considered cryptographically weak or broken by current standards. The lack of maintenance means known vulnerabilities in the library have not been patched, and the implementations have not been audited to modern standards.

PHP's recommended replacement is the OpenSSL extension (`openssl_encrypt()`, `openssl_decrypt()`), which is actively maintained, supports modern authenticated encryption modes (AES-GCM, ChaCha20-Poly1305), and is available on all current PHP installations. PHP 7.2+ also ships with the Sodium extension (`sodium_crypto_secretbox()`, etc.), which provides a modern, audited, and difficult-to-misuse cryptography API.

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

Using deprecated and removed PHP functions has two categories of impact. The first is operational: code that calls mcrypt functions will throw a fatal error on PHP 7.2+, meaning applications that have not yet migrated are running on PHP 7.1 or earlier, which has reached end-of-life and no longer receives security patches for the PHP runtime itself.

The second impact is cryptographic: mcrypt's commonly used algorithms are insecure by modern standards. DES has a 56-bit key that can be brute-forced in hours with commodity hardware. Triple-DES (3DES) is vulnerable to meet-in-the-middle attacks and Sweet32 birthday attacks. Blowfish has a maximum key size limitation and is being phased out. None of the modes supported by mcrypt include authenticated encryption, meaning ciphertexts encrypted with mcrypt can be modified by attackers without detection — the same padding oracle and bit-flipping risks as AES-CBC, covered in VNX-PHP-019.

Applications that encrypt sensitive data (credentials, personal information, health records, payment details) using these algorithms provide weaker protection than they appear to, and the ciphertext may be decryptable by a determined attacker.

## What Gets Flagged

```php
// FLAGGED: mcrypt_encrypt with deprecated algorithm
$encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $plaintext, MCRYPT_MODE_CBC, $iv);

// FLAGGED: mcrypt_decrypt
$plaintext = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $ciphertext, MCRYPT_MODE_ECB);

// FLAGGED: mcrypt generic interface
$module = mcrypt_module_open(MCRYPT_BLOWFISH, '', MCRYPT_MODE_CBC, '');
mcrypt_generic_init($module, $key, $iv);
$encrypted = mcrypt_generic($module, $data);
```

## Remediation

1. **Migrate to `openssl_encrypt()` / `openssl_decrypt()` with AES-256-GCM** for authenticated encryption.

2. **Or use the Sodium extension** (`sodium_crypto_secretbox()` / `sodium_crypto_secretbox_open()`), which provides a higher-level API with built-in authentication and correct default parameters.

3. **Upgrade the PHP runtime** to a supported version (8.1+) — PHP 7.1 and earlier are end-of-life.

4. **Re-encrypt existing data** stored with mcrypt using a migration script that decrypts with mcrypt on the old PHP version and re-encrypts with OpenSSL or Sodium.

```php
<?php
// SAFE: OpenSSL with AES-256-GCM (see also VNX-PHP-019)
$nonce      = random_bytes(12);
$ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key,
                              OPENSSL_RAW_DATA, $nonce, $tag);

// SAFE: Sodium secretbox — authenticated by default, simple API
$nonce     = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$encrypted = sodium_crypto_secretbox($plaintext, $nonce, $key);

$decrypted = sodium_crypto_secretbox_open($encrypted, $nonce, $key);
if ($decrypted === false) {
    throw new RuntimeException('Decryption failed — data may be tampered');
}
```

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CAPEC-20: Encryption Brute Forcing](https://capec.mitre.org/data/definitions/20.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – Migration from mcrypt to OpenSSL](https://www.php.net/manual/en/migration71.deprecated.php)
- [PHP Manual – Sodium functions](https://www.php.net/manual/en/book.sodium.php)
