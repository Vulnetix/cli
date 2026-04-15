---
title: "VNX-NODE-020 – Deprecated crypto.createCipher/createDecipher Without IV"
description: "Detects use of the deprecated crypto.createCipher() and crypto.createDecipher() functions that derive the initialization vector deterministically, breaking encryption security for stream and counter modes."
---

## Overview

This rule detects calls to the deprecated Node.js `crypto.createCipher()` and `crypto.createDecipher()` functions. These functions were deprecated in Node.js v10 and removed in v22 because they derive the encryption key and initialization vector (IV) deterministically from the password using a single MD5 digest. This means the IV is never random — given the same password and data, the same ciphertext is always produced.

A non-random IV is catastrophic for stream ciphers and counter-based modes (CTR, GCM, CCM, OFB). These modes require that the IV/nonce is unique for every encryption operation with the same key. When two messages are encrypted with the same key and IV, an attacker who observes both ciphertexts can XOR them together to cancel the keystream, often recovering both plaintexts. For GCM mode specifically, IV reuse also allows the attacker to forge authentication tags, completely undermining integrity protection.

The correct alternatives are `crypto.createCipheriv()` and `crypto.createDecipheriv()`, which accept an explicit IV. The IV must be generated with `crypto.randomBytes(ivLength)` for each encryption operation and transmitted alongside the ciphertext (the IV does not need to be secret).

**Severity:** High | **CWE:** [CWE-330 – Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

## Why This Matters

Deterministic IV encryption breaks confidentiality at the protocol level regardless of key strength. An attacker does not need to break AES — they only need to obtain two ciphertexts encrypted with the same password (and therefore the same IV) and XOR them. For web applications this is easily achievable: encrypt the same plaintext twice to get a reference ciphertext and use it to decode other messages.

For AES-GCM, the consequences are worse. The GCM authentication tag is computed over the IV, the associated data, and the ciphertext using a polynomial hash. When the IV repeats, the attacker can recover the hash key (`H`) and forge authentication tags for arbitrary ciphertexts. This turns an authenticated encryption scheme into unauthenticated encryption — the application can no longer trust that ciphertexts have not been tampered with.

The deprecation of `createCipher` is Node.js's own signal that this API is unsafe. Any code still using it is depending on functionality that is intentionally unavailable in modern Node.js versions.

## What Gets Flagged

```javascript
// FLAGGED: createCipher uses a deterministic IV derived from password
const cipher = crypto.createCipher('aes-256-cbc', password);
let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');

// FLAGGED: createDecipher — same problem for decryption
const decipher = crypto.createDecipher('aes-256-cbc', password);
let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
decrypted += decipher.final('utf8');
```

## Remediation

1. **Replace `createCipher` with `createCipheriv`** and generate a cryptographically random IV with `crypto.randomBytes()` for each encryption operation.

2. **Transmit the IV alongside the ciphertext** — prefix the ciphertext, or use a structured format. The IV is not secret but must be unique per operation.

3. **Use AES-256-GCM** in preference to AES-256-CBC for authenticated encryption, and store the authentication tag alongside the ciphertext.

4. **For key derivation from passwords**, use `crypto.scrypt()` or `crypto.pbkdf2()` instead of relying on the deprecated function's internal MD5 derivation.

```javascript
// SAFE: AES-256-GCM with random IV and authentication tag
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 12 bytes recommended for GCM
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes = 256 bits

function encrypt(plaintext) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  // Store: iv + tag + encrypted (each fixed-length for easy parsing)
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decrypt(ciphertext) {
  const buf = Buffer.from(ciphertext, 'base64');
  const iv  = buf.slice(0, IV_LENGTH);
  const tag = buf.slice(IV_LENGTH, IV_LENGTH + 16);
  const enc = buf.slice(IV_LENGTH + 16);
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}
```

## References

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [Node.js crypto documentation — createCipheriv](https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options)
- [Node.js deprecation list — DEP0106 (crypto.createCipher)](https://nodejs.org/api/deprecations.html#dep0106-cryptocreatecipher-and-cryptocreatedecipher)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [NIST SP 800-38D — Recommendation for GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
