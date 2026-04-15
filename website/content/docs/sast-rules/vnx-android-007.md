---
title: "VNX-ANDROID-007 – Android Weak Cryptography Using AES in ECB Mode"
description: "Detects Cipher.getInstance() calls that specify AES/ECB or plain 'AES' (which defaults to ECB mode on Android), a deterministic cipher mode that leaks data patterns and does not provide semantic security."
---

## Overview

This rule identifies Java and Kotlin code that calls `Cipher.getInstance()` with a transformation string of either `"AES"` (bare, which defaults to `AES/ECB/PKCS5Padding` on Android's Bouncy Castle provider) or any string starting with `"AES/ECB"`. ECB (Electronic Codebook) mode encrypts each 16-byte block of plaintext independently using the same key, producing the same ciphertext block for identical plaintext blocks. This deterministic property means that patterns in the plaintext are visible in the ciphertext — the canonical example being the "ECB Penguin", where encrypting a bitmap image in ECB mode preserves the visible outline of the image. This vulnerability maps to CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

ECB mode is dangerous in practice, not just in theory. Any data with repeated structure — user IDs padded to a block boundary, repeated headers in a file format, sequences of similar records — will reveal that repetition through identical ciphertext blocks. An attacker observing ECB-encrypted database rows can detect when two rows contain the same field value without decrypting anything.

Beyond pattern leakage, ECB mode is also vulnerable to block-rearrangement attacks: an attacker can reorder, duplicate, or delete 16-byte blocks in the ciphertext without detection, as there is no authentication tag. This can be exploited to manipulate encrypted data in predictable ways — for example, moving a privilege field from one record into another.

The correct choices for symmetric encryption on Android are AES-GCM (authenticated encryption, nonce-based, provides both confidentiality and integrity) or AES-CBC with PKCS5Padding paired with a separate HMAC for authentication. AES-GCM is preferred because it combines encryption and authentication into a single primitive, reducing implementation surface.

## What Gets Flagged

```java
// FLAGGED: bare "AES" defaults to ECB mode on Android
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);

// FLAGGED: ECB mode explicitly specified
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
```

```kotlin
// FLAGGED: Kotlin equivalent — still ECB
val cipher = Cipher.getInstance("AES/ECB/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)
```

## Remediation

1. **Replace ECB with AES/GCM/NoPadding** for all new encryption. GCM mode provides authenticated encryption, meaning any tampering of the ciphertext is detected on decryption.

2. **Generate a fresh random IV (nonce) for every encryption operation.** A 12-byte random nonce is required for GCM. Store the nonce alongside the ciphertext — it is not secret.

3. **Migrate existing data** encrypted under ECB by re-encrypting it under GCM at the next access opportunity, after verifying the decrypted plaintext is valid.

```java
// SAFE: AES/GCM with a fresh random nonce per encryption
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

    byte[] ciphertext = cipher.doFinal(plaintext);
    // Prepend iv to ciphertext for storage
    byte[] result = new byte[iv.length + ciphertext.length];
    System.arraycopy(iv, 0, result, 0, iv.length);
    System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
    return result;
}
```

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP MASTG – MASTG-TEST-0061: Testing the Configuration of Cryptographic Standard Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0061/)
- [OWASP MASVS – MASVS-CRYPTO-1: Cryptography](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/)
- [Android Developer Docs – Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [NIST SP 800-38D – Recommendation for GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [MITRE ATT&CK T1600 – Weaken Encryption](https://attack.mitre.org/techniques/T1600/)
