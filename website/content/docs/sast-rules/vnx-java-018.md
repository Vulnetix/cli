---
title: "VNX-JAVA-018 – Java RSA cipher without OAEP padding"
description: "Detects RSA encryption using PKCS#1 v1.5 padding or no padding, both of which are vulnerable to Bleichenbacher-style padding oracle attacks. Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding instead."
---

## Overview

This rule flags calls to `Cipher.getInstance()` that specify an RSA transformation string containing `PKCS1Padding`, `NoPadding`, or the shorthand `RSA/ECB/PKCS1`. These padding schemes are cryptographically weak and expose applications to a class of attack known as the Bleichenbacher padding oracle attack (also called the "million message attack"). The vulnerability is tracked as CWE-780 (Use of RSA Algorithm without OAEP).

PKCS#1 v1.5 padding prepends a structured sequence of bytes to the plaintext before encryption. The structure is deterministic enough that a server decrypting a modified ciphertext and responding differently based on whether the padding is valid leaks a single bit of information per query. Bleichenbacher showed in 1998 that an attacker who can distinguish "valid padding" from "invalid padding" — even through indirect means such as differing error messages, timing variations, or TLS alert types — can decrypt any RSA ciphertext with approximately one million adaptive chosen-ciphertext queries. Despite being over two decades old, this attack remains practical and has been rediscovered repeatedly in TLS implementations (ROBOT attack, 2017).

OAEP (Optimal Asymmetric Encryption Padding) provides probabilistic encryption and is provably secure in the random oracle model. It does not have a padding oracle vulnerability.

**Severity:** High | **CWE:** [CWE-780 – Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

## Why This Matters

The ROBOT (Return Of Bleichenbacher's Oracle Threat) vulnerability, disclosed in 2017, demonstrated that 27 of the top 100 Alexa websites — including Facebook, PayPal, and major US government sites — were vulnerable to the 1998 Bleichenbacher attack. An attacker with the ability to make adaptive queries against the TLS handshake could decrypt TLS session keys encrypted under RSA PKCS#1 v1.5, breaking the confidentiality of past and present sessions.

In application code, the risk is equally concrete. An API that uses RSA PKCS#1 v1.5 to decrypt tokens, license keys, or session data, and that returns different HTTP status codes or error messages depending on whether decryption succeeded, provides the oracle an attacker needs. The attacker doesn't need to access your private key directly — they use your own server as a decryption oracle to recover the plaintext incrementally.

No-padding mode (`NoPadding`) is even more dangerous: it provides textbook RSA with no randomness, making it trivially malleable. Multiplying a ciphertext by the encryption of a known value produces a ciphertext that decrypts to the plaintext multiplied by the known value — a property that enables chosen-ciphertext attacks without any oracle at all.

## What Gets Flagged

```java
// FLAGGED: PKCS#1 v1.5 padding is vulnerable to padding oracle attacks
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.DECRYPT_MODE, privateKey);
byte[] plaintext = cipher.doFinal(ciphertext);

// FLAGGED: no padding is textbook RSA — fully malleable
Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
```

## Remediation

1. Replace `PKCS1Padding` and `NoPadding` with `OAEPWithSHA-256AndMGF1Padding` in all `Cipher.getInstance()` calls that use RSA.
2. For new code, prefer `OAEPWithSHA-512AndMGF1Padding` if your key size is 4096 bits or larger.
3. Do not catch `BadPaddingException` and `IllegalBlockSizeException` separately and return different responses — always treat any decryption failure identically to prevent timing or error-message oracles.
4. Consider migrating bulk encryption to hybrid encryption: use RSA-OAEP to encrypt only an ephemeral AES key, then use AES-GCM for the actual data.

```java
// SAFE: OAEP padding prevents padding oracle attacks
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;

OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
);

Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec);

byte[] plaintext;
try {
    plaintext = cipher.doFinal(ciphertext);
} catch (Exception e) {
    // Always return the same error regardless of failure reason
    throw new CryptoException("Decryption failed");
}
```

## References

- [CWE-780: Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)
- [CAPEC-463: Padding Oracle Crypto Attack](https://capec.mitre.org/data/definitions/463.html)
- [ROBOT Attack (2017) – Return Of Bleichenbacher's Oracle Threat](https://robotattack.org/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [Java SE Security: JCA Reference Guide — Cipher](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html#GUID-94225C88-F2F1-44D1-A781-1DD9D5094566)
- [NIST SP 800-131A Rev 2: Transitioning the Use of Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
