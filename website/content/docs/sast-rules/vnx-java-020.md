---
title: "VNX-JAVA-020 – Java static IV reuse in block cipher"
description: "Detects hardcoded or static initialization vectors (IVs) passed to IvParameterSpec in Java cipher operations. Reusing the same IV with the same key undermines the security of CBC, CTR, and GCM modes."
---

## Overview

This rule detects two patterns indicating IV reuse: `IvParameterSpec` constructed from a string literal (e.g., `new IvParameterSpec("1234567890123456".getBytes())`), and static or final byte arrays named `IV` initialised with an inline array literal (e.g., `static final byte[] IV = {0x00, 0x01, ...}`). Both patterns produce a fixed IV that is the same across every invocation of the cipher, which breaks the security properties of all standard block cipher modes. The vulnerability is classified as CWE-329 (Generation of Predictable IV with CBC Mode).

An initialization vector is designed to introduce randomness into the first block of encryption so that encrypting the same plaintext twice with the same key produces different ciphertexts. When the IV is constant, this randomization is eliminated. In CBC mode, two messages that share a common prefix produce identical ciphertext until the first differing block, leaking information about the plaintext. In CTR and GCM modes, IV reuse is catastrophically worse: it allows an attacker to XOR two ciphertexts and recover the XOR of the plaintexts directly, and in GCM it also invalidates the authentication tag, enabling undetected forgery.

**Severity:** High | **CWE:** [CWE-329 – Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

## Why This Matters

GCM nonce reuse is one of the most dangerous cryptographic mistakes in practice. When two messages are encrypted under GCM with the same key and nonce (IV), an attacker can recover the authentication key `H` and the keystream for that nonce. This completely breaks both confidentiality and integrity: the attacker can decrypt any message encrypted under that nonce and forge valid authentication tags for arbitrary plaintexts. This attack, sometimes called "GCM nonce reuse" or the "Joux forbidden attack," requires only two ciphertexts produced with the same nonce.

Real-world examples abound. The BEAST attack against TLS 1.0 exploited predictable CBC IVs (not reuse per se, but IV predictability — the conceptual cousin). Disk encryption systems that use a static IV per sector allow an attacker who can observe multiple versions of a sector's contents to perform differential analysis. Many Java application-layer encryption implementations that store encrypted data in databases have been found to use static IVs, meaning the entire database is vulnerable to chosen-plaintext attacks once any plaintext-ciphertext pair is known.

## What Gets Flagged

```java
// FLAGGED: IvParameterSpec constructed from a string literal
private static final String IV_STRING = "1234567890123456";
IvParameterSpec ivSpec = new IvParameterSpec(IV_STRING.getBytes());

// FLAGGED: static final byte array used as IV
private static final byte[] IV = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
```

## Remediation

1. Generate a fresh, cryptographically random IV for every encryption operation using `SecureRandom.nextBytes()`.
2. Prepend the IV to the ciphertext so that it can be recovered for decryption — the IV is not secret, only unpredictable.
3. For GCM mode, use a 96-bit (12-byte) nonce and never encrypt more than approximately 2^32 messages under the same key without rekeying.
4. For CBC mode, use a 128-bit (16-byte) IV.

```java
// SAFE: fresh random IV generated for every encryption
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.SecureRandom;

public class AesCbcEncryptor {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public byte[] encrypt(SecretKey key, byte[] plaintext) throws Exception {
        // Generate a unique IV for this encryption
        byte[] iv = new byte[16];
        SECURE_RANDOM.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext: first 16 bytes are IV, rest is ciphertext
        byte[] output = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);
        return output;
    }

    public byte[] decrypt(SecretKey key, byte[] ivAndCiphertext) throws Exception {
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[ivAndCiphertext.length - 16];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, 16);
        System.arraycopy(ivAndCiphertext, 16, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }
}
```

## References

- [CWE-329: Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
- [CAPEC-97: Cryptanalysis of Cellular Phone Communication](https://capec.mitre.org/data/definitions/97.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS (2016)](https://eprint.iacr.org/2016/475.pdf)
- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [Java SE Security: JCA Reference Guide — Cipher](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
