---
title: "VNX-KOTLIN-002 – Kotlin RSA Key Smaller Than 2048 Bits"
description: "Detects RSA, DSA and Diffie-Hellman key pairs and DSA/DH domain parameters generated with fewer than 2048 bits in Kotlin: KeyPairGenerator.initialize(), AlgorithmParameterGenerator.init(), RSAKeyGenParameterSpec, Android keystore setKeySize() and Bouncy Castle RSAKeyGenerationParameters."
---

## Overview

The security of RSA encryption and signing depends entirely on the computational difficulty of factoring the modulus — the product of two large primes. As computing power and factoring algorithms improve, the minimum key size required to maintain adequate security increases over time. Keys of 512 bits were factored publicly in 1999; 768-bit keys were factored in 2009; 1024-bit keys are now considered within reach of well-resourced adversaries. NIST SP 800-57 Part 1 requires at least 2048 bits for RSA keys and recommends 3072 or 4096 bits for long-lived keys. This is CWE-326 (Inadequate Encryption Strength).

This rule flags Kotlin code (`.kt`, `.kts`) that generates an RSA, DSA or Diffie-Hellman key pair with a modulus below 2048 bits. It recognises `initialize(n)` and `initialize(n, random)` on a generator obtained from `KeyPairGenerator.getInstance("RSA" | "RSASSA-PSS" | "DSA" | "DH" | "DiffieHellman")` or `KeyProperties.KEY_ALGORITHM_RSA` (through a variable, a `by lazy` property, or inside `apply`/`run`/`also`/`with`), `RSAKeyGenParameterSpec(n, ...)`, `setKeySize(n)` on an Android `KeyGenParameterSpec.Builder` that feeds an RSA generator or on the legacy `KeyPairGeneratorSpec.Builder`, and Bouncy Castle `RSAKeyGenerationParameters(e, random, n, certainty)`. The size can be a literal, a constant or a parameter default that the file assigns exactly once.

It does not report 2048 bits or more, EC, EdDSA or symmetric key sizes (`ec.initialize(256)`, `KeyGenerator.init(128)`, an AES keystore `setKeySize(256)`), a size variable the file assigns on several paths, a generator whose algorithm is not visible in the file (a parameter or a variable algorithm name), unrelated `initialize()` calls, test sources, comments or string literals.

Undersized RSA keys affect every operation that uses the key pair: TLS certificates with a 1024-bit RSA key allow decryption of captured traffic once the key is factored; JWT signing keys allow token forgery; code-signing keys allow malicious package distribution. The impact is systemic because a single weak key can compromise all data ever protected by it.

**Severity:** High | **CWE:** [CWE-326 – Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## Why This Matters

The academic and practical threat to sub-2048-bit RSA keys is well documented. The Number Field Sieve algorithm has been continuously improved, and cloud computing has dramatically reduced the cost of the required computation. A 1024-bit RSA modulus is now estimated to require roughly the computational equivalent of a few months of a medium-sized cloud deployment to factor — well within the budget of a nation-state adversary or serious criminal organisation.

From an attacker's perspective, factoring a weak key is a one-time investment that pays dividends indefinitely: all past communications encrypted with the key can be decrypted retroactively if captured, and all future signatures can be forged. Passive collection of encrypted traffic against targets with weak RSA keys — common in embedded systems, IoT devices, and legacy Android applications — is a documented intelligence-gathering technique.

Android applications and embedded Kotlin services are particularly at risk because developers sometimes choose smaller key sizes for performance on constrained hardware, not realising that modern hardware can handle 2048-bit RSA without meaningful overhead in most use cases.

## What Gets Flagged

```kotlin
// FLAGGED: 1024-bit RSA key
val kpg = KeyPairGenerator.getInstance("RSA")
kpg.initialize(1024)

// FLAGGED: inside a scope function, with a SecureRandom
KeyPairGenerator.getInstance("RSA").run {
    initialize(512, SecureRandom())
    generateKeyPair()
}

// FLAGGED: the size comes from a constant
private const val RSA_KEY_BITS = 1024
kpg.initialize(RSA_KEY_BITS)

// FLAGGED: parameter spec and Android keystore builder
kpg.initialize(RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4))
KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    .setKeySize(1024)

// FLAGGED: DSA and Diffie-Hellman below 2048 bits
val dh = KeyPairGenerator.getInstance("DH")
dh.initialize(512)

// FLAGGED: DH or DSA domain parameters below 2048 bits
val paramGen = AlgorithmParameterGenerator.getInstance("DH")
paramGen.init(1024)
```

Not flagged:

```kotlin
val rsa = KeyPairGenerator.getInstance("RSA")
rsa.initialize(2048)
val ec = KeyPairGenerator.getInstance("EC")
ec.initialize(256)   // an EC size, not an RSA modulus
val aes = KeyGenerator.getInstance("AES")
aes.init(128)
```

## Remediation

1. **Use at least 2048 bits for RSA keys.** For new systems or long-lived keys (certificates valid for more than 2 years), use 3072 or 4096 bits.

2. **Consider migrating to elliptic-curve cryptography.** ECDSA with P-256 or P-384 provides equivalent or better security to 3072-bit RSA at a fraction of the key size and computational cost, which is advantageous on constrained Android or IoT hardware.

3. **Audit existing key material.** Any certificates, stored keys, or signed artifacts produced with sub-2048-bit RSA must be considered compromised and replaced.

```kotlin
// SAFE: 2048-bit RSA key (minimum acceptable)
val kpg = KeyPairGenerator.getInstance("RSA")
kpg.initialize(2048)
val keyPair = kpg.generateKeyPair()

// PREFERRED: 4096-bit RSA for long-lived keys
kpg.initialize(4096)

// PREFERRED: ECDSA as an alternative (P-256 ~ 3072-bit RSA security)
val ecKpg = KeyPairGenerator.getInstance("EC")
ecKpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
val ecKeyPair = ecKpg.generateKeyPair()
```

## References

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [NIST SP 800-57 Part 1: Key Management Recommendations](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [Android Developer Security Guide: Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [Kotlin Cryptography Best Practices](https://kotlinlang.org/docs/security.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
