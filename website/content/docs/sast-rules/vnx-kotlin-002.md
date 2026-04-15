---
title: "VNX-KOTLIN-002 – Kotlin RSA Key Smaller Than 2048 Bits"
description: "Detects RSA KeyPairGenerator initialisation with fewer than 2048 bits in Kotlin, producing keys that can be factored with modern computing resources."
---

## Overview

The security of RSA encryption and signing depends entirely on the computational difficulty of factoring the modulus — the product of two large primes. As computing power and factoring algorithms improve, the minimum key size required to maintain adequate security increases over time. Keys of 512 bits were factored publicly in 1999; 768-bit keys were factored in 2009; 1024-bit keys are now considered within reach of well-resourced adversaries. NIST SP 800-57 Part 1 requires at least 2048 bits for RSA keys and recommends 3072 or 4096 bits for long-lived keys. This is CWE-326 (Inadequate Encryption Strength).

This rule flags `KeyPairGenerator.initialize()` calls in Kotlin (`.kt`, `.kts`) where the key size argument is 512, 768, or 1024. These sizes are below the current minimum security threshold regardless of the algorithm or use case.

Undersized RSA keys affect every operation that uses the key pair: TLS certificates with a 1024-bit RSA key allow decryption of captured traffic once the key is factored; JWT signing keys allow token forgery; code-signing keys allow malicious package distribution. The impact is systemic because a single weak key can compromise all data ever protected by it.

**Severity:** High | **CWE:** [CWE-326 – Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## Why This Matters

The academic and practical threat to sub-2048-bit RSA keys is well documented. The Number Field Sieve algorithm has been continuously improved, and cloud computing has dramatically reduced the cost of the required computation. A 1024-bit RSA modulus is now estimated to require roughly the computational equivalent of a few months of a medium-sized cloud deployment to factor — well within the budget of a nation-state adversary or serious criminal organisation.

From an attacker's perspective, factoring a weak key is a one-time investment that pays dividends indefinitely: all past communications encrypted with the key can be decrypted retroactively if captured, and all future signatures can be forged. Passive collection of encrypted traffic against targets with weak RSA keys — common in embedded systems, IoT devices, and legacy Android applications — is a documented intelligence-gathering technique.

Android applications and embedded Kotlin services are particularly at risk because developers sometimes choose smaller key sizes for performance on constrained hardware, not realising that modern hardware can handle 2048-bit RSA without meaningful overhead in most use cases.

## What Gets Flagged

```kotlin
// FLAGGED: 512-bit RSA key
val kpg = KeyPairGenerator.getInstance("RSA")
kpg.initialize(512)

// FLAGGED: 1024-bit RSA key
kpg.initialize(1024)
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
