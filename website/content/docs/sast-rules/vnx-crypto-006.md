---
title: "VNX-CRYPTO-006 – Weak RSA Key Size"
description: "Detects RSA key generation using key sizes below 2048 bits (512, 768, or 1024 bits) in Python, Go, and Java, where the keys can be factored by modern hardware."
---

## Overview

This rule detects RSA key generation with bit sizes of 512, 768, or 1024 bits — all of which are too small for modern cryptographic security requirements. RSA security depends on the difficulty of factoring the product of two large primes; advances in hardware, distributed computing, and factoring algorithms (GNFS) have progressively reduced the effective security of smaller RSA keys to the point where 1024-bit keys are within reach of well-funded attackers. NIST has recommended a minimum of 2048 bits since 2010 and recommends 3072 or 4096 bits for keys that must remain secure beyond 2030. This maps to CWE-326 (Inadequate Encryption Strength).

**Severity:** High | **CWE:** [CWE-326 – Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## Why This Matters

A 512-bit RSA key can be factored in hours on commodity hardware; a 768-bit key was publicly factored in 2009 using a distributed computation across hundreds of machines over two years (a computation now achievable much faster). The 1024-bit key size sits in a grey zone: NIST deprecated it for U.S. government use after 2013, and academic research projects have estimated it is within reach of nation-state-scale cryptanalytic efforts.

In practice, if your application generates RSA key pairs for TLS certificates, SSH host keys, JWT signing keys, or data encryption and those keys are 1024 bits or less, an attacker who invests sufficient computational resources can factor the public key, derive the private key, and then decrypt all past and future traffic protected by that key (enabling retroactive decryption of captured ciphertext). MITRE ATT&CK T1557 documents the adversary-in-the-middle scenarios this enables.

## What Gets Flagged

The rule uses a regex to match key generation calls that include a small bit size (512, 768, or 1024) in Python, Go, and Java:

```python
# FLAGGED: 1024-bit RSA key generation
from Crypto.PublicKey import RSA
key = RSA.generate(1024)
```

```go
// FLAGGED: Go 1024-bit RSA key
import "crypto/rsa"
privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
```

```java
// FLAGGED: Java 1024-bit RSA via KeyPairGenerator
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(1024);
```

## Remediation

1. **Use a minimum of 2048-bit RSA keys for all new key generation.** For keys that need to remain secure beyond 2030 (long-lived CA keys, archive encryption keys), use 4096 bits.

   ```python
   # SAFE: 4096-bit RSA key
   from Crypto.PublicKey import RSA
   key = RSA.generate(4096)
   ```

   ```go
   // SAFE: Go 4096-bit RSA key
   import "crypto/rsa"
   privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
   if err != nil {
       return fmt.Errorf("key generation failed: %w", err)
   }
   ```

   ```java
   // SAFE: Java 4096-bit RSA
   KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
   kpg.initialize(4096, new SecureRandom());
   KeyPair kp = kpg.generateKeyPair();
   ```

2. **Consider migrating to Elliptic Curve cryptography (ECDSA/ECDH).** For equivalent security to 3072-bit RSA, a 256-bit elliptic curve key (P-256 or Curve25519) provides the same resistance with dramatically smaller key sizes and faster operations. Use P-384 for the equivalent of 7680-bit RSA.

   ```python
   # SAFE: ECDSA P-384 key (equivalent security to ~7680-bit RSA)
   from cryptography.hazmat.primitives.asymmetric import ec
   private_key = ec.generate_private_key(ec.SECP384R1())
   ```

3. **Revoke and replace any existing weak keys.** If 1024-bit or smaller RSA keys are in production (TLS certificates, SSH keys, JWT signing keys), generate new 2048+ bit or ECC equivalents, deploy them, and revoke the old keys. Update CRL/OCSP configurations accordingly.

4. **Add key size validation in key loading paths.** When loading RSA keys from disk or a secret store, validate the key size before use:

   ```go
   // SAFE: validate loaded key size
   if privateKey.N.BitLen() < 2048 {
       return errors.New("RSA key too small: minimum 2048 bits required")
   }
   ```

## References

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
- [NIST SP 800-57 Part 1 Rev 5 – Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-131A Rev 2 – Transitioning Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [OWASP Cryptographic Storage Cheat Sheet – Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-management)
- [keylength.com – Comparable key sizes across algorithm families](https://www.keylength.com/)
- [ECRYPT-CSA – Yearly Report on Algorithms and Key Lengths](https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf)
