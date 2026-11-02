---
title: "VNX-SWIFT-006 – Swift Non-Cryptographic PRNG Used for a Security Value"
description: "Detects the libc rand/random/drand48 family and GameplayKit random sources (directly or through a source variable) used to produce a token, nonce, salt, key, IV, PIN, OTP or password in Swift; arc4random, SystemRandomNumberGenerator and .random(in:) are CSPRNG-backed on Apple platforms and are not reported."
---

## Overview

This rule flags calls to non-cryptographic generators in Swift: the libc `rand()`, `random()`, `drand48()`, `lrand48()`, `mrand48()` and `erand48`/`nrand48`/`jrand48`, and GameplayKit's random sources and distributions (`GKRandomSource`, `GKARC4RandomSource`, `GKLinearCongruentialRandomSource`, `GKMersenneTwisterRandomSource`, `GKRandomDistribution`, `GKGaussianDistribution`, `GKShuffledDistribution`), which Apple documents as unsuitable for cryptography. A call is reported only when its result is a security value: the line (or a `let`/`var` opened up to three lines above it) assigns a name ending with token, nonce, salt, secret, password, OTP, CSRF, session id, challenge, API key, a `*Key`, IV or PIN, or the enclosing function or type is named for one (`generateToken`, `makeNonce`, `enum OTP`).

Not reported: `arc4random()`, `arc4random_uniform()`, `arc4random_buf()`, `SystemRandomNumberGenerator` and `Int.random(in:)`, which are backed by the system CSPRNG on Apple platforms; `SecRandomCopyBytes` and CryptoKit; generators used for shuffling, jitter, delays or cache keys; seeding calls on their own; string literals, comments and test files.

This maps to [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html).

**Severity:** High | **CWE:** [CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

## Why This Matters

Security properties of tokens, keys, nonces, and salts depend entirely on their unpredictability. A PRNG that is predictable — or one whose internal state can be reconstructed from observed outputs — allows an attacker to enumerate possible values, dramatically reducing the search space for brute-force attacks.

On Apple platforms `arc4random` and its variants use a ChaCha20-based CSPRNG seeded by the kernel, and Swift's `SystemRandomNumberGenerator` (used by `Int.random(in:)`, `shuffled()` and friends) is documented as cryptographically secure there. `rand()`, `random()` and the `drand48` family are linear generators whose state can be recovered from a handful of outputs, and the GameplayKit sources are deterministic, seedable generators meant for games.

The attack is most impactful when a predictable PRNG is used to generate password reset tokens, OAuth state parameters, CSRF tokens, one-time passwords, or symmetric encryption IVs. If the attacker can observe a few generated values (e.g., by triggering multiple password resets), they may be able to reconstruct the generator's state and predict all future values, compromising every account that requests a reset during the window.

Apple's `SecRandomCopyBytes` and the CryptoKit framework's `SymmetricKey` and `Nonce` types use the OS CSPRNG (`/dev/random` backed by the Secure Enclave) and are the correct choice for all security-sensitive random data generation on Apple platforms.

## What Gets Flagged

```swift
// FLAGGED: libc rand() for a reset token
let resetToken = String(rand(), radix: 16)

// FLAGGED: drand48() for a salt
let salt = drand48()

// FLAGGED: GameplayKit for a one-time code
let otp = GKRandomSource.sharedRandom().nextInt(upperBound: 1_000_000)

// FLAGGED: rand() inside a key generator
func generateSessionKey() -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 32)
    for i in 0..<bytes.count {
        bytes[i] = UInt8(truncatingIfNeeded: rand())
    }
    return bytes
}

// FLAGGED: a GameplayKit source held in a property, then drawn from
private let source = GKMersenneTwisterRandomSource(seed: 1337)
let otp = source.nextInt(upperBound: 1_000_000)

// NOT FLAGGED: jitter inside a token-refresh function
let jitter = Double(random() % 30)

// NOT FLAGGED: CSPRNG-backed on Apple platforms
let nonce = arc4random_uniform(UInt32.max)
let pin = Int.random(in: 0..<10_000)
```

## Remediation

1. **Use `SecRandomCopyBytes` for raw random bytes.** This function fills a buffer with cryptographically secure random data using the hardware RNG.

   ```swift
   // SAFE: cryptographically secure token using SecRandomCopyBytes
   import Security

   func generateSecureToken(length: Int = 32) throws -> String {
       var bytes = [UInt8](repeating: 0, count: length)
       let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
       guard status == errSecSuccess else {
           throw CryptoError.randomGenerationFailed(status)
       }
       return bytes.map { String(format: "%02x", $0) }.joined()
   }
   ```

2. **Use CryptoKit for symmetric keys, nonces, and IVs.** CryptoKit's types generate secure random values internally and enforce correct sizes for the chosen algorithm.

   ```swift
   // SAFE: AES-GCM encryption with CryptoKit-generated key and nonce
   import CryptoKit

   func encryptData(_ plaintext: Data, using key: SymmetricKey) throws -> (ciphertext: Data, tag: Data, nonce: AES.GCM.Nonce) {
       let nonce = AES.GCM.Nonce()  // Cryptographically secure, correct size
       let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
       return (sealed.ciphertext, sealed.tag, nonce)
   }

   // Generate a 256-bit key
   let key = SymmetricKey(size: .bits256)  // Cryptographically secure
   ```

3. **Use `UUID()` only for identifiers.** It is random but has a fixed format and only 122 random bits; for a secret value, generate bytes with `SecRandomCopyBytes` or CryptoKit.

4. **Audit all token and key generation code.** Search for `rand(`, `random(`, `drand48(` and `GK*RandomSource` and replace any that generate security-relevant values.

## References

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP Mobile Security Testing Guide – MSTG-CRYPTO-6 (Randomness)](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0063/)
- [Apple – SecRandomCopyBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes)
- [Apple – CryptoKit](https://developer.apple.com/documentation/cryptokit)
- [Apple – Performing Common Cryptographic Operations](https://developer.apple.com/documentation/cryptokit/performing_common_cryptographic_operations)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
- [MITRE ATT&CK T1600 – Weaken Encryption](https://attack.mitre.org/techniques/T1600/)
