---
title: "VNX-SWIFT-006 – Swift Insecure Random Number Generator Used in Security-Sensitive Context"
description: "Detects arc4random, rand, random, and SystemRandomNumberGenerator calls in code blocks that generate tokens, keys, passwords, nonces, salts, or IVs, where a cryptographically secure RNG is required."
---

## Overview

This rule flags calls to weak random number generation functions — `arc4random()`, `arc4random_uniform(`, `arc4random_buf(`, `rand()`, `random()`, and `SystemRandomNumberGenerator(` — when they appear within a 10-line context window that also contains a security-sensitive term such as `token`, `key`, `password`, `nonce`, `salt`, `secret`, `otp`, `csrf`, or `iv`. Only non-comment lines are evaluated.

The detection relies on context: using `arc4random` to shuffle a list of quiz questions is benign, but using it to generate a password reset token or a cryptographic nonce is a vulnerability. By requiring both the weak RNG call and a security-relevant term in the surrounding code, the rule produces high-confidence findings with low false-positive rates.

This maps to [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html).

**Severity:** High | **CWE:** [CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

## Why This Matters

Security properties of tokens, keys, nonces, and salts depend entirely on their unpredictability. A PRNG that is predictable — or one whose internal state can be reconstructed from observed outputs — allows an attacker to enumerate possible values, dramatically reducing the search space for brute-force attacks.

`arc4random` and its variants were originally designed to be cryptographically strong, but their behaviour and seeding quality vary by platform and libc version. Swift's `SystemRandomNumberGenerator` delegates to the OS's best available source, but has no documented security guarantee for cryptographic use and its implementation may change across OS versions. `rand()` and `random()` are not cryptographically secure on any platform and should never be used for security-sensitive values.

The attack is most impactful when a predictable PRNG is used to generate password reset tokens, OAuth state parameters, CSRF tokens, one-time passwords, or symmetric encryption IVs. If the attacker can observe a few generated values (e.g., by triggering multiple password resets), they may be able to reconstruct the generator's state and predict all future values, compromising every account that requests a reset during the window.

Apple's `SecRandomCopyBytes` and the CryptoKit framework's `SymmetricKey` and `Nonce` types use the OS CSPRNG (`/dev/random` backed by the Secure Enclave) and are the correct choice for all security-sensitive random data generation on Apple platforms.

## What Gets Flagged

```swift
// FLAGGED: arc4random_uniform used to generate a token
func generateSessionToken() -> String {
    let token = (0..<32).map { _ in
        String(arc4random_uniform(256), radix: 16)  // FLAGGED
    }.joined()
    return token
}

// FLAGGED: rand() used to generate a nonce
let nonce = rand()  // FLAGGED — used as an IV/nonce below
let iv = Data(bytes: &nonce, count: MemoryLayout.size(ofValue: nonce))

// FLAGGED: arc4random_buf filling a key buffer
var keyBuffer = [UInt8](repeating: 0, count: 32)
arc4random_buf(&keyBuffer, keyBuffer.count)  // FLAGGED
let secretKey = Data(keyBuffer)
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

3. **Use `UUID()` only for identifiers, not security tokens.** `UUID()` on Apple platforms calls `arc4random` internally and is suitable for unique identifiers but not for security-sensitive values that must be unpredictable.

4. **Audit all token and key generation code.** Search the codebase for `arc4random`, `rand(`, `random(`, and `SystemRandomNumberGenerator` and assess the security context of each usage. Replace any that generate security-relevant values.

## References

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP Mobile Security Testing Guide – MSTG-CRYPTO-6 (Randomness)](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0063/)
- [Apple – SecRandomCopyBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes)
- [Apple – CryptoKit](https://developer.apple.com/documentation/cryptokit)
- [Apple – Performing Common Cryptographic Operations](https://developer.apple.com/documentation/cryptokit/performing_common_cryptographic_operations)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
- [MITRE ATT&CK T1600 – Weaken Encryption](https://attack.mitre.org/techniques/T1600/)
