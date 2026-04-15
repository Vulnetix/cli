---
title: "VNX-JAVA-016 – Java Weak PRNG (java.util.Random) Used for Security-Sensitive Value"
description: "Detect use of java.util.Random or Math.random() where a cryptographically secure random number generator is required — such as for tokens, session IDs, nonces, passwords, or cryptographic keys."
---

## Overview

This rule flags instantiation of `java.util.Random` or calls to `Math.random()` in contexts where the random value is used for a security-sensitive purpose. Both APIs are linear-congruential generators (LCG) seeded with a 48-bit value. Their output is entirely predictable if an attacker can observe even a small sample of generated values. This maps to [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html).

**Severity:** High | **CWE:** [CWE-330 – Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

## Why This Matters

`java.util.Random` was designed for simulations, games, and statistical sampling — not security. Its 48-bit seed space means only 2^48 possible sequences exist. A determined attacker who observes a few generated values can reconstruct the internal state and predict all past and future outputs within milliseconds on a modern CPU. When that output is a session token, a password-reset link, or an encryption nonce, the attacker can:

- Predict all active session tokens and hijack sessions.
- Predict password-reset tokens and take over user accounts.
- Predict nonces and break the confidentiality of encrypted messages.

The same analysis applies to `Math.random()`, which delegates to a shared `java.util.Random` instance.

**OWASP ASVS v4.0 requirements:**

- **V6.3.1** — Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved CSPRNG when these values are intended to be unguessable by an attacker.
- **V6.3.2** — Verify that random GUIDs are created using the GUID v4 algorithm and a CSPRNG.

**Real-world CVEs:**

- CVE-2009-3274 — Firefox temporary file names predictable due to weak PRNG seeding.
- Various Java session token vulnerabilities in early application servers tied to `java.util.Random`-backed session ID generation.

## What Gets Flagged

```java
// FLAGGED: java.util.Random used for token generation
Random rng = new Random();
String token = Long.toHexString(rng.nextLong());

// FLAGGED: Math.random() used for session ID generation
String sessionId = String.valueOf((int)(Math.random() * Integer.MAX_VALUE));

// FLAGGED: new Random() seeded with current time (still predictable)
Random rng = new Random(System.currentTimeMillis());
byte[] key = new byte[32];
rng.nextBytes(key);
```

## Remediation

Replace `java.util.Random` and `Math.random()` with `java.security.SecureRandom` for any value that must be unpredictable.

**Generating a secure random token:**

```java
import java.security.SecureRandom;
import java.util.Base64;

// SAFE: SecureRandom backed by the OS CSPRNG (/dev/urandom on Linux)
SecureRandom secureRandom = new SecureRandom();
byte[] tokenBytes = new byte[32]; // 256 bits of entropy
secureRandom.nextBytes(tokenBytes);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
```

**Generating a cryptographic key:**

```java
// SAFE: key material from SecureRandom via KeyGenerator
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256, new SecureRandom());
SecretKey key = kg.generateKey();
```

**Spring Security token (already uses SecureRandom internally):**

```java
// UUID.randomUUID() uses SecureRandom — safe for non-cryptographic tokens
import java.util.UUID;
String token = UUID.randomUUID().toString();

// For CSRF tokens, Spring Security's CsrfTokenRepository uses SecureRandom by default
```

**Reuse a shared instance** — `SecureRandom` is thread-safe and expensive to seed; instantiate once:

```java
// GOOD: shared, thread-safe instance at class level
private static final SecureRandom SECURE_RANDOM = new SecureRandom();

public String generateToken() {
    byte[] bytes = new byte[32];
    SECURE_RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}
```

The secure behavior is **not the default** — Java does not warn when `java.util.Random` is used for security purposes. Developers must explicitly choose `SecureRandom`.

## References

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
- [OWASP Cryptographic Storage Cheat Sheet – Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP ASVS v4.0 – V6.3 Random Values](https://owasp.org/www-project-application-security-verification-standard/)
- [Java SecureRandom documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/SecureRandom.html)
- [NIST SP 800-90A – Recommendation for Random Number Generation Using DRBGs](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
