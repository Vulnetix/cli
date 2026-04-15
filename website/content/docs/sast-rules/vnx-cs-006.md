---
title: "VNX-CS-006 – C# Insecure Random Number Generator (System.Random for Security)"
description: "Detects use of System.Random in security-sensitive contexts such as token, password, key, nonce, salt, or session generation, where a cryptographically secure random number generator is required."
---

## Overview

This rule detects two patterns in C# code: `new Random()` or `Random x = new Random()` used within a code block that contains security-sensitive keywords (password, token, secret, key, nonce, salt, session, CSRF), and any call to `Random.NextBytes()` — both indicators that `System.Random` is being used where a cryptographically secure generator is required.

`System.Random` is a pseudo-random number generator (PRNG) seeded from a time-based value. It is designed for statistical simulations, games, and non-security use cases that need fast, repeatable sequences. It is not designed to be unpredictable. Its output can be predicted from a small number of observed values, and because its default seed is derived from the current timestamp, an attacker who knows approximately when the value was generated can brute-force the seed and reproduce the entire output sequence.

`System.Security.Cryptography.RandomNumberGenerator` (and its convenience method `RandomNumberGenerator.GetBytes()`) uses the operating system's cryptographically secure entropy source (CryptGenRandom on Windows, getrandom/urandom on Linux/macOS) and produces output that is computationally indistinguishable from true randomness.

**Severity:** High | **CWE:** [CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

## Why This Matters

Predictable random numbers in security contexts lead directly to authentication and confidentiality failures. If password reset tokens, session identifiers, CSRF tokens, or encryption key material are generated with `System.Random`, an attacker who can observe or guess the approximate generation timestamp can reproduce the sequence and predict valid tokens or keys. This has been exploited against real applications: PHP's `rand()`, Java's `java.util.Random`, and .NET's `System.Random` have all been targeted in disclosed vulnerabilities.

A concrete attack scenario: a web application generates a password reset token using `new Random(Environment.TickCount).Next()`. An attacker requests a password reset, notes the approximate time, and tries all seeds within a 10-second window — roughly 10,000 candidates. Each seed produces at most a small number of plausible tokens, making the search space trivially small for an automated attack.

`Random.NextBytes()` is particularly dangerous when used to fill key buffers or initialisation vectors, because cryptographic key material with low entropy is vulnerable to exhaustive key search even when the encryption algorithm itself is strong.

## What Gets Flagged

```csharp
// FLAGGED: System.Random used near password/token handling
var rng = new Random();
string token = rng.Next(100000, 999999).ToString();
// ... token used as password reset code

// FLAGGED: NextBytes() called to fill key material
var keyBytes = new byte[32];
new Random().NextBytes(keyBytes);    // FLAGGED: not cryptographically secure
var aes = Aes.Create();
aes.Key = keyBytes;
```

## Remediation

1. Replace all security-sensitive random number generation with `System.Security.Cryptography.RandomNumberGenerator.GetBytes()` (static method available since .NET 6) or `using var rng = RandomNumberGenerator.Create()` for older targets.
2. For generating random integers within a range, use `RandomNumberGenerator.GetInt32(fromInclusive, toExclusive)` (.NET 6+) rather than scaling byte output manually.
3. For token generation, prefer `Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))` to produce a URL-safe 256-bit token.
4. Reserve `System.Random` strictly for non-security use cases: unit test data, simulations, random sampling for analytics.

```csharp
// SAFE: cryptographically secure token generation
byte[] tokenBytes = RandomNumberGenerator.GetBytes(32);
string resetToken = Convert.ToBase64String(tokenBytes);

// SAFE: secure AES key generation
using var aes = Aes.Create();
aes.GenerateKey();    // key filled from OS entropy source

// SAFE: secure random integer in a range (.NET 6+)
int otp = RandomNumberGenerator.GetInt32(100000, 1000000);
```

## References

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [Microsoft Docs: RandomNumberGenerator class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
