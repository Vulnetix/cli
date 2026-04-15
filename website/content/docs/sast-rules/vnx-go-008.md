---
title: "VNX-GO-008 – Go Weak PRNG for Security"
description: "Detect Go code that imports math/rand for use in security-sensitive contexts such as token generation, password creation, or session ID assignment, where a cryptographically secure PRNG is required."
kind: sast
---

## Overview

This rule flags Go files that import `math/rand`. While `math/rand` is appropriate for non-security uses such as shuffling a playlist or randomizing test data, it is a pseudo-random number generator seeded deterministically and its output sequence can be predicted or reconstructed by an attacker. Any security-sensitive value — session tokens, password reset links, CSRF nonces, API keys, or one-time codes — that is generated with `math/rand` is potentially guessable. This maps to [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html).

**Severity:** Medium | **CWE:** [CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

## Why This Matters

The output of `math/rand` is fully determined by its seed. In Go 1.20 and earlier, `math/rand` defaulted to a constant seed of 1 unless explicitly seeded — meaning the same sequence of numbers appeared in every process that forgot to call `rand.Seed`. Even with a time-based seed, an attacker who can observe a few generated values (or who knows approximately when the process started) can reconstruct the internal state and predict all future outputs. A session token with only 32 bits of effective entropy drawn from `math/rand` can be brute-forced in seconds. Token guessing attacks (MITRE ATT&CK T1110 – Brute Force) targeting predictable session identifiers or password reset tokens are well-documented and actively exploited.

## What Gets Flagged

The rule fires on any `.go` file that imports the `math/rand` package. This is a conservative signal: the import does not by itself confirm that the random values are used for security, but it means the code should be reviewed to confirm `crypto/rand` is used wherever security matters.

```go
// FLAGGED: math/rand imported; values from this package must not be used for security purposes
import (
    "math/rand"
    "fmt"
)

func generateToken() string {
    // This token is predictable — do not use for authentication
    return fmt.Sprintf("%d", rand.Int63())
}
```

## Remediation

1. **Replace `math/rand` with `crypto/rand` for all security-sensitive random values.** The `crypto/rand` package reads from the operating system's cryptographically secure entropy source (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows).

```go
import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
)

// SAFE: cryptographically secure random token
func generateToken() (string, error) {
    b := make([]byte, 32) // 256 bits of entropy
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("failed to generate token: %w", err)
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

2. **Generate secure random integers using `crypto/rand` with `big.Int`.** For cases where you need a random integer in a range:

```go
import (
    "crypto/rand"
    "math/big"
)

// SAFE: cryptographically secure random integer in [0, max)
func secureRandInt(max int64) (int64, error) {
    n, err := rand.Int(rand.Reader, big.NewInt(max))
    if err != nil {
        return 0, err
    }
    return n.Int64(), nil
}
```

3. **Keep `math/rand` only for non-security use cases.** If your codebase legitimately uses `math/rand` for things like test data generation, simulations, or non-security shuffles, ensure those uses are clearly separated from security functions. Add a comment to make the intent explicit and avoid accidental reuse for security purposes.

4. **Audit all token, key, and nonce generation in your codebase.** Search for all call sites that produce values used in authentication, authorization, or cryptographic operations, and confirm each uses `crypto/rand`.

## References

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Go crypto/rand package documentation](https://pkg.go.dev/crypto/rand)
- [Go math/rand package documentation](https://pkg.go.dev/math/rand)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
- [MITRE ATT&CK T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
