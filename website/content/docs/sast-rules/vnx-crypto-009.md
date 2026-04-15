---
title: "VNX-CRYPTO-009 – Use of Cryptographically Weak PRNG (rand/srand/random in C/C++)"
description: "Detects use of rand(), srand(), drand48(), lrand48(), and related non-cryptographic pseudo-random number generator functions in C and C++ code where cryptographically secure randomness is required."
---

## Overview

This rule flags calls to `rand()`, `srand()`, `drand48()`, `erand48()`, `lrand48()`, `nrand48()`, `mrand48()`, `jrand48()`, `lcong48()`, `srand48()`, and `seed48()` in C and C++ source files (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`). These functions, defined in `<stdlib.h>`, implement linear congruential or similar simple pseudo-random number generators that are not designed for cryptographic use. Commented-out lines are excluded.

The generators in this family are designed for statistical uniformity in simulations, games, and procedural generation — not for security. Their internal state is small (typically 32–48 bits), their output is predictable given a small number of observed values, and their seeding via `srand(time(NULL))` or similar is trivially guessable. Using these functions to generate session tokens, nonces, password reset codes, cryptographic keys, or any other security-sensitive random value gives an attacker a tractable search space to find the generated value.

**Severity:** High | **CWE:** [CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)

## Why This Matters

The predictability of `rand()` and friends has been demonstrated in numerous real-world attacks. A classic example is the exploitation of PHP's `rand()`-seeded session IDs, where attackers who could determine the server's start time (visible via HTTP response headers) could enumerate all possible session tokens. Similar attacks apply whenever a weak PRNG is used to generate tokens, OTPs, or password reset links.

In C and C++ code, a common vulnerable pattern is: `srand(time(NULL)); token = rand();`. Because `time(NULL)` has one-second granularity and many servers start within a predictable window, the seed space is tiny. An attacker making requests to the system can narrow down the seed within minutes and predict or brute-force the generated tokens. NIST SP 800-90A defines the properties required of a cryptographically secure PRNG, and `rand()` meets none of them.

This vulnerability is particularly dangerous in key generation, nonce generation for cryptographic protocols, anti-CSRF token generation, and session ID generation. Any of these generated with `rand()` can be predicted by an attacker with modest computational resources, potentially bypassing authentication, defeating replay protection, or recovering encrypted messages. This maps to CAPEC-112 (Brute Force) and ATT&CK T1600 (Weaken Encryption).

## What Gets Flagged

```c
// FLAGGED: rand() seeded with time, used for session token
srand(time(NULL));
unsigned int token = rand();

// FLAGGED: drand48 used for key material generation
double key_component = drand48();

// FLAGGED: lrand48 used for nonce
long nonce = lrand48();
```

## Remediation

1. Use `getrandom()` (Linux 3.17+) or read from `/dev/urandom` to obtain cryptographically secure random bytes.
2. Use libsodium's `randombytes_buf()` for a portable, secure, and easy-to-use CSPRNG.
3. On platforms with OpenSSL, use `RAND_bytes()` or `RAND_priv_bytes()` (OpenSSL 1.1.1+).
4. Reserve `rand()` and `drand48()` strictly for non-security purposes such as statistical simulations, test data generation, and games.

```c
#include <sys/random.h>

// SAFE: getrandom() fills buffer with cryptographically secure random bytes
unsigned char token[32];
if (getrandom(token, sizeof(token), 0) != sizeof(token)) {
    handle_error();
}

// SAFE: reading /dev/urandom
#include <fcntl.h>
#include <unistd.h>
unsigned char nonce[16];
int fd = open("/dev/urandom", O_RDONLY);
if (fd < 0 || read(fd, nonce, sizeof(nonce)) != sizeof(nonce)) {
    handle_error();
}
close(fd);

// SAFE: libsodium portable CSPRNG
#include <sodium.h>
unsigned char key[32];
randombytes_buf(key, sizeof(key));
```

## References

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP – Cryptographic Storage Cheat Sheet – Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-90A – Recommendation for Random Number Generation Using Deterministic Random Bit Generators](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [libsodium – Generating Random Data](https://doc.libsodium.org/generating_random_data)
- [Linux man page: getrandom(2)](https://man7.org/linux/man-pages/man2/getrandom.2.html)
