---
title: "VNX-CRYPTO-009 – Use of Cryptographically Weak PRNG (rand/srand/random in C/C++)"
description: "Detects a value from rand(), random(), the drand48 family, std::rand() or a <random> engine such as std::mt19937 becoming a token, nonce, salt, IV, key, password, session id, CSRF token or OTP in C, C++ and Objective-C code. Ordinary rand() use for sampling, shuffling and jitter is not reported."
---

## Overview

This rule reports a call to a non-cryptographic PRNG (`rand()`, `random()`, `rand_r()`, `drand48()`, `erand48()`, `lrand48()`, `nrand48()`, `mrand48()`, `jrand48()`, `std::rand()`, or a `<random>` engine such as `std::mt19937`, `std::minstd_rand` or `std::default_random_engine`) when its value becomes a security value. That means one of:

- it is assigned to, or `snprintf`'d into, a variable or field named as a token, nonce, salt, IV, secret, password, session id, CSRF token, OTP, PIN, challenge, cookie, ticket or crypto key (`token[i] = ...`, `c->session_id`, `h->nonce`);
- it is assigned to a variable that one of those receives within the next few lines;
- it is produced inside a function or method named for what it makes (`generate_token`, `make_nonce`, `new_otp`, `- (NSString *)generateSessionId`).

Files are C, C++ and Objective-C (`.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, `.m`, `.mm` and similar). Not reported: `rand()` used for sampling, shuffling, jitter, hash seeds, dictionary keys, counts, sizes or timeouts, which is almost every `rand()` call in real code; `srand()`, `srand48()` and `seed48()` on their own; `arc4random()`, `getrandom()`, `RAND_bytes()`, `randombytes_buf()` and `std::random_device`; calls inside comments or string literals; and test files. The rule follows one intermediate variable within a function; longer flows and flows across functions are not followed.

The generators in this family are designed for statistical uniformity in simulations, games, and procedural generation, not for security. Their internal state is small (typically 32–48 bits), their output is predictable given a small number of observed values, and their seeding via `srand(time(NULL))` or similar is trivially guessable. Using these functions to generate session tokens, nonces, password reset codes, cryptographic keys, or any other security-sensitive random value gives an attacker a tractable search space to find the generated value.

**Severity:** High | **CWE:** [CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)

## Why This Matters

The predictability of `rand()` and friends has been demonstrated in numerous real-world attacks. A classic example is the exploitation of PHP's `rand()`-seeded session IDs, where attackers who could determine the server's start time (visible via HTTP response headers) could enumerate all possible session tokens. Similar attacks apply whenever a weak PRNG is used to generate tokens, OTPs, or password reset links.

In C and C++ code, a common vulnerable pattern is: `srand(time(NULL)); token = rand();`. Because `time(NULL)` has one-second granularity and many servers start within a predictable window, the seed space is tiny. An attacker making requests to the system can narrow down the seed within minutes and predict or brute-force the generated tokens. NIST SP 800-90A defines the properties required of a cryptographically secure PRNG, and `rand()` meets none of them.

This vulnerability is particularly dangerous in key generation, nonce generation for cryptographic protocols, anti-CSRF token generation, and session ID generation. Any of these generated with `rand()` can be predicted by an attacker with modest computational resources, potentially bypassing authentication, defeating replay protection, or recovering encrypted messages. This maps to CAPEC-112 (Brute Force) and ATT&CK T1600 (Weaken Encryption).

## What Gets Flagged

```c
// FLAGGED: a reset token built from rand()
for (size_t i = 0; i < 32; i++)
    token[i] = alphabet[rand() % (sizeof(alphabet) - 1)];

// FLAGGED: session fields filled from lrand48()/random()
c->csrf = (unsigned int) lrand48();
snprintf(c->session_id, sizeof(c->session_id), "%08lx%08lx", random(), random());

// FLAGGED: one intermediate variable
long v = nrand48(xsubi);
h->nonce = (uint32_t) v ^ 0x5a5a5a5aU;

// FLAGGED: inside a function named for what it makes
int new_otp(void) {
    int out;
    out = 100000 + rand() % 900000;
    return out;
}
```

```cpp
// FLAGGED: a std::mt19937 engine drawn through a distribution
std::uniform_int_distribution<int> pick(0, 15);
for (int i = 0; i < 32; ++i)
    sessionToken += chars[pick(rng_)];
```

```c
// NOT FLAGGED: sampling, jitter and dictionary keys
int idx = rand() % n;
usleep(1000 + rand() % 500);
char *key = stringFromLongLong(rand() % n);
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
