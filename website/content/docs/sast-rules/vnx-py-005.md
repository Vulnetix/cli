---
title: "VNX-PY-005 – Weak PRNG for Security Operations"
description: "Detect values from Python's random module assigned to, passed as or returned from security-named values (passwords, tokens, nonces, salts, OTPs, session ids), where the secrets module is required."
---

## Overview

This rule flags calls to functions from Python's `random` module (`random.randint`, `random.choice`, `random.random`, `random.uniform`, `random.randrange`) when the value they produce is stored in, passed as, or returned from something named as a secret (`password`, `token`, `secret`, `nonce`, `salt`, `otp`, `session_id` and similar). The `random` module uses the Mersenne Twister algorithm (MT19937), which is a high-quality statistical PRNG but is explicitly documented as not suitable for security purposes. An attacker who observes enough outputs from a Mersenne Twister can reconstruct its internal 624-integer state and predict all future outputs. This maps to [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html).

**Severity:** Medium | **CWE:** [CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)

## Why This Matters

The Mersenne Twister's internal state is fully determinable from 624 consecutive 32-bit outputs — roughly 2.5 KB of observed random data. In a web application context an attacker can collect this data by making requests that return `random`-derived values (session IDs, CSRF tokens, password reset tokens, verification codes). Once the state is known, every future and past value from the same instance is predictable, breaking authentication, CSRF protection, and password reset flows simultaneously.

For a concrete example: if a password reset token is generated with `''.join(random.choices(string.ascii_letters, k=32))`, an attacker who can observe other `random`-derived outputs from the same process can predict the reset token for any account without ever having access to the target's email. The attack requires no elevated privilege — only the ability to observe enough application outputs.

## What Gets Flagged

The rule fires on a `random` module call (through the module, an `import random as r` alias or a name imported with `from random import randint`) whose result is assigned to, passed as a keyword to, or stored under a dict key with a security name (password, token, secret, nonce, salt, otp, session id, api key, csrf, reset/verification code, pin), or that is returned or assigned inside a function with such a name.

Not flagged: `secrets`, `random.SystemRandom()`, numpy's random module, random values with no security name (sampling, colours, shuffling), jitter such as `time.sleep(random.uniform(0, 1))` inside a token function, test files, and mentions in comments or strings.

```python
# FLAGGED: weak token generation
import random
import string

def generate_session_token():
    # random.choices is Mersenne Twister — predictable
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# FLAGGED: weak password generation
def generate_temp_password():
    return ''.join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))

# FLAGGED: weak salt generation
def make_salt():
    return str(random.randint(100000, 999999))

# FLAGGED: weak OTP
otp = str(random.randint(0, 999999)).zfill(6)
```

## Remediation

1. **Use `secrets.token_urlsafe()` for URL-safe tokens.** This generates a cryptographically random token using the OS's CSPRNG (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows) and encodes it as base64url. The `nbytes` argument controls entropy — 32 bytes gives 256 bits.

```python
import secrets

# SAFE: 256-bit cryptographically random URL-safe token
session_token = secrets.token_urlsafe(32)

# SAFE: hex-encoded random token
reset_token = secrets.token_hex(32)
```

2. **Use `secrets.randbelow()` for integer ranges.**

```python
import secrets

# SAFE: cryptographically secure integer in [0, 1000000)
otp = secrets.randbelow(1_000_000)
otp_str = str(otp).zfill(6)
```

3. **Use `secrets.choice()` for sampling from a sequence.**

```python
import secrets
import string

alphabet = string.ascii_letters + string.digits + string.punctuation

# SAFE: cryptographically secure character selection
password = ''.join(secrets.choice(alphabet) for _ in range(20))
```

4. **Use `os.urandom()` for raw bytes when you need a byte string directly.**

```python
import os
import hashlib

# SAFE: 32 bytes of OS CSPRNG output
salt = os.urandom(32)
# Then hash: hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
```

5. **Audit `import random` globally.** Remove the `random` module import from any module that handles authentication, sessions, CSRF, or key material. Having the import present makes it easy to accidentally call the wrong function.

## References

- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Python docs – secrets module](https://docs.python.org/3/library/secrets.html)
- [Python docs – random module (security note)](https://docs.python.org/3/library/random.html#notes-on-reproducibility)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
