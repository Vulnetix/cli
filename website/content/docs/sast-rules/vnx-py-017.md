---
title: "VNX-PY-017 – MD5 or SHA1 Used as Password Hash"
description: "Detect Python code that uses hashlib.md5() or hashlib.sha1() to hash passwords — both algorithms are cryptographically broken and unsuitable for password storage."
---

## Overview

This rule detects Python code that uses `hashlib.md5()`, `hashlib.sha1()`, or `hashlib.new("md5"/"sha1")` to hash passwords. MD5 and SHA-1 were designed as fast message-digest functions for data integrity, not password storage. Because they are optimized for speed, modern GPU hardware can compute billions of MD5 or SHA-1 hashes per second, making brute-force and rainbow-table attacks trivially fast against any password database protected with these algorithms.

Both MD5 and SHA-1 have well-documented cryptographic weaknesses beyond raw speed: MD5 has known collision attacks since 2004, and SHA-1 was officially broken by the SHAttered attack in 2017. Even without these structural weaknesses, the fundamental problem remains: a general-purpose hash is the wrong tool for passwords. Password hashing requires an algorithm that is deliberately slow and memory-hard to resist offline cracking.

The correct choice is a purpose-built password hashing function such as `hashlib.scrypt()` (available in the standard library since Python 3.6), `bcrypt` (via the `bcrypt` package), or `argon2-cffi` (Argon2id, the winner of the Password Hashing Competition). These functions incorporate salt automatically, are designed to be tunable in cost, and remain computationally expensive even on modern hardware.

**Severity:** High | **CWE:** [CWE-327 – Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Why This Matters

A real-world data breach scenario: an attacker exploits a SQL injection vulnerability and dumps the `users` table. If passwords are stored as unsalted MD5 hashes, the attacker can crack the entire dataset within hours using freely available tools like Hashcat with a consumer GPU. Crackstation's public lookup table alone covers billions of common passwords in MD5 format. Even salted MD5 can be cracked at billions of guesses per second with modern hardware.

The consequences compound quickly. Users reuse passwords across services, so cracked passwords from your breach become credential-stuffing ammunition against banking, email, and other high-value targets. Regulatory frameworks including GDPR, PCI DSS, and NIST SP 800-63B explicitly prohibit the use of MD5 and SHA-1 for password storage.

The attack requires no network access after the initial breach. An offline attacker with the hash database can work indefinitely without triggering any alerts, rate limits, or account lockout policies.

## What Gets Flagged

```python
import hashlib

# FLAGGED: MD5 used as password hash
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# FLAGGED: SHA1 used as password hash
def store_password(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()

# FLAGGED: hashlib.new() with md5
def create_hash(password: str) -> str:
    h = hashlib.new("md5")
    h.update(password.encode())
    return h.hexdigest()

# FLAGGED: hashlib.new() with sha1
def legacy_hash(password: str) -> str:
    h = hashlib.new("SHA1")
    h.update(password.encode())
    return h.hexdigest()
```

The rule applies only to `.py` files.

## Remediation

1. Replace `hashlib.md5()` / `hashlib.sha1()` with a purpose-built password hashing function.
2. When migrating an existing system, use a rehash-on-login strategy: verify the old hash for existing users, then store the new hash on successful login.
3. Tune cost parameters so that hashing takes at least 100–300 ms on your production hardware; increase the parameters periodically as hardware improves.

```python
import hashlib
import os
import bcrypt
from argon2 import PasswordHasher

# SAFE: hashlib.scrypt (stdlib, Python 3.6+)
def hash_password_scrypt(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,   # CPU/memory cost factor
        r=8,
        p=1,
        dklen=32,
    )
    # Store salt + derived key together
    return salt.hex() + ":" + dk.hex()

def verify_scrypt(password: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return dk.hex() == dk_hex

# SAFE: bcrypt (pip install bcrypt)
def hash_password_bcrypt(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_bcrypt(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# SAFE: Argon2id (pip install argon2-cffi) — recommended
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

def hash_password_argon2(password: str) -> str:
    return ph.hash(password)

def verify_argon2(password: str, hashed: str) -> bool:
    return ph.verify(hashed, password)
```

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Python Security Project](https://owasp.org/www-project-python-security/)
- [Python hashlib.scrypt() Documentation](https://docs.python.org/3/library/hashlib.html#hashlib.scrypt)
- [argon2-cffi Documentation](https://argon2-cffi.readthedocs.io/en/stable/)
- [NIST SP 800-63B – Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [SHAttered: SHA-1 Collision Attack](https://shattered.io/)
