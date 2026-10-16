---
title: "VNX-PHP-016 – PHP weak hash function (md5/sha1)"
description: "A password is hashed with MD5 or SHA-1, fast unsalted digests that GPUs and rainbow tables reverse in bulk. Reported: md5(), sha1(), hash('md5'|'sha1'|'md4'|'md2', ...) and MD5-crypt (crypt() with a '$1$' salt) when an argument names a password (a variable, property or array key such as $pass, $pass_new, $password, $userPassword, $pwd, $_POST['password'], $input['passwd']) or when the result is assigned to one ($user->password = md5(...), $hashedPassword = sha1(...), 'password' => md5(...)). Not reported: password_hash()/password_verify(), md5/sha1 of non-credential data (cache keys, ETags, checksums, md5_file(), the SHA-1 prefix sent to the Have I Been Pwned range API), hash('sha256', ...) (a fast hash for passwords is still weak but outside this rule), a digest of nothing but a random generator stored under a password name (substr(md5(rand()), 0, 8) generating a temporary password), password-reset tokens, lookalike names such as $bypass, and the call inside a comment or a string literal. A password passed straight into md5()/sha1()/hash('md5'|'sha1', ...) ($pass = md5($pass), md5($_POST['password']), sha1($salt . $password)) is reported by VNX-CRYPTO-007, a password hashed with a fast hash, and not here; this rule keeps the PHP shapes that rule does not read: MD5-crypt, hash('md4'|'md2'), and a digest stored under a password name ($user->password = md5($input['secret']), 'password' => md5(...)). Other MD5/SHA-1 uses are reported by VNX-327, VNX-CRYPTO-001 and VNX-CRYPTO-002."
---

## Overview

This rule detects calls to `md5()` or `sha1()` in code where the surrounding context suggests the value being hashed is a password, credential, or secret. Both MD5 and SHA1 are general-purpose cryptographic hash functions that were never designed for password hashing — they are fast, which is exactly the wrong property for a password hashing algorithm.

Password hashing requires a function that is deliberately slow and includes a salt to prevent precomputation attacks. MD5 and SHA1 are so fast on modern hardware that billions of hashes can be computed per second using commodity GPUs. When an attacker obtains a database of MD5 or SHA1 password hashes, they can crack most common passwords in minutes using rainbow tables or brute-force attacks.

Beyond speed, both algorithms have known cryptographic weaknesses: MD5 has been broken for collision resistance since 2004 and for preimage resistance in certain contexts, and SHA1 is considered weak against collision attacks. Neither should be used for any security-sensitive purpose. The rule reports `md5()`/`sha1()`/`hash('md5'|'sha1', ...)`/MD5-crypt when an argument names a password or the result is stored under a password name.

A password passed straight into the call (`$pass = md5($pass)`, `md5($_POST['password'])`, `sha1($salt . $password)`) is reported by [VNX-CRYPTO-007](vnx-crypto-007), a password hashed with a fast hash, so the line is reported once; this rule keeps the PHP shapes that rule does not read: MD5-crypt (`crypt()` with a `$1$` salt), `hash('md4'|'md2', ...)`, and a digest stored under a password name.

**Severity:** Medium | **CWE:** [CWE-328 – Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)

## Why This Matters

Database breaches that expose password hashes are routine. When those hashes are MD5 or SHA1, the attacker can recover most plaintext passwords quickly. Cracked passwords are then used in credential stuffing attacks against every other service where the user may have reused the same password — email, banking, cloud services. This creates widespread account compromise that extends far beyond the original breach.

Sites like HaveIBeenPwned contain billions of cracked MD5/SHA1 hashes, meaning many passwords are already compromised before an attacker even starts cracking. Unsalted MD5 hashes are particularly vulnerable since identical passwords produce identical hashes, allowing instant lookup.

PHP provides `password_hash()` and `password_verify()` as purpose-built functions that handle salting, algorithm selection, and future cost factor upgrades. There is no legitimate reason to use `md5()` or `sha1()` for passwords in modern PHP code.

## What Gets Flagged

```php
// REPORTED BY VNX-CRYPTO-007: a password passed straight into the digest
$hashedPassword = md5($password);
$pass = md5( $pass );
$h = hash('sha1', $userPassword . $salt);

// FLAGGED: MD5-crypt, and the result stored as a password
$hash = crypt($input, '$1$' . $salt);
$user->password = md5($input['secret']);
return ['password' => md5($input['p'])];
```

Not flagged: `password_hash()`/`password_verify()`, `md5($body)` ETags, `sha1($key)` cache paths, `md5_file()` checksums, the SHA-1 prefix sent to the Have I Been Pwned range API, `hash('sha256', $password)` (a fast hash, but outside this rule), a generated value such as `$tempPassword = substr(md5(rand()), 0, 8)` or a password-reset token, and lookalike names such as `$bypass`.

## Remediation

1. **Use `password_hash($password, PASSWORD_BCRYPT)`** or **`password_hash($password, PASSWORD_ARGON2ID)`** for all password storage.

2. **Use `password_verify($input, $storedHash)`** for authentication — never compare hashes manually or with `==`.

3. **For non-password secrets** (HMAC keys, API tokens, verification tokens), use `hash_hmac('sha256', $data, $key)` or `hash('sha256', $data)`.

4. **Migrate existing MD5/SHA1 password hashes** by re-hashing on next successful login using `password_hash()`, then replacing the old hash.

```php
<?php
// SAFE: password storage with bcrypt
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// SAFE: password verification
if (password_verify($inputPassword, $storedHash)) {
    // authenticated
}

// SAFE: auto-upgrade if algorithm or cost changes
if (password_needs_rehash($storedHash, PASSWORD_BCRYPT, ['cost' => 12])) {
    $newHash = password_hash($inputPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    // persist $newHash
}

// SAFE: HMAC for non-password secrets
$mac = hash_hmac('sha256', $message, $secretKey);
```

## References

- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CAPEC-55: Rainbow Table Password Cracking](https://capec.mitre.org/data/definitions/55.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – password_hash()](https://www.php.net/manual/en/function.password-hash.php)
- [NIST SP 800-63B – Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
