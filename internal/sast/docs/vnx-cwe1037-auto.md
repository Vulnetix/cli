---
title: "VNX-1037 – Processor Optimization Removal of Security-critical Code"
description: "Reports C and C++ secrets wiped with memset, bzero or ZeroMemory just before the memory is freed or goes out of scope, a dead store the optimizer may delete."
---

## Overview

VNX-1037 covers [CWE-1037: Processor Optimization Removal or Modification of Security-critical Code](https://cwe.mitre.org/data/definitions/1037.html). Processor-level removal (speculative execution) has no line-level signature, so this rule reports the concrete optimizer case: a compiler's dead-store elimination of a buffer clear ([CWE-14](https://cwe.mitre.org/data/definitions/14.html)).

What is reported, in C and C++:

- A zeroing call (`memset`/`std::memset` with fill value `0`, `'\0'` or `0x00`, `bzero`, `ZeroMemory` or `RtlZeroMemory`).
- Whose buffer is named as a secret: key, password, passwd, passphrase, pwd, pin, otp, secret, seed, token, cred/credential, plaintext or master, including camelCase and prefixes such as `szPassword` or `session_key`.
- Whose next statements, before any read of the buffer, free it (`free`, `OPENSSL_free`, `g_free`, `kfree`, `HeapFree`, `LocalFree`, `delete` ...) or, for a local array, struct or `std::array` declared in the function, return or close its scope.

Not reported: `explicit_bzero`, `memset_s`, `SecureZeroMemory`, `RtlSecureZeroMemory`, `OPENSSL_cleanse`, `sodium_memzero` and other guaranteed wipes; a clear followed by a read of the buffer or by a compiler barrier that names it (initialisation, `asm volatile`); a clear of caller-owned memory (a pointer parameter or a struct member that outlives the function); buffers not named as secrets; non-zero fill patterns; test code, comments and strings.

**Severity:** Medium | **CWE:** [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html), [CWE-14](https://cwe.mitre.org/data/definitions/14.html)

## Why This Matters

The C and C++ standards let a compiler delete a store that nothing reads afterwards. A `memset(password, 0, sizeof password)` right before `free(password)` or the end of the function is exactly such a store, and GCC, Clang and MSVC remove it at ordinary optimisation levels. The source code says the secret was wiped, but the binary leaves it in freed heap or on the stack, where a later allocation, a core dump, a swap file or a memory-disclosure bug can read it.

## What Gets Flagged

```c
char password[64];
read_password(password, sizeof password);
check(password);
memset(password, 0, sizeof(password));       /* FLAGGED: dead store before return */
return ok;
```

```c
unsigned char derived_key[32];
pbkdf2(pin, derived_key, sizeof derived_key);
unlock_store(derived_key);
memset(derived_key, 0x00, sizeof derived_key);   /* FLAGGED: local array leaves scope */
}
```

```cpp
std::memset(master_key.data(), 0, master_key.size());   // FLAGGED: std::array leaves scope
}
```

## What Is Not Flagged

```c
explicit_bzero(password, sizeof password);
OPENSSL_cleanse(key, key_len);
SecureZeroMemory(szPassword, sizeof szPassword);
```

## Remediation

1. Use a wipe the compiler must keep: `explicit_bzero` (glibc, BSD), `memset_s` (C11 Annex K), `SecureZeroMemory`/`RtlSecureZeroMemory` (Windows), `OPENSSL_cleanse` or `sodium_memzero`.
2. In C++, wrap secrets in a type whose destructor calls one of those functions.
3. If none is available, write through a `volatile` function pointer to `memset`, or follow the clear with a compiler barrier that names the buffer.

## References

- [CWE-1037: Processor Optimization Removal or Modification of Security-critical Code](https://cwe.mitre.org/data/definitions/1037.html)
- [CWE-14: Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)
- [SEI CERT MSC06-C: Beware of compiler optimizations](https://wiki.sei.cmu.edu/confluence/display/c/MSC06-C.+Beware+of+compiler+optimizations)
