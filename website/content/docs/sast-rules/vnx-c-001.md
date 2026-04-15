---
title: "VNX-C-001 – Use of Unbounded String Copy Function (strcpy/strcat/gets)"
description: "Detects calls to strcpy, stpcpy, strcat, gets, wcscpy, wcscat, and related unbounded string copy functions in C and C++ code. These functions copy data without checking the destination buffer size, enabling classic stack and heap buffer overflow attacks."
---

## Overview

This rule flags any call to the family of C string functions that perform copies or concatenations without a length argument: `strcpy`, `stpcpy`, `strcat`, `gets`, `wcscpy`, `wcpcpy`, `wcscat`, `_mbscpy`, `_mbscat`, and equivalent wide-character variants. The check applies to `.c`, `.h`, `.cpp`, `.cc`, and `.cxx` files and excludes lines that begin with a comment marker.

These functions share a fundamental design flaw: they write into the destination buffer until they encounter a null terminator in the source, with no knowledge of how large the destination buffer is. If the source string is longer than the destination buffer, the function writes past the end of the buffer, corrupting adjacent memory. That corrupted memory may contain return addresses, function pointers, security-critical flags, or other sensitive data.

`gets` is the most dangerous of the set: it was entirely removed from the C11 standard (ISO/IEC 9899:2011) precisely because it cannot be used safely under any circumstances — there is no interface to pass a buffer size. All other functions in this family can theoretically be used safely only when the programmer can statically guarantee that the source will always be shorter than the destination, a guarantee that is almost never verifiable when input originates from external sources.

**Severity:** High | **CWE:** [CWE-120](https://cwe.mitre.org/data/definitions/120.html), [CWE-676](https://cwe.mitre.org/data/definitions/676.html), [CWE-787](https://cwe.mitre.org/data/definitions/787.html)

## Why This Matters

Buffer overflows via unbounded string copies are one of the oldest and most well-studied vulnerability classes, yet they continue to appear in real-world disclosures for network daemons, parsers, and embedded systems. Stack-based overflows can overwrite saved return addresses, enabling an attacker to redirect execution to shellcode or a return-oriented programming (ROP) chain. Heap-based overflows can corrupt heap metadata or adjacent allocations, enabling controlled writes to arbitrary memory locations.

The Morris Worm (1988) exploited a `gets`-based overflow in the `fingerd` daemon — this is arguably the first documented case of a buffer overflow being weaponised at scale. Decades later, `strcpy` and `strcat` continue to appear in CVEs. Modern mitigations such as stack canaries (`-fstack-protector-strong`), ASLR, and NX bits raise the bar for exploitation but do not eliminate the risk: attackers with a memory disclosure primitive can bypass all of them. The correct fix is to eliminate the vulnerability at the source by switching to bounded functions.

Real-world examples:

- **CVE-2021-3156 (sudo "Baron Samedit")** — a heap-based buffer overflow triggered by a `sudoedit` invocation that passed unsanitised data through code paths ultimately relying on unchecked string operations, granting any local user root privileges on millions of Linux systems.
- **CVE-2010-2568 (Windows Shell .lnk)** — a `strcpy`-class overflow in Windows Shell parsing of shortcut files, exploited by Stuxnet for initial propagation.

Exploitation of this class maps to ATT&CK T1203 (Exploitation for Client Execution) and CAPEC-100 (Overflow Buffers).

## What Gets Flagged

```c
// FLAGGED: strcpy with user-supplied source, no bounds check
char buf[64];
strcpy(buf, user_input);

// FLAGGED: gets reads from stdin with no limit whatsoever
char line[256];
gets(line);   // gets() removed from C11; cannot be used safely

// FLAGGED: strcat appends without checking remaining space in destination
char result[128] = "Hello, ";
strcat(result, username);

// FLAGGED: wide-character equivalents carry the same risk
wchar_t wbuf[64];
wcscpy(wbuf, wide_input);
```

The rule also catches `stpcpy`, `wcpcpy`, `_mbscpy`, and `_mbscat` because these functions carry the same unbounded-copy behaviour.

## Remediation

**Primary: use bounded replacements and always pass the destination size.**

| Unsafe function | Safe replacement | Notes |
|---|---|---|
| `strcpy(dst, src)` | `strlcpy(dst, src, sizeof(dst))` | BSD/macOS/OpenBSD; available in glibc 2.38+ |
| `strcpy(dst, src)` | `strcpy_s(dst, sizeof(dst), src)` | C11 Annex K; requires `__STDC_LIB_EXT1__` |
| `strcat(dst, src)` | `strlcat(dst, src, sizeof(dst))` | Always pass total destination size |
| `strcat(dst, src)` | `strncat(dst, src, sizeof(dst) - strlen(dst) - 1)` | Error-prone; `strlcat` preferred |
| `gets(buf)` | `fgets(buf, sizeof(buf), stdin)` | Strip trailing newline after call |
| `wcscpy(dst, src)` | `wcsncpy(dst, src, n-1); dst[n-1] = L'\0';` | Or use `wcslcpy` where available |

```c
// SAFE: strlcpy with explicit destination size
char buf[64];
strlcpy(buf, user_input, sizeof(buf));

// SAFE: fgets with buffer size limit; strip the newline
char line[256];
if (fgets(line, sizeof(line), stdin) == NULL) {
    handle_eof_or_error();
}
line[strcspn(line, "\n")] = '\0';

// SAFE: strlcat — pass the total destination buffer size, not remaining space
char result[128] = "Hello, ";
strlcat(result, username, sizeof(result));
```

**Compiler hardening (defence-in-depth — not a substitute for fixing the code):**

```sh
# GCC / Clang: detect unsafe libc calls at compile time and add runtime guards
-Wall -Wextra -Wformat-security
-D_FORTIFY_SOURCE=2          # compile-time and runtime bounds checks on libc calls
-fstack-protector-strong     # stack canary on functions with buffers
-fsanitize=address           # AddressSanitizer: catches overflows at test time
```

`-D_FORTIFY_SOURCE=2` causes GCC/Clang to replace `strcpy`, `memcpy`, and similar calls with fortified variants that detect overflows at runtime when buffer sizes are statically known. It does not protect calls where the destination size is unknown at compile time.

**SEI CERT C rule:** STR31-C — Guarantee that storage for strings has sufficient space for character data and the null terminator.

**OWASP ASVS v4.0:** V5.2.1 — Verify that the application uses memory-safe string, safer memory copy, and pointer arithmetic to detect or prevent stack, buffer, or heap overflows.

## References

- [CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-676: Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [SEI CERT C – STR31-C: Guarantee that storage for strings has sufficient space](https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator)
- [CAPEC-100: Overflow Buffers](https://capec.mitre.org/data/definitions/100.html)
- [OWASP – Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [CodeQL – Potentially unsafe use of strcat](https://codeql.github.com/codeql-query-help/cpp/cpp-unsafe-strcat/)
- [Embedded Application Security Best Practices – Buffer and Stack Overflow Protection](https://scriptingxss.gitbook.io/embedded-appsec-best-practices/1_buffer_and_stack_overflow_protection)
