---
title: "VNX-C-005 – Integer Overflow in malloc/calloc Size Arithmetic"
description: "Detects calls to malloc(), realloc(), valloc(), and aligned_alloc() where the size argument contains arithmetic operations (multiplication or addition) without prior overflow validation, which can produce an undersized allocation and a subsequent heap buffer overflow."
---

## Overview

This rule flags C and C++ source files (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`) where `malloc()`, `valloc()`, `realloc()`, or `aligned_alloc()` is called with a size argument that contains an arithmetic expression involving `+` or `*`. The check excludes commented lines. The concern is that integer arithmetic in C uses the type's natural overflow semantics: if the result wraps around (overflows), the allocator receives a much smaller number than intended and allocates far less memory than the code assumes.

This vulnerability most commonly arises when computing the size of an array of structures: `malloc(count * sizeof(struct foo))`. If `count` is attacker-controlled and large, the multiplication can overflow a `size_t` or `int`, wrapping to a small value. The allocator returns a small buffer, but the code subsequently writes `count` elements into it, overflowing the heap allocation. The same issue applies to `realloc()` calls that grow a buffer based on arithmetic involving incoming data lengths.

**Severity:** High | **CWE:** [CWE-190 – Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)

## Why This Matters

Integer overflow in allocation sizes has been the root cause of significant heap overflows in widely deployed software. The PHP `gdImageCreate` overflow (CVE-2006-4484), various OpenSSL allocation vulnerabilities, and numerous media parsing vulnerabilities follow this exact pattern: a size computed from input data overflows and produces an undersized buffer, followed by a write that extends far past the allocation boundary.

Heap overflows of this type are often directly exploitable for remote code execution. An attacker can control the overflow amount by choosing a specific input size, arrange the heap layout to place a sensitive object after the allocation, and then corrupt it via the overflow. Alternatively, overwriting heap chunk metadata can allow attackers to redirect subsequent `free()` calls into arbitrary memory writes. This is covered by CAPEC-92 (Forced Integer Overflow) and ATT&CK T1203.

The subtlety that makes this vulnerability persistent is that the code looks correct: `malloc(n * sizeof(T))` is idiomatic C. The overflow only occurs with a specific range of large input values, making it easy to miss in testing.

## What Gets Flagged

```c
// FLAGGED: multiplication in malloc size without overflow check
size_t count = get_user_count();
struct Record *records = malloc(count * sizeof(struct Record));

// FLAGGED: addition in malloc size
char *buf = malloc(prefix_len + user_data_len);

// FLAGGED: arithmetic in realloc
buf = realloc(buf, current_size + new_chunk_size);
```

## Remediation

1. For element-count allocations, use `calloc(count, sizeof(T))` — it performs the multiplication internally with overflow checking on most implementations, and also zero-initialises the memory.
2. For other arithmetic, validate that the result does not overflow before calling `malloc`. Check: `if (a > SIZE_MAX - b)` for addition, `if (b != 0 && a > SIZE_MAX / b)` for multiplication.
3. Use helper macros or inline functions that perform checked arithmetic and return an error on overflow.
4. Enable UBSan (`-fsanitize=undefined`) and compile with `-ftrapv` to catch integer overflows at runtime during testing.

```c
// SAFE: calloc performs overflow-safe multiply internally
size_t count = get_user_count();
struct Record *records = calloc(count, sizeof(struct Record));
if (records == NULL) handle_alloc_failure();

// SAFE: explicit overflow check before malloc
size_t total;
if (prefix_len > SIZE_MAX - user_data_len) {
    return ERROR_OVERFLOW;
}
total = prefix_len + user_data_len;
char *buf = malloc(total);

// SAFE: overflow-checked multiplication helper
static inline int checked_mul(size_t a, size_t b, size_t *result) {
    if (b != 0 && a > SIZE_MAX / b) return -1;
    *result = a * b;
    return 0;
}
size_t sz;
if (checked_mul(count, sizeof(struct Record), &sz) != 0) return ERROR_OVERFLOW;
struct Record *records = malloc(sz);
```

## References

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [SEI CERT C Coding Standard – INT30-C: Ensure that unsigned integer operations do not wrap](https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap)
- [OWASP – Integer Overflow](https://owasp.org/www-community/vulnerabilities/Integer_overflow)
- [CAPEC-92: Forced Integer Overflow](https://capec.mitre.org/data/definitions/92.html)
