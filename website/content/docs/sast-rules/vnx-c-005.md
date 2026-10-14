---
title: "VNX-C-005 – Integer Overflow in malloc/calloc Size Arithmetic"
description: "Reports a C or C++ allocation (malloc, realloc, calloc, aligned_alloc and common wrappers) whose size multiplies or adds a count parsed or received in the 30 lines above (atoi/strtol family, ntohl, getenv, scanf/fread/read/recv out-arguments) with no overflow check. Checked or clamped counts, 8- and 16-bit counts, plain calloc(n, size), and sizes from constants or internal lengths are not reported."
---

## Overview

This rule reports a C or C++ allocation whose size can wrap: `malloc`, `xmalloc`, `g_malloc`, `kmalloc`, `kzalloc`, `valloc`, `realloc`, `xrealloc`, `g_realloc`, `calloc`, `aligned_alloc` or `memalign` (including `std::` forms) whose size, or the variable it was computed into a few lines above, combines with `*` or `+` a count that came from outside the program in the 30 lines above: a value parsed by `atoi`/`strtol`/`strtoul` and friends or `std::stoi`, converted by `ntohl`/`be32toh`, read from `getenv`, or filled through an `&out` argument of `scanf`/`fscanf`/`sscanf`/`fread`/`read`/`recv`. A parse call written directly in the size is reported too. When the product or sum wraps, the allocator returns a buffer smaller than the code that fills it assumes. The rule does not report a count compared with `<`/`>` or checked against `SIZE_MAX`, `__builtin_mul_overflow` or `ckd_mul` (or reassigned) before the allocation, an 8- or 16-bit count (promoted before the arithmetic), `calloc(n, size)` with plain arguments, `reallocarray`, and sizes made from constants, `sizeof` or internal lengths such as `strlen(s) + 1`. Counts that arrive through struct fields, parameters or other files are out of scope.

This vulnerability most commonly arises when computing the size of an array of structures: `malloc(count * sizeof(struct foo))`. If `count` is attacker-controlled and large, the multiplication can overflow a `size_t` or `int`, wrapping to a small value. The allocator returns a small buffer, but the code subsequently writes `count` elements into it, overflowing the heap allocation. The same issue applies to `realloc()` calls that grow a buffer based on arithmetic involving incoming data lengths.

**Severity:** High | **CWE:** [CWE-190 – Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)

## Why This Matters

Integer overflow in allocation sizes has been the root cause of significant heap overflows in widely deployed software. The PHP `gdImageCreate` overflow (CVE-2006-4484), various OpenSSL allocation vulnerabilities, and numerous media parsing vulnerabilities follow this exact pattern: a size computed from input data overflows and produces an undersized buffer, followed by a write that extends far past the allocation boundary.

Heap overflows of this type are often directly exploitable for remote code execution. An attacker can control the overflow amount by choosing a specific input size, arrange the heap layout to place a sensitive object after the allocation, and then corrupt it via the overflow. Alternatively, overwriting heap chunk metadata can allow attackers to redirect subsequent `free()` calls into arbitrary memory writes. This is covered by CAPEC-92 (Forced Integer Overflow) and ATT&CK T1203.

The subtlety that makes this vulnerability persistent is that the code looks correct: `malloc(n * sizeof(T))` is idiomatic C. The overflow only occurs with a specific range of large input values, making it easy to miss in testing.

## What Gets Flagged

```c
// FLAGGED: record count from the wire multiplied by the element size
uint32_t count = ntohl(*(const uint32_t *)pkt);
struct record *recs = malloc(count * sizeof(struct record));

// FLAGGED: 32-bit length + 1 wraps to 0
uint32_t len = ntohl(*(const uint32_t *)pkt);
char *name = malloc(len + 1);

// FLAGGED: size computed into a variable first
int width = atoi(argv[1]);
int height = atoi(argv[2]);
size_t bytes = width * height * sizeof(int);
int *cells = malloc(bytes);

// FLAGGED: count filled by fread, then realloc
if (fread(&extra, sizeof extra, 1, f) != 1)
    return -1;
v->items = realloc(v->items, (v->len + extra) * sizeof(double));
```

Not flagged: `if (count > SIZE_MAX / sizeof(struct item)) return NULL;` before the `malloc`, `calloc(n, sizeof(long))`, `malloc(SLOTS * sizeof(struct slot))`, `malloc(strlen(s) + 1)` and a `uint16_t` length read with `ntohs`.

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
