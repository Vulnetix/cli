---
title: "VNX-C-006 – Use of alloca() for Dynamic Stack Allocation"
description: "Reports C, C++ and Objective-C stack allocations with an unbounded run-time size: alloca, _alloca and __builtin_alloca whose size names a variable or call, strdupa of a non-literal, and variable-length arrays sized by strlen() or by a count parsed or received just above. Constant sizes, sizes compared or clamped first, _malloca, declarations, macros and comments are not reported."
---

## Overview

This rule reports a stack allocation whose size is decided at run time without a bound: `alloca()`, `_alloca()` and `__builtin_alloca()` whose size names a variable, member or call (`alloca(len)`, `alloca(strlen(a) + strlen(b) + 2)`, `alloca(n * sizeof(T))`), `strdupa()` of a non-literal string, and a variable-length array whose size uses `strlen()` or a count parsed or received in the 30 lines above (`atoi`/`strtol`, `ntohl`, `getenv`, an `&out` of `scanf`/`fread`/`read`/`recv`). It does not report sizes built only from literals, upper-case macros and `sizeof`, a size compared with `<`/`>` in the 15 lines above or in a ternary on the same line (`n < 256 ? alloca(n) : malloc(n)`), a `MIN()` clamp, `_malloca` (which falls back to the heap), `strndupa`, other functions whose names contain `alloca`, declarations, `#define` macros, VLAs sized by a plain parameter, string literals and comments. Unlike `malloc()`, `alloca()` has no failure return: an oversized request moves the stack pointer past the guard page into whatever memory lies beyond.

The core problem is that `alloca()` provides no way to detect or handle exhaustion of available stack space. If the requested size is large — whether due to a logic error, a large input, or attacker manipulation — the function silently adjusts the stack pointer past the end of the available stack, overwriting memory below the stack in process (typically memory belonging to other stack frames, signal handlers, or the kernel guard page). This either causes a crash or — in the absence of guard pages — corrupts adjacent stack data including return addresses and saved registers.

**Severity:** High | **CWE:** [CWE-676 – Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)

## Why This Matters

`alloca()` failures are silent and do not propagate as errors; code that calls `alloca()` and then uses the returned pointer has no way to detect that the allocation exceeded the available stack space. This is fundamentally different from `malloc()` which returns `NULL` on failure and allows the programmer to handle the error gracefully.

When the size passed to `alloca()` comes from external input — a packet length field, a user-provided count, or a value read from a file — an attacker can supply a size large enough to overflow the stack. Stack overflows can corrupt the return address of the current function or of a calling function, enabling classic stack smashing attacks. On systems without guard pages between stack frames (embedded systems, some kernels), the corruption may extend into other thread stacks or process memory.

Even without explicit attacker control, `alloca()` is dangerous when called inside loops (stack usage grows with each iteration until function return) or in functions that are themselves called recursively. A deep call tree with `alloca()` at each level can exhaust the stack even with modest per-call sizes. This is CWE-1325 (Improperly Controlled Sequential Memory Allocation) as well as CWE-676.

## What Gets Flagged

```c
// FLAGGED: size from the lengths of caller strings
char *path = alloca(strlen(root) + strlen(name) + 2);

// FLAGGED: length from the wire
uint32_t len = ntohl(*(const uint32_t *)pkt);
uint8_t *copy = alloca(len);

// FLAGGED: strdupa copies a string of any length onto the stack
char *work = strdupa(input);

// FLAGGED: variable-length arrays sized by input
int count = atoi(argv[1]);
int values[count];
char copy[strlen(name) + 1];
```

```cpp
// FLAGGED: C++ and MSVC spellings
char *scratch = static_cast<char *>(__builtin_alloca(title.size() + 1));
wchar_t *buf = (wchar_t *)_alloca(chars * sizeof(wchar_t));
```

Not flagged: `alloca(sizeof(struct hdr))`, `alloca(FRAME_BYTES)`, `if (n > STACK_LIMIT) return NULL;` before `alloca(n)`, `len < 256 ? alloca(len) : malloc(len)` and `_malloca(n)`.

## Remediation

1. Replace `alloca()` with `malloc()` or `calloc()` with explicit size validation before the allocation.
2. Validate the size against a reasonable maximum before allocating, regardless of whether you use stack or heap allocation.
3. For small, fixed upper bounds, use a fixed-size stack array instead: `char buf[MAX_BUF_SIZE]`.
4. If performance is a concern and you know the size at compile time, use a VLA (variable-length array) only with a compile-time constant or a carefully validated maximum — and be aware that VLAs have the same stack overflow risk as `alloca()` and are optional in C11 and later.

```c
// SAFE: malloc with size validation and NULL check
void process_packet(size_t pkt_len) {
    if (pkt_len == 0 || pkt_len > MAX_PACKET_SIZE) {
        return handle_error(ERR_INVALID_SIZE);
    }
    char *buf = malloc(pkt_len);
    if (buf == NULL) {
        return handle_error(ERR_ALLOC);
    }
    read_packet(buf, pkt_len);
    handle(buf);
    free(buf);
}

// SAFE: fixed-size stack buffer with explicit size limit
void process_name(const char *input) {
    char buf[MAX_NAME_LEN + 1];
    strlcpy(buf, input, sizeof(buf));
    use_name(buf);
}
```

## References

- [CWE-676: Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
- [CWE-1325: Improperly Controlled Sequential Memory Allocation](https://cwe.mitre.org/data/definitions/1325.html)
- [SEI CERT C Coding Standard – MEM05-C: Avoid large stack allocations](https://wiki.sei.cmu.edu/confluence/display/c/MEM05-C.+Avoid+large+stack+allocations)
- [OWASP – Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [CAPEC-100: Overflow Buffers](https://capec.mitre.org/data/definitions/100.html)
