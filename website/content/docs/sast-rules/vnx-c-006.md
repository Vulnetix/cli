---
title: "VNX-C-006 – Use of alloca() for Dynamic Stack Allocation"
description: "Detects calls to alloca() in C and C++ code, which allocates memory on the stack based on a runtime-determined size with no bounds checking, enabling stack overflow or stack frame corruption when the size is large or attacker-controlled."
---

## Overview

This rule flags any call to `alloca()` in C and C++ source files (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`). Unlike `malloc()` which allocates from the heap with a well-defined failure mode (returning `NULL`), `alloca()` allocates directly from the stack frame of the calling function by adjusting the stack pointer. No bounds checking occurs, there is no failure return value, and stack space is not unlimited. Commented-out lines are excluded from detection.

The core problem is that `alloca()` provides no way to detect or handle exhaustion of available stack space. If the requested size is large — whether due to a logic error, a large input, or attacker manipulation — the function silently adjusts the stack pointer past the end of the available stack, overwriting memory below the stack in process (typically memory belonging to other stack frames, signal handlers, or the kernel guard page). This either causes a crash or — in the absence of guard pages — corrupts adjacent stack data including return addresses and saved registers.

**Severity:** High | **CWE:** [CWE-676 – Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)

## Why This Matters

`alloca()` failures are silent and do not propagate as errors; code that calls `alloca()` and then uses the returned pointer has no way to detect that the allocation exceeded the available stack space. This is fundamentally different from `malloc()` which returns `NULL` on failure and allows the programmer to handle the error gracefully.

When the size passed to `alloca()` comes from external input — a packet length field, a user-provided count, or a value read from a file — an attacker can supply a size large enough to overflow the stack. Stack overflows can corrupt the return address of the current function or of a calling function, enabling classic stack smashing attacks. On systems without guard pages between stack frames (embedded systems, some kernels), the corruption may extend into other thread stacks or process memory.

Even without explicit attacker control, `alloca()` is dangerous when called inside loops (stack usage grows with each iteration until function return) or in functions that are themselves called recursively. A deep call tree with `alloca()` at each level can exhaust the stack even with modest per-call sizes. This is CWE-1325 (Improperly Controlled Sequential Memory Allocation) as well as CWE-676.

## What Gets Flagged

```c
// FLAGGED: alloca with user-supplied size, no bounds check possible
void process_packet(size_t pkt_len) {
    char *buf = alloca(pkt_len);  // stack overflow if pkt_len is large
    read_packet(buf, pkt_len);
    handle(buf);
}

// FLAGGED: alloca inside a loop (stack not reclaimed between iterations)
for (int i = 0; i < count; i++) {
    char *tmp = alloca(item_size);
    process(tmp, item_size);
}
```

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
