---
title: "VNX-C-004 – Use-After-Free: Pointer Used After free()"
description: "Detects patterns where a pointer is freed with free() and then referenced on the immediately following non-blank, non-comment line without being reassigned to NULL or a new allocation, indicating a use-after-free bug."
---

## Overview

This rule detects a common use-after-free pattern in C and C++ files (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`) by looking for a `free(ptr)` call on one line immediately followed by a reference to the same identifier on the next non-comment line, where the next line does not reassign the pointer and does not call `free()` on it again. The check is a windowed two-line pattern; it catches the most common case of a pointer being used directly after being freed.

Use-after-free occurs when a program frees a heap-allocated object and then accesses memory through the now-dangling pointer. After `free()` returns the memory to the allocator, the contents of that memory are undefined — the allocator may have modified them, a subsequent allocation may have reused the memory with different contents, or the memory may have been returned to the OS. Reading through a freed pointer yields unpredictable or attacker-influenced data; writing through one corrupts the heap.

**Severity:** High | **CWE:** [CWE-416 – Use After Free](https://cwe.mitre.org/data/definitions/416.html)

## Why This Matters

Use-after-free vulnerabilities are among the most exploited memory safety bugs in modern software. Chrome, Firefox, the Linux kernel, and countless other production systems have had critical use-after-free CVEs. The reason they are so exploitable is that an attacker who can trigger a specific allocation between the `free()` and the subsequent access can control the contents of the freed memory — by allocating an object of their choice in the same heap slot — and influence the behaviour of the use through carefully crafted data.

In browsers and language runtimes, use-after-free bugs are routinely turned into arbitrary code execution by heap spraying: filling memory with attacker-controlled data so that when the freed pointer is dereferenced, it reads attacker data. In server applications, a use-after-free in a parsing or protocol handling code path can be triggered remotely, turning a memory safety bug into remote code execution. This is covered by ATT&CK T1203 and CAPEC-123.

The pattern is also a common source of security-relevant logic bugs even when not directly exploitable for code execution: reading freed memory can return credentials, session tokens, or other sensitive data that a previous allocation stored in that memory region.

## What Gets Flagged

```c
// FLAGGED: buffer freed then used on the next line
free(buffer);
memcpy(dest, buffer, len);   // use-after-free

// FLAGGED: node freed then field accessed
free(node);
next = node->next;           // use-after-free

// FLAGGED: pointer freed then passed to function
free(ctx);
crypto_finish(ctx);          // use-after-free
```

## Remediation

1. Set the pointer to `NULL` immediately after every `free()` call: `free(ptr); ptr = NULL;`.
2. Before dereferencing a pointer, check that it is not `NULL`.
3. Adopt ownership conventions: once a pointer is freed, its variable goes out of scope, is reassigned, or is set to `NULL` — never left pointing at freed memory.
4. Use static analysis tools (Valgrind, AddressSanitizer, HeapTrack) in development and testing to catch use-after-free bugs at runtime.
5. Consider moving to C++ with RAII, smart pointers (`std::unique_ptr`, `std::shared_ptr`), or to a memory-safe language.

```c
// SAFE: pointer nulled immediately after free
free(buffer);
buffer = NULL;
// ... later use with guard ...
if (buffer != NULL) {
    memcpy(dest, buffer, len);
}

// SAFE: save value before freeing, use the saved value
char *next_node = node->next;
free(node);
node = NULL;
// Use next_node, not node
process(next_node);

// SAFE: C++ RAII — memory freed automatically when unique_ptr goes out of scope
auto ctx = std::make_unique<CryptoContext>();
crypto_init(ctx.get());
// ctx freed automatically, no dangling pointer possible
```

## References

- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [SEI CERT C Coding Standard – MEM30-C: Do not access freed memory](https://wiki.sei.cmu.edu/confluence/display/c/MEM30-C.+Do+not+access+freed+memory)
- [OWASP – Using Components with Known Vulnerabilities (use-after-free context)](https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities)
- [CAPEC-123: Buffer Manipulation](https://capec.mitre.org/data/definitions/123.html)
- [Google AddressSanitizer documentation](https://clang.llvm.org/docs/AddressSanitizer.html)
