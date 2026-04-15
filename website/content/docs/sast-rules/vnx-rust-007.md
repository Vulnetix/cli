---
title: "VNX-RUST-007 – Integer Arithmetic Overflow Without Checked Arithmetic"
description: "Detect Rust integer arithmetic on size, count, offset, or length variables that does not use checked_add, checked_sub, checked_mul, saturating, or wrapping variants, risking silent wraparound in release builds."
---

## Overview

This rule flags Rust source files where arithmetic operators (`+`, `-`, `*`) are applied to variables commonly associated with sizes, lengths, offsets, or counts — such as `len`, `size`, `count`, `offset`, `index`, `total`, `sum`, or `capacity` — without using Rust's explicit overflow-handling methods (`checked_add`, `checked_sub`, `checked_mul`, `saturating_add`, `wrapping_add`, etc.).

Rust's integer arithmetic behaves differently between build profiles. In debug builds, overflow causes a panic, providing immediate feedback during development. In release builds (the default for production), overflow wraps around silently according to two's complement arithmetic. This means code that appears to work correctly during development and testing can silently produce wrong values in production when inputs are at or near integer boundaries.

This rule corresponds to [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html).

**Severity:** Medium | **CWE:** [CWE-190 – Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)

## Why This Matters

Integer overflow in size and length calculations is a classic source of security vulnerabilities. The Rust language makes such bugs non-exploitable for memory safety — there are no buffer overflows in safe Rust — but overflow in size calculations can still lead to logic vulnerabilities, denial of service, and incorrect security decisions.

A representative scenario: a network protocol parser accumulates the sizes of received chunks with `total_size + chunk_size`. An attacker sends many chunks whose combined size exceeds `usize::MAX`. In a release build, `total_size` wraps back to a small number. A subsequent check `if total_size > MAX_PAYLOAD` passes when it should not, and the application processes an oversized payload it believes to be within limits.

Similarly, a loop counter that overflows can produce an infinite loop or an incorrect termination condition. An allocation calculated as `capacity + extra` that wraps to a very small number can lead to a panic on the next heap allocation or to a buffer that is much smaller than the code expects.

## What Gets Flagged

The rule matches `.rs` files where arithmetic operators are used on variables named with common size/length identifiers, without any checked or saturating arithmetic in the same expression.

```rust
// FLAGGED: addition on len without overflow check
let new_len = len + additional; // wraps in release builds

// FLAGGED: multiplication on size without check
let total = count * item_size; // classic overflow in allocation sizing

// FLAGGED: offset arithmetic without protection
let end_offset = offset + size;
```

## Remediation

1. **Use `checked_add` / `checked_sub` / `checked_mul` when you need to handle overflow as an error.** These methods return `Option<T>`, returning `None` on overflow, which forces the caller to decide what to do:

```rust
// SAFE: checked addition — returns None on overflow
let new_len = len.checked_add(additional)
    .ok_or(AppError::SizeOverflow)?;
```

2. **Use `saturating_add` / `saturating_sub` when clamping to the maximum is the correct behaviour.** Saturating arithmetic never overflows — it stops at the type's maximum or minimum value:

```rust
// SAFE: saturating addition — clamps at usize::MAX
let total = count.saturating_mul(item_size);
if total > MAX_ALLOWED {
    return Err(AppError::PayloadTooLarge);
}
```

3. **Use `wrapping_add` / `wrapping_mul` when intentional two's complement wrap-around is required.** This documents the intent explicitly and avoids the implicit panic in debug / silent wrap in release:

```rust
// SAFE: intentional wrapping documented at the call site
let hash = hash.wrapping_add(byte as u64);
```

4. **Consider using the `num-traits` crate's `CheckedAdd` / `CheckedMul` traits** for generic code that operates over multiple numeric types.

## References

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CAPEC-92: Forced Integer Overflow](https://capec.mitre.org/data/definitions/92.html)
- [The Rust Book – Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Rust std – checked integer arithmetic](https://doc.rust-lang.org/std/primitive.u64.html#method.checked_add)
- [Rust Reference – Integer types and overflow](https://doc.rust-lang.org/reference/types/numeric.html)
