---
title: "VNX-RUST-007 – Integer Arithmetic Overflow Without Checked Arithmetic"
description: "Reports +, -, * and << on an integer just parsed or decoded from runtime data (parse::<T>(), from_str_radix, from_be_bytes, read_u32); checked/saturating/wrapping calls, values bounded by a comparison or min/clamp, and values that were not decoded are not reported."
---

## Overview

This rule flags Rust arithmetic (`+`, `-`, `*`, `<<`) applied to a value that was just decoded from outside the program: parsed as an integer (`parse::<u32>()`, `let n: usize = s.parse()`, `from_str_radix`) or read from bytes (`from_be_bytes`, `from_le_bytes`, `read_u32` and its siblings). A decoded length plus a header, or a size product, is how an undersized allocation or a bypassed bounds check happens.

Rust's integer arithmetic behaves differently between build profiles. In debug builds, overflow causes a panic, providing immediate feedback during development. In release builds (the default for production), overflow wraps around silently according to two's complement arithmetic.

Not reported: arithmetic on values that did not come from a decode, floats and strings, a value compared against a limit or clamped with `min`/`clamp` before the arithmetic, `checked_*`/`saturating_*`/`wrapping_*`/`overflowing_*` calls, and comments and string literals. Arithmetic on a decode in the same expression (`s.parse::<u32>().unwrap_or(0) + offset`) is reported on that line.

This rule corresponds to [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html).

**Severity:** Medium | **CWE:** [CWE-190 – Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)

## Why This Matters

Integer overflow in size and length calculations is a classic source of security vulnerabilities. The Rust language makes such bugs non-exploitable for memory safety — there are no buffer overflows in safe Rust — but overflow in size calculations can still lead to logic vulnerabilities, denial of service, and incorrect security decisions.

A representative scenario: a network protocol parser accumulates the sizes of received chunks with `total_size + chunk_size`. An attacker sends many chunks whose combined size exceeds `usize::MAX`. In a release build, `total_size` wraps back to a small number. A subsequent check `if total_size > MAX_PAYLOAD` passes when it should not, and the application processes an oversized payload it believes to be within limits.

Similarly, a loop counter that overflows can produce an infinite loop or an incorrect termination condition. An allocation calculated as `capacity + extra` that wraps to a very small number can lead to a panic on the next heap allocation or to a buffer that is much smaller than the code expects.

## What Gets Flagged

The finding is reported on the arithmetic line, either the same line as the decode or a later line (within 40 lines) that uses the decoded variable, unless a comparison against a limit or a `min`/`clamp` on that variable comes between them.

```rust
// FLAGGED: a decoded length plus a header
let len = u32::from_be_bytes(hdr) as usize;
let total = len + HEADER_LEN;

// FLAGGED: a size product from parsed input
let width: usize = w.parse()?;
let height = h.parse::<usize>()?;
let buf = Vec::with_capacity(width * height * 4);

// FLAGGED: underflow and shift
let n = raw.parse::<usize>().unwrap_or(0);
n - 1
let bits = u32::from_str_radix(raw, 10).unwrap_or(0);
let m = 1u64 << bits;

// NOT FLAGGED: checked arithmetic
let total = len.checked_add(HEADER_LEN).ok_or(Error::TooLarge)?;
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
