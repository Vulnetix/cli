---
title: "VNX-RUST-006 – Integer Truncation or Sign-Change Cast After Parsing"
description: "Detect Rust code that parses a value into a wide integer type (i64, u64, isize, usize) then immediately casts it to a narrower or sign-changed type without range validation, risking silent value truncation or sign inversion."
---

## Overview

This rule flags Rust source files where a value is parsed into a wide integer type — `i64`, `u64`, `i128`, `u128`, `isize`, or `usize` — and then immediately cast to a narrower type such as `u8`, `i8`, `u16`, `i16`, `u32`, or `i32` using the `as` keyword. It also flags casts from unsigned types (`usize`, `u64`, `u32`) to signed types (`i8`, `i16`, `i32`, `i64`) that can silently produce negative values.

Rust's `as` casting is intentionally defined as a bit-reinterpretation or modulo-reduction operation with no overflow check. When a value exceeds the range of the target type, the high bits are silently discarded. A value of `256u64` cast to `u8` becomes `0`. A value of `32768u32` cast to `i16` becomes `-32768`. These silent transformations can cause authentication bypasses (a check `if length < MAX_SIZE` where `length` has been truncated), buffer overflows, or incorrect business logic.

This rule corresponds to [CWE-681: Incorrect Conversion between Numeric Types](https://cwe.mitre.org/data/definitions/681.html) and [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html).

**Severity:** Medium | **CWE:** [CWE-681 – Incorrect Conversion between Numeric Types](https://cwe.mitre.org/data/definitions/681.html)

## Why This Matters

Integer truncation bugs are a well-documented class of security vulnerability. In C and C++ they have caused countless memory safety issues; in Rust the memory safety guarantees prevent buffer overflows at the language level, but the incorrect values produced by truncation can still cause logic-level vulnerabilities.

A representative attack scenario: a web service reads a `Content-Length` header, parses it as `u64`, then casts to `u32` before allocating a buffer. An attacker sends `Content-Length: 4294967297` (2^32 + 1). After the cast to `u32`, the value is `1`. The server allocates a 1-byte buffer but then reads up to 4 GB of data, triggering either a panic (heap allocation failure) or heap corruption depending on the allocator behaviour.

Sign-change casts introduce a different class of bug: a user-supplied offset that is positive as a `u64` becomes negative as `i64`, reversing the direction of pointer arithmetic or causing an array access to underflow.

## What Gets Flagged

The rule matches `.rs` files (excluding comments) where `.parse::<wide_type>()` is followed on the same line by an `as narrower_type` cast, or where an unsigned type is cast to a signed type.

```rust
// FLAGGED: parse to u64 then truncate to u8 on the same line
let port = s.parse::<u64>().unwrap() as u8;

// FLAGGED: parse to i64 then narrow to i32
let offset: i32 = input.parse::<i64>().unwrap() as i32;

// FLAGGED: unsigned to signed — may produce a negative value
let signed_len = buffer.len() as i32; // len() returns usize
```

## Remediation

1. **Use `TryFrom` / `TryInto` for checked narrowing conversions.** These traits return a `Result` that is `Err` when the value is out of range, making the failure explicit and handleable:

```rust
use std::convert::TryFrom;

// SAFE: checked conversion — returns Err if value does not fit
let raw: u64 = s.parse()?;
let port = u16::try_from(raw).map_err(|_| AppError::InvalidPort(raw))?;
```

2. **Parse directly into the target type.** If the target type is wide enough for all valid inputs, parse into it directly rather than parsing wide and casting narrow:

```rust
// SAFE: parse directly into the correct type
let port: u16 = s.parse().map_err(|_| AppError::InvalidPort)?;
```

3. **Validate range before casting.** When a checked conversion trait is not available or when you need a custom error message, validate the value explicitly before using `as`:

```rust
// SAFE: explicit range check before narrowing cast
let raw: u64 = s.parse()?;
if raw > u32::MAX as u64 {
    return Err(AppError::ValueTooLarge(raw));
}
let n = raw as u32;
```

## References

- [CWE-681: Incorrect Conversion between Numeric Types](https://cwe.mitre.org/data/definitions/681.html)
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CAPEC-92: Forced Integer Overflow](https://capec.mitre.org/data/definitions/92.html)
- [The Rust Reference – Type cast expressions](https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions)
- [Rust std::convert::TryFrom documentation](https://doc.rust-lang.org/std/convert/trait.TryFrom.html)
- [The Rust Book – Numeric Types](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-types)
