---
title: "VNX-GO-016 – Integer Downcast After strconv.Atoi/ParseInt/ParseUint"
description: "Detects integer values parsed with strconv.Atoi, ParseInt, or ParseUint that are immediately cast to a narrower integer type without range validation, risking silent truncation or sign flip."
---

## Overview

This rule detects code that parses an integer using `strconv.Atoi()`, `strconv.ParseInt()`, or `strconv.ParseUint()` and then immediately casts the result to a narrower integer type (`int8`, `int16`, `int32`, `uint8`, `uint16`, or `uint32`) on the same line or the immediately following line, without any intervening range validation. Silent truncation or sign change during the cast can produce completely different values than the input intended — for example, parsing the string `"300"` into an `int` and then casting to `uint8` silently produces `44` due to modular wrapping. This maps to CWE-681 (Incorrect Conversion Between Numeric Types) and CWE-190 (Integer Overflow or Wraparound).

In security-sensitive contexts this class of bug has historically been exploited for authentication bypasses (where a user ID wraps to an admin ID), length confusion in buffer sizing (leading to heap overflows), and off-by-one errors in access controls. Go's type system does not provide any runtime error on an out-of-range integer cast — the truncation is silent and the resulting value is silently incorrect.

**Severity:** Medium | **CWE:** [CWE-681 – Incorrect Conversion Between Numeric Types](https://cwe.mitre.org/data/definitions/681.html), [CWE-190 – Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)

## Why This Matters

`strconv.Atoi` returns an `int`, which is 64 bits on all 64-bit platforms. Casting that value to `int32` or smaller without checking whether it fits is a latent bug. An attacker who controls the string input — from an HTTP query parameter, a JSON body field, or a configuration value — can supply a value that parses successfully but produces a different integer after the cast.

CAPEC-92 (Forced Integer Overflow) documents this technique. A concrete example: an API that parses a page size parameter with `strconv.Atoi` and casts to `int16` will silently wrap for values above 32767 (`"65536"` → `0`), potentially causing a zero-length allocation or an infinite loop. If the cast is to `uint8` and the original value is negative (e.g., `"-1"` → `255` when converted to unsigned), an attacker might bypass a range check that only tested for non-negative values before the cast.

## What Gets Flagged

```go
// FLAGGED: Atoi result cast to int32 on the same line
size := int32(n)  // where n came from strconv.Atoi on the same/previous line

// FLAGGED: ParseInt result narrowed to int16 without validation
val, _ := strconv.ParseInt(r.FormValue("count"), 10, 64)
count := int16(val) // truncation if val > 32767
```

## Remediation

1. **Validate that the parsed value fits within the target type's range before casting.** The `math` package provides typed constants for all integer bounds.

   ```go
   // SAFE: range check before narrowing cast
   import "math"

   n, err := strconv.Atoi(r.FormValue("size"))
   if err != nil {
       return fmt.Errorf("invalid size: %w", err)
   }
   if n < 0 || n > math.MaxInt32 {
       return fmt.Errorf("size out of range: %d", n)
   }
   size := int32(n)
   ```

2. **Use `strconv.ParseInt` with a `bitSize` argument** that matches your target type. When `bitSize` is set to 16 or 32, `ParseInt` returns an error if the value does not fit, eliminating the need for a separate bounds check.

   ```go
   // SAFE: ParseInt with bitSize=32 rejects values that don't fit int32
   v, err := strconv.ParseInt(input, 10, 32)
   if err != nil {
       return fmt.Errorf("value out of int32 range: %w", err)
   }
   size := int32(v) // safe: ParseInt already validated the range
   ```

3. **For `uint` targets, use `strconv.ParseUint` with the appropriate `bitSize`** rather than parsing a signed integer and casting to unsigned, which masks negative inputs.

   ```go
   // SAFE: ParseUint rejects negative strings and out-of-range values
   v, err := strconv.ParseUint(input, 10, 8)
   if err != nil {
       return fmt.Errorf("invalid byte value: %w", err)
   }
   b := uint8(v)
   ```

## References

- [CWE-681: Incorrect Conversion Between Numeric Types](https://cwe.mitre.org/data/definitions/681.html)
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CAPEC-92: Forced Integer Overflow](https://capec.mitre.org/data/definitions/92.html)
- [Go documentation – strconv.ParseInt](https://pkg.go.dev/strconv#ParseInt)
- [Go documentation – strconv.ParseUint](https://pkg.go.dev/strconv#ParseUint)
- [OWASP Go-SCP – Input validation](https://owasp.org/www-project-go-secure-coding-practices-guide/)
- [Go security best practices – Integer handling](https://go.dev/security/best-practices)
