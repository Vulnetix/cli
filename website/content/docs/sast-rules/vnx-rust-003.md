---
title: "VNX-RUST-003 – Rust Unsafe Block or Function"
description: "Reports unsafe blocks and expressions, unsafe fn declarations and unsafe impls that carry no safety justification (a // SAFETY: comment or a # Safety doc section); documented unsafe and the word unsafe in strings, comments and lint attributes are not reported."
---

## Overview

This rule detects Rust code that uses `unsafe` blocks or declares `unsafe fn` functions. The `unsafe` keyword tells the Rust compiler to disable its memory safety checks within the annotated scope, placing the burden of correctness entirely on the developer. While `unsafe` is sometimes necessary for FFI, hardware access, or performance-critical code, it is the primary vector for memory safety vulnerabilities in Rust programs.

**Severity:** Medium | **CWE:** [CWE-119 – Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)

## Why This Matters

Rust's safety guarantees — no null pointer dereferences, no data races, no buffer overflows, no use-after-free — only hold in safe Rust. The moment you write `unsafe`, you opt out of these guarantees and can introduce:

- **Buffer overflows** via unchecked indexing or pointer arithmetic
- **Use-after-free** by dereferencing freed memory
- **Data races** from mutable aliasing across threads
- **Undefined behaviour** from violating type invariants or misusing transmute

Unsafe Rust is not inherently wrong — the standard library itself uses it extensively — but every unsafe block is a location that demands manual review and careful invariant documentation. This rule surfaces those locations so they receive the scrutiny they require.

## What Gets Flagged

Unsafe regions with no safety justification on the same line or in the comment block directly above (attributes and doc comments in between are skipped):

```rust
let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };   // FLAGGED

// copy the bytes over                                      (not a justification)
unsafe {                                                    // FLAGGED
    std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
}

/// Writes `count` bytes of `value` starting at `ptr`.     (no # Safety section)
pub unsafe fn fill(ptr: *mut u8, value: u8, count: usize) { // FLAGGED

unsafe impl Send for Handle {}                              // FLAGGED
```

Not flagged:

```rust
// SAFETY: `ptr` comes from `data` and index 0 is in bounds (len checked above).
unsafe { *ptr.add(0) = 0; }

/// # Safety
/// `ptr` must be valid for `count` writes.
pub unsafe fn fill(ptr: *mut u8, value: u8, count: usize) { ... }

// SAFETY: the caller hands over a pointer to len initialised bytes.
let slice =
    unsafe { std::slice::from_raw_parts(ptr, len) };

unsafe {
    // SAFETY: dst is a valid, exclusively borrowed slice of dst.len() bytes.
    std::ptr::write_bytes(dst.as_mut_ptr(), byte, dst.len());
}

#![forbid(unsafe_code)]
```

The rule does not judge whether a justification is correct, only that one is written.

## Remediation

1. **Ask whether `unsafe` is truly necessary.** Many uses of unsafe have safe alternatives:

   ```rust
   // Instead of unsafe pointer indexing:
   // unsafe { *ptr.add(i) }

   // Use checked indexing or iterators:
   let value = slice.get(i).expect("index out of bounds");
   // Or:
   for item in slice.iter() { ... }
   ```

2. **Encapsulate unsafe code in a safe abstraction.** If unsafe is required, wrap it in a function with a safe public API and document the safety invariants:

   ```rust
   /// Reads a u32 from the given memory-mapped register address.
   ///
   /// # Safety contract (internal)
   /// - `addr` must be a valid, aligned pointer to a mapped hardware register
   /// - The register must not have side effects on read that violate our state machine
   pub fn read_register(addr: *const u32) -> u32 {
       // SAFETY: addr is validated by the Register type constructor
       // which only accepts addresses in the mapped MMIO range
       unsafe { core::ptr::read_volatile(addr) }
   }
   ```

3. **Document every `unsafe` block with a `// SAFETY:` comment.** Explain why the invariants are upheld — not just what the code does, but why it's sound:

   ```rust
   // SAFETY: We hold the exclusive lock on `buffer` and the index
   // has been bounds-checked on the line above.
   unsafe { *buffer.get_unchecked_mut(index) = value; }
   ```

4. **Prefer well-audited crates over hand-rolled unsafe.** For FFI, use `cxx` or `bindgen`. For SIMD, use `std::simd` or `packed_simd2`. For atomics, use `crossbeam` or `std::sync::atomic`.

5. **Run `cargo clippy` and `miri` on unsafe code.** Miri is an interpreter that detects undefined behaviour at runtime:

   ```bash
   # Install and run Miri
   rustup +nightly component add miri
   cargo +nightly miri test
   ```

## References

- [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CAPEC-100: Overflow Buffers](https://capec.mitre.org/data/definitions/100.html)
- [MITRE ATT&CK T1211 – Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)
- [The Rustonomicon – Unsafe Rust](https://doc.rust-lang.org/nomicon/)
- [Rust Reference – Unsafe Keyword](https://doc.rust-lang.org/reference/unsafe-keyword.html)
- [Rust API Guidelines – Safety Documentation](https://rust-lang.github.io/api-guidelines/documentation.html#c-failure)
- [cargo-miri – Undefined Behaviour Detection](https://github.com/rust-lang/miri)
- [OWASP ASVS V14 – Configuration](https://owasp.org/www-project-application-security-verification-standard/)
