---
title: "VNX-RUST-002 – Rust unwrap May Panic"
description: "Detects .unwrap() and .expect() calls on Result and Option types in Rust source files, which can cause unexpected panics and denial of service in production."
---

## Overview

This rule detects calls to `.unwrap()` and `.expect()` on `Result<T, E>` and `Option<T>` values in Rust `.rs` source files. Both methods will panic — terminating the current thread or the entire process (in single-threaded contexts) — if the value is `Err` or `None` at runtime. While `.unwrap()` and `.expect()` are useful during prototyping and in tests, their presence in production application code represents unhandled error paths that can be triggered by unexpected inputs, network conditions, or file system states. This maps to CWE-248 (Uncaught Exception).

**Severity:** Low | **CWE:** [CWE-248 – Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)

## Why This Matters

Rust's type system forces you to explicitly acknowledge that a `Result` or `Option` might be an error or absent value — `.unwrap()` is the escape hatch that says "I'm sure this won't fail, crash me if I'm wrong." In production systems, this confidence is often misplaced:

- A file that "always exists" gets deleted by a cleanup script
- A network connection that "always succeeds" times out under load
- An integer parse that "will always work" encounters unexpected user input
- An environment variable that "is always set" is missing in a new deployment

When a panic propagates in a multi-threaded Rust service, Tokio and async runtimes typically catch it at the task boundary and log an error, but the task is aborted and any in-flight request fails. In worst cases — particularly with `rayon` thread pools or custom panic hooks — a panic can bring down the entire process, creating a denial-of-service condition.

Beyond availability, panics can expose internal state through stack traces in error responses, and abrupt task termination can leave shared data structures in inconsistent states if locks are held when the panic propagates.

## What Gets Flagged

The rule matches any `.unwrap()` or `.expect(...)` call in Rust source files (`.rs` extension):

```rust
// FLAGGED: unwrap on file open — panics if file does not exist
let file = File::open("config.toml").unwrap();

// FLAGGED: expect on env var — panics if env var is not set
let port = env::var("PORT").expect("PORT must be set");

// FLAGGED: unwrap on parse — panics on unexpected input
let count: u32 = user_input.trim().parse().unwrap();
```

## Remediation

1. **Use the `?` operator to propagate errors to the caller.** This is idiomatic Rust and requires your function to return `Result<T, E>`. In `main()` and async entry points, return `Result<(), Box<dyn std::error::Error>>` to enable `?` at the top level.

   ```rust
   // SAFE: ? propagates the error to the caller
   use std::fs::File;
   use std::io::Read;

   fn read_config(path: &str) -> Result<String, std::io::Error> {
       let mut file = File::open(path)?;
       let mut contents = String::new();
       file.read_to_string(&mut contents)?;
       Ok(contents)
   }

   fn main() -> Result<(), Box<dyn std::error::Error>> {
       let config = read_config("config.toml")?;
       println!("{config}");
       Ok(())
   }
   ```

2. **Use `match` or `if let` when you need to handle the error case explicitly.**

   ```rust
   // SAFE: handle both cases with match
   match env::var("PORT") {
       Ok(val) => val.parse::<u16>().unwrap_or(8080),
       Err(_) => 8080,
   }

   // SAFE: if let for the success path with a fallback
   let port = env::var("PORT")
       .ok()
       .and_then(|v| v.parse::<u16>().ok())
       .unwrap_or(8080);
   ```

3. **Use combinators on `Option` and `Result`.** Methods like `.unwrap_or()`, `.unwrap_or_else()`, `.unwrap_or_default()`, `.map()`, `.and_then()`, and `.ok_or()` express intent clearly without panicking.

   ```rust
   // SAFE: provide a default instead of panicking
   let name = config.get("name").unwrap_or("anonymous");

   // SAFE: convert Option to Result and propagate
   let value = config.get("key")
       .ok_or_else(|| anyhow::anyhow!("'key' missing from config"))?;
   ```

4. **`.unwrap()` and `.expect()` are acceptable in tests.** The rule fires on all `.rs` files, including tests. Panicking in a test is expected and correct behavior — a test failure is informative. Consider suppressing this rule in test modules if the noise is high.

   ```rust
   #[cfg(test)]
   mod tests {
       #[test]
       fn test_parse() {
           // unwrap in tests is fine — a panic here means a test failure
           let val: u32 = "42".parse().unwrap();
           assert_eq!(val, 42);
       }
   }
   ```

5. **Use `anyhow` or `thiserror` for ergonomic error handling in applications.** The `anyhow` crate provides `Context::context()` as a drop-in replacement for `.expect()` that adds contextual messages without panicking, and integrates cleanly with `?`.

   ```rust
   // SAFE: anyhow adds context without panicking
   use anyhow::Context;
   let file = File::open("config.toml")
       .context("failed to open config.toml")?;
   ```

## References

- [CWE-248: Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
- [Rust Book – Recoverable Errors with Result](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)
- [Rust Book – The ? Operator](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html#a-shortcut-for-propagating-errors-the--operator)
- [Rust std::result::Result](https://doc.rust-lang.org/std/result/enum.Result.html)
- [anyhow crate – context-aware error handling](https://docs.rs/anyhow/latest/anyhow/)
- [thiserror crate – derive macro for custom error types](https://docs.rs/thiserror/latest/thiserror/)
- [Rust API Guidelines – Error handling](https://rust-lang.github.io/api-guidelines/interoperability.html#error-types-are-meaningful-and-well-behaved-c-good-err)
