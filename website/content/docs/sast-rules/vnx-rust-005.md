---
title: "VNX-RUST-005 – panic!() or unwrap()/expect() in a Result-Returning Function"
description: "Reports panic!(), and .unwrap()/.expect() on a fallible I/O, parse, decode, database or await result, in the body of the function that directly encloses them when it returns Result (including io::Result, anyhow::Result and crate aliases); lock().unwrap(), literal parses, other return types and test code are not reported."
---

## Overview

This rule flags Rust source files where `panic!()`, `.unwrap()`, or `.expect()` are called inside a function whose signature declares a `Result` return type. A function that returns `Result<T, E>` makes a contract with its callers: recoverable errors will be communicated as an `Err` variant that the caller can handle. Calling `panic!()` or the convenience methods that wrap it — `.unwrap()` and `.expect()` — breaks this contract by terminating the entire process on failure instead of returning an error to the caller.

In library code, panicking inside a `Result`-returning function is especially harmful because callers cannot use standard Rust error propagation (the `?` operator, `match`, `map_err`) to handle the failure gracefully. The application crashes instead of degrading gracefully, making denial-of-service vulnerabilities trivially exploitable if the panic condition can be triggered by external input.

This rule corresponds to [CWE-755: Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html).

**Severity:** Medium | **CWE:** [CWE-755 – Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)

## Why This Matters

Rust's type system distinguishes between unrecoverable errors (bugs, invariant violations) — which should use `panic!()` — and recoverable errors (I/O failures, parse errors, network timeouts) — which should use `Result`. Mixing these in a `Result`-returning function undermines the guarantees that make Rust code predictable and safe to integrate.

In a server application, any code path reachable from a network request that panics will abort the current thread or, in the case of `tokio` async runtimes, crash the task. If the attacker can reliably trigger the panic by sending a specific request (a malformed payload, a boundary value, a missing field), the service becomes unavailable. The attacker does not need to compromise the system — they only need to keep sending the triggering input.

Beyond denial of service, unexpected panics can also leave resources (file handles, database transactions, locks) in an inconsistent state. Depending on the application, this can lead to data corruption or security-relevant state inconsistencies.

## What Gets Flagged

Each `panic!`, and each `.unwrap()` / `.expect(...)` applied directly to a fallible operation (I/O, an awaited future, parsing or deserialising, a database call, `env::var`, `try_into`), is judged by the function that directly encloses it, whose signature may span several lines:

```rust
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
    let cfg: Config = toml::from_str(&text).unwrap();          // FLAGGED
    Ok(cfg)
}

pub fn save(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut f = std::fs::File::create(path).expect("create output"); // FLAGGED

fn process(data: &[u8]) -> anyhow::Result<()> {
    if data.is_empty() {
        panic!("empty input");                                  // FLAGGED
    }
```

Not flagged: functions returning `Option`, `fmt::Result` or a plain value, `self.inner.lock().unwrap()` (the poisoning convention), `Regex::new("^[a-z]+$").unwrap()` (a constant), and `#[cfg(test)]` modules, `#[test]` functions, `tests/`, `examples/`, `benches/` and `build.rs`.

## Remediation

1. **Use the `?` operator to propagate errors to the caller.** The `?` operator is shorthand for returning the `Err` variant immediately if an operation fails. It is idiomatic Rust and composes cleanly with the error type in the function signature:

```rust
// SAFE: ? propagates errors to the caller
fn parse_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let cfg: Config = serde_json::from_str(&content)?;
    Ok(cfg)
}
```

2. **Return `Err(...)` explicitly for error conditions.** When the error type is domain-specific, construct and return a meaningful `Err` variant rather than panicking:

```rust
// SAFE: explicit Err return — caller can match on the variant
fn get_user(id: u64) -> Result<User, DbError> {
    db.query_one(id).ok_or(DbError::NotFound(id))
}
```

3. **Use `.map_err()` to convert foreign error types.** When an operation returns a different error type than your function signature, convert it rather than unwrapping:

```rust
// SAFE: convert the error type, propagate with ?
fn load_key(path: &str) -> Result<Vec<u8>, AppError> {
    std::fs::read(path).map_err(|e| AppError::Io(e))?;
    // ...
    Ok(key)
}
```

## References

- [CWE-755: Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
- [The Rust Book – Recoverable Errors with Result](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)
- [The Rust Book – To panic! or Not to panic!](https://doc.rust-lang.org/book/ch09-03-to-panic-or-not-to-panic.html)
- [Rust Reference – The ? operator](https://doc.rust-lang.org/reference/expressions/operator-expr.html#the-question-mark-operator)
- [Rust API Guidelines – Error Handling](https://rust-lang.github.io/api-guidelines/interoperability.html#error-types-are-meaningful-and-well-behaved-c-good-err)
