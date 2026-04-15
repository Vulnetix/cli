---
title: "VNX-RUST-001 – Missing Cargo.lock"
description: "Detects Rust projects that have a Cargo.toml but no Cargo.lock file, allowing non-deterministic dependency resolution that enables supply chain attacks."
---

## Overview

This rule detects Rust project directories where `Cargo.toml` is present but `Cargo.lock` is absent. Without a lock file, `cargo build` resolves dependency version ranges non-deterministically at build time: the exact versions selected depend on what is available in the crates.io index at that moment. This means two builds of the same source tree can silently incorporate different dependency versions, including versions that introduce security vulnerabilities or malicious code. This maps to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

**Severity:** High | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

Supply chain attacks against package registries have become one of the most effective attack vectors in software security. The `cargo` ecosystem has seen incidents including the `rustdecimal` typosquatting attack and the broader pattern of maintainer account takeovers used to push malicious patch releases. When a crate you depend on is compromised (e.g., `serde@1.0.193` becomes malicious), a build without a lock file will pull the compromised version if it satisfies your version constraint in `Cargo.toml`.

With a `Cargo.lock` file committed to version control, the exact version hash of every transitive dependency is pinned. A `cargo audit` or `cargo deny` check against the lock file can detect known-vulnerable versions before the build proceeds. Without the lock file, you have no stable dependency inventory to audit.

The Cargo team's official guidance is that all binary crates (applications) should commit `Cargo.lock`, and MITRE ATT&CK T1195.001 (Compromise Software Dependencies and Development Tools) covers this attack class directly.

## What Gets Flagged

The rule checks every directory identified as containing a Rust project (via `dirs_by_language["rust"]`). For each such directory, it constructs the expected `Cargo.lock` path and raises a finding if that file is absent from the file set.

```
# FLAGGED: project structure missing Cargo.lock
my-rust-app/
├── Cargo.toml       ← present
├── src/
│   └── main.rs
└── (no Cargo.lock)  ← FLAGGED
```

## Remediation

1. **Generate `Cargo.lock` immediately and commit it to version control.**

   ```bash
   # Generate the lock file
   cargo generate-lockfile

   # Verify it was created
   ls -la Cargo.lock

   # Add it to git
   git add Cargo.lock
   git commit -m "chore: add Cargo.lock to pin dependency versions"
   ```

2. **Update your `.gitignore` to stop ignoring `Cargo.lock` for binary crates.** A common mistake is adding `Cargo.lock` to `.gitignore` based on library crate advice without recognizing that binary crates should always commit it.

   ```gitignore
   # WRONG for binary crates — remove this line:
   # Cargo.lock

   # If you have a mixed workspace (libraries + binaries),
   # use per-package overrides or commit the lock file
   ```

3. **Add `cargo audit` to your CI pipeline.** Once the lock file is committed, `cargo audit` checks it against the RustSec Advisory Database (a curated database of Rust security advisories) and fails the build if any dependency has a known vulnerability.

   ```yaml
   # GitHub Actions example
   - name: Security audit
     run: |
       cargo install cargo-audit --locked
       cargo audit
   ```

4. **Use `cargo deny` for comprehensive supply chain policy.** `cargo-deny` extends `cargo audit` with license checks, banned crate lists, and alternative registry enforcement. This provides a complete supply chain policy as code.

   ```toml
   # deny.toml
   [advisories]
   db-path = "~/.cargo/advisory-db"
   db-urls = ["https://github.com/rustsec/advisory-db"]
   vulnerability = "deny"
   unmaintained = "warn"
   ```

5. **Pin to exact versions in `Cargo.toml` for security-critical dependencies.** Using `=1.2.3` instead of `^1.2.3` eliminates the version range entirely, though this makes updating more manual. A lock file provides the same protection with more flexibility.

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [CAPEC-185: Malicious Software Update](https://capec.mitre.org/data/definitions/185.html)
- [MITRE ATT&CK T1195.001 – Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [Cargo documentation – Cargo.lock](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html)
- [RustSec Advisory Database](https://rustsec.org/)
- [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
- [cargo-deny](https://embarkstudios.github.io/cargo-deny/)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
