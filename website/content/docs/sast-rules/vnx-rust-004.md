---
title: "VNX-RUST-004 – Rust Command Injection via process::Command"
description: "Detect Rust code that constructs process::Command using format! macro or shell invocation, enabling command injection when user input is interpolated."
---

## Overview

This rule detects Rust code that constructs a `std::process::Command` using the `format!` macro to build the command string, or that invokes a shell interpreter (`sh -c`) through `Command`. When user-controlled input is interpolated into the command string, an attacker can inject shell metacharacters (`;`, `|`, `&&`, `$(...)`) to execute arbitrary commands on the host system.

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Command injection is consistently ranked among the most critical application vulnerabilities:

- **Remote Code Execution (RCE):** An attacker can run any command the application's user can — read files, install backdoors, pivot to other systems
- **Rust doesn't protect you automatically:** Unlike SQL parameterization, Rust's type system doesn't prevent you from building command strings unsafely
- **Shell invocation amplifies risk:** Passing arguments through `sh -c` exposes the full shell metacharacter surface (pipes, redirections, command substitution)
- **Exploitation is trivial:** If user input flows into a command string, the attacker simply includes `;malicious_command` in their input

## What Gets Flagged

**Pattern 1: Command::new with format! macro**

```rust
// Flagged: user input interpolated into command string
let cmd = Command::new(format!("grep {} /var/log/app.log", user_query))
    .output();

// Flagged: format! used to construct the program path
let output = Command::new(format!("/opt/tools/{}", tool_name))
    .output()?;
```

**Pattern 2: Shell invocation via sh -c**

```rust
// Flagged: shell invocation with user input
let output = Command::new("sh").arg("-c")
    .arg(format!("find /data -name '{}'", filename))
    .output()?;
```

The rule applies only to `.rs` files.

## Remediation

1. **Pass user input as separate arguments, never as part of the command string.** `Command::new` with `.arg()` does not invoke a shell and does not interpret metacharacters:

   ```rust
   use std::process::Command;

   // Safe: user_query is passed as a separate argument
   let output = Command::new("grep")
       .arg(&user_query)      // Treated as a literal string, not shell-parsed
       .arg("/var/log/app.log")
       .output()?;
   ```

2. **Avoid shell invocation entirely.** Do not use `sh -c` or `bash -c` unless absolutely necessary:

   ```rust
   // Instead of: Command::new("sh").arg("-c").arg(format!("wc -l {}", path))
   // Use:
   let output = Command::new("wc")
       .arg("-l")
       .arg(&path)  // Safe: no shell interpretation
       .output()?;
   ```

3. **Validate and sanitize input if it must form part of a command.** Use an allowlist of acceptable characters:

   ```rust
   fn is_safe_filename(name: &str) -> bool {
       name.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
   }

   if !is_safe_filename(&user_input) {
       return Err(anyhow!("Invalid filename"));
   }
   ```

4. **Use Rust-native libraries instead of shelling out.** For common operations, prefer crates:

   ```rust
   // Instead of shelling out to `find`:
   use walkdir::WalkDir;
   for entry in WalkDir::new("/data").into_iter().filter_map(|e| e.ok()) {
       if entry.file_name().to_str() == Some(&target) {
           // found
       }
   }
   ```

5. **If you must use format! with Command, ensure the interpolated values are from trusted sources** (constants, configuration files you control, enum variants) — never from user input, environment variables, or external APIs.

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [Rust std::process::Command Documentation](https://doc.rust-lang.org/std/process/struct.Command.html)
- [OWASP ASVS V5.3 – Output Encoding and Injection Prevention](https://owasp.org/www-project-application-security-verification-standard/)
