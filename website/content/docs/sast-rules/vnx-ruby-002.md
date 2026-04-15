---
title: "VNX-RUBY-002 – eval() or system() in Ruby"
description: "Detect calls to eval() and system() in Ruby source files, which can execute arbitrary code or OS commands when called with user-controlled input."
---

## Overview

This rule flags calls to `eval()` and `system()` in Ruby source files. Both functions allow arbitrary code or OS command execution. When an argument to either function is derived from user-supplied input — HTTP parameters, environment variables, file contents — an attacker can execute arbitrary Ruby code or shell commands on the server. `eval` maps to [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html); `system` maps to [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** High | **CWE:** [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | **OWASP ASVS:** V5.2, V5.3

## Why This Matters

`eval()` compiles and executes an arbitrary string as Ruby source code in the current binding. Any application that constructs an eval argument from user-supplied data is functionally equivalent to exposing a remote code execution endpoint. Even partial control of the input is sufficient for exploitation — injecting a method call, string escape sequence, or closing delimiter can redirect execution.

`Kernel.system()` passes its first argument to the underlying shell (`/bin/sh -c`) when called with a single string. Shell metacharacters such as `;`, `&&`, `|`, `` ` ``, and `$()` then redirect control flow to attacker-chosen commands. This is distinct from calling `system` with an array of separate arguments, which bypasses shell interpretation entirely.

The [Rails Security Guide](https://guides.rubyonrails.org/security.html#command-line-injection) explicitly warns against constructing shell commands with user input. RuboCop's `Security/Eval` cop flags `eval` calls for the same reason. This rule also covers backtick execution (`` `cmd` ``) and `Kernel#exec` with string arguments, which share the same risk surface.

## What Gets Flagged

```ruby
# FLAGGED: eval with user-controlled input — remote code execution
eval(params[:code])
eval("User.find(#{user_id}).destroy")

# FLAGGED: system with user-controlled input — command injection
system("ls #{params[:dir]}")
system("convert #{filename} output.png")

# NOT flagged (false-positive suppression in rule):
operating_system.name   # contains "system" substring but is not a method call
```

## Remediation

**Remove `eval` entirely.** Almost every legitimate use case has a safer alternative:

```ruby
# UNSAFE: eval to call a dynamic method by name
eval("#{params[:action]}_report")

# SAFE: use public_send with an explicit allowlist
ALLOWED_ACTIONS = %w[monthly quarterly annual].freeze
action = params[:action].to_s
raise ActionController::BadRequest, "Invalid action" unless ALLOWED_ACTIONS.include?(action)
send("#{action}_report")
```

**For `system`, pass arguments as an array to avoid shell interpretation:**

```ruby
# UNSAFE: single string — shell interprets metacharacters
system("convert #{filename} output.png")

# SAFE: array form — no shell involved, each element is a literal argument
system("convert", filename, "output.png")
```

**Capture output safely with `Open3`:**

```ruby
require "open3"

# SAFE: capture stdout/stderr without spawning a shell
stdout, stderr, status = Open3.capture3("convert", filename, "output.png")
raise "Conversion failed: #{stderr}" unless status.success?
```

**Validate all inputs before any command execution:**

```ruby
# Restrict filename to known-safe characters before any system call
raise ArgumentError, "Invalid filename" unless filename.match?(/\A[\w\-\.]+\z/)
```

## References

- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP ASVS v4 – V5.2 Sanitization and Sandboxing](https://owasp.org/www-project-application-security-verification-standard/)
- [Rails Security Guide – Command Line Injection](https://guides.rubyonrails.org/security.html#command-line-injection)
- [RuboCop Security cops – Security/Eval](https://docs.rubocop.org/rubocop/cops_security.html)
- [CAPEC-35: Leverage Executable Code in Non-Executable Files](https://capec.mitre.org/data/definitions/35.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
