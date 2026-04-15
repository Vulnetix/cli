---
title: "VNX-RUBY-002 – eval() or system() in Ruby"
description: "Detect calls to eval() and system() in Ruby source files, which can execute arbitrary code or OS commands when called with user-controlled input."
---

## Overview

This rule flags calls to `eval()` and `system()` in Ruby source files. `eval()` executes a string as Ruby code, and `system()` executes a string as a shell command via the system shell. Both functions, when called with any argument that includes attacker-controlled data, provide a direct path to arbitrary code execution or OS command injection. This maps to [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html).

**Severity:** High | **CWE:** [CWE-94 – Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

`eval()` in Ruby accepts a complete Ruby expression string. If an attacker can inject Ruby code into the evaluated string — through a parameter, a database value, a template, or any other input channel — they can read files, make network requests, spawn subprocesses, and install persistent backdoors. The Ruby object model makes this particularly powerful: with `eval()`, an attacker can call any method on any loaded class, including Rails internals.

`system()` passes its argument to `/bin/sh -c`, meaning shell metacharacters — `;`, `|`, `&&`, backticks, `$()`, redirections — are interpreted. An attacker who can influence the string gains the ability to execute arbitrary OS commands with the privileges of the web server process. Rails applications running on cloud infrastructure are high-value targets because the server process often has IAM roles, environment-variable-injected database credentials, and network access to internal services.

Backtick syntax (`` `command` ``) and `%x{command}` are equivalent to `Kernel.` `` ` `` and carry the same risks.

## What Gets Flagged

The rule matches `.rb` files where a line contains `eval(` or `system(` (excluding `operating_system` to avoid false positives in OS detection code).

```ruby
# FLAGGED: eval with user-supplied data
eval(params[:expression])

# FLAGGED: eval with interpolated string
eval("User.find(#{params[:id]}).role")

# FLAGGED: system() with string concatenation
system("convert " + params[:filename] + " output.png")

# FLAGGED: system() with interpolated shell command
system("git log --oneline #{branch}")

# FLAGGED: backtick command execution with user input
result = `ls #{params[:dir]}`

# FLAGGED: Kernel.system with user value
Kernel.system("ping #{host}")
```

## Remediation

1. **Eliminate `eval()` entirely.** There is almost never a legitimate reason to `eval()` user-supplied data in a web application. Refactor dynamic dispatch to use a hash of lambdas or a case/when statement:

```ruby
# SAFE: dispatch table instead of eval
OPERATIONS = {
  'sum'     => ->(a, b) { a + b },
  'product' => ->(a, b) { a * b },
}.freeze

op = params[:operation]
unless OPERATIONS.key?(op)
  render json: { error: 'Invalid operation' }, status: :bad_request
  return
end

result = OPERATIONS[op].call(a.to_i, b.to_i)
```

2. **Replace `system()` with `Open3.capture2` or `Open3.capture3` and pass arguments as an array.** When arguments are passed as separate array elements rather than a single shell string, Ruby calls `execve()` directly without invoking a shell — metacharacters in arguments are treated as literal data:

```ruby
require 'open3'

# SAFE: array form — no shell interpolation, each argument is literal
filename = params[:filename]

# Validate first: only allow safe characters before even calling the command
unless filename.match?(/\A[a-zA-Z0-9._-]+\z/)
  render json: { error: 'Invalid filename' }, status: :bad_request
  return
end

stdout, stderr, status = Open3.capture3('convert', filename, 'output.png')
```

3. **Use the array form of `system()` when you must call it.** Passing multiple arguments to `system()` (not a single interpolated string) also bypasses shell interpretation:

```ruby
# SAFE: multi-argument system() — no shell involved
system('git', 'log', '--oneline', branch)
# Each argument is passed directly to execve, metacharacters are inert
```

4. **Validate arguments against an allowlist before any command call.** Even with the array form, validate that arguments contain only expected characters before passing them to a subprocess:

```ruby
# SAFE: allowlist validation + array form
ALLOWED_BRANCHES = /\A[a-zA-Z0-9._\-\/]+\z/

unless branch.match?(ALLOWED_BRANCHES)
  raise ArgumentError, "Invalid branch name: #{branch.inspect}"
end

stdout, _err, status = Open3.capture2('git', 'log', '--oneline', branch)
```

5. **Prefer pure-Ruby libraries over shell commands.** For file manipulation, image processing, compression, and other common tasks, Ruby gems (`mini_magick`, `rubyzip`, `git` gem) provide safe interfaces that never invoke a shell:

```ruby
# SAFE: use the 'git' gem instead of shelling out
require 'git'

repo = Git.open('/path/to/repo')
commits = repo.log.first(10)
```

## References

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CAPEC-35: Leverage Executable Code in Non-Executable Files](https://capec.mitre.org/data/definitions/35.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Rails Security Guide – Command Line Injection](https://guides.rubyonrails.org/security.html#command-line-injection)
- [Ruby docs: Open3](https://ruby-doc.org/stdlib/libdoc/open3/rdoc/Open3.html)
- [Ruby docs: Kernel#system](https://ruby-doc.org/core/Kernel.html#method-i-system)
