---
title: "VNX-GO-022 – Use of eval() or dynamic code execution"
description: "Detects request data, the request body or a caller-supplied parameter passed as code to an embedded interpreter or expression engine (goja, otto, yaegi, gopher-lua, govaluate, expr, gval, cel-go, tengo, starlark) or parsed as an html/template or text/template. Constant, embedded and configured scripts are not reported."
---

## Overview

This rule flags instances where dynamic code execution functions like `eval()` or template execution are used with potentially user-controlled input. This pattern can lead to Remote Code Execution (RCE) vulnerabilities because attackers can inject malicious code that gets executed on the server.

This maps to [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html).

**Severity:** High | **CWE:** [CWE-94 – Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html) | **OWASP ASVS:** [V5.2.1 – Input Validation](https://owasp.org/www-project-application-security-verification-standard/)

## Why This Matters

Dynamic code execution functions allow code to be generated and executed at runtime. When these functions process user-controlled input without proper validation, attackers can inject malicious code that will be executed with the privileges of the application. This can lead to complete system compromise, data theft, or malware installation.

## What Gets Flagged

Go has no `eval()`, so the rule looks for the embedded interpreters,
expression engines and template parsers that play its part, and reports them
only when the code they are given comes from a request or from the caller.

```go
// FLAGGED: the request body is JavaScript and goja runs it
src, err := io.ReadAll(r.Body)
v, err := vm.RunString(string(src))

// FLAGGED: an expression the requester writes
q := r.URL.Query().Get("filter")
program, err := expr.Compile(q, expr.Env(env))

// FLAGGED: server-side template injection
body := r.FormValue("template")
t, err := template.New("preview").Parse(body)

// NOT FLAGGED: scripts and rules that ship with the program or its config
vm.RunString(shim)
expr.Compile(r.When, expr.Env(env)) // r ranges over configured rules
```

## Remediation

1. **Avoid dynamic template execution with user input:** Never use user input as the template source:
   ```go
   // SAFE: Use predefined templates
   tmpl := template.Must(template.New("safe").Parse(`
       <div>{{.}}</div>
   `))
   tmpl.Execute(w, userInput) // Data is escaped, not code
   ```

2. **Validate and sanitize template input:** If dynamic templates are absolutely necessary:
   ```go
   // SAFE: Restrict template to safe operations only
   func isSafeTemplate(t string) bool {
       // Implement strict validation - allow only specific safe constructs
       // Reject any template with dangerous actions
   }
   
   if isSafeTemplate(userInput) {
       tmpl := template.New("dynamic").Parse(userInput)
       // Continue with execution
   }
   ```

3. **Use static analysis and code review:** For plugin systems or code generation:
   - Restrict plugin sources to trusted locations
   - Validate plugin signatures
   - Limit plugin capabilities through interfaces
   - Review generated code before execution

4. **Consider architectural alternatives:** Instead of executing user code:
   - Use configuration files with restricted syntax
   - Implement rule engines with predefined actions
   - Use sandboxed environments (like gVisor or WASM) for untrusted code

## References

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [OWASP Application Security Verification Standard v4.0 – V5.2.1 Input Validation](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Code Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Code_Injection_Prevention_Cheat_Sheet.html)
- [Go template package documentation](https://pkg.go.dev/html/template)
- [Go plugin package documentation](https://pkg.go.dev/plugin)