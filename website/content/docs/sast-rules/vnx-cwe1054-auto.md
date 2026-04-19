---
title: "VNX-1054 – GUI Input without Validation"
description: "Detects user input collection patterns across Go, Java, Node.js, PHP, and Python that may lack input validation, enabling injection, XSS, or other data-integrity attacks."
---

## Overview

VNX-1054 is an auto-generated broad-pattern rule that searches for user input collection primitives across Go, Java, Node.js, PHP, and Python source files. The rule targets `fmt.Scanf` in Go, `JOptionPane` in Java, `prompt` in Node.js, `$_GET` in PHP, and `input()` in Python. These are associated with [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html) in the rule metadata.

Note: CWE-1054 in MITRE's catalog covers "Invokable Control Element not Accessible." The vulnerability concern this rule addresses — missing input validation — maps to [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html). The CWE mapping is a known limitation of this auto-generated rule.

All flagged patterns represent points where data crosses a trust boundary from user-controlled to application-controlled. Every flagged location should be reviewed to confirm that input is validated, typed, and bounded before use.

**Severity:** Medium | **CWE:** [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

## Why This Matters

Unvalidated input is the root cause of the majority of injection vulnerability classes: SQL injection, command injection, XSS, path traversal, and template injection all stem from data taken from the user being used in a sensitive context without verification that it conforms to expectations.

PHP's `$_GET` superglobal is a particularly high-signal indicator because it directly exposes HTTP request parameters. Any use of `$_GET` values in database queries, HTML output, file paths, or shell commands without sanitisation is a potential injection vulnerability.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, and Python source files for user input collection patterns:

```python
# FLAGGED: Python input() in a networked context
user_id = input("Enter user ID: ")
query = f"SELECT * FROM users WHERE id = {user_id}"
```

```php
// FLAGGED: PHP $_GET used directly
$name = $_GET['name'];
echo "Hello, $name";  // XSS if not escaped
```

```go
// FLAGGED: Go fmt.Scanf reading user input
var filename string
fmt.Scanf("%s", &filename)
os.Open(filename)  // path traversal risk if unvalidated
```

## Remediation

1. Validate all input immediately at the point of collection against a strict type and format specification (length, character set, range).
2. For PHP `$_GET` values: use `filter_input(INPUT_GET, 'param', FILTER_SANITIZE_*)` or validate against an allowlist before any use.
3. Never pass unvalidated input directly to database queries, shell commands, file paths, or HTML output — apply the appropriate contextual encoding or parameterisation at the point of use.
4. In Python CLI tools that parse user input for use in system operations, convert to the expected type immediately and handle conversion errors explicitly.
5. Use an input validation framework or library appropriate to your language rather than ad-hoc string checks.

## References

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
