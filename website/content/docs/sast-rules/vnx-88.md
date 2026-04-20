---
title: "VNX-88 – Argument Injection"
description: "User-controlled data is inserted into command arguments without proper escaping. An attacker can inject additional flags"
---

## Overview

User-controlled data is inserted into command arguments without proper escaping. An attacker can inject additional flags or arguments (e.g. starting with '-') to alter the behaviour of the target program, potentially bypassing security controls or causing data exfiltration.

**Severity:** High | **CWE:** [CWE-88 – Argument Injection](https://cwe.mitre.org/data/definitions/88.html)

## Why This Matters

Violations of CWE-88 can expose the application to exploitation. This rule detects source code patterns associated with this weakness across multiple languages and frameworks.

## What Gets Flagged

This rule fires when source code contains patterns indicative of CWE-88. Review the flagged code to confirm whether the identified pattern represents a genuine vulnerability in context.

## Remediation

1. Review the flagged code and understand the specific weakness described in CWE-88.
2. Apply the recommended remediation for your language/framework.
3. Add appropriate input validation, access controls, or safe API usage as applicable.
4. Add a test case that verifies the fix.

## References

- [CWE-88 – Argument Injection](https://cwe.mitre.org/data/definitions/88.html)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
