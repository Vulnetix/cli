---
title: "VNX-20 – CWE-20"
description: "Detects Detects request data flowing to sensitive sinks without an intervening validation call."
---

## Overview

VNX-20 maps to [CWE-20: CWE-20](https://cwe.mitre.org/data/definitions/20.html). Detects request data flowing to sensitive sinks without an intervening validation call.

**Severity:** Medium | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | **Languages:** go, java, node, python

## Why This Matters

This weakness class (CWE-20) creates a concrete exploit surface: the rule searches for the concrete source-level patterns most commonly associated with CWE-20 and surfaces them for review. Each finding should be evaluated in context — the rule catches the pattern, not the context.

## What Gets Flagged

```python
// FLAGGED: contains 'request.' pattern
request.
```

## Remediation

1. Review each flagged line and determine whether the pattern represents a real instance of CWE-20 or a false positive.
2. Replace the flagged construct with a documented safe alternative appropriate to your language and framework.
3. For confirmed false positives, add a `# vulnetix-ignore: VNX-20` comment on the line.
4. Ensure equivalent test coverage exists to prevent regression.

## References

- [CWE-20: CWE-20](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
