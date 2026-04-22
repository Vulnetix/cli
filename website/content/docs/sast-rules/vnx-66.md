---
title: "VNX-66 – Improper Handling of File Names that Identify Virtual Resources"
description: "Detects Detects source patterns associated with CWE-66 (Improper Handling of File Names that Identify Virtual Resources). Each finding should be manually reviewed for exploitability in context."
---

## Overview

VNX-66 maps to [CWE-66: Improper Handling of File Names that Identify Virtual Resources](https://cwe.mitre.org/data/definitions/66.html). Detects source patterns associated with CWE-66 (Improper Handling of File Names that Identify Virtual Resources). Each finding should be manually reviewed for exploitability in context.

**Severity:** Medium | **CWE:** [CWE-66](https://cwe.mitre.org/data/definitions/66.html) | **Languages:** c, cpp, csharp, go, java, python

## Why This Matters

This weakness class (Improper Handling of File Names that Identify Virtual Resources) creates a concrete exploit surface: the rule searches for the concrete source-level patterns most commonly associated with CWE-66 and surfaces them for review. Each finding should be evaluated in context — the rule catches the pattern, not the context.

## What Gets Flagged

```c
// FLAGGED: contains 'CON' pattern
CON
```

## Remediation

1. Review each flagged line and determine whether the pattern represents a real instance of CWE-66 or a false positive.
2. Replace the flagged construct with a documented safe alternative appropriate to your language and framework.
3. For confirmed false positives, add a `# vulnetix-ignore: VNX-66` comment on the line.
4. Ensure equivalent test coverage exists to prevent regression.

## References

- [CWE-66: Improper Handling of File Names that Identify Virtual Resources](https://cwe.mitre.org/data/definitions/66.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
