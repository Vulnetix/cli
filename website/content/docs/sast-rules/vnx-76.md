---
title: "VNX-76 – Improper Neutralization of Equivalent Special Elements"
description: "Detects Detects source patterns associated with CWE-76 (Improper Neutralization of Equivalent Special Elements). Each finding should be manually reviewed for exploitability in context."
---

## Overview

VNX-76 maps to [CWE-76: Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html). Detects source patterns associated with CWE-76 (Improper Neutralization of Equivalent Special Elements). Each finding should be manually reviewed for exploitability in context.

**Severity:** Medium | **CWE:** [CWE-76](https://cwe.mitre.org/data/definitions/76.html) | **Languages:** java, node, python

## Why This Matters

This weakness class (Improper Neutralization of Equivalent Special Elements) creates a concrete exploit surface: the rule searches for the concrete source-level patterns most commonly associated with CWE-76 and surfaces them for review. Each finding should be evaluated in context — the rule catches the pattern, not the context.

## What Gets Flagged

```python
// FLAGGED: contains 'replace('<','&lt;'' pattern
replace('<','&lt;'
```

## Remediation

1. Review each flagged line and determine whether the pattern represents a real instance of CWE-76 or a false positive.
2. Replace the flagged construct with a documented safe alternative appropriate to your language and framework.
3. For confirmed false positives, add a `# vulnetix-ignore: VNX-76` comment on the line.
4. Ensure equivalent test coverage exists to prevent regression.

## References

- [CWE-76: Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
