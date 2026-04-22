---
title: "VNX-59 – Improper Link Resolution Before File Access ('Link Following')"
description: "Detects Detects source patterns associated with CWE-59 (Improper Link Resolution Before File Access ('Link Following')). Each finding should be manually reviewed for exploitability in context."
---

## Overview

VNX-59 maps to [CWE-59: Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html). Detects source patterns associated with CWE-59 (Improper Link Resolution Before File Access ('Link Following')). Each finding should be manually reviewed for exploitability in context.

**Severity:** High | **CWE:** [CWE-59](https://cwe.mitre.org/data/definitions/59.html) | **Languages:** c, cpp, go, python

## Why This Matters

This weakness class (Improper Link Resolution Before File Access ('Link Following')) creates a concrete exploit surface: the rule searches for the concrete source-level patterns most commonly associated with CWE-59 and surfaces them for review. Each finding should be evaluated in context — the rule catches the pattern, not the context.

## What Gets Flagged

```c
// FLAGGED: contains 'open(' pattern
open(
```

```go
// FLAGGED: contains 'os.Readlink(' pattern
os.Readlink(
```

```python
// FLAGGED: contains 'os.readlink(' pattern
os.readlink(
```

## Remediation

1. Review each flagged line and determine whether the pattern represents a real instance of CWE-59 or a false positive.
2. Replace the flagged construct with a documented safe alternative appropriate to your language and framework.
3. For confirmed false positives, add a `# vulnetix-ignore: VNX-59` comment on the line.
4. Ensure equivalent test coverage exists to prevent regression.

## References

- [CWE-59: Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
