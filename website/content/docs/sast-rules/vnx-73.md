---
title: "VNX-73 – External Control of File Name or Path"
description: "Detects Detects source patterns associated with CWE-73 (External Control of File Name or Path). Each finding should be manually reviewed for exploitability in context."
---

## Overview

VNX-73 maps to [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html). Detects source patterns associated with CWE-73 (External Control of File Name or Path). Each finding should be manually reviewed for exploitability in context.

**Severity:** High | **CWE:** [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | **Languages:** java, node, python

## Why This Matters

This weakness class (External Control of File Name or Path) creates a concrete exploit surface: the rule searches for the concrete source-level patterns most commonly associated with CWE-73 and surfaces them for review. Each finding should be evaluated in context — the rule catches the pattern, not the context.

## What Gets Flagged

```python
// FLAGGED: contains 'open(' pattern
open(
```

```java
// FLAGGED: contains 'new FileInputStream(' pattern
new FileInputStream(
```

```javascript
// FLAGGED: contains 'fs.createReadStream(' pattern
fs.createReadStream(
```

## Remediation

1. Review each flagged line and determine whether the pattern represents a real instance of CWE-73 or a false positive.
2. Replace the flagged construct with a documented safe alternative appropriate to your language and framework.
3. For confirmed false positives, add a `# vulnetix-ignore: VNX-73` comment on the line.
4. Ensure equivalent test coverage exists to prevent regression.

## References

- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
