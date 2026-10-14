---
title: "VNX-1041 – Use of Redundant Code"
description: "Reports a check the code has just made being made again: an else-if that repeats a condition of its own if chain, a && / || whose two operands are the same expression, and a security check statement repeated on the next line."
---

## Overview

VNX-1041 reports redundant checks, the copy-paste shape of [CWE-1041: Use of Redundant Code](https://cwe.mitre.org/data/definitions/1041.html), in Go, Java, JavaScript/TypeScript, PHP, Python and Ruby. Three shapes are reported:

- An `else if` / `elseif` / `elif` / `elsif` whose condition repeats a condition earlier in the same if chain. That branch can never run, because the earlier branch always wins.
- A condition joined by `&&`, `||`, `and` or `or` whose two adjacent operands are the same expression, such as `user.isAdmin() || user.isAdmin()`.
- A security check statement (a call named `check...`, `verify...`, `validate...`, `require...`, `ensure...`, `enforce...`, `authorize...`/`authorise...`, `authenticate...`, `protect...` or `guard...`) repeated identically on the next code line.

Not reported: the same condition in a separate `if` statement or in a nested chain, operands that differ only in an argument, a check called twice with different arguments, checks passed as arguments (such as route middleware lists), conditions that span lines, redundancy across functions or files, minified JavaScript, test code, comments and string literals.

**Severity:** Low | **CWE:** [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html)

## Why This Matters

A duplicated check is usually a copy that was meant to be edited and was not. `else if (user.hasRole("ADMIN"))` written after an identical first branch means the role it should have tested is never handled. `isAuthenticated() && isAuthenticated()` means the second requirement, perhaps ownership, is never enforced. When two copies of the same check exist, a later fix to one leaves the other behind and the enforcement becomes inconsistent.

## What Gets Flagged

```java
if (user.hasRole("ADMIN")) {
    return Level.FULL;
} else if (user.hasRole("SUPPORT")) {
    return Level.READ;
} else if (user.hasRole("ADMIN")) {          // FLAGGED: dead branch
    return Level.AUDIT;
}
```

```python
if user.has_perm("reports.export") and user.has_perm("reports.export"):   # FLAGGED
    return report.owner_id == user.id
```

```ruby
authorize! :update, @post
authorize! :update, @post                    # FLAGGED: repeated check
```

## What Is Not Flagged

```typescript
app.post('/rest/2fa/setup',
  security.isAuthorized(),                   // a middleware argument, not a statement
  twoFactor.setup)
return user && user.profile && user.profile.name
```

## Remediation

1. Decide what the duplicated copy was meant to test, and change it to that condition or check.
2. If the duplicate is genuinely unnecessary, delete it.
3. Move a check that several places need into one function, so there is a single copy to keep correct.

## References

- [CWE-1041: Use of Redundant Code](https://cwe.mitre.org/data/definitions/1041.html)
- [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html)
