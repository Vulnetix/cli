---
title: "VNX-1054 – Commented-out code"
description: "Detects blocks of comment lines that read as code (statements, control flow, calls) rather than prose, in Go, Java, JavaScript/TypeScript, PHP, Python and Ruby."
---

## Overview

VNX-1054 reports a block of comments that is really disabled code. Disabled code can hold old credentials, bypassed security checks or deprecated algorithms that a developer might re-enable by uncommenting it.

A comment is reported only when **at least three consecutive comment lines look like code**: they end the way a statement ends (`{`, `}`, `;`, `)`), start with a keyword (`if`, `for`, `return`, `def`, `import`...) or contain an assignment or call, and they do not read as a sentence. Prose that happens to begin with `for`, `if` or `token` is not commented-out code and is not reported. Godoc samples (a tab after `//`) are documentation and are skipped, and so is a code-like line indented deeper than the prose of the same comment block: that is a usage example in a doc comment (RDoc, godoc, Javadoc), not disabled code. Test files and library code copied into `static/`, `assets/` or `public/` trees are skipped too. One finding is reported per block, at its first code-like line.

**Severity:** Low | **CWE:** [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html)

## What Gets Flagged

```go
// FLAGGED: a disabled branch left behind
// if err != nil {
//     return err
// }
// x := compute(y)
```

```python
# FLAGGED: a disabled loop
# for item in items:
#     total += item.price
#     print(total)
```

```java
// TODO put this back once the SSO migration is done
// FLAGGED: a disabled authorisation check
// if (!request.user().hasRole("ADMIN")) {
//     return Response.forbidden();
// }
```

```ruby
# FLAGGED: disabled filters
# before_action :authenticate_user!
# before_action :require_admin, only: [:destroy]
# if current_user.locked?
#   redirect_to root_path
# end
```

## What Is Not Flagged

```go
// for a one-shot command where the only thing that matters is total wall time.
// token expiry is checked on every request and cached for the process lifetime.

// A single commented-out line:
// x := 1
```

```ruby
# A settings store that reads values from the environment first and the
# YAML file second, so a deployment can override any key.
#
#   settings = Acme::Settings.new("config/app.yml")
#   settings[:timeout] = 30
#   settings.fetch(:region) # => "eu-west-1"
```

## Remediation

Delete the code. Version control keeps the history; a comment keeps only the risk.

## References

- [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html)
