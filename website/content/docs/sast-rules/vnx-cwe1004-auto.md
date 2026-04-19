---
title: "VNX-1004 – Excessive Use of Resource"
description: "Detects patterns associated with cryptographic hashing and resource-intensive library use across multiple languages, flagging code that may indicate excessive or unsafe resource consumption."
---

## Overview

VNX-1004 is an auto-generated broad-pattern rule that searches for cryptographic hashing and resource library imports across Go, Java, Node.js, PHP, Python, and Ruby source files. The rule targets indicators such as `hashlib` imports in Python, `crypto/` package use in Go, `java.security` in Java, `Digest::` in Ruby, and `hash_` functions in PHP. These patterns are associated with [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) in the rule metadata.

Note: CWE-1004 in MITRE's catalog is "Sensitive Cookie Without 'HttpOnly' Flag." The rule metadata name "Excessive Use of Resource" more closely aligns with CWE-400 (Uncontrolled Resource Consumption). This mismatch is a known metadata limitation of the auto-generated rule set. The rule is primarily useful for surfacing all cryptographic API usage for manual review.

Because this rule uses broad substring matching rather than data-flow analysis, it has a higher false-positive rate than targeted rules. Every flagged line warrants manual inspection to determine whether the usage is safe and appropriate.

**Severity:** Medium | **CWE:** [CWE-1004 – Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

Cryptographic APIs are frequently misused: weak algorithms chosen for convenience, digest functions applied without salting, or hashing used where encryption is required. Identifying all cryptographic library usage in a codebase is a useful first step toward a cryptographic inventory audit, even if most individual findings are benign.

Uncontrolled resource consumption via cryptographic operations can also create denial-of-service conditions when untrusted input controls loop iterations or hash rounds. Auditing the flagged locations confirms that resource limits, algorithm choices, and input constraints are appropriate.

## What Gets Flagged

The rule scans Go, Java, Node.js, PHP, Python, and Ruby source files for patterns associated with cryptographic resource use:

```python
# FLAGGED: Python hashlib import
import hashlib

digest = hashlib.sha256(data).hexdigest()
```

```javascript
// FLAGGED: Node.js require of crypto
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(input).digest('hex');
```

```go
// FLAGGED: Go crypto package import
import "crypto/md5"

h := md5.New()
```

## Remediation

1. Review every flagged location and confirm the cryptographic algorithm is appropriate for the use case (e.g., SHA-256 or stronger for integrity, bcrypt/argon2 for password hashing).
2. Replace weak algorithms (MD5, SHA-1) with modern equivalents (SHA-256, SHA-3, BLAKE2).
3. For password storage, use a purpose-built KDF such as `bcrypt`, `scrypt`, or `argon2` rather than a raw hash.
4. Ensure that cryptographic operations on user-supplied data apply size limits to prevent resource exhaustion.
5. Suppress false positives by adding a `# vulnetix-ignore: VNX-1004` comment on lines that have been reviewed and confirmed safe.

## References

- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CAPEC-97: Cryptanalysis of Cellular Phone Communication](https://capec.mitre.org/data/definitions/97.html)
