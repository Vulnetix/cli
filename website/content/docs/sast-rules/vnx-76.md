---
title: "VNX-76 – Improper Neutralization of Equivalent Special Elements"
description: "A dangerous multi-character sequence (../, <script>, javascript:, &&, a SQL keyword, a URL scheme in an RFI filter) is neutralised by deleting it once, so input that rebuilds it after the deletion passes through."
---

## Overview

VNX-76 maps to [CWE-76: Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html). It reports a single-pass removal, a replacement with the empty string, of a sequence that an attacker can reassemble from the pieces left behind.

**Severity:** Medium | **CWE:** [CWE-76](https://cwe.mitre.org/data/definitions/76.html) | **Languages:** java, node, php, python

## Why This Matters

Deleting a sequence once does not remove it from the input, only from one spelling of it. `....//` becomes `../`, `<scr<script>ipt>` becomes `<script>`, `&;&` becomes `&&` once `;` is also stripped, and `hthttp://tp://` becomes `http://`. The filter gives the appearance of protection and the attack still lands.

## What Gets Flagged

```python
return name.replace("../", "")
html = re.sub(r"<script>", "", html)
```

```javascript
return input.replace(/<script>/gi, '');
return url.replaceAll('javascript:', '');
```

```java
return path.replace("../", "");
userId = userId.toUpperCase().replace("FROM", "").replace("SELECT", "");
```

```php
$file = str_replace( array( "../", "..\\" ), "", $file );
$target = str_replace(array('&&', ';'), '', $target);
$name = str_replace( '<script>', '', $_GET[ 'name' ] );
```

Not flagged: a removal repeated in a loop until the sequence is gone, removal of a single character (it cannot be rebuilt), a replacement with a non-empty string (`&lt;`, `_`), a URL scheme stripped to get a host name with no other removal nearby, test code, comments and strings.

## Remediation

1. Reject input that contains the sequence instead of editing it.
2. For output, encode for the context (HTML-escape, a templating engine's autoescape) rather than strip tags.
3. For paths, take the basename or canonicalise and check containment.
4. For SQL, use parameterised queries; keyword filters are never sufficient.

## References

- [CWE-76: Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)
- [CWE-182: Collapse of Data into Unsafe Value](https://cwe.mitre.org/data/definitions/182.html)
