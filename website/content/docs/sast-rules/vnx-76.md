---
title: "VNX-76 – Improper Neutralization of Equivalent Special Elements"
description: "A dangerous multi-character sequence (an HTML tag other than script, vbscript:, &&, $(, a SQL or script keyword) is neutralised by deleting it once, so input that rebuilds it after the deletion passes through. Traversal, script-tag and javascript: removals are reported by VNX-182."
---

## Overview

VNX-76 maps to [CWE-76: Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html). It reports a single-pass removal, a replacement with the empty string, of a sequence that an attacker can reassemble from the pieces left behind.

**Severity:** Medium | **CWE:** [CWE-76](https://cwe.mitre.org/data/definitions/76.html) | **Languages:** java, node, php, python

## Why This Matters

Deleting a sequence once does not remove it from the input, only from one spelling of it. `....//` becomes `../`, `<scr<script>ipt>` becomes `<script>`, `&;&` becomes `&&` once `;` is also stripped, and `hthttp://tp://` becomes `http://`. The filter gives the appearance of protection and the attack still lands.

## What Gets Flagged

```python
return q.replace("UNION", "").replace(" ", "")
```

```javascript
return html.replace(/<iframe/g, '');
return url.replaceAll('vbscript:', '');
return cmd.replace('&&', '').replace('||', '');
```

```java
userId = userId.toUpperCase().replace("FROM", "").replace("SELECT", "");
```

```php
$target = str_replace(array('&&', ';'), '', $target);
```

Not flagged: a removal repeated in a loop until the sequence is gone, removal of a single character (it cannot be rebuilt), a replacement with a non-empty string (`&lt;`, `_`), a URL scheme stripped to get a host name with no other removal nearby, test code, comments and strings.

Not flagged here because [VNX-182](../vnx-182/) reports the same collapse on that line: a removal of a path-traversal sequence (`../`, `..\`, `..`), a script tag or element pattern (`<script>`, `</script>`, `<script[^>]*>`) or `javascript:`, and an `http://`/`https://` strip beside one of them, such as `str_replace( array( "../", "..\\" ), "", $file )` or `str_replace( '<script>', '', $name )`.

## Remediation

1. Reject input that contains the sequence instead of editing it.
2. For output, encode for the context (HTML-escape, a templating engine's autoescape) rather than strip tags.
3. For paths, take the basename or canonicalise and check containment.
4. For SQL, use parameterised queries; keyword filters are never sufficient.

## References

- [CWE-76: Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)
- [CWE-182: Collapse of Data into Unsafe Value](https://cwe.mitre.org/data/definitions/182.html)
