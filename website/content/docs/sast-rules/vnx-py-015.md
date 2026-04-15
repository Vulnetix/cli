---
title: "VNX-PY-015 – Python ReDoS via User-Controlled Regex"
description: "Detect Python code that passes user-controlled input directly to re.compile, re.match, or re.search, enabling Regular Expression Denial of Service (ReDoS) attacks."
---

## Overview

This rule detects Python code that passes user-controlled input (such as Flask/Django request parameters) directly into regular expression functions like `re.compile()`, `re.match()`, `re.search()`, or `re.fullmatch()`. When an attacker can control the regex pattern, they can craft a pathological expression that causes catastrophic backtracking, consuming CPU and memory until the application becomes unresponsive.

**Severity:** High | **CWE:** [CWE-1333 – Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)

## Why This Matters

Regular Expression Denial of Service (ReDoS) is a practical, low-effort attack. A single HTTP request with a carefully crafted regex pattern can:

- Pin a CPU core at 100% for seconds, minutes, or longer
- Block the event loop or worker thread handling the request, causing cascading timeouts
- Bring down an entire application if enough malicious requests arrive in parallel
- Bypass rate limiters, since the attack payload is tiny but the compute cost is enormous

Python's `re` module uses a backtracking NFA engine, which is inherently vulnerable to patterns with nested quantifiers or ambiguous alternations. Even patterns that look harmless — like `(a+)+b` — can exhibit exponential backtracking.

## What Gets Flagged

This rule flags lines where a request parameter is passed directly to a `re` function:

```python
# Flagged: user-controlled regex pattern from Flask request
pattern = re.compile(request.args.get("q"))

# Flagged: search with request form data
result = re.search(request.form["pattern"], text)

# Flagged: match with request data
if re.match(request.data, some_string):
    ...

# Flagged: fullmatch with JSON body
re.fullmatch(request.json["regex"], input_text)
```

The rule applies only to `.py` files.

## Remediation

1. **Never let users supply raw regex patterns.** If you need user-driven search, use literal string matching (`str.find()`, `str.count()`, or `fnmatch` for glob patterns) instead of regex:

   ```python
   # Safe: literal substring search
   results = [item for item in items if query in item.lower()]
   ```

2. **Use the `google-re2` library for linear-time matching.** The RE2 engine guarantees O(n) execution regardless of pattern complexity, eliminating catastrophic backtracking entirely:

   ```python
   import re2

   # Safe: RE2 guarantees linear-time matching
   pattern = re2.compile(user_input)
   result = pattern.search(text)
   ```

   Install with: `pip install google-re2`

3. **If you must use Python's `re` module, validate and constrain the pattern.** Escape user input with `re.escape()` if it should be treated as a literal:

   ```python
   import re

   # Safe: escape treats the input as a literal string, not a pattern
   safe_pattern = re.escape(request.args.get("q", ""))
   results = re.findall(safe_pattern, text)
   ```

4. **Set a timeout for regex operations.** Python 3.11+ supports the `timeout` parameter:

   ```python
   import re

   try:
       result = re.search(fixed_pattern, text, timeout=1.0)
   except re.error:
       # Pattern evaluation exceeded timeout
       abort(400, "Search pattern too complex")
   ```

5. **Reject patterns that contain dangerous constructs.** If users must supply patterns, reject those with nested quantifiers like `(a+)+`, `(a*)*`, or `(a|b)*` before compilation.

## References

- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- [OWASP: Regular Expression Denial of Service (ReDoS)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [CAPEC-197: Exponential Data Expansion](https://capec.mitre.org/data/definitions/197.html)
- [MITRE ATT&CK T1499.004 – Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004/)
- [google-re2 Python Library](https://github.com/google/re2)
- [Python re Module Documentation](https://docs.python.org/3/library/re.html)
- [OWASP ASVS V5 – Validation, Sanitization, and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
