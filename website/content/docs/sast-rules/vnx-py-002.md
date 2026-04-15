---
title: "VNX-PY-002 – eval() / exec() Usage"
description: "Detect use of Python's eval() and exec() built-in functions, which execute arbitrary code and enable remote code execution when any part of their input is user-controlled."
---

## Overview

This rule flags calls to Python's built-in `eval()` and `exec()` functions. Both functions evaluate their string argument as executable Python code, making them equivalent to giving an attacker a Python shell if any portion of the argument originates from user input, a network response, a file, or any other external source. Even usage with seemingly static input is dangerous because it establishes a pattern that is easy to accidentally extend with dynamic content. This maps to [CWE-94: Improper Control of Generation of Code (Code Injection)](https://cwe.mitre.org/data/definitions/94.html).

**Severity:** High | **CWE:** [CWE-94 – Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

A successful code injection via `eval()` or `exec()` gives an attacker the same privileges as the Python process. In a web application context this typically means the ability to read environment variables (and therefore secrets and credentials), open outbound network connections, read or write arbitrary files, and execute system commands. Unlike many other vulnerability classes, there is no partial exploitation — the attacker has full control once the injection succeeds.

Developers often reach for `eval()` as a shortcut to parse structured data (JSON-like expressions, configuration, arithmetic) or to implement plugin systems. Every one of those use cases has a safe, purpose-built alternative. The `exec()` function is commonly used in code generation or test tooling, but even in those contexts restricting the globals/locals dictionaries does not provide meaningful security — an attacker can escape the restriction using `__builtins__` introspection.

## What Gets Flagged

Any line in a `.py` file that calls `eval(` or `exec(` is flagged, regardless of the argument.

```python
# FLAGGED: eval with user input — direct RCE
result = eval(request.form["expression"])

# FLAGGED: exec with string concatenation
exec("import " + user_supplied_module)

# FLAGGED: even with restricted globals, escape is possible
exec(user_code, {"__builtins__": {}})

# FLAGGED: eval inside a helper function still executes arbitrary code
def parse_expr(s):
    return eval(s)
```

## Remediation

1. **For parsing data literals, use `ast.literal_eval()`.** This function only evaluates Python literals (strings, numbers, tuples, lists, dicts, booleans, and `None`). It raises a `ValueError` for anything that is not a safe literal and cannot execute arbitrary code.

```python
import ast

# SAFE: parses only Python literals, raises ValueError for anything else
value = ast.literal_eval(user_input)
```

2. **For parsing structured data, use a dedicated parser.**

```python
import json

# SAFE: parse JSON without executing code
data = json.loads(user_input)
```

3. **For arithmetic evaluation, use a math-safe library.**

```python
import simpleeval  # pip install simpleeval

# SAFE: evaluates arithmetic expressions without code execution
result = simpleeval.simple_eval(expression)
```

4. **For plugin and extension systems, use importlib with an explicit allowlist.**

```python
import importlib

ALLOWED_PLUGINS = {"plugin_a", "plugin_b", "plugin_c"}

def load_plugin(name: str):
    if name not in ALLOWED_PLUGINS:
        raise ValueError(f"Unknown plugin: {name}")
    return importlib.import_module(f"myapp.plugins.{name}")
```

5. **For template rendering, use a template engine.** Replace `exec`-based string templating with Jinja2 or similar, which separates code from data by design.

6. **If you genuinely need dynamic code execution (e.g., a REPL or notebook), isolate it.** Run the dynamic code in a subprocess with reduced privileges, a container, or a sandbox such as `RestrictedPython`.

## References

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Python docs – ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval)
- [Python docs – Built-in functions: eval](https://docs.python.org/3/library/functions.html#eval)
- [CAPEC-35: Leverage Executable Code in Non-Executable Files](https://capec.mitre.org/data/definitions/35.html)
- [MITRE ATT&CK T1059.006 – Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
