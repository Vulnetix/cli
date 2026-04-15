---
title: "VNX-PY-004 – yaml.load() Without SafeLoader"
description: "Detect calls to yaml.load() that omit a safe Loader argument, allowing YAML documents to execute arbitrary Python code during parsing."
---

## Overview

This rule flags calls to `yaml.load()` that do not pass an explicit safe Loader (`SafeLoader`, `CSafeLoader`, or `BaseLoader`). Python's PyYAML library supports YAML tags that instantiate arbitrary Python objects during parsing. Without a safe loader, a malicious YAML document can call any Python constructor, effectively giving an attacker the ability to run arbitrary code simply by having their YAML parsed. The vulnerability is exploited by embedding a `!!python/object/apply` or `!!python/object/new` tag in the input. This maps to [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

**Severity:** High | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

YAML's full-load feature was designed for serializing and restoring Python objects — a legitimate use case when reading your own trusted data. However, the moment a YAML document crosses a trust boundary (network request body, user-uploaded config file, webhook payload, database value), the full loader becomes an RCE vector. Exploiting it requires no memory corruption or binary exploitation — just a specially crafted string:

```yaml
# Malicious YAML payload that executes a shell command when loaded
!!python/object/apply:subprocess.check_output
- ["id"]
```

When passed to `yaml.load()` without a safe loader, this YAML calls `subprocess.check_output(["id"])` and returns the result. An attacker can substitute any command or use `os.system` / `subprocess.Popen` to gain a shell, exfiltrate files, or establish persistence.

## What Gets Flagged

The rule flags any `yaml.load(` call that does not include `Loader=`, `SafeLoader`, `CSafeLoader`, or `BaseLoader` on the same line, and is not already using `safe_load`.

```python
# FLAGGED: no Loader argument — uses full loader by default (PyYAML < 6.0)
data = yaml.load(stream)

# FLAGGED: Loader not specified even with variable input
data = yaml.load(request.body)

# FLAGGED: loading from a file without a safe loader
with open("config.yaml") as f:
    config = yaml.load(f)
```

## Remediation

1. **Replace `yaml.load()` with `yaml.safe_load()`.** This is the simplest fix and handles the vast majority of use cases. `safe_load()` only supports standard YAML types: strings, numbers, lists, dicts, booleans, and null. It raises `yaml.constructor.ConstructorError` for any Python-specific tag.

```python
import yaml

# SAFE: safe_load cannot instantiate Python objects
config = yaml.safe_load(stream)
```

2. **If you must use `yaml.load()`, pass the safe Loader explicitly.**

```python
import yaml

# SAFE: explicit SafeLoader restricts to standard YAML types
config = yaml.load(stream, Loader=yaml.SafeLoader)

# SAFE: CSafeLoader is a faster C extension equivalent
config = yaml.load(stream, Loader=yaml.CSafeLoader)
```

3. **Use a context manager and validate the result's type.** Even with a safe loader it is good practice to validate the structure of the parsed data before using it:

```python
import yaml
from typing import Any

def load_config(path: str) -> dict[str, Any]:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("Config file must be a YAML mapping")
    return data
```

4. **For configuration with Python-specific types, prefer an alternative format.** If you genuinely need to round-trip Python objects, consider `json` (for standard types), `tomllib` (Python 3.11+ built-in), or `dataclasses` with a JSON schema validator. These formats have no equivalent of YAML's arbitrary constructor tags.

5. **Audit all PyYAML imports.** Search for `import yaml` and `from yaml import` and review every `yaml.load` call. PyYAML 6.0+ emits a warning when `yaml.load()` is called without a Loader; upgrading to 6.0+ makes unfixed calls visible in test output.

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PyYAML documentation – Loading YAML](https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml)
- [Python docs – yaml.safe_load](https://yaml.readthedocs.io/en/latest/api/#ruamel.yaml.YAML.safe_load)
- [CVE-2017-18342 – PyYAML arbitrary code execution](https://nvd.nist.gov/vuln/detail/CVE-2017-18342)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [MITRE ATT&CK T1059.006 – Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
