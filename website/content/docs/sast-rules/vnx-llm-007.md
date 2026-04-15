---
title: "VNX-LLM-007 – torch.load() Without weights_only=True"
description: "Detects torch.load() calls without the weights_only=True parameter, which allows arbitrary code execution when loading untrusted or attacker-supplied PyTorch model files via Python's pickle protocol."
---

## Overview

`torch.load()` uses Python's `pickle` module by default to deserialise model files. Pickle is a general-purpose serialisation format that can encode arbitrary Python objects, including objects whose `__reduce__` method executes arbitrary code when unpickled. Loading an attacker-supplied model file with `torch.load()` is equivalent to executing arbitrary Python code with the privileges of the loading process. This is CWE-502 (Deserialization of Untrusted Data).

PyTorch version 1.13 introduced the `weights_only=True` parameter, which restricts deserialisation to a safe subset of types (tensors, numeric types, and basic containers) and disables the arbitrary object deserialisation that enables code execution. From PyTorch 2.0 onwards, a `FutureWarning` is emitted when `weights_only` is not specified, signalling that the default will eventually change. This rule flags any `torch.load()` call in a Python file that does not include `weights_only=True`.

The `safetensors` format (developed by Hugging Face) is a safer alternative that natively supports only tensor data and has no deserialisation vulnerability by design. Migrating model storage to safetensors is the most robust long-term solution.

**Severity:** High | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Machine learning model files are increasingly distributed through public repositories (Hugging Face Hub, PyTorch Hub, TensorFlow Hub), model registries, and artifact stores. An attacker who can supply or modify a model file — through a compromised registry, a dependency confusion attack, a poisoned training pipeline, or a man-in-the-middle on an unverified download — can achieve code execution on any machine that loads the file with `torch.load()`.

The attack is reliable and requires no vulnerability in the application code. A malicious model file is a valid PyTorch model file that also embeds a pickle payload. When loaded, the payload executes first, before the model weights are ever used. The loading machine's filesystem, environment variables, network access, and process credentials are all accessible to the payload.

This attack vector is particularly concerning in MLOps pipelines where models are automatically downloaded and loaded as part of training or inference workflows. A single poisoned model in a shared model registry can compromise every node in a distributed training cluster or every inference server in a deployment.

## What Gets Flagged

```python
# FLAGGED: torch.load() without weights_only parameter
model = torch.load("model.pth")

# FLAGGED: torch.load() with map_location but no weights_only
model.load_state_dict(torch.load("checkpoint.pt", map_location="cpu"))

# FLAGGED: loading from a path variable
state = torch.load(model_path)
```

## Remediation

1. **Add `weights_only=True`** to all `torch.load()` calls. This is a one-argument change that prevents arbitrary code execution from pickle payloads.

2. **Verify model integrity** before loading. Download model files over HTTPS, verify SHA-256 checksums against a trusted manifest, and sign model files in internal registries.

3. **Migrate to safetensors** for new model storage. The `safetensors` library supports PyTorch, TensorFlow, JAX, and NumPy arrays, and its format is immune to deserialisation attacks by design.

4. **Load models in a sandboxed environment** if loading from untrusted sources is unavoidable (e.g., user-submitted model files). Use a container with no network access, minimal filesystem access, and resource limits.

```python
# SAFE: weights_only=True prevents arbitrary pickle execution
import torch

model = torch.load("model.pth", weights_only=True)

# SAFE: with map_location and weights_only
state_dict = torch.load("checkpoint.pt", map_location="cpu", weights_only=True)
model.load_state_dict(state_dict)
```

```python
# PREFERRED: safetensors format (no deserialisation vulnerability)
from safetensors.torch import load_file, save_file

# Save
save_file(model.state_dict(), "model.safetensors")

# Load
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

```python
# SAFE: integrity verification before loading
import hashlib

EXPECTED_SHA256 = "a3f5e8c1..."  # from trusted manifest

with open(model_path, "rb") as f:
    actual = hashlib.sha256(f.read()).hexdigest()

if actual != EXPECTED_SHA256:
    raise ValueError(f"Model checksum mismatch: {actual} != {EXPECTED_SHA256}")

model = torch.load(model_path, weights_only=True)
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch Security: torch.load() Documentation](https://pytorch.org/docs/stable/generated/torch.load.html)
- [Hugging Face safetensors Library](https://huggingface.co/docs/safetensors/)
- [OWASP LLM Top 10: LLM05 – Supply Chain Vulnerabilities](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS: ML Supply Chain Compromise (AML.T0010)](https://atlas.mitre.org/techniques/AML.T0010)
