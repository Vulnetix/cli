---
title: "VNX-PY-013 – ML/AI Insecure Deserialization"
description: "Detect Python ML and data science code that loads model or data files using pickle-based deserializers, which can execute arbitrary code embedded in a malicious model file."
---

## Overview

This rule flags Python code that loads ML model files or serialized data using pickle-based functions: `torch.load()`, `joblib.load()`, `pandas.read_pickle()`, `pd.read_pickle()`, `pickle.load()`, `pickle.loads()`, `cPickle.load()`, `cPickle.loads()`, `shelve.open()`, `dill.load()`, `dill.loads()`, and `numpy.load()` with `allow_pickle=True`. These functions deserialize Python objects from a binary stream. Any model or data file loaded this way can contain embedded code that executes automatically at load time, giving an attacker who controls the file arbitrary code execution on the machine running the model. This maps to [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

**Severity:** Critical | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

ML model files are a relatively new and rapidly growing attack surface. Model files are large binary objects that are routinely shared via model hubs (Hugging Face Hub, PyTorch Hub, TensorFlow Hub), emailed between teams, downloaded from papers and blog posts, and committed to source repositories. Unlike source code, model files are not human-readable, so malicious payloads are invisible without specialised tooling.

Because PyTorch's `.pt`/`.pth` format uses pickle internally, any `.pt` file is a pickle stream that can contain arbitrary Python code in `__reduce__` hooks. When `torch.load(model_path)` is called, pickle executes this code before any model tensors are returned. An attacker who can influence which model file you load — by compromising a model hub account, performing a supply chain attack, serving a fake model via a MITM, or convincing a developer to load their "pretrained" model — gains full code execution on every machine that loads that file.

This threat is not theoretical: researchers have published proof-of-concept malicious PyTorch models, and model scanning tools like Protect AI's `modelscan` detect them in real-world model repositories.

## What Gets Flagged

```python
# FLAGGED: standard torch.load — uses pickle internally
model = torch.load("model.pt")
model = torch.load(model_path, map_location="cpu")

# FLAGGED: joblib deserialization
clf = joblib.load("classifier.pkl")

# FLAGGED: pandas read_pickle
df = pandas.read_pickle("data.pkl")
df = pd.read_pickle(cache_path)

# FLAGGED: dill is pickle-compatible with more type coverage
model = dill.load(open("model.dill", "rb"))

# FLAGGED: numpy with allow_pickle=True
embeddings = numpy.load("embeddings.npy", allow_pickle=True)
arr = np.load("data.npy", allow_pickle=True)

# FLAGGED: shelve uses pickle for values
db = shelve.open("cache")
```

## Remediation

1. **Use `torch.load(..., weights_only=True)` for PyTorch models (PyTorch 2.0+).** The `weights_only=True` flag restricts deserialization to tensor data only, refusing to unpickle arbitrary Python objects. This is the safe default for loading models from untrusted sources:

```python
import torch

# SAFE: weights_only=True blocks arbitrary code execution (PyTorch >= 2.0)
model = torch.load("model.pt", map_location="cpu", weights_only=True)
state_dict = torch.load("checkpoint.pt", weights_only=True)
```

2. **Use the SafeTensors format.** SafeTensors is a simple binary format designed specifically for safe model weight storage. It contains only numeric tensor data — no Python objects, no code. It is supported by Hugging Face Transformers, Diffusers, and the safetensors library:

```python
from safetensors.torch import load_file, save_file

# SAFE: SafeTensors contains only tensors, no executable code
tensors = load_file("model.safetensors")

# Saving a model in SafeTensors format
save_file(model.state_dict(), "model.safetensors")
```

3. **For scikit-learn and joblib models, export to ONNX or PMML instead of pickle.** These formats store model parameters as structured data rather than Python objects:

```python
# Export scikit-learn model to ONNX (requires skl2onnx)
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

initial_type = [("float_input", FloatTensorType([None, 4]))]
onnx_model = convert_sklearn(sklearn_model, initial_types=initial_type)

# SAFE: load ONNX model (no pickle, no code execution)
import onnxruntime as rt
sess = rt.InferenceSession("model.onnx")
```

4. **For numpy arrays, use `allow_pickle=False` and save in `.npy`/`.npz` format without object arrays.**

```python
import numpy as np

# SAFE: allow_pickle defaults to False in numpy >= 1.16.3
arr = np.load("data.npy")  # allow_pickle=False is default

# SAFE: save numeric arrays in npz format
np.savez("data.npz", embeddings=embedding_array, labels=label_array)
data = np.load("data.npz")  # numpy structured format, no pickle
```

5. **Verify model file integrity before loading.** Regardless of format, verify the SHA-256 hash of downloaded model files against a known-good value published by the model's author before loading:

```python
import hashlib

EXPECTED_SHA256 = "a3f8b2..."

def verify_and_load(path: str, expected_hash: str):
    with open(path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(f"Model file hash mismatch: {actual_hash}")
    return torch.load(path, weights_only=True)
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PyTorch documentation – torch.load weights_only parameter](https://pytorch.org/docs/stable/generated/torch.load.html)
- [SafeTensors – A simple, safe format for storing tensors](https://github.com/huggingface/safetensors)
- [Protect AI – modelscan (model security scanner)](https://github.com/protectai/modelscan)
- [Hugging Face – Pickle scanning and SafeTensors adoption](https://huggingface.co/docs/hub/security-pickle)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
