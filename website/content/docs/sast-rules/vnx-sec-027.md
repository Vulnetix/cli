---
title: "VNX-SEC-027 – Hugging Face API Token Hardcoded"
description: "Detect Hugging Face user access tokens (hf_ followed by 34 to 40 letters or digits) hardcoded in code, notebooks and config, ignoring placeholders, hf_-prefixed CamelCase identifiers and test paths."
---

## Overview

This rule flags source files that contain a string matching the Hugging Face API token format: the prefix `hf_` followed by 34 or more alphanumeric characters. Hugging Face API tokens authenticate access to the Hugging Face Hub, the central repository for machine learning models and datasets. Depending on the token's scope, it may provide read access to private repositories, write access to publish or modify models and datasets, or inference API access to hosted model endpoints.

As the adoption of AI/ML infrastructure grows, Hugging Face tokens have become high-value credentials. Private models may represent significant intellectual property investment. Datasets may contain sensitive training data. Inference endpoints often process confidential inputs. A hardcoded token exposes all of these resources to anyone who can read the repository.

This rule corresponds to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hugging Face hosts both public and private model repositories. Organizations frequently host fine-tuned proprietary models, confidential datasets, and internal tooling on private Hugging Face repositories. A leaked API token grants an attacker the ability to download proprietary model weights and training data, modify or delete hosted models, publish malicious model versions to a trusted repository (potentially poisoning downstream users), and make inference API calls at the token owner's expense.

Token theft from source code is particularly common in AI/ML projects because research code is often written quickly, tokens are pasted directly into notebooks or scripts for convenience, and the code is later shared or published without cleaning credentials. Automated scanners monitor public repositories continuously, and a valid token may be harvested and used within minutes of exposure.

Hugging Face tokens are also scoped at creation time. A token created with `write` scope on all repositories provides a much larger blast radius than a read-only token, but both warrant immediate revocation on exposure.

## What Gets Flagged

The rule reports `hf_` followed by 34 to 40 letters or digits, delimited on both sides, with the entropy of a random token:

```text
# FLAGGED
login(token="hf_<34 random characters>")
HF_TOKEN=hf_<34 random characters>
const hf = new HfInference(`hf_<34 random characters>`);
"os.environ['HUGGING_FACE_HUB_TOKEN'] = 'hf_<34 random characters>'\n"   (inside a .ipynb)
```

Not flagged: `hf_xxxx...` and `hf_<YOUR_TOKEN>` placeholders, identifiers such as `hf_TokenizerFastLoaderForSequenceModels`, `os.environ["HF_TOKEN"]`, a regular expression for the token, and test or fixture paths.

## Remediation

1. **Revoke the token immediately** at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens). Delete the exposed token and generate a new one with the minimum scope required.

2. **Use environment variables to provide the token at runtime.** The `huggingface_hub` library automatically reads `HF_TOKEN` from the environment:

```python
# SAFE: token injected via environment variable
import os
from huggingface_hub import login

login(token=os.environ["HF_TOKEN"])
```

3. **Use the Hugging Face CLI for interactive authentication.** For developer workstations, use `huggingface-cli login` which stores the token in the OS keyring rather than in source files:

```bash
# SAFE: stores token securely, not in source code
huggingface-cli login
```

4. **In CI/CD pipelines, inject the token as an encrypted secret.** Never embed tokens in workflow files or Dockerfiles:

```yaml
# SAFE: GitHub Actions secret
- name: Download model
  env:
    HF_TOKEN: ${{ secrets.HUGGINGFACE_TOKEN }}
  run: python download_model.py
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Hugging Face – User access tokens](https://huggingface.co/docs/hub/security-tokens)
- [Hugging Face – Security and privacy](https://huggingface.co/docs/hub/security)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub Actions – Encrypted secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
