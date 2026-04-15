---
title: "VNX-LLM-003 – Hardcoded LLM API Key"
description: "An LLM provider API key is hardcoded in source code, enabling unauthorized model usage and billing abuse by anyone with repository access."
---

## Overview

An LLM provider API key — such as an OpenAI key (sk-), an Anthropic key (sk-ant-), or a similar credential — is hardcoded as a string literal in source code or configuration. Hardcoded keys are committed to version control and can be exposed through repository leaks, logs, or build artifacts, allowing anyone who discovers the key to consume your quota or access your data.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

LLM API keys are credentials with real monetary value. A leaked OpenAI key can be used to run expensive inference jobs at your cost, access fine-tuned models, retrieve embeddings from your data, or abuse your usage tier. Attackers actively scan GitHub for exposed keys and begin exploiting them within minutes of exposure. Unlike database passwords, API keys for LLM services are often directly monetizable without any further lateral movement.

## What Gets Flagged

Hardcoded string literals matching known LLM API key patterns, or assignments to variables named after LLM API keys with a literal string value.

```python
# FLAGGED: OpenAI key hardcoded
openai.api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"

# FLAGGED: Anthropic key in variable
ANTHROPIC_API_KEY = "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXX"

# FLAGGED: key in constructor argument
client = openai.OpenAI(api_key="sk-abcdefghijklmnop1234567890ABCDEF")
```

## Remediation

1. Remove hardcoded keys from all source files and git history.
2. Rotate any exposed keys immediately via the provider's dashboard.
3. Load credentials from environment variables or a secrets manager.
4. Add key patterns to your `.gitignore` and pre-commit hooks.

```python
# SAFE: load key from environment variable
import os
client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OpenAI – Best Practices for API Key Safety](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety)
- [OWASP – Hardcoded Passwords](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
