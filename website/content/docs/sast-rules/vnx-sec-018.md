---
title: "VNX-SEC-018 – AI Provider API Key"
description: "Detects hardcoded Anthropic (sk-ant-), OpenAI (sk-proj-), and Hugging Face (hf_) API keys in source code, which grant access to paid AI services."
---

## Overview

This rule detects API keys for major AI providers in source files: Anthropic keys matching `sk-ant-[A-Za-z0-9\-_]{20,}`, OpenAI project keys matching `sk-proj-[A-Za-z0-9]{20,}`, and Hugging Face tokens matching `hf_[A-Za-z0-9]{34,}`. These keys authenticate requests to large language model APIs and other AI services. Leaking them results in unauthorized use charged to your account, potential data exfiltration through the API, and abuse of your usage limits and rate limits.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

AI API costs can be substantial — GPT-4, Claude, and similar models charge per token, and an attacker with access to your API key can run unlimited queries at your expense. Automated bots scan public repositories specifically for AI provider key patterns, and abuse often begins within minutes of a key being committed to a public repository. Beyond financial harm, an attacker using your API key could use your account's conversation history and organizational context to extract sensitive business information that has been submitted to the API in previous requests.

Hugging Face tokens with write or admin scopes can modify model repositories, datasets, or spaces — a supply chain attack vector if your organization publishes open models or datasets. In a CI/CD context, a leaked inference API token can be used to probe proprietary fine-tuned models, extract training data, or conduct model inversion attacks.

## What Gets Flagged

```python
# FLAGGED: Anthropic API key hardcoded
import anthropic

client = anthropic.Anthropic(api_key="sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
message = client.messages.create(
    model="claude-opus-4-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}]
)
```

```python
# FLAGGED: OpenAI API key hardcoded
from openai import OpenAI

client = OpenAI(api_key="sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
completion = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}]
)
```

```python
# FLAGGED: Hugging Face token hardcoded
from huggingface_hub import InferenceClient

client = InferenceClient(token="hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
```

## Remediation

1. **Rotate the API key immediately.**
   - **Anthropic:** Go to console.anthropic.com → API Keys → Disable the exposed key → Create a new one.
   - **OpenAI:** Go to platform.openai.com → API Keys → Revoke the exposed key → Create a new one.
   - **Hugging Face:** Go to huggingface.co → Settings → Access Tokens → Delete → Create new.

2. **Check for unauthorized usage.** Review usage logs in the respective provider console. For Anthropic and OpenAI, look for unexpected token consumption or unusual query patterns.

3. **Remove from source code.** Load the key from an environment variable:

```python
# SAFE: Anthropic key from environment
import anthropic
import os

client = anthropic.Anthropic(api_key=os.environ['ANTHROPIC_API_KEY'])
```

```python
# SAFE: OpenAI key from environment
# OpenAI SDK automatically reads OPENAI_API_KEY if not specified
from openai import OpenAI

client = OpenAI()  # reads from OPENAI_API_KEY environment variable
```

```python
# SAFE: Hugging Face token from environment
import os
from huggingface_hub import InferenceClient

client = InferenceClient(token=os.environ['HF_TOKEN'])
```

4. **Scope the new API key with minimum permissions.** OpenAI supports project-level API keys with restricted capabilities. Hugging Face tokens can be scoped to read-only, specific repositories, or read/write. Create separate keys for development and production.

5. **Use a secrets manager in production.** Store AI API keys in AWS Secrets Manager, HashiCorp Vault, or your cloud provider's secret store, and fetch them at runtime:

```python
# SAFE: fetch Anthropic API key from AWS Secrets Manager
import boto3, json, os

def get_ai_credentials():
    client = boto3.client('secretsmanager', region_name=os.environ['AWS_REGION'])
    secret = client.get_secret_value(SecretId='prod/ai/anthropic')
    return json.loads(secret['SecretString'])

api_key = get_ai_credentials()['api_key']
```

6. **Set spending limits and usage alerts** in your AI provider dashboards to detect unauthorized use through anomalous spending patterns even if the key was leaked but not yet detected.

7. **Scan git history** for the exposed key:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'sk-ant-xxxx==>REDACTED_ANTHROPIC_KEY')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Anthropic: API key management](https://docs.anthropic.com/en/api/getting-started)
- [OpenAI: API key safety best practices](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety)
- [Hugging Face: User access tokens](https://huggingface.co/docs/hub/en/security-tokens)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
