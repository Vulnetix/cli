---
title: "VNX-SEC-018 – AI Provider API Key"
description: "Detects hardcoded Anthropic (sk-ant-), OpenAI (sk-proj-), and Hugging Face (hf_) API keys in source code, which grant access to paid AI services."
---

## Overview

This rule detects API keys for major AI providers in source files: Anthropic keys matching `sk-ant-[A-Za-z0-9\-_]{20,}`, OpenAI project keys matching `sk-proj-[A-Za-z0-9]{20,}`, and Hugging Face tokens matching `hf_[A-Za-z0-9]{34,}`. These keys authenticate requests to large language model APIs and other AI services. Leaking them results in unauthorized use charged to your account, potential data exfiltration through the API, and abuse of your usage limits and rate limits.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

AI API costs can be substantial — GPT-4, Claude, and similar models charge per token, and an attacker with access to your API key can run unlimited queries at your expense. Automated bots scan public repositories specifically for AI provider key patterns, and abuse often begins within minutes of a key being committed to a public repository. Beyond financial harm, an attacker using your API key could use your account's conversation history and organisational context to extract sensitive business information that has been submitted to the API in previous requests.

Hugging Face tokens with write or admin scopes can modify model repositories, datasets, or spaces — a supply chain attack vector if your organisation publishes open models or datasets. In a CI/CD context, a leaked inference API token can be used to probe proprietary fine-tuned models, extract training data, or conduct model inversion attacks.

**OWASP ASVS v4** requirement V2.10.1 prohibits storing service credentials in source code, requiring instead that they be loaded from environment variables or secrets management infrastructure at runtime.

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

Note: lock files (`.lock`, `.sum`) and minified JavaScript (`.min.js`) are excluded from analysis.

## Remediation

### Immediate steps when a key is found

1. **Rotate the API key immediately.**
   - **Anthropic:** Go to [console.anthropic.com](https://console.anthropic.com) → API Keys → Disable the exposed key → Create a new one.
   - **OpenAI:** Go to [platform.openai.com/api-keys](https://platform.openai.com/api-keys) → Revoke the exposed key → Create a new one.
   - **Hugging Face:** Go to [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens) → Delete → Create new.

2. **Check for unauthorised usage.** Review usage logs in the respective provider console. For Anthropic and OpenAI, look for unexpected token consumption or unusual query patterns. For Hugging Face, check the audit log for unexpected inference calls or repository modifications.

3. **Purge from git history.** The key is permanently in version control until history is rewritten:

```bash
# Using git-filter-repo (recommended over filter-branch)
pip install git-filter-repo
git filter-repo --replace-text <(printf 'sk-ant-api03-THEEXPOSEDKEY==>REDACTED_ANTHROPIC_KEY\n')

# Verify the key is gone
git log -p | grep "sk-ant-"

# Force push all branches and tags
git push --force --all
git push --force --tags
```

### Replacing hardcoded keys

```python
# SAFE: Anthropic key from environment
import anthropic, os

client = anthropic.Anthropic(api_key=os.environ['ANTHROPIC_API_KEY'])
```

```python
# SAFE: OpenAI SDK reads OPENAI_API_KEY automatically
from openai import OpenAI

client = OpenAI()  # reads OPENAI_API_KEY from environment
```

```python
# SAFE: Hugging Face token from environment
import os
from huggingface_hub import InferenceClient

client = InferenceClient(token=os.environ['HF_TOKEN'])
```

### Secrets management in production

```python
# SAFE: fetch from AWS Secrets Manager
import boto3, json, os

def get_ai_credentials():
    client = boto3.client('secretsmanager', region_name=os.environ['AWS_REGION'])
    secret = client.get_secret_value(SecretId='prod/ai/anthropic')
    return json.loads(secret['SecretString'])

api_key = get_ai_credentials()['api_key']
```

### Scoping and spending controls

4. **Create scoped API keys with minimum permissions.** OpenAI supports project-level API keys with restricted model access. Hugging Face tokens can be scoped to read-only, specific repositories, or read/write. Use separate keys for development and production.

5. **Set spending limits and usage alerts.** Configure budget alerts in your AI provider dashboards to detect unauthorised use through anomalous spending, even if a key leak is not yet detected.

### Preventing future regressions

```bash
# Install and configure detect-secrets
pip install detect-secrets
detect-secrets scan > .secrets.baseline
# Commit .secrets.baseline and add to pre-commit hooks

# Or use gitleaks as a pre-commit hook
# .pre-commit-config.yaml:
# - repo: https://github.com/gitleaks/gitleaks
#   rev: v8.18.0
#   hooks:
#     - id: gitleaks

# Or use git-secrets from AWS Labs
git secrets --install
git secrets --register-aws  # includes AI provider patterns
```

In GitHub Actions, store keys in [encrypted secrets](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions) and reference them via `${{ secrets.ANTHROPIC_API_KEY }}`.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP ASVS v4 – V2.10: Service Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [Anthropic: API key management](https://docs.anthropic.com/en/api/getting-started)
- [OpenAI: API key safety best practices](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety)
- [Hugging Face: User access tokens](https://huggingface.co/docs/hub/en/security-tokens)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [OWASP: Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [detect-secrets: Yelp's secret scanning tool](https://github.com/Yelp/detect-secrets)
- [gitleaks: Secret scanning tool](https://github.com/gitleaks/gitleaks)
- [git-secrets: AWS Labs secret scanning](https://github.com/awslabs/git-secrets)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
