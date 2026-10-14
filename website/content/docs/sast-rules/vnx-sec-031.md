---
title: "VNX-SEC-031 – Mailgun API Key Hardcoded"
description: "Detect Mailgun private API keys (key- plus 32 characters, or the 32-8-8 hex form) hardcoded in files that name Mailgun, ignoring pubkey- validation keys and unrelated key- values."
---

## Overview

This rule flags source files where a Mailgun API key appears to be hardcoded. The pattern requires both a `key-` prefix followed by 32 alphanumeric characters (the Mailgun key format) and a Mailgun-related identifier in the same line — such as `mailgun`, `mg_api`, or `mg_key`. Mailgun API keys authenticate requests to the Mailgun API for email sending, log retrieval, domain configuration, and account management.

Mailgun API keys are account-level credentials. Unlike more modern API designs that support per-resource scopes, the Mailgun API key grants full access to send email from any domain in the account, retrieve message logs (potentially including email content), and modify domain settings including routing rules. An attacker with a valid Mailgun key can send phishing or spam email from your domain, access a log of messages sent or received, and configure routing rules to silently copy inbound email to an attacker-controlled address.

This rule corresponds to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Email sending credentials are high-value targets because they have both direct and indirect utility. Directly, they enable an attacker to send email as your domain — which can be used to send phishing messages to your users, send spam at your expense, and damage your domain's email reputation (leading to deliverability problems for legitimate messages).

Indirectly, Mailgun logs contain metadata about messages sent and received through the service. For transactional email systems, logs may contain password reset links, account activation tokens, or notification content — all of which can be used to take over user accounts without directly attacking the application.

A hardcoded API key in a repository is particularly dangerous if the repository is or ever was public, as automated scanners continuously monitor GitHub and similar platforms for credentials. Even private repositories can be exposed through accidental setting changes, compromised developer accounts, or third-party CI integrations.

## What Gets Flagged

The rule reports a legacy `key-` key (32 lowercase letters or digits) in a file that mentions Mailgun or an `MG_API_KEY`-style name, and the current `<32 hex>-<8 hex>-<8 hex>` form when Mailgun is named within three lines:

```text
# FLAGGED
auth=("api", "key-<32 characters>"),                  (requests.post to api.mailgun.net)
MAILGUN_API_KEY=key-<32 characters>
$mg = Mailgun::create('key-<32 characters>');
"MAILGUN_API_KEY": "<32 hex>-<8 hex>-<8 hex>",
```

Not flagged: `pubkey-` public validation keys, `key-` values in files with no Mailgun context (licence keys), the 32-8-8 hex shape far from any Mailgun name, placeholders, environment references, and test or fixture paths.

## Remediation

1. **Revoke the key immediately** at [app.mailgun.com/settings/api_security](https://app.mailgun.com/settings/api_security). Generate a new key only after revoking the old one.

2. **Load the key from an environment variable at runtime.** This is the standard approach for any API credential:

```python
# SAFE: key loaded from environment variable
import os
import requests

api_key = os.environ["MAILGUN_API_KEY"]
response = requests.post(
    f"https://api.mailgun.net/v3/{domain}/messages",
    auth=("api", api_key),
    data={...}
)
```

3. **Use a dedicated secrets manager for production.** HashiCorp Vault, AWS Secrets Manager, and similar tools provide audit logs, automatic rotation, and fine-grained access control for credentials:

```python
# SAFE: retrieve from AWS Secrets Manager
import boto3, json

secret = boto3.client("secretsmanager").get_secret_value(SecretId="mailgun/api-key")
api_key = json.loads(secret["SecretString"])["api_key"]
```

4. **Audit logs for evidence of misuse.** After revoking the key, check Mailgun logs for unexpected sending activity or log access that could indicate the key was already used maliciously.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Mailgun – API security and access management](https://documentation.mailgun.com/en/latest/api-security.html)
- [Mailgun – API reference](https://documentation.mailgun.com/en/latest/api_reference.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [AWS Secrets Manager documentation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
