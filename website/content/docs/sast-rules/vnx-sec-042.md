---
title: "VNX-SEC-042 – Slack Incoming Webhook URL"
description: "Detects hardcoded Slack incoming webhook URLs (hooks.slack.com) that grant the ability to post messages to a Slack channel."
---

## Overview

This rule detects Slack incoming webhook URLs in the form `https://hooks.slack.com/{services,workflows,triggers}/<43-56 char token>`. Slack webhooks let anyone who knows the URL post arbitrary messages to the channel the webhook is wired to. They cannot read messages, but they are routinely abused for phishing (fake "your account was compromised" alerts), spam, and pivoting into a workspace's trust graph.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Webhook URLs are long, high-entropy strings, but unlike API tokens they are routinely pasted into code samples, blog posts, and Stack Overflow answers. Once exposed, the only way to invalidate them is to delete the webhook in the Slack app configuration and create a new one. Because Slack does not surface webhook URLs in any secret-scanning program, they often go unnoticed in public repos for years.

## What Gets Flagged

```python
# FLAGGED
slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
requests.post(slack_webhook, json={"text": "Hello from CI"})
```

## Remediation

1. **Delete the webhook in api.slack.com** → Your App → Incoming Webhooks. The old URL immediately stops accepting posts.
2. **Create a new webhook** and store its URL in a secrets manager (AWS Secrets Manager, GitHub Actions secrets, HashiCorp Vault).
3. **If you must reference a webhook in a public repo** (e.g. example code), use a clearly fake placeholder like `https://hooks.slack.com/services/REPLACE/WITH/YOUR-WEBHOOK-URL`.
4. **Audit Slack audit logs** for posts you did not initiate between the time the URL was committed and the revocation.
5. **Consider migrating to a Slack app with OAuth** so users can revoke access at any time without rotating a single secret.

## References

- [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `slack-webhook-url`](https://github.com/gitleaks/gitleaks)
- [truffleHog `SlackWebhook`](https://github.com/trufflesecurity/trufflehog)
- [MITRE ATT&CK T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)
