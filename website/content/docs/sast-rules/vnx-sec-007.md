---
title: "VNX-SEC-007 – Slack Token or Webhook"
description: "Reports a hard-coded Slack token (xoxb-, xoxp-, xoxa-, xoxo-, xoxr-, xoxs- with a numeric id) or incoming-webhook/workflow URL in any file, excluding Slack's documented example webhook, placeholders, configured base URLs, environment references and test files."
---

## Overview

This rule detects two categories of Slack credentials in source files: API tokens matching the pattern `xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{10,}`, and incoming webhook URLs matching `https://hooks.slack.com/services/T.../B.../...`. Slack tokens authenticate bot, user, and app interactions with the Slack API, while webhooks allow posting messages to channels. Both types of credential, if exposed, can be used to read workspace content, send messages impersonating your application, or enumerate workspace members.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Slack workspaces frequently contain sensitive business information: product roadmaps, customer data shared in support channels, internal credentials pasted in chats, and personnel discussions. A leaked bot token with `channels:read` and `messages:read` scopes can silently exfiltrate months of conversation history. Tokens with `chat:write` scope can impersonate your bot to send phishing messages to team members within the workspace.

Webhook URLs are often considered less sensitive, but they allow anyone with the URL to post arbitrary messages to the associated channel — enabling social engineering attacks, misinformation campaigns, or channel spam that disrupts your team.

Token types by prefix:
- `xoxb-`: Bot token — most common, used by Slack apps
- `xoxp-`: User token — acts as a real user, highest impact
- `xoxa-`: App-level token — workspace-level permissions
- `xoxs-`: Workspace token (legacy)
- `xoxr-`: Refresh token

## What Gets Flagged

A Slack bot, user, workspace, refresh or legacy token (`xoxb-`, `xoxp-`, `xoxa-`, `xoxo-`, `xoxr-`, `xoxs-` followed by a numeric team or user id and a secret segment), and an incoming-webhook or workflow URL (`https://hooks.slack.com/services/T.../B.../<secret>`, `/workflows/T.../A.../<id>/<secret>`, `/triggers/T.../<id>/<secret>`).

```python
# FLAGGED: bot token passed to the SDK
client = WebClient(token="xoxb-<team id>-<user id>-<secret>")
```

```go
// FLAGGED: webhook URL in a constant
const alertWebhook = "https://hooks.slack.com/services/T<id>/B<id>/<secret>"
```

Not flagged:

- Slack's documented example webhook (`T00000000/B00000000/XXXXXXXX...`) and other placeholder runs.
- Tokens without a numeric id (`xoxb-your-token`).
- A webhook base URL with no secret segment, built from configuration.
- Prefix lists, environment references (`os.environ["SLACK_BOT_TOKEN"]`), and test, fixture, vendored and generated files.

Configuration-refresh (`xoxe-`) and app-level (`xapp-`) tokens are VNX-SEC-419/420/421.

## Remediation

1. **Rotate the token immediately.** For bot/app tokens: go to api.slack.com → Your Apps → select the app → OAuth & Permissions → Reinstall App (this issues new tokens). For webhook URLs: go to the app's Incoming Webhooks section and regenerate the webhook URL.

2. **Remove from source code.** Load from environment variables:

```python
# SAFE: load Slack token from environment
import os
from slack_sdk import WebClient

client = WebClient(token=os.environ['SLACK_BOT_TOKEN'])
response = client.chat_postMessage(channel='#general', text='Hello!')
```

```bash
# SAFE: webhook URL from environment in shell
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Deploy complete"}' \
  "${SLACK_WEBHOOK_URL}"
```

3. **Review Slack audit logs** if your workspace is on a Business+ or Enterprise plan. Check for unexpected API calls or message activity using the token. In the Slack Admin Console go to Security → Audit Logs.

4. **Apply minimal scopes when creating new tokens.** When creating a new Slack app or bot, request only the OAuth scopes your code actually uses. A notification bot needs `chat:write` but not `channels:history` or `users:read`.

5. **Use Slack's Socket Mode for apps** running behind firewalls — this eliminates the need for webhook URLs entirely, replacing them with a persistent WebSocket connection authenticated via an app-level token stored securely.

6. **Scan git history** for any exposed tokens or webhook URLs:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'xoxb-123456789012==>REDACTED_SLACK_TOKEN')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Slack: Token types](https://api.slack.com/authentication/token-types)
- [Slack: Rotating tokens](https://api.slack.com/authentication/rotation)
- [Slack: App security best practices](https://api.slack.com/authentication/best-practices)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
