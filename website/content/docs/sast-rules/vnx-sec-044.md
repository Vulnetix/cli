---
title: "VNX-SEC-044 – Microsoft Teams Webhook URL"
description: "Detects Microsoft Teams incoming webhook URLs hardcoded in source code."
---

## Overview

This rule detects Microsoft Teams incoming webhook URLs in the form `https://*.webhook.office.com/webhookb2/...`. These URLs grant the ability to post messages to a Teams channel and are commonly leaked in CI logs and public config files.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Teams webhook URL lets any attacker post to the channel, which is often the same channel where incident-response and security alerts are delivered. The attacker can use this for phishing (fake "your password expires today" messages), social engineering, or simply to drown out real alerts with noise.

Microsoft has deprecated the legacy Office 365 Connectors in favour of Workflows, but a large number of pre-2025 webhooks remain valid.

## Remediation

1. **Delete the webhook in Teams** → Channel • • • → Connectors → Incoming Webhook → Configure → Delete.
2. **Migrate to a Power Automate workflow** with an HTTP trigger and an Azure AD-protected endpoint.
3. **Store the new webhook URL in Azure Key Vault or GitHub Actions secrets**.
4. **Audit Teams channel activity** for messages you did not post.
5. **Purge from git history** with `git filter-repo`.

## References

- [Microsoft Teams Incoming Webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
- [Microsoft 365 Connectors retirement](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `microsoft-teams-webhook`](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)
