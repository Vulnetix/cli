---
title: "Secrets — Webhooks & Signed URLs"
description: "Slack/Teams/Discord webhook URLs and signed URLs with embedded secrets."
weight: 13
---

Slack/Teams/Discord webhook URLs and signed URLs with embedded secrets.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-099"></a>VNX-SEC-099 | Zapier webhook URL | High | keyword + regex |
| <a id="vnx-sec-180"></a>VNX-SEC-180 | Cloudflare Workers / Pages deploy webhook URL | Medium | keyword + regex |
| <a id="vnx-sec-417"></a>VNX-SEC-417 | Discord webhook URL | High | keyword + regex |
| <a id="vnx-sec-457"></a>VNX-SEC-457 | Microsoft Teams incoming webhook URL (Power Automate) | High | keyword + regex |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
