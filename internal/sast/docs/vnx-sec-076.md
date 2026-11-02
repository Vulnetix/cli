---
title: "VNX-SEC-076 – Telegram Bot API Token"
description: "Reports a whole Telegram Bot API token (bot id, a colon and a 35-character AA... secret) in any file, excluding placeholders, low-entropy bodies, environment references and test files."
---

## Overview

This rule reports a Telegram Bot API token: the bot's numeric id (8 to 10 digits), a colon and the 35-character secret that begins `AA`, quoted, assigned, inside an `api.telegram.org/bot<token>/` URL or in a `.env` file. The token is redacted in the finding's snippet.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded telegram bot api token values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## What Gets Flagged

```python
# FLAGGED: token passed to the bot framework
TOKEN = "<bot id>:AA<33 characters>"
app = ApplicationBuilder().token(TOKEN).build()
```

```bash
# FLAGGED: token inside the Bot API URL
curl -s "https://api.telegram.org/bot<bot id>:AA<33 characters>/sendMessage" -d chat_id=-100123456
```

Not flagged:

- A bot id on its own, and lookalikes such as `20240115:AAPL`.
- Placeholder or low-entropy bodies (`123456789:AAxxxx...`, `AAAA...`).
- Environment references (`os.environ["TELEGRAM_BOT_TOKEN"]`).
- Test, fixture, vendored and generated files.

VNX-SEC-728 reports the same token.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
