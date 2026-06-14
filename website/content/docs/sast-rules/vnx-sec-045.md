---
title: "VNX-SEC-045 – Discord Bot Token"
description: "Detects Discord bot tokens hardcoded in source code."
---

## Overview

This rule detects Discord bot tokens in the form `<base64-id>.<7-char>.<38-char>`. Discord bot tokens grant the ability to act on behalf of the bot — read every DM the bot receives, post messages to channels the bot is in, and modify server settings the bot has permissions for.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Discord bot token can be used to scrape every DM the bot receives — including user reports, support tickets, and personal data. Discord's API does not require a re-authorization flow to use an existing bot token, so the attacker can act as the bot indefinitely until the token is regenerated.

## Remediation

1. **Regenerate the bot token in the Discord developer portal** → Applications → Bot → Reset Token.
2. **Store the new token in a secrets manager** (AWS SSM, Vault, Doppler, GitHub Actions secrets).
3. **Audit the bot's recent DMs and channel posts** for messages you did not author.
4. **Purge from git history** with `git filter-repo`.

## References

- [Discord Bot Tokens](https://discord.com/developers/docs/topics/oauth2#bot-tokens)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `discord-bot-token`](https://github.com/gitleaks/gitleaks)
- [truffleHog DiscordBot detector](https://github.com/trufflesecurity/trufflehog)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
