---
title: "VNX-SEC-043 – Twilio API Key"
description: "Detects Twilio API keys (SK prefix, 32 hex chars) hardcoded in source code."
---

## Overview

This rule detects Twilio API keys matching `SK[0-9a-fA-F]{32}`. These keys (different from the Account SID + Auth Token pair) are issued via the Twilio console and grant the ability to send SMS, make voice calls, and read account logs.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Twilio API key is sufficient to drain the account balance via SMS pumping fraud (sending thousands of messages to premium-rate numbers controlled by the attacker) or to use the account for phishing and account-takeover campaigns (e.g. by sending "your account was compromised, click here" messages).

## Remediation

1. **Delete the API key in the Twilio console** → Account → API keys & tokens.
2. **Enable geo-permissions and 2FA on the Twilio account** to limit blast radius.
3. **Store the new key in Twilio Vault, AWS Secrets Manager, or a CI secret store**.
4. **Audit the Twilio usage logs** for SMS sent to numbers you did not intend to contact.
5. **Purge from git history** with `git filter-repo`.

## References

- [Twilio API Keys](https://www.twilio.com/docs/iam/api-keys)
- [Twilio SMS Pumping Fraud mitigation](https://www.twilio.com/docs/messaging/compliance/sms-pumping)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `twilio-api-key`](https://github.com/gitleaks/gitleaks)
- [truffleHog Twilio detector](https://github.com/trufflesecurity/trufflehog)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
