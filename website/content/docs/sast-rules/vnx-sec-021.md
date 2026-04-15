---
title: "VNX-SEC-021 – Twilio API Credentials"
description: "Detects hardcoded Twilio API keys (SK prefix) and Account SIDs (AC prefix) in source code, which grant access to SMS, voice, and video communication services."
---

## Overview

This rule detects Twilio credentials in source files: API keys matching `SK[a-f0-9]{32}` and Account SIDs matching `AC[a-f0-9]{32}`. Twilio credentials authenticate requests to the Twilio API for SMS messaging, voice calls, WhatsApp, video conferencing, and email services. An Account SID combined with an Auth Token (or an API key pair) provides full programmatic access to all communication services on the account, including the ability to send messages, make calls, and access call logs.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Leaked Twilio credentials enable several high-impact attack scenarios. The most immediate is SMS-based fraud and harassment: an attacker can use your account to send bulk SMS messages to phone numbers around the world, generating large bills on your Twilio account. Twilio charges per message, and a sustained attack can accumulate thousands of dollars in charges within hours.

Beyond financial harm, an attacker can use your Twilio account to conduct SMS phishing (smishing) campaigns that appear to originate from your verified sender ID, impersonating your service to your users. They can also intercept OTP (one-time password) messages if your account is used for 2FA delivery, and access call recordings or message logs containing sensitive customer information.

There are documented cases of attackers stealing Twilio credentials from source repositories and using them to intercept 2FA codes for downstream attacks on other services — as demonstrated by the 2022 Twilio breach that affected Okta, Signal, and other companies in a supply chain compromise.

## What Gets Flagged

```python
# FLAGGED: Twilio credentials hardcoded
from twilio.rest import Client

account_sid = 'ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
auth_token = 'your_auth_token_here'
client = Client(account_sid, auth_token)

message = client.messages.create(
    body='Your verification code is 123456',
    from_='+15017122661',
    to='+15558675310'
)
```

```python
# FLAGGED: Twilio API key hardcoded
from twilio.rest import Client

client = Client(
    'SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',  # API key SID
    'your_api_key_secret'                  # API key secret
)
```

## Remediation

1. **Revoke the credentials immediately.** For Auth Tokens: log into console.twilio.com → Account → API keys & tokens → Secondary Auth Token → Promote to primary (this invalidates the old primary). For API keys: Account → API keys & tokens → find the key → Revoke.

2. **Review Twilio usage logs.** In the Twilio Console go to Monitor → Logs → Messages and Calls. Filter by date to identify any messages or calls made during the exposure window.

3. **Remove from source code.** Load credentials from environment variables:

```python
# SAFE: load Twilio credentials from environment
import os
from twilio.rest import Client

account_sid = os.environ['TWILIO_ACCOUNT_SID']
auth_token = os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)

message = client.messages.create(
    body='Your verification code is 123456',
    from_=os.environ['TWILIO_FROM_NUMBER'],
    to=recipient_number
)
```

4. **Use API keys instead of the primary Auth Token** for application code. API keys can be revoked individually and scoped. Store only API key credentials in your application:

```python
# SAFE: use API key pair instead of primary Auth Token
import os
from twilio.rest import Client

# API key provides same access but can be revoked without affecting other keys
client = Client(
    username=os.environ['TWILIO_API_KEY_SID'],
    password=os.environ['TWILIO_API_KEY_SECRET'],
    account_sid=os.environ['TWILIO_ACCOUNT_SID']
)
```

5. **Enable Twilio Geo Permissions** to restrict SMS sending to only the countries your service legitimately operates in. This limits the geographic scope of abuse if credentials are compromised.

6. **Set up Twilio usage alerts and spending limits** in the Console to detect anomalous usage quickly. An attacker sending thousands of messages will trigger these alerts.

7. **Scan git history** for exposed credentials:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'ACxxxxxxxxxxxxxxxx==>REDACTED_TWILIO_SID')
git filter-repo --replace-text <(echo 'SKxxxxxxxxxxxxxxxx==>REDACTED_TWILIO_KEY')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Twilio: API key documentation](https://www.twilio.com/docs/iam/api-keys)
- [Twilio: Security best practices](https://www.twilio.com/docs/usage/security)
- [Twilio: Geo permissions](https://www.twilio.com/docs/sms/geo-permissions/understanding-geo-permissions)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
