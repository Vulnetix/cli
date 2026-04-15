---
title: "VNX-SEC-009 – SendGrid API Key"
description: "Detects hardcoded SendGrid API keys (SG. prefix) in source code, which grant access to email sending services and can be abused for phishing or spam."
---

## Overview

This rule detects SendGrid API keys matching the pattern `SG.[0-9A-Za-z\-_]{22}.[0-9A-Za-z\-_]{43}` in source files. SendGrid API keys authenticate requests to the SendGrid email delivery API, which can send transactional emails, marketing campaigns, or bulk messages at scale. Depending on the permissions granted to the key, an attacker with access to it can send emails impersonating your domain, access your contact lists, read previously sent message data, and damage your sending reputation.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Email is the primary vector for phishing and social engineering attacks. A leaked SendGrid API key with `mail.send` permission allows an attacker to send emails that appear to come from your verified domain — bypassing SPF, DKIM, and DMARC checks because the email is genuinely being sent through your legitimate SendGrid account. Recipients have no way to distinguish these emails from real ones.

Beyond phishing, an attacker can use your SendGrid account to send bulk spam, which will damage your domain's sending reputation and cause your legitimate emails to be delivered to spam folders. SendGrid may also suspend your account for abuse, disrupting your transactional email pipeline (password resets, order confirmations, etc.). Recovering from a burned sending reputation can take weeks or months.

## What Gets Flagged

```python
# FLAGGED: SendGrid API key hardcoded
import sendgrid
from sendgrid.helpers.mail import Mail

sg = sendgrid.SendGridAPIClient(api_key='SG.xxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
message = Mail(
    from_email='no-reply@example.com',
    to_emails='customer@example.com',
    subject='Your order has shipped',
    html_content='<p>Your order is on its way!</p>'
)
sg.send(message)
```

```javascript
// FLAGGED: SendGrid key in Node.js
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey('SG.xxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
```

## Remediation

1. **Rotate the API key immediately.** In the SendGrid Dashboard go to Settings → API Keys → find the key → Delete. Create a new key with only the permissions your application needs.

2. **Check SendGrid activity logs.** In the Dashboard go to Activity → Email Activity. Filter by the date range when the key was exposed and look for unexpected recipient addresses, high-volume sends, or unusual from addresses.

3. **Remove from source code.** Load from an environment variable:

```python
# SAFE: load SendGrid API key from environment
import os
import sendgrid
from sendgrid.helpers.mail import Mail

sg = sendgrid.SendGridAPIClient(api_key=os.environ['SENDGRID_API_KEY'])
message = Mail(
    from_email='no-reply@example.com',
    to_emails='customer@example.com',
    subject='Your order has shipped',
    html_content='<p>Your order is on its way!</p>'
)
sg.send(message)
```

4. **Scope the new API key with minimum permissions.** SendGrid supports restricted keys. A transactional email service only needs `mail.send` — it does not need access to contacts, templates, or marketing campaigns. Create separate keys for separate use cases.

5. **Monitor sender reputation.** Set up SendGrid's email activity feed and reputation monitoring. Consider enabling SendGrid's Enforced TLS setting and IP Access Management to restrict which IP addresses can use the key.

6. **Verify DMARC, DKIM, and SPF are properly configured.** If your domain's DMARC policy is set to `reject` or `quarantine`, unauthorized sends via a stolen key will be blocked by receiving mail servers. Run `dig TXT _dmarc.yourdomain.com` to check your current policy.

7. **Scan git history** for the exposed key:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'SG.xxxx==>REDACTED_SENDGRID_KEY')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [SendGrid: API key permissions](https://docs.sendgrid.com/ui/account-and-settings/api-keys)
- [SendGrid: Sender authentication](https://docs.sendgrid.com/ui/account-and-settings/how-to-set-up-domain-authentication)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
