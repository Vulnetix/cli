---
title: "VNX-SEC-006 – Stripe Secret Key"
description: "Detects hardcoded Stripe secret API keys (sk_live_ or sk_test_ prefix) in source code, which grant full access to Stripe account payment operations."
---

## Overview

This rule detects Stripe secret API keys matching the patterns `sk_live_[0-9a-zA-Z]{24,}` and `sk_test_[0-9a-zA-Z]{24,}` in source files. Stripe secret keys are used to make authenticated requests to the Stripe API and provide complete control over a Stripe account: creating charges, issuing refunds, accessing customer payment methods, creating subscriptions, and downloading financial reports. Live keys (`sk_live_`) operate against real payment data; test keys (`sk_test_`) affect only the Stripe test environment but still represent a credential management failure.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Stripe live secret key gives an attacker the ability to issue refunds draining your balance, create fraudulent charges to your customers' saved payment methods, download your entire customer and transaction database, create new API keys and webhooks for persistent access, and exfiltrate payout account details. Stripe tracks API usage and can flag unusual activity, but by the time a finding is raised significant damage may already be done.

Test keys (`sk_test_`) are less immediately dangerous but their presence indicates poor secrets hygiene that is likely to extend to live keys as well. Additionally, test mode can be used to enumerate customers and understand your integration before pivoting to a live key obtained elsewhere.

Note that Stripe also issues restricted keys and publishable keys — this rule specifically targets secret keys because they provide write access to the account.

## What Gets Flagged

Any source line containing a string starting with `sk_live_` or `sk_test_` followed by at least 24 alphanumeric characters.

```python
# FLAGGED: hardcoded Stripe live secret key
import stripe

stripe.api_key = 'sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx'

charge = stripe.Charge.create(
    amount=2000,
    currency='usd',
    source='tok_visa',
)
```

```javascript
// FLAGGED: key in Node.js application
const stripe = require('stripe')('sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx');
```

## Remediation

1. **Rotate the key immediately.** Log into the Stripe Dashboard → Developers → API keys → Roll key. Stripe lets you roll a key without downtime by generating a new key and providing a transition period.

2. **Check Stripe logs for unauthorized use.** In the Dashboard go to Developers → Logs. Filter by the date range when the key was exposed and look for unexpected charges, refund requests, or customer data access.

3. **Remove from source code.** Load from environment variables:

```python
# SAFE: load Stripe key from environment
import stripe
import os

stripe.api_key = os.environ['STRIPE_SECRET_KEY']

charge = stripe.Charge.create(
    amount=2000,
    currency='usd',
    source='tok_visa',
)
```

```javascript
// SAFE: load from environment in Node.js
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
```

4. **Use Stripe restricted keys for limited-scope operations.** Rather than the full secret key, create a restricted key in the Dashboard that is scoped to only the API resources your code needs. For example, a webhook handler that only needs to read charge objects should not use a key with write access.

5. **Implement webhook signature verification** to ensure incoming webhook events are genuinely from Stripe rather than forged requests:

```python
# SAFE: verify webhook signatures
import stripe
import os

endpoint_secret = os.environ['STRIPE_WEBHOOK_SECRET']

event = stripe.Webhook.construct_event(
    payload, sig_header, endpoint_secret
)
```

6. **Scan git history** for the exposed key and rewrite history if found:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'sk_live_xxxx==>REDACTED_STRIPE_KEY')
```

7. **Understand the difference between test and live keys.** Never use live keys in development or staging environments. Set up environment-specific configuration so `sk_test_` keys are used for non-production and `sk_live_` keys are used only in production, loaded exclusively from secure secrets storage.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Stripe: API keys documentation](https://stripe.com/docs/keys)
- [Stripe: Restricted API keys](https://stripe.com/docs/keys#limit-access)
- [Stripe: Webhook signature verification](https://stripe.com/docs/webhooks/signatures)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
