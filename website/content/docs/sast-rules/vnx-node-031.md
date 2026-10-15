---
title: "VNX-NODE-031 – Logging of sensitive data"
description: "Reports console, logger (winston, pino, bunyan) and debug-package calls that pass a variable or property named as a password, secret, token, API key, credential, authorization header, CVV, SSN or card number; words in the message text alone are not reported."
---

## Overview

This rule detects `console.log`, `console.info`, `console.warn`, `console.error`, and structured logging calls via `logger.*`, `winston.*`, `bunyan.*`, or `pino.*` where an argument passes a variable or property named as a secret: `password`/`pass`/`pwd`, `secret`, `token`, `apiKey`/`privateKey`, `credential`, `authorization`, `jwt`, `otp`, `pin`, `ssn`, `cvv`, `cardNumber`/`creditCard`. The value must be read in the call; a sensitive word in the message text alone is not reported. Logging sensitive data causes those values to appear in log files, log aggregation systems, and monitoring dashboards — surfaces that typically have broader access than the application's primary datastore and are retained for extended periods. This is classified as CWE-532 (Insertion of Sensitive Information into Log File).

Sensitive values commonly end up in logs through debugging practices (logging request bodies or full objects), error handling (logging caught exceptions that include the originating data), and audit trails that inadvertently capture authentication material. Once written to a log, sensitive data may propagate to SIEM systems, cold storage, third-party log management services, and developer workstations — each an additional attack surface.

**Severity:** High | **CWE:** [CWE-532 – Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) | **OWASP:** [A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | **CAPEC:** [CAPEC-63 – Cross-Site Scripting (XSS)](https://capec.mitre.org/data/definitions/63.html)

## Why This Matters

Credentials and tokens written to logs are a documented attack path for credential theft, privilege escalation, and compliance violation. Attackers who compromise a log aggregation system (e.g., a poorly secured Elasticsearch cluster or a shared Splunk instance) gain access to every sensitive value ever logged. Security researchers and red teams routinely discover API keys, JWT tokens, database passwords, and PII in application logs during penetration tests.

From a compliance perspective, logging passwords or cardholder data (card numbers, CVV) violates PCI-DSS Requirements 3 and 10, and logging authentication tokens or PII without appropriate controls violates GDPR and HIPAA. Breach disclosures frequently cite logging of sensitive data as an aggravating factor. Unlike a compromised secret that can be rotated, historical log entries containing that secret may be retained in backups for years.

## What Gets Flagged

```javascript
// FLAGGED: the password argument
console.log('authenticating %s:%s', name, pass);

// FLAGGED: API key in a structured log, token in a concatenation
logger.info({ endpoint, apiKey }, 'calling upstream');
logger.debug('received token ' + accessToken);

// FLAGGED: template interpolation and request headers
winston.info(`login ok for ${userId} with session ${sessionToken}`);
log.info('auth header', req.headers.authorization);
console.error('charge failed', cardNumber, cvv);
```

Not flagged: the word only in the message (`logger.info('password changed for user %s', user.id)`), derived values (`token.length`, `!!password`, `typeof token`, `token.substring(0, 8)`), redacted or hashed values (`redact(secret)`, `sha256(password)`), lookalike names (`tokens`, `tokenizer`, `isTokenValid`, `passwordPolicy`), and test files.

## Remediation

1. Remove all logging statements that include sensitive field values. Log the event and its outcome without logging the sensitive value itself (e.g., log `'password changed for user X'` not the old or new password value).
2. Use structured logging with field redaction. Configure your logger to automatically scrub fields matching sensitive patterns before they are written to any transport.
3. If an object must be logged for debugging, clone it and delete sensitive keys before passing it to the logger.
4. Implement a `sanitize()` helper that deep-clones objects and redacts known sensitive fields, and apply it consistently before logging.

```javascript
// SAFE: log the event outcome, not the credential
logger.info({ userId, action: 'login' }, 'User authenticated successfully');

// SAFE: redact sensitive fields before logging
const SENSITIVE_KEYS = new Set([
  'password', 'passwd', 'secret', 'token', 'authorization',
  'creditCard', 'cardNumber', 'cvv', 'ssn', 'pin',
]);

function redact(obj, seen = new WeakSet()) {
  if (typeof obj !== 'object' || obj === null || seen.has(obj)) return obj;
  seen.add(obj);
  return Object.fromEntries(
    Object.entries(obj).map(([k, v]) => [
      k,
      SENSITIVE_KEYS.has(k.toLowerCase()) ? '[REDACTED]' : redact(v, seen),
    ])
  );
}

// Log the sanitized object
logger.info(redact({ userId, password, token }), 'Processing request');
// Output: { userId: 42, password: '[REDACTED]', token: '[REDACTED]' }

// SAFE: pino with built-in redaction
const pino = require('pino');
const log = pino({
  redact: {
    paths: ['password', 'token', '*.secret', 'req.headers.authorization'],
    censor: '[REDACTED]',
  },
});
```

## References

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Top 10 A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [pino — redact option](https://getpino.io/#/docs/redaction)
- [PCI-DSS v4.0 — Requirement 3: Protect Stored Account Data](https://www.pcisecuritystandards.org/)
- [PortSwigger Web Security Academy — Information disclosure in error messages](https://portswigger.net/web-security/information-disclosure)
