---
title: "VNX-SEC-022 – Sensitive Data in Log Statement"
description: "Detects log statements that may include passwords, tokens, API keys, or other secrets, which exposes credentials in log files, monitoring systems, and log aggregators."
---

## Overview

This rule detects calls to logging functions (`console.log`, `logger.info`, `logger.debug`, `print`, `println`, `System.out.print`, etc.) where the argument references variables or parameters named `password`, `passwd`, `secret_key`, `api_key`, `apikey`, `private_key`, `auth_token`, or `access_token`. Logging sensitive data is a common developer mistake that creates a persistent secondary copy of secrets in log files, standard output streams, monitoring dashboards, and log aggregation services.

**Severity:** Medium | **CWE:** [CWE-532 – Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

## Why This Matters

Log files have very different access control properties than application secrets. Logs are often:
- Aggregated into centralized systems (Splunk, Elasticsearch, Datadog, CloudWatch) accessible to many team members
- Retained for months or years for compliance and debugging purposes
- Shipped to third-party SaaS log management services
- Included in support bundles and incident reports shared with vendors
- Accessible to infrastructure teams who do not need application-level secrets

A password logged during a failed authentication attempt, a token logged when a request is made, or an API key logged in a "debug mode" that was accidentally left enabled can persist in log infrastructure long after the credential is rotated in the application. If the log system is breached, every secret that was ever logged becomes available to the attacker.

## What Gets Flagged

```python
# FLAGGED: password logged in debug statement
import logging

logger = logging.getLogger(__name__)

def authenticate(username, password):
    logger.debug(f"Authenticating user {username} with password {password}")
    # ... authenticate
```

```javascript
// FLAGGED: API key logged in Node.js
const apiKey = req.headers['x-api-key'];
console.log('Received request with api_key:', apiKey);
```

```java
// FLAGGED: token in Java log statement
String access_token = getTokenFromHeader(request);
log.info("Processing request with access_token: " + access_token);
```

## Remediation

1. **Remove the sensitive parameter from the log statement entirely.** Log the operation, user identity, or request ID — not the credential:

```python
# SAFE: log the operation, not the credential
import logging
logger = logging.getLogger(__name__)

def authenticate(username, password):
    logger.debug(f"Authenticating user: {username}")  # no password
    success = check_password(username, password)
    if not success:
        logger.warning(f"Failed authentication attempt for user: {username}")
    return success
```

2. **Use structured logging with explicit field exclusion.** Structured loggers make it easy to include context without accidentally including secrets:

```python
# SAFE: structured logging — only include safe fields
import structlog

log = structlog.get_logger()

def process_request(user_id, api_key, data):
    log.info("processing_request",
             user_id=user_id,
             # api_key intentionally omitted
             data_size=len(data))
```

```javascript
// SAFE: structured logging in Node.js — redact sensitive fields
const pino = require('pino');
const logger = pino({
    redact: ['req.headers.authorization', 'req.headers["x-api-key"]', 'password', 'token']
});

logger.info({ req, user_id }, 'request received');
```

3. **Implement a log scrubber** in your logging pipeline to catch accidentally logged secrets. Some log aggregators support field-level redaction:

```python
# SAFE: custom log filter that redacts sensitive patterns
import logging
import re

class SensitiveDataFilter(logging.Filter):
    PATTERNS = [
        (re.compile(r'(password|passwd|secret|api_key|token)\s*[=:]\s*\S+', re.IGNORECASE), r'\1=[REDACTED]'),
        (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'), 'Bearer [REDACTED]'),
    ]

    def filter(self, record):
        message = record.getMessage()
        for pattern, replacement in self.PATTERNS:
            message = pattern.sub(replacement, message)
        record.msg = message
        record.args = ()
        return True

logging.getLogger().addFilter(SensitiveDataFilter())
```

4. **Never log authentication request bodies in full.** For HTTP request logging, explicitly exclude authorization headers and request body fields that may contain credentials:

```python
# SAFE: exclude sensitive headers from request logs
SENSITIVE_HEADERS = {'Authorization', 'X-API-Key', 'Cookie'}

def log_request(request):
    safe_headers = {k: v for k, v in request.headers.items()
                    if k not in SENSITIVE_HEADERS}
    logger.info("request", method=request.method, path=request.path,
                headers=safe_headers)
```

5. **Review log aggregator access controls.** Audit who has access to your centralized logs and ensure access follows the principle of least privilege. Consider separate log streams for security events vs. application debug logs with different retention and access policies.

6. **Check existing logs** for previously logged secrets. Search your log aggregator for patterns like `password=`, `api_key=`, `Bearer ` to assess the scope of historical exposure.

## References

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [pino: Redaction documentation](https://getpino.io/#/docs/redaction)
- [structlog: Context variables](https://www.structlog.org/en/stable/contextvars.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [CAPEC-215: Fuzzing for application mapping](https://capec.mitre.org/data/definitions/215.html)
