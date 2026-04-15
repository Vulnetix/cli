---
title: "VNX-PY-006 – Django DEBUG=True in Production"
description: "Detect Django settings files that have DEBUG set to True, which exposes detailed error tracebacks, SQL queries, and application internals to any visitor."
---

## Overview

This rule flags `DEBUG = True` in Django settings files (`settings.py`, `settings/base.py`, `settings/production.py`, `settings/prod.py`). When Django's debug mode is enabled it renders a full HTML error page for every unhandled exception, including the complete Python traceback, local variable values at every stack frame, the full list of Django settings, and the SQL queries that ran during the request. This information gives an attacker a detailed map of your application's internals without needing any special access. This maps to [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html).

**Severity:** Medium | **CWE:** [CWE-489 – Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

## Why This Matters

Django's debug error page is designed for development — it is intentionally information-dense to help developers understand failures quickly. In production that same information becomes a reconnaissance gift for attackers. A single unhandled exception (triggered by a malformed request, a 404 on a guessable path, or an invalid query parameter) reveals:

- **Database schema** — table names, column names, and query parameters visible in the SQL panel
- **File system paths** — absolute paths to all Python source files in the traceback
- **Configuration values** — the full `settings` module printed in the error page, potentially including `SECRET_KEY`, database credentials, and API keys if they were not loaded from the environment
- **Source code context** — 5 lines of source around each frame in the traceback
- **Installed apps and middleware** — the full application architecture

Additionally, `DEBUG = True` causes Django to keep an in-memory list of every SQL query executed since the process started, which grows unboundedly and can cause memory exhaustion under load.

## What Gets Flagged

Any line matching `DEBUG = True` (with optional surrounding whitespace) in a Django settings file.

```python
# FLAGGED: settings.py
DEBUG = True

# FLAGGED: with leading whitespace
    DEBUG = True

# FLAGGED: production settings file still has debug on
# settings/production.py
DEBUG = True
```

## Remediation

1. **Set DEBUG to False unconditionally in production settings.** The simplest approach is to have a separate settings file for production that explicitly sets `DEBUG = False`:

```python
# settings/production.py
DEBUG = False
```

2. **Read DEBUG from an environment variable so it can be controlled at deployment time without code changes.** This is the recommended pattern for twelve-factor applications:

```python
# settings.py
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() == "true"
```

With this pattern, `DEBUG` defaults to `False` unless `DJANGO_DEBUG=true` is explicitly set in the environment. Your local development environment sets the variable; your production environment does not.

3. **Ensure `ALLOWED_HOSTS` is configured.** When `DEBUG = False`, Django requires `ALLOWED_HOSTS` to be set to the exact hostnames your application serves. This prevents HTTP Host header injection:

```python
# settings/production.py
DEBUG = False
ALLOWED_HOSTS = ["yourdomain.example", "www.yourdomain.example"]
```

4. **Configure error reporting for production.** With `DEBUG = False`, Django will send exception details to the addresses in `ADMINS` via email (if mail is configured) or to Sentry / another error tracking service. Set this up so you do not lose visibility when errors occur:

```python
ADMINS = [("Ops Team", "ops@yourcompany.example")]

# Or use django-sentry-sdk
import sentry_sdk
sentry_sdk.init(dsn=os.environ["SENTRY_DSN"])
```

5. **Check that `SECRET_KEY` is not hard-coded.** The debug page renders `settings`, so any hard-coded secrets in `settings.py` are exposed. Load `SECRET_KEY` from the environment:

```python
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

## References

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [Django documentation – DEBUG setting](https://docs.djangoproject.com/en/stable/ref/settings/#debug)
- [Django documentation – Deployment checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [OWASP Top 10 A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP Application Security Verification Standard – V14 Configuration](https://owasp.org/www-project-application-security-verification-standard/)
- [CAPEC-116: Excavation](https://capec.mitre.org/data/definitions/116.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
