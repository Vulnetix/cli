---
title: "VNX-PY-008 – Flask Debug Mode Enabled"
description: "Detect Flask applications started with debug=True, which enables the Werkzeug interactive debugger and allows remote code execution through the debugger console."
---

## Overview

This rule flags Flask `app.run()` calls that include `debug=True`. When Flask runs in debug mode it enables the Werkzeug interactive debugger. This debugger provides an in-browser Python console that evaluates arbitrary code in the context of the running application — by design, for development use. In production, this means any user who triggers an unhandled exception and navigates to the error page has access to an interactive Python shell running as the application's OS user. This maps to [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html).

**Severity:** High | **CWE:** [CWE-489 – Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

## Why This Matters

The Werkzeug debugger includes a PIN protection mechanism — it generates a PIN from machine-specific information and requires the developer to enter it before the console is accessible. However, this protection has been bypassed multiple times in practice. Depending on the Flask version, the PIN can be derived from:

- The machine's MAC address (often obtainable via an SSRF or path traversal to `/proc/net/arp`)
- The machine ID (readable from `/etc/machine-id` or `/proc/self/cgroup`)
- The current user's username and home directory
- The absolute path to the Flask application file

An attacker who can read any of these values through a separate information disclosure vulnerability (LFI, SSRF, directory traversal) can compute the PIN offline and then use the debugger console for full RCE. This attack chain has been exploited in the wild and is well-documented.

Beyond the PIN bypass, even if the PIN were unbreakable, having the debugger present in production generates detailed tracebacks visible to end users, leaking application code, file system paths, and configuration.

## What Gets Flagged

Any line where `.run(` is called with `debug=True` anywhere in the argument list.

```python
# FLAGGED: direct debug=True
app.run(debug=True)

# FLAGGED: with host and port also set
app.run(host="0.0.0.0", port=5000, debug=True)

# FLAGGED: debug=True at the end
app.run(port=8080, debug=True)
```

## Remediation

1. **Set `debug=False` explicitly, or omit the `debug` argument.** The default value of `debug` is `False`, so omitting it is safe. Being explicit documents intent:

```python
# SAFE: debug mode disabled
app.run(host="0.0.0.0", port=5000, debug=False)
```

2. **Read the debug flag from an environment variable.** This follows the twelve-factor app pattern and ensures that debug mode is only enabled when explicitly configured, never accidentally left on in production:

```python
import os
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug)
```

3. **Use the `FLASK_ENV` and `FLASK_DEBUG` environment variables.** Flask respects these variables automatically. In production, ensure neither is set to `development` or `1`:

```bash
# Production environment — never set these
# FLASK_ENV=production  (Flask < 2.3)
# FLASK_DEBUG=0         (or unset)

# Development environment only
export FLASK_DEBUG=1
flask run
```

4. **Do not run `app.run()` in production at all.** The `app.run()` development server is not suitable for production use. Use a production WSGI server such as Gunicorn or uWSGI, which do not have a debug mode:

```bash
# Production deployment with Gunicorn
gunicorn --workers=4 --bind=0.0.0.0:8000 myapp:app
```

```python
# wsgi.py — the Gunicorn entry point has no debug mode
from myapp import app

# No app.run() here; Gunicorn handles serving
```

5. **Configure error handling for production.** With debug mode off, unhandled exceptions return a generic 500 error to users. Add a proper error handler and integrate with an error tracking service:

```python
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn=os.environ["SENTRY_DSN"],
    integrations=[FlaskIntegration()],
)

@app.errorhandler(500)
def internal_error(error):
    return {"error": "An unexpected error occurred"}, 500
```

## References

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [Flask documentation – Debug Mode](https://flask.palletsprojects.com/en/stable/debugging/)
- [Flask documentation – Deploying to Production](https://flask.palletsprojects.com/en/stable/deploying/)
- [Werkzeug debugger PIN bypass (HackTricks)](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)
- [OWASP Top 10 A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CAPEC-116: Excavation](https://capec.mitre.org/data/definitions/116.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
