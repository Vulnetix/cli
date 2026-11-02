---
title: "VNX-15 – External Control of System or Configuration Setting"
description: "A value read from an HTTP request is written into a process-wide setting: an environment variable, the module search path, runtime configuration (viper, ini_set, System.setProperty) or a JDBC connection's catalog."
---

## Overview

VNX-15 maps to [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html). It reports a request value written into a setting that governs the whole process, either directly on the setting line or through a variable assigned from the request in the 15 lines above.

**Severity:** Medium | **CWE:** [CWE-15](https://cwe.mitre.org/data/definitions/15.html) | **Languages:** go, java, node, php, python

## Why This Matters

Environment variables, include paths, runtime configuration and the database catalog are read by every later request, library and child process. A caller who can set `HTTP_PROXY`, `include_path`, `sys.path` or the active catalog can redirect outbound traffic, load code from a directory they choose, switch databases or silence logging for everybody, not just for their own request.

## What Gets Flagged

```go
os.Setenv("TZ", r.FormValue("tz"))

level := r.URL.Query().Get("level")
viper.Set("log.level", level)
```

```python
os.environ["LANG"] = request.form.get("lang", "C")
sys.path.insert(0, request.args["dir"])
```

```javascript
process.env[req.body.key] = req.body.value;
Object.assign(process.env, req.body.overrides);
```

```java
System.setProperty("http.proxyHost", request.getParameter("proxy"));
conn.setCatalog(request.getParameter("catalog"));
```

```php
ini_set('include_path', $_GET['path']);
putenv("TZ=" . $_POST['tz']);
```

Not flagged: constant values, settings taken from the environment or a configuration file, reading the environment next to request data, a request value checked against an allow-list (`not in ALLOWED`, `includes`, `in_array`, a regex match) before the write, and the same text in comments or string literals.

## Remediation

1. Do not let a request choose a process-wide setting. If the feature needs it, map the request to one of a fixed set of values on the server.
2. Keep per-request preferences (locale, time zone, log verbosity) in the request or session, not in the process environment.
3. For JDBC, choose the catalog from the authenticated tenant, never from a parameter.

## References

- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
