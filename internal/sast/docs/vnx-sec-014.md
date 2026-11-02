---
title: "VNX-SEC-014 – Hardcoded Password in Variable"
description: "Detects a literal password assigned to a variable, field, key or keyword argument named password, passwd, passphrase, secret_key or *_pwd, passed to a password setter, PHP define() or an XML property, or written as a bare value in a config file or docker-compose environment list, outside tests, templates and placeholders."
---

## Overview

This rule reports a quoted literal of at least 6 characters assigned to a name that ends in `password`, `passwd`, `passphrase`, `secret_key`/`secretKey` or `_pwd` (`DB_PASSWORD`, `adminPassword`, `self.password`, `$db_password`, `@smtp_password`), the same name used as an object, dict, hash or JSON key or as a keyword argument, and a bare value on such a line in YAML, `.properties`, `.ini`, `.conf` and `.env` files. It does not report values read from the environment or interpolated (`${DB_PASSWORD}`, `%s`, f-strings), values with spaces (labels), field names (`password_confirmation`), placeholders (`changeme`, `<password>`, `********`), comparisons, SQL text, concatenations (`'--password='.$pw`), test and fixture paths, translation catalogues and config templates (`.example`, `.sample`, `.dist`). Hardcoded passwords in source code are one of the most common and impactful security findings: they are committed to version control, visible to everyone with repository access, cannot be rotated without a code change, and often end up in logs, error messages, and backups.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html), [CWE-259 – Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

## Why This Matters

Hardcoded passwords represent a fundamental violation of the principle that secrets and code should live in separate, independently access-controlled systems. Every developer who clones the repository knows the password. Every CI/CD pipeline that checks out the code has the password in its workspace. Every historical commit containing the password preserves it indefinitely even after rotation.

A particularly common scenario is developers hardcoding a default or weak password during initial development, meaning to replace it before production — but the "temporary" value gets deployed and stays for months or years. The 2021 Verkada security camera breach, for example, was partly attributed to a super-admin password found hardcoded in source code.

## What Gets Flagged

```python
# FLAGGED: hardcoded database password
import psycopg2

DB_PASSWORD = "s3cr3tP@ssword123!"
conn = psycopg2.connect(host='localhost', user='app', password=DB_PASSWORD)
```

```yaml
# FLAGGED: bare value in a Spring config file
spring:
  datasource:
    password: Spr1ngB00t-db
```

```php
// FLAGGED: PHP variable and array key
$db_password = 'Lamp$tack99';
$config = ['password' => 'MyS9l-Pr0d!'];
```

```javascript
// FLAGGED: admin password in config object
const config = {
    "database": {
        "host": "localhost",
        "password": "hunter2_admin_pass"
    }
};
```

```java
// FLAGGED: hardcoded JDBC password
String password = "mysupersecretpassword";
Connection conn = DriverManager.getConnection(url, username, password);
```

## Remediation

1. **Change the password immediately** if it is used in any real system. Assume it has been leaked to anyone who can read the repository.

2. **Remove from source code.** Replace the literal with an environment variable read:

```python
# SAFE: load password from environment variable
import os
import psycopg2

conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASSWORD']
)
```

```python
# SAFE: Django SECRET_KEY from environment
import os
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
```

3. **Use a `.env` file for local development** (and ensure it is gitignored). Libraries like `python-decouple` or `python-dotenv` make this pattern convenient:

```python
# SAFE: python-decouple reads from .env or environment
from decouple import config

DB_PASSWORD = config('DB_PASSWORD')
SECRET_KEY = config('SECRET_KEY')
```

```bash
# .env file — NEVER commit this file
DB_PASSWORD=local_dev_password_only
SECRET_KEY=local-dev-secret-key-not-used-in-production
```

```bash
# .gitignore — ensure .env is excluded
echo ".env" >> .gitignore
```

4. **For production, use a dedicated secrets manager:**

```python
# SAFE: retrieve password from HashiCorp Vault
import hvac, os

client = hvac.Client(url=os.environ['VAULT_ADDR'], token=os.environ['VAULT_TOKEN'])
secret = client.secrets.kv.read_secret_version(path='db/app')
db_password = secret['data']['data']['password']
```

5. **Ensure CI/CD pipelines use secrets injection.** GitHub Actions secrets, GitLab CI/CD variables, and Jenkins credentials are all preferable to hardcoded values in workflow files.

6. **Scan git history** for the hardcoded password:

```bash
gitleaks detect --source . --verbose
git log --all -p | grep -i 'password\s*='
git filter-repo --replace-text <(echo 's3cr3tP@ssword123!==>REDACTED_PASSWORD')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [12-Factor App: Config](https://12factor.net/config)
- [python-decouple documentation](https://pypi.org/project/python-decouple/)
- [HashiCorp Vault: KV secrets engine](https://developer.hashicorp.com/vault/docs/secrets/kv)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
