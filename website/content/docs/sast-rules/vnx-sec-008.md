---
title: "VNX-SEC-008 – Database Connection String with Credentials"
description: "Detects database connection strings with embedded usernames and passwords for PostgreSQL, MySQL, MongoDB, Redis, and MSSQL in source code."
---

## Overview

This rule detects connection strings matching the pattern `<scheme>://<user>:<password>@<host>` for PostgreSQL, MySQL, MongoDB (including mongodb+srv), Redis, and MSSQL embedded in source files. Database connection strings with embedded credentials are a critical finding because they expose not only the password but also the database host, port, and database name — giving an attacker everything needed to connect directly to your database from the internet if it is not properly network-isolated.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A database is typically the most sensitive component in an application — it holds user data, financial records, health information, or business secrets. A hardcoded connection string in a public repository gives an attacker immediate access to that data if the database is reachable from the internet (for example, a MongoDB Atlas cluster, Heroku Postgres instance, or Railway database with public IP). Even for databases behind a firewall, the credential is exposed to anyone who can read the source code, which in a company includes all developers and CI systems.

Hardcoded connection strings also make credential rotation painful, because every instance of the string must be found and updated across the codebase and all deployment configurations.

## What Gets Flagged

```python
# FLAGGED: PostgreSQL connection string with credentials
import psycopg2

conn = psycopg2.connect("postgresql://appuser:s3cr3tpassword@db.example.com:5432/myapp")
```

```javascript
// FLAGGED: MongoDB connection string in Node.js
const mongoose = require('mongoose');
mongoose.connect('mongodb://admin:hunter2@mongo.example.com:27017/production');
```

```python
# FLAGGED: Redis URL with password
import redis

r = redis.from_url("redis://:mypassword@redis.example.com:6379/0")
```

## Remediation

1. **Rotate the database password immediately.** Change the password in your database server. For cloud databases, use the provider's console or CLI. Also check whether the database has public IP access enabled and disable it if not required.

2. **Audit database access logs.** Check for connections from IP addresses other than your application servers. Postgres logs connection attempts; MongoDB has an audit log in Atlas.

3. **Remove the connection string from source code.** Load it from an environment variable at runtime:

```python
# SAFE: PostgreSQL — load DSN from environment
import os
import psycopg2

conn = psycopg2.connect(os.environ['DATABASE_URL'])
```

```javascript
// SAFE: MongoDB — load from environment in Node.js
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGODB_URI);
```

4. **Use separate environment variables for each component** if a full DSN is not suitable, then construct it at runtime without logging the result:

```python
# SAFE: construct DSN from parts at runtime
import os
from urllib.parse import quote_plus

db_url = (
    f"postgresql://{os.environ['DB_USER']}:{quote_plus(os.environ['DB_PASSWORD'])}"
    f"@{os.environ['DB_HOST']}:{os.environ['DB_PORT']}/{os.environ['DB_NAME']}"
)
```

5. **Use a secrets manager for production.** Services like AWS Secrets Manager, HashiCorp Vault, and GCP Secret Manager support automatic credential rotation and inject secrets at runtime without storing them in environment variables on disk:

```python
# SAFE: retrieve database password from AWS Secrets Manager
import boto3, json, os

def get_db_password():
    client = boto3.client('secretsmanager')
    secret = client.get_secret_value(SecretId='prod/db/password')
    return json.loads(secret['SecretString'])['password']
```

6. **Ensure connection strings are never logged.** Many frameworks log configuration at startup; ensure the `DATABASE_URL` environment variable is masked in log output and is not included in error messages.

7. **Scan git history** and rewrite if the connection string appears:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'postgresql://appuser:s3cr3tpassword@==>postgresql://REDACTED@')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [12-Factor App: Config](https://12factor.net/config)
- [AWS Secrets Manager: Rotating secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [HashiCorp Vault: Database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
