---
title: "VNX-PY-022 – SQL injection via string concatenation in Python"
description: "Detects Python cursor.execute() and cursor.executescript() calls that construct SQL queries using string concatenation, % formatting, or .format(), leaving them vulnerable to SQL injection."
---

## Overview

This rule detects calls to `cursor.execute()` or `cursor.executescript()` where the SQL string argument is constructed using Python string concatenation (`+`), old-style `%` formatting, or `.format()` method calls. Each of these patterns embeds user-supplied data directly into the SQL string before it reaches the database driver, allowing an attacker who controls any part of that input to alter the query's structure. This vulnerability is classified as CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).

Python database drivers — including `sqlite3`, `psycopg2`, `MySQLdb`, `cx_Oracle`, and `pyodbc` — all support parameterized query APIs that separate SQL structure from data values. When parameterized queries are used, the driver handles quoting and escaping internally, making injection structurally impossible regardless of the input content. Despite this, string-formatted queries remain common in Python codebases due to the language's expressive string formatting syntax, which makes it syntactically tempting to build queries inline.

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) | **CAPEC:** [CAPEC-66 – SQL Injection](https://capec.mitre.org/data/definitions/66.html) | **ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/)

## Why This Matters

SQL injection is consistently ranked as one of the most critical web application vulnerabilities and has led to some of the largest data breaches in history. A successful injection can exfiltrate entire databases, bypass authentication, modify or delete records, and in some database configurations (e.g., PostgreSQL with `COPY TO/FROM PROGRAM`, MySQL `INTO OUTFILE`) achieve remote code execution on the database host.

Python's `executescript()` method for SQLite is particularly dangerous: it executes multiple SQL statements in a single call, so an injected payload can easily terminate the current statement and append a `DROP TABLE` or `SELECT` statement, making the impact immediate and severe. Old-style `%` formatting and `.format()` produce identically dangerous results but may appear safer to developers unfamiliar with the distinction between format strings and parameterized queries.

## What Gets Flagged

```python
# FLAGGED: string concatenation in execute()
username = request.args.get('username')
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# FLAGGED: % formatting in SQL string
user_id = request.form['id']
cursor.execute("DELETE FROM sessions WHERE user_id = %s" % user_id)

# FLAGGED: .format() used to build query
table = request.json['table']
cursor.execute("SELECT * FROM {} WHERE active = 1".format(table))

# FLAGGED: executescript with user input
cursor.executescript("UPDATE prefs SET value='" + value + "' WHERE key='theme'")
```

## Remediation

1. Use the database driver's parameterized query interface: pass a query string with `?` or `%s` placeholders (depending on driver) and a separate tuple of values. The driver binds the values safely.
2. Never use Python string formatting operators (`%`, `.format()`, f-strings) to construct SQL — even for values you believe are safe. The safe pattern is always a literal SQL template with a parameters tuple.
3. For dynamic identifiers (table names, column names) that cannot be parameterized, maintain an explicit allowlist and validate the identifier against it before interpolation.
4. Use an ORM (SQLAlchemy, Django ORM, Peewee) with parameterized query methods to eliminate manual SQL construction wherever possible.

```python
# SAFE: parameterized query with sqlite3 (? placeholder)
import sqlite3

conn = sqlite3.connect('app.db')
cursor = conn.cursor()

username = request.args.get('username')
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
rows = cursor.fetchall()

# SAFE: parameterized query with psycopg2 (%s placeholder)
import psycopg2

conn = psycopg2.connect(dsn)
cursor = conn.cursor()

cursor.execute(
    "UPDATE accounts SET balance = %s WHERE account_id = %s",
    (new_balance, account_id),
)
conn.commit()

# SAFE: SQLAlchemy ORM — no raw SQL needed
from sqlalchemy.orm import Session

with Session(engine) as session:
    user = session.get(User, user_id)

# SAFE: SQLAlchemy Core with bound parameters (dynamic table via allowlist)
ALLOWED_TABLES = {'users', 'products', 'orders'}
table_name = request.json.get('table')
if table_name not in ALLOWED_TABLES:
    raise ValueError('Invalid table name')
result = conn.execute(text(f"SELECT * FROM {table_name} WHERE id = :id"), {"id": record_id})
```

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Python sqlite3 documentation — Placeholders](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders)
- [psycopg2 — Passing parameters to SQL queries](https://www.psycopg.org/docs/usage.html#passing-parameters-to-sql-queries)
- [PortSwigger Web Security Academy — SQL Injection](https://portswigger.net/web-security/sql-injection)
