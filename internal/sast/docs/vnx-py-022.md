---
title: "VNX-PY-022 – SQL injection via joined SQL pieces in Python"
description: "Reports SQL assembled by joining a list of pieces, one of them built from a variable, and passed to execute(), executemany(), executescript(), Django objects.raw() or pandas read_sql(). SQL built in one expression is reported by VNX-PY-011."
---

## Overview

This rule detects SQL that is assembled from a list of pieces and joined: `clauses.append(f"AND name = '{name}'")` followed by `cursor.execute(" ".join(clauses))`, directly or through a variable assigned `" ".join(clauses)` in the 20 lines above. The list must hold SQL (a piece in its literal or an `append()`), and one piece added by `=`, `+=`, `append()`, `extend()` or `insert()` must be built from a variable: an f-string, `+`, `%` or `.format()`, or a bare non-constant name (`parts.append(order)`). That embeds the value into the SQL string before it reaches the database driver, so an attacker who controls it can alter the query's structure. This vulnerability is classified as CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).

SQL built in a single expression (concatenation, `%` formatting, `.format()` or an f-string, inline, through a variable, extended with `+=`, or a SQL template variable formatted inside the call) is reported by [VNX-PY-011](../vnx-py-011/), which used to report the same lines as this rule. VNX-PY-011 does not follow a list of pieces into `join()`, which is the shape this rule covers.

Python database drivers — including `sqlite3`, `psycopg2`, `MySQLdb`, `cx_Oracle`, and `pyodbc` — all support parameterized query APIs that separate SQL structure from data values. When parameterized queries are used, the driver handles quoting and escaping internally, making injection structurally impossible regardless of the input content. Despite this, string-formatted queries remain common in Python codebases due to the language's expressive string formatting syntax, which makes it syntactically tempting to build queries inline.

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) | **CAPEC:** [CAPEC-66 – SQL Injection](https://capec.mitre.org/data/definitions/66.html) | **ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/)

## Why This Matters

SQL injection is consistently ranked as one of the most critical web application vulnerabilities and has led to some of the largest data breaches in history. A successful injection can exfiltrate entire databases, bypass authentication, modify or delete records, and in some database configurations (e.g., PostgreSQL with `COPY TO/FROM PROGRAM`, MySQL `INTO OUTFILE`) achieve remote code execution on the database host.

Python's `executescript()` method for SQLite is particularly dangerous: it executes multiple SQL statements in a single call, so an injected payload can easily terminate the current statement and append a `DROP TABLE` or `SELECT` statement, making the impact immediate and severe. Old-style `%` formatting and `.format()` produce identically dangerous results but may appear safer to developers unfamiliar with the distinction between format strings and parameterized queries.

## What Gets Flagged

```python
# FLAGGED: an f-string piece joined into the query
clauses = ["SELECT id, name FROM people WHERE 1 = 1"]
if name:
    clauses.append(f"AND name = '{name}'")
cursor.execute(" ".join(clauses))

# FLAGGED: a bare value appended, joined through a variable
parts = []
parts.append("SELECT id FROM people ORDER BY")
parts.append(order)
stmt = " ".join(parts)
cursor.execute(stmt)

# NOT FLAGGED HERE: SQL built in one expression (reported by VNX-PY-011)
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
```

Not flagged: pieces that carry placeholders with the values passed as a parameters argument (`clauses.append("AND name = ?")` ... `cursor.execute(" ".join(clauses), params)`), pieces built only from UPPER_CASE constants, lists that hold no SQL, and placeholder lists built with `",".join("?" * len(ids))`.

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

# SAFE BUT STILL REPORTED: the allowlist check is not something this
# line-oriented rule can see; review and suppress the finding
# SQLAlchemy Core with bound parameters (dynamic table via allowlist)
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
