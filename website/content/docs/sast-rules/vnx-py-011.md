---
title: "VNX-PY-011 – Python SQL Injection"
description: "Detect SQL queries built with string formatting or concatenation in Python code, which are vulnerable to SQL injection attacks that can expose or destroy database contents."
---

## Overview

This rule flags Python code that constructs SQL queries using string formatting (`f-strings`, `%`-formatting, or `.format()`) or raw string concatenation. When user-supplied values are interpolated directly into SQL strings, an attacker can inject SQL syntax that alters the query's meaning — reading data they should not see, bypassing authentication, modifying records, or deleting tables. The rule covers Django's `.raw()` and `.extra()`, SQLAlchemy's `text()` and `execute()`, and raw `cursor.execute()` calls with psycopg2, sqlite3, and similar DB-API 2 drivers. This maps to [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html).

**Severity:** Critical | **CWE:** [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection is consistently ranked among the most impactful web vulnerabilities and is straightforward to exploit. A single injectable query can give an attacker read access to the entire database, including password hashes, session tokens, PII, and any stored credentials. With write access, they can modify or delete records, create admin accounts, or corrupt data integrity. On some database configurations (MSSQL with xp_cmdshell enabled, PostgreSQL COPY TO/FROM) SQL injection can escalate to OS command execution.

Despite being a well-understood problem with a simple fix, SQL injection remains in OWASP Top 10 A03:2021 (Injection) because developers continue to reach for string formatting as the natural way to insert a value into a string — without recognising that SQL parsing happens after string construction.

## What Gets Flagged

The rule covers a broad set of patterns across popular Python database libraries:

```python
# FLAGGED: Django ORM .raw() with f-string
user_id = request.GET.get("id")
users = User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")

# FLAGGED: Django .extra() with f-string in where clause
queryset = User.objects.extra(where=[f"name = '{name}'"])

# FLAGGED: SQLAlchemy text() with f-string
from sqlalchemy import text
result = db.execute(text(f"SELECT * FROM products WHERE category = '{category}'"))

# FLAGGED: raw cursor.execute with f-string
cursor.execute(f"SELECT * FROM orders WHERE user_id = {user_id}")

# FLAGGED: execute with %s formatting in the query string itself
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)

# FLAGGED: execute with .format()
cursor.execute("DELETE FROM sessions WHERE token = '{}'".format(token))
```

## Remediation

**The universal fix is parameterized queries.** Pass user values as separate parameters, not as part of the SQL string. The database driver handles quoting and escaping internally, and the database engine parses the SQL structure before substituting parameters — so injected SQL syntax cannot alter the query's structure.

1. **DB-API 2 drivers (psycopg2, sqlite3, mysql-connector-python, etc.)**

```python
import sqlite3

# SAFE: parameter placeholder — sqlite3 uses ?
conn = sqlite3.connect("app.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# SAFE: psycopg2 uses %s (but as a placeholder, not string formatting)
import psycopg2
cursor.execute(
    "SELECT * FROM orders WHERE user_id = %s AND status = %s",
    (user_id, status),
)

# SAFE: named parameters with psycopg2
cursor.execute(
    "UPDATE users SET email = %(email)s WHERE id = %(id)s",
    {"email": new_email, "id": user_id},
)
```

2. **Django ORM — use the queryset API instead of `.raw()`**

```python
# SAFE: Django ORM builds parameterized queries automatically
from myapp.models import User

user = User.objects.get(id=user_id)
users = User.objects.filter(name=name, status="active")

# SAFE: if you must use .raw(), pass parameters separately
users = User.objects.raw(
    "SELECT * FROM users WHERE id = %s",
    [user_id],
)
```

3. **SQLAlchemy — use ORM queries or bound parameters with `text()`**

```python
from sqlalchemy import text, select
from myapp.models import Product

# SAFE: ORM query — SQLAlchemy generates parameterized SQL
products = session.query(Product).filter_by(category=category).all()

# SAFE: Core expression language
stmt = select(Product).where(Product.category == category)
products = session.execute(stmt).scalars().all()

# SAFE: text() with bound parameters (colon-style named params)
stmt = text("SELECT * FROM products WHERE category = :cat AND price < :max_price")
result = db.execute(stmt, {"cat": category, "max_price": max_price})
```

4. **For dynamic column names or table names, use an explicit allowlist.** Parameterized queries only work for values, not for identifiers (table names, column names). Validate identifiers against an allowlist:

```python
SORTABLE_COLUMNS = {"name", "created_at", "price"}

def get_sorted_products(sort_by: str):
    if sort_by not in SORTABLE_COLUMNS:
        raise ValueError(f"Invalid sort column: {sort_by}")
    # Now safe to use in an f-string — it must be from the allowlist
    cursor.execute(f"SELECT * FROM products ORDER BY {sort_by}")
```

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [Django documentation – SQL injection protection](https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection)
- [SQLAlchemy documentation – Using Textual SQL](https://docs.sqlalchemy.org/en/14/core/sqlelement.html#sqlalchemy.sql.expression.text)
- [psycopg2 documentation – Passing parameters to SQL queries](https://www.psycopg.org/docs/usage.html#passing-parameters-to-sql-queries)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
