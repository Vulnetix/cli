---
title: "VNX-89 – SQL Injection"
description: "Detect SQL query strings built by concatenating or interpolating user-controlled data instead of using parameterised queries or prepared statements."
---

## Overview

This rule flags SQL query construction that uses string concatenation, f-strings, template literals, or format methods to embed user-controlled data directly into a query string. SQL injection allows an attacker to break out of the intended query structure and read any data in the database, modify or delete records, bypass authentication logic, call stored procedures, or — on some databases — execute OS commands. This maps to [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html).

**Severity:** Critical | **CWE:** [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection has ranked in the OWASP Top Ten for over two decades. It was the attack vector behind some of the largest data breaches in history — Sony, LinkedIn, Heartland Payment Systems, and many others. The fix — parameterised queries — has been available in every major language and database driver for as long as SQL injection has been a known attack. There is no legitimate reason to concatenate user input into a SQL string in modern code; any occurrence is a defect. The rule covers six languages and the most common database access patterns in each.

## What Gets Flagged

```javascript
// FLAGGED: Node.js — template literal in query
app.get('/user', async (req, res) => {
    const id = req.query.id;
    const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
    res.json(rows);
});
```

```python
# FLAGGED: Python — f-string in cursor.execute
@app.route('/search')
def search():
    term = request.args['q']
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return jsonify(cursor.fetchall())
```

```java
// FLAGGED: Java — Statement with string concatenation
String id = request.getParameter("id");
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
```

```php
<?php
// FLAGGED: PHP mysql_query with superglobal
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = " . $id);
```

```ruby
# FLAGGED: Ruby ActiveRecord with string interpolation
User.where("name = '#{params[:name]}'")
```

```go
// FLAGGED: Go — string concatenation in db.Query
func handler(w http.ResponseWriter, r *http.Request) {
    id := r.FormValue("id")
    rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
    defer rows.Close()
}
```

## Remediation

1. **Always use parameterised queries / prepared statements.** The database driver handles safe interpolation; user input is never interpreted as SQL syntax.

```javascript
// SAFE: Node.js — parameterised query
const rows = await db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);
// With pg (PostgreSQL):
const { rows } = await client.query('SELECT * FROM users WHERE id = $1', [id]);
```

```python
# SAFE: Python — parameterised with %s placeholders
cursor.execute("SELECT * FROM products WHERE name LIKE %s", ('%' + term + '%',))
# With SQLAlchemy:
result = session.execute(text("SELECT * FROM products WHERE name LIKE :term"),
                         {"term": f"%{term}%"})
```

```java
// SAFE: Java — PreparedStatement
String id = request.getParameter("id");
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, id);
ResultSet rs = ps.executeQuery();
```

```php
<?php
// SAFE: PHP — PDO prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$rows = $stmt->fetchAll();
```

```ruby
# SAFE: Rails — parameterised ActiveRecord query
User.where(name: params[:name])
# Or with explicit placeholder:
User.where("name = ?", params[:name])
```

```go
// SAFE: Go — parameterised query
rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)
```

2. **Use an ORM.** Object-relational mappers like Hibernate, SQLAlchemy, ActiveRecord, GORM, and Prisma generate safe parameterised queries from model operations. Avoid the `.raw()` / `find_by_sql()` escape hatches unless strictly necessary.

3. **Apply least-privilege database accounts.** The application database user should have only the permissions it needs — no DROP, no FILE, no SUPER — so that injection cannot be leveraged to destroy the database or access the OS.

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
