---
title: "VNX-NODE-007 – Node.js SQL Injection"
description: "Detects SQL queries built with string concatenation or template literals in Node.js database libraries (mysql2, pg, knex, sequelize), enabling SQL injection attacks."
---

## Overview

This rule detects SQL query strings assembled via string concatenation (`+`) or template literals with interpolation (`` ` `` with `${}`) when passed to database query methods in Node.js (`mysql`, `mysql2`, `pg`, `knex`, `sequelize`). When any interpolated value comes from user input — a request parameter, body field, or query string — an attacker can manipulate the SQL statement structure to bypass authentication, extract data from arbitrary tables, modify or delete records, or in some configurations execute OS commands. This is CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).

**Severity:** Critical | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

## Why This Matters

SQL injection has been the number-one web application vulnerability for over two decades and remains in the OWASP Top 10. A single injectable query can expose an entire database: an attacker uses `UNION SELECT` to combine results from any table, `OR '1'='1'` to bypass authentication, or `; DROP TABLE users--` to cause catastrophic data loss. In MySQL and SQL Server configurations with file privilege, `INTO OUTFILE` and `LOAD DATA INFILE` can be used to read and write server files, potentially escalating to OS-level compromise.

Node.js applications are particularly susceptible because template literals make it syntactically natural to embed variables directly in strings, and developers coming from languages with built-in ORM abstractions may not realise they are writing raw SQL.

## What Gets Flagged

The rule matches `.query()` calls where the argument is a string literal containing SELECT/INSERT/UPDATE/DELETE, and also `.query()` calls where a template literal with `${` is used.

```javascript
// FLAGGED: string concatenation in mysql2 query
const userId = req.params.id;
connection.query('SELECT * FROM users WHERE id = ' + userId, (err, rows) => {
  res.json(rows);
});

// FLAGGED: template literal in pg query
const name = req.query.name;
pool.query(`SELECT * FROM products WHERE name = '${name}'`, (err, result) => {
  res.json(result.rows);
});
```

Payload: `?name=' OR '1'='1` returns all rows. Payload: `?id=1; DROP TABLE users--` destroys the table.

## Remediation

1. **Use parameterized queries (prepared statements) in all database libraries.** Parameterized queries separate the SQL structure from the data — the database driver handles escaping, and user input can never alter query structure.

   ```javascript
   // SAFE: parameterized query with mysql2
   const [rows] = await connection.execute(
     'SELECT * FROM users WHERE id = ?',
     [req.params.id]
   );
   res.json(rows);

   // SAFE: parameterized query with pg (node-postgres)
   const result = await pool.query(
     'SELECT * FROM products WHERE name = $1',
     [req.query.name]
   );
   res.json(result.rows);

   // SAFE: parameterized query with knex
   const users = await knex('users')
     .where('id', req.params.id)
     .select();
   res.json(users);
   ```

2. **Use ORM query builder methods** that generate parameterized queries automatically:

   ```javascript
   // SAFE: Sequelize findOne with object filter — never interpolated
   const user = await User.findOne({ where: { id: req.params.id } });

   // SAFE: knex builder chaining
   const products = await knex('products')
     .where({ name: req.query.name, active: true })
     .select('id', 'name', 'price');
   ```

3. **Validate and type-check inputs before they reach the database.** Even with parameterized queries, reject malformed IDs or unexpected input shapes early:

   ```javascript
   // SAFE: validate numeric ID before use
   const id = parseInt(req.params.id, 10);
   if (isNaN(id) || id <= 0) return res.status(400).json({ error: 'Invalid ID' });

   const [rows] = await connection.execute(
     'SELECT id, name, email FROM users WHERE id = ?',
     [id]
   );
   ```

4. **Never use `mysql.escape()` as a substitute for parameterization.** Manual escaping is error-prone and has edge cases across character sets. Parameterized queries are the only reliable defence.

5. **Limit database user privileges.** The application's database account should only have the permissions it needs: `SELECT` on read-only tables, `INSERT`/`UPDATE` on write tables. It should never have `DROP`, `FILE`, or `SUPER` privileges.

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [node-postgres (pg) parameterized queries](https://node-postgres.com/features/queries#parameterized-query)
- [mysql2 prepared statements](https://github.com/sidorares/node-mysql2#using-prepared-statements)
- [knex.js query builder documentation](https://knexjs.org/guide/query-builder.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
