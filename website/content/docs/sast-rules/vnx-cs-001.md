---
title: "VNX-CS-001 – C# SQL Injection via String Concatenation in SqlCommand"
description: "Detects SQL queries constructed by concatenating or interpolating user-supplied input into SqlCommand, OleDbCommand, OdbcCommand, or OracleCommand instead of using parameterised queries."
---

## Overview

This rule flags C# code that builds SQL query strings by concatenating or interpolating user-controlled values directly into `SqlCommand`, `OleDbCommand`, `OdbcCommand`, or `OracleCommand` constructors, or by assigning a dynamically built string to `CommandText`. Whether the concatenation is done with the `+` operator, `string.Format()`, or a C# interpolated string (`$"..."`), the structural query is never fixed — any data supplied at runtime can reshape the SQL statement itself.

SQL injection remains one of the most consistently exploited vulnerability classes (CWE-89, CAPEC-66). The root cause is always the same: the application conflates the structure of a SQL command with its data by mixing them into a single string, then sending that string to the database engine. Parameterised queries fix this by separating the command structure (which is compiled once) from the data values (which are bound later and never interpreted as SQL).

The rule checks two patterns: a `new SqlCommand(...)` (or equivalent) call on the same line as a concatenation or interpolation expression, and a `CommandText = ...` assignment that includes a `+` operator, `string.Format`, or an interpolated string literal.

> **ASP.NET Core default:** Parameterised queries are NOT enforced by default. ADO.NET, Dapper, and raw `SqlCommand` usage all allow string-concatenated queries without any framework-level warning. Entity Framework Core uses parameterised queries by default for LINQ queries, but raw SQL methods (`FromSqlRaw`, `ExecuteSqlRaw`) do not.

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

**OWASP ASVS v4:** [V5.3.4](https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md) — Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterised queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks.

## Why This Matters

An attacker who controls the injected value can terminate the intended query and append arbitrary SQL. In a login form that concatenates the password field into a `WHERE` clause, a classic payload like `' OR '1'='1` bypasses authentication entirely. More damaging payloads can use `UNION SELECT` to dump any table in the database, `xp_cmdshell` to run OS commands (SQL Server), or stacked queries to drop tables.

Beyond data theft, SQL injection frequently leads to full server compromise. Once an attacker can execute arbitrary SQL as the application's database account, they can read files from the filesystem, write web shells, and enumerate internal network topology using DNS or HTTP features built into the database engine. The 2017 Equifax breach, multiple healthcare breaches, and countless e-commerce compromises all began with a SQL injection entry point.

Even "well-sanitised" string concatenation approaches — manual escaping, allow-listing characters, rejecting quotes — are fragile. Encoding context mismatches, multibyte character exploits, and future maintenance that widens the allowed character set each reopen the vulnerability. Parameterised queries make SQL injection structurally impossible at that code path.

## What Gets Flagged

```csharp
// FLAGGED: query string built with + operator
string query = "SELECT * FROM Users WHERE Name = '" + userName + "'";
var cmd = new SqlCommand(query, connection);

// FLAGGED: SqlCommand constructor with string interpolation
var cmd = new SqlCommand($"DELETE FROM Orders WHERE Id = {orderId}", conn);

// FLAGGED: CommandText assigned from string.Format
cmd.CommandText = string.Format("UPDATE Products SET Price = {0} WHERE Id = {1}", price, id);

// FLAGGED: OleDbCommand with concatenation
var oleCmd = new OleDbCommand("SELECT * FROM Customers WHERE Id = " + customerId, oleConn);
```

## Remediation

1. Replace every inline SQL string that contains user data with a parameterised query using `@param` placeholder syntax.
2. Declare `SqlParameter` objects for every value that originates outside the application's trust boundary. Prefer `cmd.Parameters.Add(new SqlParameter("@name", SqlDbType.NVarChar))` with explicit type over `AddWithValue` to avoid implicit type conversion issues.
3. Consider using Entity Framework Core for new data access code — LINQ-to-Entities generates parameterised SQL automatically. For raw SQL in EF Core, use `FromSqlInterpolated` (which is safe) rather than `FromSqlRaw` with user input.
4. At the application level, enforce least privilege: the database account used by the application should not have DDL rights or access to sensitive tables it does not need.
5. For Dapper, use the `@param` placeholder syntax in the SQL template and pass an anonymous object or `DynamicParameters` — never build the SQL string with user input.

```csharp
// SAFE: parameterised query — user input is bound as data, not SQL structure
string query = "SELECT * FROM Users WHERE Name = @name AND Active = @active";
using var cmd = new SqlCommand(query, connection);
cmd.Parameters.Add(new SqlParameter("@name", SqlDbType.NVarChar, 100) { Value = userName });
cmd.Parameters.Add(new SqlParameter("@active", SqlDbType.Bit) { Value = true });

// SAFE: stored procedure call — structure is fixed server-side
using var cmd = new SqlCommand("sp_GetUserById", connection);
cmd.CommandType = CommandType.StoredProcedure;
cmd.Parameters.Add(new SqlParameter("@userId", SqlDbType.Int) { Value = userId });

// SAFE: Entity Framework Core LINQ query (parameterised automatically)
var user = await dbContext.Users
    .Where(u => u.Name == userName && u.Active)
    .FirstOrDefaultAsync();

// SAFE: EF Core interpolated raw SQL (parameterised — NOT FromSqlRaw)
var results = dbContext.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {userName}")
    .ToList();

// SAFE: Dapper with parameter object
var user = await connection.QueryFirstOrDefaultAsync<User>(
    "SELECT * FROM Users WHERE Name = @Name",
    new { Name = userName });
```

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [Microsoft Docs: SqlCommand and parameterised queries](https://learn.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand)
- [Microsoft Docs: Entity Framework Core – Raw SQL queries](https://learn.microsoft.com/en-us/ef/core/querying/sql-queries)
- [OWASP ASVS v4 – V5.3.4 Database Query Requirements](https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
