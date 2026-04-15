---
title: "VNX-CS-001 – C# SQL Injection via String Concatenation in SqlCommand"
description: "Detects SQL queries constructed by concatenating or interpolating user-supplied input into SqlCommand, OleDbCommand, OdbcCommand, or OracleCommand instead of using parameterised queries."
---

## Overview

This rule flags C# code that builds SQL query strings by concatenating or interpolating user-controlled values directly into `SqlCommand`, `OleDbCommand`, `OdbcCommand`, or `OracleCommand` constructors, or by assigning a dynamically built string to `CommandText`. Whether the concatenation is done with the `+` operator, `string.Format()`, or a C# interpolated string (`$"..."`), the structural query is never fixed — any data supplied at runtime can reshape the SQL statement itself.

SQL injection remains one of the most consistently exploited vulnerability classes (CWE-89, CAPEC-66). The root cause is always the same: the application conflates the structure of a SQL command with its data by mixing them into a single string, then sending that string to the database engine. Parameterised queries fix this by separating the command structure (which is compiled once) from the data values (which are bound later and never interpreted as SQL).

The rule checks two patterns: a `new SqlCommand(...)` (or equivalent) call on the same line as a concatenation or interpolation expression, and a `CommandText = ...` assignment that includes a `+` operator, `string.Format`, or an interpolated string literal.

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

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
```

## Remediation

1. Replace every inline SQL string that contains user data with a parameterised query.
2. Declare `SqlParameter` objects (or use the `@param` placeholder syntax) for every value that originates outside the application's trust boundary.
3. At the application level, enforce least privilege: the database account used by the application should not have DDL rights or access to sensitive tables it does not need.
4. Consider using an ORM (Entity Framework Core, Dapper) that parameterises by default rather than hand-building SQL strings.

```csharp
// SAFE: parameterised query — user input is bound as data, not SQL structure
string query = "SELECT * FROM Users WHERE Name = @name";
using var cmd = new SqlCommand(query, connection);
cmd.Parameters.AddWithValue("@name", userName);

// SAFE: stored procedure call — structure is fixed server-side
using var cmd = new SqlCommand("sp_GetUserById", connection);
cmd.CommandType = CommandType.StoredProcedure;
cmd.Parameters.AddWithValue("@userId", userId);
```

## References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Microsoft Docs: SqlCommand and parameterised queries](https://learn.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
