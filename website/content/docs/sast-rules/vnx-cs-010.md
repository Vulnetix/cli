---
title: "VNX-CS-010 – C# Hardcoded Connection String with Credentials"
description: "Detects database connection string literals in C# source files that contain a Password= or pwd= key-value pair with a plaintext value, indicating hardcoded database credentials that cannot be rotated without a code change."
---

## Overview

This rule scans C# files (`.cs`) for lines that contain a `Password=` or `pwd=` pattern (case-insensitive) followed by a non-empty value not ending at a semicolon, brace, or whitespace, where the line also contains a double-quote character indicating it is a string literal. Lines that reference `ConfigurationManager`, `GetConnectionString`, `Environment.Get`, or `appsettings` are excluded, as those patterns indicate the connection string is being read from configuration rather than being defined inline.

Database connection strings in source code are one of the highest-impact forms of credential exposure. They typically contain database server hostnames, database names, usernames, and passwords in a single string, providing everything needed to connect directly to the database and access or exfiltrate all stored data. Unlike API keys or tokens that may have limited scope, direct database credentials usually grant full read/write access to the application's data.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded database credentials in C# source code are a consistently high-severity finding in security audits and bug bounty programs. A single developer committing a connection string with credentials to a repository — even a private one — creates durable exposure: the credentials are visible in version control history, build logs, CI artefact archives, and any other copies of the repository. If the repository is later made public, forked, or accessed by an attacker, the credentials are immediately available.

The 2017 Uber breach and numerous other high-profile incidents involved credentials committed to source code repositories. Automated scanners continuously monitor GitHub, GitLab, and other platforms for credential patterns, and the mean time between a credential being committed and being discovered and exploited by external parties is measured in minutes.

In .NET applications, connection strings should be stored in `appsettings.json` in a format that can be overridden by environment variables, or managed entirely through Azure Key Vault, AWS Secrets Manager, or .NET's User Secrets feature in development. The `ASPNETCORE_ENVIRONMENT` configuration system makes this straightforward, and there is no legitimate reason to hardcode database passwords in source code. This maps to ATT&CK T1552 (Unsecured Credentials) and CAPEC-191 (Read Sensitive Constants Within an Executable).

## What Gets Flagged

```csharp
// FLAGGED: hardcoded SQL Server connection string with password
private string connStr = "Server=db.example.com;Database=AppDB;User ID=appuser;Password=MySecret123;";

// FLAGGED: hardcoded connection string in method
public SqlConnection GetConnection()
{
    return new SqlConnection("Data Source=prod-db;Initial Catalog=Users;User ID=sa;Password=P@ssw0rd;");
}

// FLAGGED: PostgreSQL connection string with embedded password
string pgConn = "Host=localhost;Username=postgres;Password=adminpass;Database=mydb";
```

## Remediation

1. Move connection strings to `appsettings.json` (development) and use environment variable overrides or Azure Key Vault / AWS Secrets Manager in production. Never put real passwords in `appsettings.json` that is committed to version control.
2. Use .NET's `IConfiguration` system to read the connection string at runtime: `configuration.GetConnectionString("DefaultConnection")`.
3. In Azure environments, use Managed Identity to authenticate to Azure SQL without any password at all — the identity is granted access at the database level.
4. Rotate any hardcoded credentials immediately, audit git history with a tool like `gitleaks` or `truffleHog`, and invalidate any sessions or tokens derived from the compromised credentials.

```csharp
// SAFE: connection string read from configuration (backed by Key Vault in production)
public class AppDbContext : DbContext
{
    private readonly IConfiguration _config;

    public AppDbContext(IConfiguration config)
    {
        _config = config;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlServer(_config.GetConnectionString("DefaultConnection"));
    }
}

// SAFE: Azure Managed Identity — no password needed
// In appsettings.json: "ConnectionStrings": { "DefaultConnection": "Server=myserver.database.windows.net;Database=mydb;Authentication=Active Directory Managed Identity;" }
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP .NET Security Cheat Sheet – Connection Strings](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#database-connection-strings)
- [Microsoft Docs – Safe storage of app secrets in development in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets)
- [Microsoft Docs – Azure Key Vault configuration provider in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration)
- [MITRE ATT&CK T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
