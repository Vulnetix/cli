---
title: "VNX-CS-010 – C# Hardcoded Connection String with Credentials"
description: "Reports C# source that hardcodes the password of a database or cache connection: a Password=/Pwd= value in a connection-string literal, or a literal assigned to the Password of a ConnectionStringBuilder, Redis ConfigurationOptions or RabbitMQ ConnectionFactory. Passwords from configuration, format and interpolation holes, placeholders, SQL text, comments, test projects and configuration files are not reported."
---

## Overview

This rule reports a line of C# (`.cs`) that hardcodes a connection password. Two shapes are reported:

- **A connection-string literal** (regular, verbatim `@"..."`, interpolated `$"..."`, or one part of a `+` concatenation) holding a `Password=` or `Pwd=` key (also `Jet OLEDB:Database Password=` and the StackExchange.Redis `,password=` option) whose value is a literal. The string must be recognisably a connection string: another connection key (`Server`, `Data Source`, `Host`, `Database`, `Initial Catalog`, `User Id`, `Uid`, `Port`, `Provider` ...) in it or in the concatenation lines around it, a Redis `host:port,` endpoint at its start, or a connection sink on the line (`new SqlConnection(`, `new NpgsqlConnection(`, `UseSqlServer(`, `UseNpgsql(`, `ConnectionMultiplexer.Connect(`, `ConnectionString =`). Attribute arguments such as a `Settings.Designer.cs` `DefaultSettingValueAttribute` and default parameter values count.
- **A builder property:** a literal assigned to `Password` (or the `["Password"]` indexer) of a `*ConnectionStringBuilder`, a StackExchange.Redis `ConfigurationOptions` or a RabbitMQ `ConnectionFactory`, by assignment (`csb.Password = "..."`) or in its object initializer.

Deliberately not reported:

- A password read from configuration, the environment or a variable: `string.Format("...Password={0}", ...)`, `$"...Password={pwd}"`, `"...Password=" + pwd`, `builder.Password = _config["Db:Password"]`.
- An empty value (`Password=;`), Integrated Security and managed-identity strings.
- Placeholders: `<password>`, `[password]`, `myPassword`, `YOUR_PASSWORD`, `***`, `#{DbPassword}#`, `$(SqlPassword)`, `%DB_PASS%`, `__DB_PASSWORD__`, `@p`.
- SQL text that compares or sets a `Password` column, and code that redacts or inspects a connection string.
- Comments, test projects (`tests/`, `*.Tests/`, `*.IntegrationTests/`, `*Tests.cs`), and configuration files such as `appsettings.json` and `Web.config`, which other rules cover.
- URI-form connection strings (`postgres://user:pass@host`) are reported by VNX-SEC-008, Azure `AccountKey`/`SharedAccessKey` values by the generated secret rules, and a plain `string password = "..."` by VNX-259. A connection string spread over the lines of one multi-line verbatim literal is not seen.

Database connection strings in source code are one of the highest-impact forms of credential exposure. They typically contain the server, the database, the user and the password in a single string, which is everything needed to connect directly and read or change all stored data. Unlike API keys with limited scope, direct database credentials usually grant full read/write access to the application's data.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded database credentials in C# source code are a consistently high-severity finding in security audits and bug bounty programs. A connection string with a password committed to a repository, even a private one, is durable exposure: the credentials live on in version control history, build logs, CI artefact archives, every clone, and the compiled assembly, where `strings` recovers them. If the repository is later made public, forked, or accessed by an attacker, the credentials are immediately available.

The 2017 Uber breach and numerous other high-profile incidents involved credentials committed to source code repositories. Automated scanners continuously monitor GitHub, GitLab, and other platforms for credential patterns, and the time between a credential being committed and being found by someone else is measured in minutes.

In .NET applications, connection strings belong in configuration that can be overridden by environment variables, or entirely in Azure Key Vault, AWS Secrets Manager, or .NET's User Secrets in development. `Scaffold-DbContext` even emits `#warning To protect potentially sensitive information in your connection string, you should move it out of source code.` above the string it writes into `OnConfiguring`. This maps to ATT&CK T1552 (Unsecured Credentials) and CAPEC-191 (Read Sensitive Constants Within an Executable).

## What Gets Flagged

```csharp
// FLAGGED: literal password passed to a connection
using var conn = new SqlConnection("Server=db01.internal;Database=Orders;User Id=orders_app;Password=Q7v!m2Lp;");

// FLAGGED: scaffolded DbContext
optionsBuilder.UseSqlServer("Server=tcp:shop.database.windows.net,1433;Initial Catalog=Shop;User ID=shopadmin;Password=Sh0p-Adm1n;Encrypt=True;");

// FLAGGED: the password half of a concatenated string, and an interpolated one
private static readonly string Conn = "Server=10.0.4.12;Database=Ledger;" +
    "User Id=ledger;Password=L3dger#2023;";
var cs = $"Host={_host};Username=etl;Password=Etl-Load-9;Database={_db}";

// FLAGGED: builder and Redis configuration
csb.Password = "Npg-Secret-1";
ConnectionMultiplexer.Connect("cache.internal:6380,password=R3dis-Cache-Key,ssl=True");

// NOT FLAGGED: the password comes from configuration or a format hole
options.UseSqlServer(_config.GetConnectionString("DefaultConnection"));
string.Format("Server={0};User Id={1};Password={2};", server, user, password);
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
