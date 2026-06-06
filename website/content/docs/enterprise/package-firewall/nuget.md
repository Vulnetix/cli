---
title: "NuGet"
weight: 9
description: "Configure NuGet (nuget.org v3) to use the Vulnetix Package Firewall."
---

.NET packages are firewalled via the v3 service index, filtering blocked versions from registration.

- **Proxy URL:** `https://packages.vulnetix.com/nuget/`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are removed from the registration metadata.

## Getting started

```bash
vulnetix package-firewall nuget
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.nuget/NuGet/NuGet.Config`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.nuget/NuGet/NuGet.Config`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="vulnetix" value="https://packages.vulnetix.com/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <vulnetix>
      <add key="Username" value="YOUR_ORG_UUID" />
      <add key="ClearTextPassword" value="YOUR_API_KEY" />
    </vulnetix>
  </packageSourceCredentials>
</configuration>
```

## Use it

```bash
dotnet restore
dotnet add package Newtonsoft.Json
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. NuGet resolves an allowed version; a blocked version is absent from registration. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall nuget` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- `<clear />` removes nuget.org so only the firewall is used; remove it to keep nuget.org as a fallback (which would bypass policy).
- Encrypted credentials: use `ClearTextPassword` as shown, or `dotnet nuget add source` with `--username/--password`.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
