---
title: "Package Firewall"
weight: 3
description: "Configure package managers to use the Vulnetix Package Firewall for dependency policy enforcement."
---

The Vulnetix Package Firewall sits between your package manager and upstream registries. It authenticates your organization, checks dependency policy, and proxies allowed packages from trusted mirrors.

Go is the first supported package manager. NPM support is planned next.

## Go Setup

Run:

```bash
vulnetix package-firewall go
```

The command:

- verifies your Vulnetix CLI credentials
- derives an API key when your CLI is authenticated with SigV4
- writes Basic auth credentials to `.netrc`
- persists `GOPROXY=https://packages.vulnetix.com`
- persists `GOAUTH=netrc`
- updates detected project files at the git root: `.env`, `.envrc`, and `Makefile`

Preview changes without writing files:

```bash
vulnetix package-firewall go --dry-run
```

## Authentication

Go reads credentials from `.netrc` when `GOAUTH=netrc` is set.

Linux and macOS:

```netrc
machine packages.vulnetix.com
login your-organization-uuid
password your-api-key-hex
```

```bash
chmod 600 ~/.netrc
```

Windows:

```text
%USERPROFILE%\_netrc
```

Use the same machine entry:

```netrc
machine packages.vulnetix.com
login your-organization-uuid
password your-api-key-hex
```

## Manual Go Configuration

The setup command writes the persistent equivalent of:

```bash
export GOPROXY="https://packages.vulnetix.com"
export GOAUTH="netrc"
```

Fish:

```fish
set -gx GOPROXY https://packages.vulnetix.com
set -gx GOAUTH netrc
```

PowerShell:

```powershell
Add-Content $PROFILE '$env:GOPROXY = "https://packages.vulnetix.com"'
Add-Content $PROFILE '$env:GOAUTH = "netrc"'
```

CMD:

```cmd
setx GOPROXY "https://packages.vulnetix.com"
setx GOAUTH "netrc"
```

## Project Files

When run inside a git repository, the CLI updates existing files only:

`.env`

```dotenv
GOPROXY=https://packages.vulnetix.com
GOAUTH=netrc
```

`.envrc`

```bash
export GOPROXY="https://packages.vulnetix.com"
export GOAUTH="netrc"
```

`Makefile`

```make
export GOPROXY=https://packages.vulnetix.com
export GOAUTH=netrc
```

## Verify

```bash
vulnetix auth status
go env GOPROXY GOAUTH
go list -m all
```

If `auth status` reports that `.netrc` permissions are too open, run:

```bash
chmod 600 ~/.netrc
```
