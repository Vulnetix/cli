---
title: "Go"
weight: 1
description: "Configure Go (Go module proxy) to use the Vulnetix Package Firewall."
---

Go modules are firewalled with a GOPROXY-compatible module proxy. This is the free, community-tier ecosystem.

- **Proxy URL:** `https://packages.vulnetix.com`
- **Plan:** Community — free
- **Enforcement:** Native module-proxy; each `@v/<version>` request is checked individually.

## Getting started

```bash
vulnetix package-firewall go
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `GOPROXY`/`GOAUTH` into your shell rc and, if a git root is detected, into `.env`/`.envrc`/`Makefile`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

The command sets, in a `# Vulnetix Package Firewall` block in your shell rc:

```bash
export GOPROXY="https://packages.vulnetix.com"
export GOAUTH="netrc"
```

and a `~/.netrc` entry:

```text
machine packages.vulnetix.com
login YOUR_ORG_UUID
password YOUR_API_KEY
```

Manual equivalent:

```bash
go env -w GOPROXY=https://packages.vulnetix.com GOAUTH=netrc
```

## Use it

```bash
go get rsc.io/quote@v1.5.2
go mod download
```

Verify the proxy is active:

```bash
go env GOPROXY GOAUTH
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. `go get` prints `403`/`4xx` with the JSON reason for the blocked version; other versions resolve normally. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall go` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- `GOAUTH=netrc` must be set or Go will not send credentials → `401`.
- Private modules: set `GOPRIVATE`/`GONOSUMCHECK` for paths that should bypass the proxy and sumdb.
- Stale module cache: `go clean -modcache`.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
