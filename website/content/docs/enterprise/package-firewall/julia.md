---
title: "Julia"
weight: 14
description: "Configure Julia (Julia Pkg server) to use the Vulnetix Package Firewall."
---

Julia packages are firewalled by pointing the Pkg server at the proxy. Automatic CLI config is not yet implemented — set the environment variable manually.

- **Proxy URL:** `https://packages.vulnetix.com/julia`
- **Plan:** Pro
- **Enforcement:** Gate — content-addressed artifacts; blocked downloads are rejected.

## Getting started

{{< callout type="warning" >}}
`vulnetix package-firewall julia` is not yet automated. Set `JULIA_PKG_SERVER` manually.
{{< /callout >}}

## Configuration

Add to your shell rc / CI:

```bash
export JULIA_PKG_SERVER="https://packages.vulnetix.com/julia"
```

## Use it

```julia
using Pkg
Pkg.add("Example")
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked package/version download returns the policy status; the registry is content-addressed and not rewritten. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall julia` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- `JULIA_PKG_SERVER` must be set before Julia starts.
- Julia Pkg-server authentication differs from Basic auth; for private/authenticated setups consult the Pkg server auth docs.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
