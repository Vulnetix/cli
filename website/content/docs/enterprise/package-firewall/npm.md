---
title: "npm"
weight: 2
description: "Configure npm (npm registry) to use the Vulnetix Package Firewall."
---

JavaScript/Node.js packages are firewalled by filtering the packument so your resolver never selects a blocked version.

- **Proxy URL:** `https://packages.vulnetix.com/npm/`
- **Plan:** Pro
- **Enforcement:** Filter — disallowed versions are removed from the packument.

## Getting started

```bash
vulnetix package-firewall npm
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.npmrc`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.npmrc`:

```ini
registry=https://packages.vulnetix.com/npm/
//packages.vulnetix.com/npm/:username=YOUR_ORG_UUID
//packages.vulnetix.com/npm/:_password=BASE64(YOUR_API_KEY)
//packages.vulnetix.com/npm/:always-auth=true
```

`_password` is the base64 of your API key. Per-project, write the same lines to a project `.npmrc`.

## Use it

```bash
npm install lodash
```

Verify:

```bash
npm config get registry
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. npm installs an allowed version; a blocked version is absent from the packument. Pinning a blocked exact version fails to resolve. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall npm` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Yarn uses its own config — set `npmRegistryServer` (Yarn 2+) or `.yarnrc` `registry` plus `npmAuthIdent`.
- Scoped packages inherit the default registry; add `@scope:registry=...` if a scope needs the firewall explicitly.
- Stale cache: `npm cache clean --force`.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
