---
title: "Conan"
weight: 11
description: "Configure Conan (ConanCenter) to use the Vulnetix Package Firewall."
---

C/C++ packages are firewalled by adding a Conan remote and gating blocked downloads.

- **Proxy URL:** `https://packages.vulnetix.com/conan`
- **Plan:** Pro
- **Enforcement:** Gate — recipe/binary downloads for a blocked version are rejected.

## Getting started

```bash
vulnetix package-firewall conan
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.conan2/remotes.json` and `~/.conan2/credentials.json`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.conan2/remotes.json`:

```json
{
  "remotes": [
    { "name": "vulnetix", "url": "https://packages.vulnetix.com/conan", "verify_ssl": true },
    { "name": "conancenter", "url": "https://center2.conan.io", "verify_ssl": true, "disabled": true }
  ]
}
```

`~/.conan2/credentials.json`:

```json
{ "credentials": [ { "remote": "vulnetix", "user": "YOUR_ORG_UUID", "password": "YOUR_API_KEY" } ] }
```

## Use it

```bash
conan install . --remote=vulnetix
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked recipe/binary download returns the policy status. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall conan` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- ConanCenter is added disabled so packages resolve only through the firewall; remove it entirely to be strict.
- Conan 2.x paths shown; Conan 1.x uses `~/.conan/remotes.json` and `conan remote add`/`conan user`.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
