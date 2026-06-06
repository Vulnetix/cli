---
title: "Debian / Ubuntu"
weight: 16
description: "Configure Debian / Ubuntu (Debian/Ubuntu APT) to use the Vulnetix Package Firewall."
---

APT packages are firewalled in gate mode (the GPG-signed index is untouched). Requires root — configure manually.

- **Proxy URL:** `https://packages.vulnetix.com/debian`
- **Plan:** Enterprise
- **Enforcement:** Gate — the signed index is unchanged; `.deb` downloads for blocked versions are rejected.

## Getting started

{{< callout type="warning" >}}
APT configuration requires root and is not automated by the CLI.
{{< /callout >}}

## Configuration

`/etc/apt/sources.list.d/vulnetix.list`:

```text
deb https://packages.vulnetix.com/debian stable main
```

`/etc/apt/auth.conf.d/vulnetix.conf` (mode 600):

```text
machine packages.vulnetix.com
login YOUR_ORG_UUID
password YOUR_API_KEY
```

## Use it

```bash
sudo apt update
sudo apt install <package>
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked `.deb` download fails with the policy status; the signed `Release`/`Packages` index is served unchanged so signature verification still passes. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall debian` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Keep credentials in `auth.conf.d` (mode 600), not in the `sources.list` URL.
- APT verifies the repository signature; the firewall never edits the index, so this keeps working.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
