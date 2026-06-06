---
title: "RPM"
weight: 17
description: "Configure RPM (RHEL / Fedora yum/dnf) to use the Vulnetix Package Firewall."
---

dnf/yum packages are firewalled in gate mode. Requires root — configure manually.

- **Proxy URL:** `https://packages.vulnetix.com/rpm`
- **Plan:** Enterprise
- **Enforcement:** Gate — the signed repodata is unchanged; `.rpm` downloads for blocked versions are rejected.

## Getting started

{{< callout type="warning" >}}
yum/dnf repo configuration requires root and is not automated by the CLI.
{{< /callout >}}

## Configuration

`/etc/yum.repos.d/vulnetix.repo`:

```ini
[vulnetix]
name=Vulnetix Package Firewall
baseurl=https://packages.vulnetix.com/rpm/releases/$releasever/Everything/$basearch/os/
enabled=1
gpgcheck=1
username=YOUR_ORG_UUID
password=YOUR_API_KEY
```

## Use it

```bash
sudo dnf install <package>
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked `.rpm` download fails with the policy status; the signed `repomd.xml`/`primary.xml` is served unchanged. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall rpm` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- `username`/`password` in the `.repo` file are read by dnf/yum directly.
- Keep `gpgcheck=1`; the firewall never edits repodata so signature checks pass.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
