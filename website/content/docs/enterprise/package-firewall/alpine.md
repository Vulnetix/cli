---
title: "Alpine"
weight: 18
description: "Configure Alpine (Alpine apk) to use the Vulnetix Package Firewall."
---

apk packages are firewalled in gate mode. Requires root — configure manually.

- **Proxy URL:** `https://packages.vulnetix.com/alpine`
- **Plan:** Enterprise
- **Enforcement:** Gate — the signed APKINDEX is unchanged; `.apk` downloads for blocked versions are rejected.

## Getting started

{{< callout type="warning" >}}
apk repository configuration requires root and is not automated by the CLI.
{{< /callout >}}

## Configuration

`/etc/apk/repositories` — add the authenticated mirror:

```text
https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/alpine/v3.20/main
https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/alpine/v3.20/community
```

## Use it

```bash
apk update
apk add <package>
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked `.apk` download fails with the policy status; the RSA-signed `APKINDEX` is served unchanged. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall alpine` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- apk verifies the signed index; the firewall never edits it, so signing keys keep working.
- Match the Alpine version in the path (`v3.20`, `edge`, …) to your image.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
