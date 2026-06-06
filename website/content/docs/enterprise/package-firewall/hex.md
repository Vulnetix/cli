---
title: "Hex"
weight: 6
description: "Configure Hex (Hex.pm) to use the Vulnetix Package Firewall."
---

Elixir/Erlang packages are firewalled in gate mode: the Ed25519-signed registry is passed through untouched (so verification still passes) and policy is enforced on the tarball download.

- **Proxy URL:** `https://packages.vulnetix.com/hex`
- **Plan:** Pro
- **Enforcement:** Gate — the signed registry is served unchanged; a blocked version's tarball download is rejected.

## Getting started

```bash
vulnetix package-firewall hex
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.config/vulnetix/package-firewall/hex.env`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

The setup writes an env file:

```bash
export HEX_MIRROR="https://packages.vulnetix.com/hex"
```

`source` it (or add it to your shell rc / CI). Mix then fetches packages and tarballs through the firewall.

## Use it

```bash
source ~/.config/vulnetix/package-firewall/hex.env
mix deps.get
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked version's tarball download returns the policy status; the registry index itself is unmodified. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall hex` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Because the protocol is signed, blocking is at download time, not by hiding the version from the index.
- `HEX_MIRROR` must be present in the environment Mix runs in (shell rc or CI).
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
