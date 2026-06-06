---
title: "pub.dev"
weight: 7
description: "Configure pub.dev (pub.dev) to use the Vulnetix Package Firewall."
---

Dart/Flutter packages are firewalled via the `PUB_HOSTED_URL` mirror, filtering blocked versions from the package listing.

- **Proxy URL:** `https://packages.vulnetix.com/pub`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are removed from the package metadata.

## Getting started

```bash
vulnetix package-firewall pub
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.config/vulnetix/package-firewall/pub.env`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

```bash
export PUB_HOSTED_URL="https://packages.vulnetix.com/pub"
```

`source` it (or add to your shell rc / CI).

## Use it

```bash
source ~/.config/vulnetix/package-firewall/pub.env
dart pub get   # or: flutter pub get
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. pub resolves an allowed version; a blocked version is absent from the listing. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall pub` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- `PUB_HOSTED_URL` must be exported in the environment that runs `dart`/`flutter`.
- Clear the pub cache if a stale resolution persists.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
