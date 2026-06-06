---
title: "Composer"
weight: 10
description: "Configure Composer (Packagist) to use the Vulnetix Package Firewall."
---

PHP packages are firewalled via a Composer repository that filters blocked versions; Packagist is disabled so all metadata transits the firewall.

- **Proxy URL:** `https://packages.vulnetix.com/composer`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are removed from the package metadata.

## Getting started

```bash
vulnetix package-firewall composer
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.composer/config.json`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.composer/config.json`:

```json
{
  "repositories": {
    "vulnetix": { "type": "composer", "url": "https://packages.vulnetix.com/composer" },
    "packagist.org": false
  },
  "http-basic": {
    "packages.vulnetix.com": { "username": "YOUR_ORG_UUID", "password": "YOUR_API_KEY" }
  }
}
```

Per-project, place the same `repositories`/`http-basic` in the project `composer.json` and `auth.json`.

## Use it

```bash
composer install
composer require monolog/monolog
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. Composer resolves an allowed version; a blocked version is absent from the metadata. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall composer` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- `"packagist.org": false` disables the public repo so nothing bypasses the firewall.
- Stale cache: `composer clear-cache`.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
