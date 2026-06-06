---
title: "RubyGems"
weight: 5
description: "Configure RubyGems (RubyGems compact index) to use the Vulnetix Package Firewall."
---

Ruby gems are firewalled by filtering the compact index. RubyGems/Bundler do not read netrc, so credentials are embedded in the source URL.

- **Proxy URL:** `https://packages.vulnetix.com/gem/`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are removed from the compact index.

## Getting started

```bash
vulnetix package-firewall gem
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.gemrc`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.gemrc`:

```yaml
:sources:
- https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/gem/
```

For Bundler, set the same authenticated source in your `Gemfile`, or run `bundle config packages.vulnetix.com YOUR_ORG_UUID:YOUR_API_KEY`.

## Use it

```bash
gem install rails
bundle install
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. Bundler resolves an allowed version; a blocked version is absent from the compact index. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall gem` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Bundler may warn about credentials in the source — use `bundle config` to store them outside the Gemfile.
- Remove other `:sources:` entries so resolution only uses the firewall.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
