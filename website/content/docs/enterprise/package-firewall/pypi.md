---
title: "PyPI"
weight: 3
description: "Configure PyPI (PyPI Simple index) to use the Vulnetix Package Firewall."
---

Python packages are firewalled by filtering the PEP 503/691 Simple index so pip never selects a blocked release.

- **Proxy URL:** `https://packages.vulnetix.com/pypi/`
- **Plan:** Pro
- **Enforcement:** Filter — blocked files are removed from the Simple index.

## Getting started

```bash
vulnetix package-firewall pypi
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.config/pip/pip.conf`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.config/pip/pip.conf`:

```ini
[global]
index-url = https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/pypi/simple/
```

Works with `pip`, `pip-tools`, and `uv` (`uv pip install --index-url ...`). For Poetry, add a source pointing at the same URL.

## Use it

```bash
pip install flask
```

Verify:

```bash
pip config list
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. pip resolves an allowed version; pinning a blocked version (`flask==0.5`) returns `426`/policy status and fails. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall pypi` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Credentials in the URL must be URL-encoded — the CLI does this for you.
- `uv`/Poetry keep separate config; point their index/source at the same URL.
- Stale cache: `pip cache purge`.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
