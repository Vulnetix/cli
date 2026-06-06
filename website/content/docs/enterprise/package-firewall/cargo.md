---
title: "Cargo"
weight: 4
description: "Configure Cargo (crates.io sparse index) to use the Vulnetix Package Firewall."
---

Rust crates are firewalled by filtering the sparse index. Cargo does not read netrc, so a token is written for it.

- **Proxy URL:** `https://packages.vulnetix.com/cargo/`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are dropped from the sparse index.

## Getting started

```bash
vulnetix package-firewall cargo
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.cargo/config.toml` and `~/.cargo/credentials.toml`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "vulnetix"

[source.vulnetix]
registry = "sparse+https://packages.vulnetix.com/cargo/"

[registries.vulnetix]
index = "sparse+https://packages.vulnetix.com/cargo/"
credential-provider = ["cargo:token"]
```

`~/.cargo/credentials.toml` (Cargo sends this token verbatim as the `Authorization` header):

```toml
[registries.vulnetix]
token = "Basic BASE64(YOUR_ORG_UUID:YOUR_API_KEY)"
```

## Use it

```bash
cargo build
cargo add serde
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. Cargo resolves an allowed version; a blocked version is absent from the index. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall cargo` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Requires Cargo ≥ 1.74 for sparse-registry token auth.
- Delete the cached index after switching: `rm -rf ~/.cargo/registry/index`.
- `Cargo.lock` pinned to a blocked version will fail — update the lock.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
