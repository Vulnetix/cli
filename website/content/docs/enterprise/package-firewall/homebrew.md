---
title: "Homebrew"
weight: 23
description: "Configure Homebrew (formula API + bottles) to use the Vulnetix Package Firewall."
---

Homebrew is firewalled through its API-mode client: the formula API and bottle artifacts are served through the proxy, and bottle downloads are gated so a blocked bottle cannot be fetched.

- **Proxy URL:** `https://packages.vulnetix.com/homebrew/api` (API) and `https://packages.vulnetix.com/homebrew-bottle` (bottles)
- **Plan:** Pro
- **Enforcement:** Gate — the formula API is proxied; a blocked bottle download returns a policy status.

## Getting started

```bash
vulnetix package-firewall homebrew
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes a shell env file to `~/.config/vulnetix/package-firewall/homebrew.env`. Homebrew reads these settings from environment variables, so source the file to activate it:

```bash
source ~/.config/vulnetix/package-firewall/homebrew.env
```

Add that `source` line to your shell profile (`~/.zshrc`, `~/.bashrc`, …) to persist it. Re-run the command any time; it updates the file in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.config/vulnetix/package-firewall/homebrew.env`:

```bash
export HOMEBREW_API_DOMAIN="https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/homebrew/api"
export HOMEBREW_ARTIFACT_DOMAIN="https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/homebrew-bottle"
export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK="1"
```

`HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1` is required: without it Homebrew falls back to `ghcr.io` when a bottle is blocked, bypassing the firewall's bottle gate.

## Use it

```bash
brew install wget
```

Verify the firewall is active:

```bash
brew config | grep HOMEBREW_API_DOMAIN
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked bottle download returns the policy status; with `NO_FALLBACK=1` set, Homebrew does not silently fall back to `ghcr.io`. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall homebrew` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- The env vars must be loaded into the shell that runs `brew` — `source` the env file or add it to your shell profile / CI environment.
- Keep `HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1`; removing it lets Homebrew bypass a blocked bottle via `ghcr.io`.
- Stale metadata: `brew update` re-fetches the formula API through the firewall.
- Remove it later with [`vulnetix package-firewall uninstall homebrew`](/docs/enterprise/package-firewall/uninstall/).
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
