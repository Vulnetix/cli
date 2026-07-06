---
title: "Troubleshooting"
weight: 32
description: "Diagnose Package Firewall authentication, shell/environment, and package-manager issues."
---

## Check what is configured

```bash
vulnetix auth status
```

This prints your credential source and a **Package Firewall ecosystems** section listing which package managers currently point at `packages.vulnetix.com` and the file that matched.

## Authentication

All ecosystems authenticate against the host `packages.vulnetix.com` with your **org UUID** (username) and **API key** (password).

- **`401 Unauthorized`** — credentials are missing, wrong, or not being sent by the tool.
  - Re-run the setup: `vulnetix package-firewall <ecosystem>`.
  - Confirm `~/.netrc` has a `machine packages.vulnetix.com` entry with `login` and `password`, and is mode `600` (`chmod 600 ~/.netrc`).
  - Confirm the tool actually reads the credential you wrote — not every tool reads `~/.netrc` (see below).
- **Where credentials come from.** The CLI resolves them in order: `VULNETIX_API_KEY` + `VULNETIX_ORG_ID` env, `VVD_ORG` + `VVD_SECRET` (SigV4) env, `.vulnetix/credentials.json`, `~/.vulnetix/credentials.json`, then the `~/.netrc` entry. Run `vulnetix auth login` if none are present.

### Which tools read `~/.netrc`?

The CLI always writes `~/.netrc`, but package managers differ:

- **Read netrc:** Go (`GOAUTH=netrc`), and anything using libcurl — CRAN sets `download.file.method = "libcurl"` for this reason. Conda (via `requests`) reads it too.
- **Do not read netrc — credentials live in the tool's own config:** npm (`.npmrc`), pip (URL in `pip.conf`), Cargo (`credentials.toml` token), RubyGems (URL in `.gemrc`), Maven (`settings.xml`), NuGet (`NuGet.Config`), Composer (`auth.json`/`config.json`), Conan (`credentials.json`). The CLI writes these for you.

## Shell & environment

Some ecosystems are activated by an environment variable that must be loaded into your shell:

- **Go** — `GOPROXY` and `GOAUTH` are written to your shell rc (`~/.bashrc`, `~/.zshrc`, `~/.config/fish/config.fish`, …) inside a `# Vulnetix Package Firewall` block, and to `.env`/`.envrc`/`Makefile` at your git root if present. Open a new shell or `source` the file.
- **Hex** (`HEX_MIRROR`), **pub.dev** (`PUB_HOSTED_URL`), **Julia** (`JULIA_PKG_SERVER`) — the value is written to a file under `~/.config/vulnetix/package-firewall/`. `source` it, or export the variable in your shell rc / CI environment.
- **CI** — prefer setting the variables and credentials as CI secrets rather than relying on a developer's shell rc. Use `--dry-run` locally to see exactly what to set.

## Host systems & package managers

- **Permissions** — OS package managers (APT, dnf/yum, apk) and the Docker daemon write to system paths and usually need `root`. The CLI does not modify system files for these; follow the manual steps on each ecosystem page.
- **Caches** — a tool may already have a cached index or lockfile. Clear it after pointing at the firewall (`npm cache clean --force`, `pip cache purge`, `go clean -modcache`, `rm -rf ~/.cargo/registry/index`, `composer clear-cache`, etc.).
- **Lockfiles with pinned hashes** — if a lockfile pins a version the firewall blocks, resolution fails on that entry. Update the lockfile to an allowed version.
- **`502 Bad Gateway`** — the firewall could not reach an upstream mirror for that ecosystem; check the **Mirrors** tab in the console or your network egress to the upstream.
- **Corporate proxy** — if your network requires an HTTP proxy to reach `packages.vulnetix.com`, configure it too. See [Corporate Proxy](/docs/enterprise/corporate-proxy/).

## Start over

Re-running `vulnetix package-firewall <ecosystem>` is idempotent — it updates the managed block / keys in place. To preview without writing:

```bash
vulnetix package-firewall <ecosystem> --dry-run
```

To back the configuration out entirely, use [`uninstall`](/docs/enterprise/package-firewall/uninstall/) — it removes the managed blocks, whole-file configs, and shell/env changes, and (with `--remove-credentials` / `--purge`) the shared `~/.netrc` entry:

```bash
vulnetix package-firewall uninstall npm --dry-run   # preview
vulnetix package-firewall uninstall --purge          # remove everything, credential included
```
