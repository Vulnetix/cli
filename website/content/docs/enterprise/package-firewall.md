---
title: Package Firewall
weight: 10
---

# Vulnetix Package Firewall

The Vulnetix Package Firewall is a registry proxy that sits between your package
managers and upstream registries. Every requested package/version is checked
against Vulnetix intelligence (CVSS, EPSS, Coalition ESS, CISA KEV, malware,
weaponized exploits, active exploitation, PoCs, and bad-actor links) before it
reaches your build.

Run one CLI command to configure a package manager to use the firewall.

## Supported ecosystems

| Command | Registry | Plan |
|---|---|---|
| `vulnetix package-firewall go` | Go modules (GOPROXY) | Community |
| `vulnetix package-firewall go-dev` | pkg.go.dev API (pkgsite-cli) | Community |
| `vulnetix package-firewall npm` | npm | Pro |
| `vulnetix package-firewall pypi` | PyPI | Pro |
| `vulnetix package-firewall cargo` | Cargo | Pro |
| `vulnetix package-firewall gem` | RubyGems | Pro |
| `vulnetix package-firewall homebrew` | Homebrew | Pro |
| `vulnetix package-firewall docker` | Docker / OCI | Enterprise |
| ... | ... | ... |

## Go modules

Configure Go to download modules through the firewall:

```bash
vulnetix package-firewall go
```

This writes your Basic-auth credentials to `~/.netrc` and sets `GOPROXY` and
`GOAUTH` in your shell profile (or project `.env` / `.envrc` / `Makefile` when
present).

## pkg.go.dev API

Google's `pkgsite-cli` can query the `pkg.go.dev/v1beta` API through the
firewall, so search, package metadata, versions, symbols, and vulnerability data
are filtered by your org policy:

```bash
vulnetix package-firewall go-dev
```

Because `pkgsite-cli` does not persist a config file, the command prints the
alias or flag to use. After running it, either:

```bash
alias pkgsite-cli='pkgsite-cli -api https://packages.vulnetix.com/go-dev/v1beta'
pkgsite-cli search uuid
```

or pass the API base directly:

```bash
pkgsite-cli -api https://packages.vulnetix.com/go-dev/v1beta package github.com/google/go-cmp/cmp
```

Your netrc credentials are used automatically for Basic auth.

## Homebrew

Configure Homebrew's API-mode client to use the firewall:

```bash
vulnetix package-firewall homebrew
```

This writes a shell env file to `~/.config/vulnetix/package-firewall/homebrew.env`
containing:

```bash
export HOMEBREW_API_DOMAIN="https://<org>:<key>@packages.vulnetix.com/homebrew/api"
export HOMEBREW_ARTIFACT_DOMAIN="https://<org>:<key>@packages.vulnetix.com/homebrew-bottle"
export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK="1"
```

Source the file to activate it for the current shell, and add the same `source`
line to your shell profile (`~/.zshrc`, `~/.bashrc`, etc.) to persist it:

```bash
source ~/.config/vulnetix/package-firewall/homebrew.env
```

`HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1` is required so that Homebrew cannot
bypass the firewall's bottle gate by falling back to `ghcr.io` when a bottle is
blocked.

## Dry run

Preview every change the command would make:

```bash
vulnetix package-firewall go --dry-run
vulnetix package-firewall npm --dry-run
```

## Custom proxy URL

For on-prem or staging deployments:

```bash
vulnetix package-firewall go --proxy-url https://firewall.internal
```
