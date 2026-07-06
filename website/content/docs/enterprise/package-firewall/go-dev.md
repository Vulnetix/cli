---
title: "Go pkg.go.dev API"
weight: 22
description: "Configure pkgsite-cli to query the pkg.go.dev API through the Vulnetix Package Firewall."
---

`go-dev` proxies Google's `pkg.go.dev` API (used by `pkgsite-cli`) through the firewall, so search, package metadata, versions, symbols, and vulnerability data are filtered by your org policy. It is a companion to the [Go module proxy](/docs/enterprise/package-firewall/go/), not a separate package registry — it only writes a netrc credential.

- **API base URL:** `https://packages.vulnetix.com/go-dev/v1beta`
- **Plan:** Community — free
- **Enforcement:** API proxy — responses are filtered by org policy.

## Getting started

```bash
vulnetix package-firewall go-dev
```

This resolves your organization credentials and writes them to `~/.netrc` for `packages.vulnetix.com`. Because `pkgsite-cli` does not persist a config file, the command prints the alias / flag to use.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Use it

Set an alias:

```bash
alias pkgsite-cli='pkgsite-cli -api https://packages.vulnetix.com/go-dev/v1beta'
pkgsite-cli search uuid
```

Or pass the API base per invocation:

```bash
pkgsite-cli -api https://packages.vulnetix.com/go-dev/v1beta package github.com/google/go-cmp/cmp
```

Your `~/.netrc` credentials are used automatically for Basic auth.

## Troubleshooting

- `go-dev` writes only the shared netrc credential — there is no config file to remove. Drop the credential with [`vulnetix package-firewall uninstall go-dev --remove-credentials`](/docs/enterprise/package-firewall/uninstall/) (or `--purge`).
- For downloading modules (not the API), configure the [Go module proxy](/docs/enterprise/package-firewall/go/) instead.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
