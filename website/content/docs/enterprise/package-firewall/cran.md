---
title: "CRAN"
weight: 13
description: "Configure CRAN (CRAN) to use the Vulnetix Package Firewall."
---

R packages are firewalled by setting the CRAN repo to the proxy. Authentication uses netrc via libcurl.

- **Proxy URL:** `https://packages.vulnetix.com/cran`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are removed from the PACKAGES index.

## Getting started

```bash
vulnetix package-firewall cran
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.Rprofile`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.Rprofile`:

```r
options(repos = c(CRAN = "https://packages.vulnetix.com/cran"))
options(download.file.method = "libcurl")
```

`download.file.method = "libcurl"` lets R authenticate from `~/.netrc`, which the setup writes.

## Use it

```r
install.packages("ggplot2")
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. `install.packages` resolves an allowed version; a blocked version is absent from PACKAGES. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall cran` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- If you see `401`, confirm `download.file.method` is `libcurl` and `~/.netrc` has the entry.
- CRAN metadata has no publish time, so cooldown does not apply.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
