---
title: "VDB Command Reference"
weight: 2
description: "Access the Vulnetix Vulnerability Database for vulnerability lookups, package vulnerabilities, and ecosystem data."
---

The `vdb` subcommand provides access to the Vulnetix Vulnerability Database (VDB) API, offering comprehensive vulnerability intelligence from multiple authoritative sources.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Supported Identifier Formats](#supported-identifier-formats)
- [CLI Commands](#cli-commands)
  - [vdb vuln](#vdb-vuln)
  - [vdb ecosystems](#vdb-ecosystems)
  - [vdb product](#vdb-product)
  - [vdb vulns](#vdb-vulns)
  - [vdb spec](#vdb-spec)
  - [vdb exploits](#vdb-exploits)
  - [vdb fixes](#vdb-fixes)
  - [vdb versions](#vdb-versions)
  - [vdb gcve](#vdb-gcve)
  - [vdb purl](#vdb-purl)
  - [vdb gcve-issuances](#vdb-gcve-issuances)
  - [vdb ids](#vdb-ids)
  - [vdb search](#vdb-search)
  - [vdb sources](#vdb-sources)
  - [vdb metric-types](#vdb-metric-types)
  - [vdb exploit-sources](#vdb-exploit-sources)
  - [vdb exploit-types](#vdb-exploit-types)
  - [vdb fix-distributions](#vdb-fix-distributions)
- [API-Only Endpoints](#api-only-endpoints)
- [Examples](#examples)
- [Rate Limiting](#rate-limiting)

## Overview

The VDB API aggregates vulnerability data from:

- **Primary Sources**: MITRE CVE, NIST NVD, CISA KEV
- **Enhanced Intelligence**: VulnCheck KEV/NVD++/XDB, CrowdSec
- **Ecosystem Sources**: GitHub Security Advisories, OSV, EUVD
- **Risk Scoring**: FIRST EPSS, Coalition CESS

## Authentication

### Recommended: `vulnetix auth login`

```bash
vulnetix auth login    # interactive setup — saves to ~/.vulnetix/credentials.json
```

### Environment Variables

**Direct API Key** (recommended):
```bash
export VULNETIX_ORG_ID="your-organization-uuid"
export VULNETIX_API_KEY="your-api-key-hex"
```

**SigV4**:
```bash
export VVD_ORG="your-organization-uuid"
export VVD_SECRET="your-secret-key"
```

### Configuration File

Create `~/.vulnetix/credentials.json`:

```json
{
  "org_id": "your-organization-uuid",
  "api_key": "your-api-key-hex",
  "method": "apikey"
}
```

### Command-Line Flags

```bash
# Direct API Key
vulnetix vdb ecosystems --org-id "your-uuid" --api-key "your-key"

# SigV4
vulnetix vdb ecosystems --org-id "your-uuid" --secret "your-secret"
```

### Credential Precedence

1. Command-line flags (`--org-id` + `--api-key` or `--secret`)
2. Environment variables: `VULNETIX_API_KEY` + `VULNETIX_ORG_ID`
3. Environment variables: `VVD_ORG` + `VVD_SECRET`
4. Project file: `.vulnetix/credentials.json`
5. Home file: `~/.vulnetix/credentials.json`

### Obtaining Credentials

1. **Via Demo Request**: Visit https://www.vulnetix.com and complete the demo request form
2. **Via Email**: Send a request to sales@vulnetix.com with subject "VDB API Access Request"

## Supported Identifier Formats

The VDB accepts **78+ vulnerability identifier formats**. You are not limited to CVE — any command that takes a `<vuln-id>` accepts any of these:

### Core & Ecosystem

| Format | Example | Source |
|--------|---------|--------|
| `CVE` | `CVE-2021-44228` | MITRE / NIST NVD |
| `GHSA` | `GHSA-jfh8-3a1q-hjz9` | GitHub Security Advisories |
| `PYSEC` | `PYSEC-2024-123` | PyPI |
| `GO` | `GO-2024-1234` | Go vulnerability database |
| `RUSTSEC` | `RUSTSEC-2024-1234` | RustSec |
| `EUVD` | `EUVD-2025-14498` | EU Vulnerability Database |
| `OSV` | `OSV-2024-1234` | OSV (generic) |
| `GSD` | `GSD-2024-1234` | Global Security Database |
| `VDB` | `VDB-2025-1` | Vulnetix Database |
| `GCVE` | `GCVE-VVD-2025-0001` | Vulnetix-generated CVE |

### Vendor & Research

| Format | Example | Source |
|--------|---------|--------|
| `SNYK` | `SNYK-JAVA-ORGCLOJURE-5740378` | Snyk |
| `ZDI` | `ZDI-23-1714` | Trend Micro Zero Day Initiative |
| `MSCVE` / `MSRC` | `MSCVE-2025-21415` | Microsoft |
| `RHSA` | `RHSA-2025:1730` | Red Hat Security Advisory |
| `TALOS` | `TALOS-2023-1896` | Cisco Talos |
| `EDB` | `EDB-10102` | OffSec Exploit Database |
| `WORDFENCE` | `WORDFENCE-00086b84-...` | Defiant Wordfence |
| `PATCHSTACK` | `PATCHSTACK/spectrum/wordpress-theme` | Patchstack |
| `MFSA` | `MFSA2024-51` | Mozilla Foundation |
| `JVNDB` | `JVNDB-2023-006199` | Japan Vulnerability Notes |
| `CNVD` | `CNVD-2024-02713` | China National Vulnerability DB |
| `BDU` | `BDU:2024-00390` | Russian Data Bank |
| `HUNTR` | `HUNTR-001d1c29-...` | ProtectAI Huntr |

### Linux Distribution Advisories

| Format | Example | Source |
|--------|---------|--------|
| `DSA` | `DSA-4741-1` | Debian Security Advisory |
| `DLA` | `DLA-2931-1` | Debian LTS Advisory |
| `USN` | `USN-7040-1` | Ubuntu Security Notice |
| `ALSA` | `ALSA-2019:2722` | AlmaLinux |
| `RLSA` | `RLSA-2024:7346` | Rocky Linux |
| `MGASA` | `MGASA-2024-0327` | Mageia |
| `OPENSUSE` | `OPENSUSE-SU-2019:1915-1` | openSUSE |
| `FreeBSD` | `FreeBSD-SA-00:01.make` | FreeBSD |
| `BIT` | `BIT-OPENBLAS-2021-4048` | Bitnami |

> See `vulnetix vdb spec` for the complete OpenAPI specification and the full list of accepted identifier patterns.

## CLI Commands

### vdb vuln

Retrieve detailed information about a specific vulnerability.

**Usage:**
```bash
vulnetix vdb vuln <vuln-id> [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# CVE (MITRE / NVD)
vulnetix vdb vuln CVE-2021-44228

# GitHub Security Advisory
vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9

# PyPI vulnerability
vulnetix vdb vuln PYSEC-2024-123

# Red Hat advisory
vulnetix vdb vuln RHSA-2025:1730

# JSON output
vulnetix vdb vuln CVE-2021-44228 --output json

# Save to file
vulnetix vdb vuln CVE-2021-44228 -o json > log4shell.json
```

**Response includes:**
- Vulnerability identifier and aliases
- Description
- Published and modified dates
- CVSS scores (v2, v3, v4 where available)
- References and advisories
- Affected products and versions
- EPSS probability scores
- KEV (Known Exploited Vulnerabilities) status

---

### vdb ecosystems

List all available package ecosystems in the VDB.

**Usage:**
```bash
vulnetix vdb ecosystems [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List ecosystems
vulnetix vdb ecosystems

# Get ecosystems as JSON
vulnetix vdb ecosystems --output json
```

**Typical ecosystems include:**
- npm (JavaScript/Node.js)
- PyPI (Python)
- Maven (Java)
- Go
- RubyGems
- NuGet (.NET)
- crates.io (Rust)
- And many more...

---

### vdb product

Get version information for a specific product or package.

**Usage:**
```bash
vulnetix vdb product <product-name> [version] [ecosystem] [flags]
```

**Flags:**
- `--limit int`: Maximum number of results to return (default 100)
- `--offset int`: Number of results to skip (default 0)
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List all versions of a product
vulnetix vdb product express

# Get specific version information
vulnetix vdb product express 4.17.1

# Get specific version scoped to ecosystem
vulnetix vdb product express 4.17.1 npm

# List with pagination
vulnetix vdb product express --limit 50 --offset 100

# Get all versions as JSON
vulnetix vdb product lodash --output json
```

**List response includes:**
- Package/product name
- Total number of versions
- Array of version records, each with:
  - `version` — version string
  - `ecosystem` — package ecosystem (e.g. npm, PyPI)
  - `sources` — contributing data sources
- Pagination information (hasMore, limit, offset)

**Specific version response includes:**
- Detailed version metadata
- Dependencies
- Known vulnerabilities
- Release date
- Maintainer information

---

### vdb vulns

Retrieve all known vulnerabilities for a specific package.

**Usage:**
```bash
vulnetix vdb vulns <package-name> [flags]
```

**Flags:**
- `--limit int`: Maximum number of results to return (default 100)
- `--offset int`: Number of results to skip (default 0)
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# Get vulnerabilities for a package
vulnetix vdb vulns express

# Get vulnerabilities with pagination
vulnetix vdb vulns lodash --limit 20

# Get vulnerabilities as JSON
vulnetix vdb vulns moment --output json

# Get next page of results
vulnetix vdb vulns react --offset 100
```

**Response includes:**
- Total vulnerability count
- Array of vulnerabilities with:
  - Vulnerability identifiers (CVE, GHSA, and other formats)
  - Severity levels
  - CVSS scores
  - Affected version ranges
  - Fixed versions
  - Descriptions
  - References
- Pagination information

---

### vdb spec

Retrieve the OpenAPI specification for the VDB API.

**Usage:**
```bash
vulnetix vdb spec [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# View the API specification
vulnetix vdb spec

# Save specification to file
vulnetix vdb spec --output json > vdb-openapi-spec.json

# Use with other tools
vulnetix vdb spec -o json | jq '.paths'
```

---

### vdb exploits

Retrieve exploit intelligence for a specific vulnerability.

**Usage:**
```bash
vulnetix vdb exploits <vuln-id> [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# CVE
vulnetix vdb exploits CVE-2021-44228

# GitHub Security Advisory
vulnetix vdb exploits GHSA-jfh8-3a1q-hjz9

# JSON output
vulnetix vdb exploits CVE-2021-44228 --output json
```

**Sources include:** ExploitDB, Metasploit modules, Nuclei templates, VulnCheck, CrowdSec, and GitHub proof-of-concept repositories.

---

### vdb fixes

Retrieve comprehensive fix data for a specific vulnerability.

**Usage:**
```bash
vulnetix vdb fixes <vuln-id> [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# CVE
vulnetix vdb fixes CVE-2021-44228

# GitHub Security Advisory
vulnetix vdb fixes GHSA-jfh8-3a1q-hjz9

# JSON output
vulnetix vdb fixes CVE-2021-44228 --output json
```

**Response includes:** Patches, advisories, workarounds, KEV required actions, and AI-generated analysis.

---

### vdb versions

List all known versions for a package across ecosystems.

**Usage:**
```bash
vulnetix vdb versions <package-name> [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# Get all versions of a package
vulnetix vdb versions express

# Get versions as JSON
vulnetix vdb versions express --output json
```

---

### vdb gcve

Retrieve a paginated list of vulnerabilities published within a date range, with enrichment data.

**Usage:**
```bash
vulnetix vdb gcve --start <YYYY-MM-DD> --end <YYYY-MM-DD> [flags]
```

**Flags:**
- `--start string`: Start date (YYYY-MM-DD) **[required]**
- `--end string`: End date (YYYY-MM-DD) **[required]**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# Get vulnerabilities published in January 2024
vulnetix vdb gcve --start 2024-01-01 --end 2024-01-31

# Get all 2024 vulnerabilities as JSON
vulnetix vdb gcve --start 2024-01-01 --end 2024-12-31 --output json

# Save to file
vulnetix vdb gcve --start 2024-01-01 --end 2024-01-31 -o json > jan-2024-vulns.json
```

---

### vdb purl

Query the VDB using a standard [Package URL (PURL)](https://github.com/package-url/purl-spec) string. The PURL is parsed automatically and the appropriate VDB endpoint is called based on the dispatch logic below.

**Usage:**
```bash
vulnetix vdb purl <purl-string> [flags]
```

**Dispatch logic:**

| PURL contains | Flag | Action |
|---------------|------|--------|
| Version + known ecosystem | — | Product version+ecosystem lookup |
| Version + unknown ecosystem | — | Product version lookup |
| No version | `--vulns` | Package vulnerabilities |
| No version | (default) | List product versions |

**Flags:**
- `--vulns`: Show vulnerabilities instead of versions (only effective when PURL has no version)
- `--limit int`: Maximum number of results (default 100)
- `--offset int`: Number of results to skip (default 0)
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# Version + known ecosystem → product version+ecosystem lookup
vulnetix vdb purl "pkg:npm/express@4.17.1"

# Version in Maven ecosystem (with namespace)
vulnetix vdb purl "pkg:maven/org.apache.commons/commons-lang3@3.12.0"

# No version + --vulns → package vulnerabilities
vulnetix vdb purl "pkg:pypi/requests" --vulns

# Version + JSON output
vulnetix vdb purl "pkg:golang/github.com/go-chi/chi/v5@5.0.8" -o json

# No version (default) → list product versions
vulnetix vdb purl "pkg:npm/lodash"
```

---

### vdb gcve-issuances

List GCVE issuance identifiers (GCVE-VVD-YYYY-NNNN) published in a given calendar month.

**Usage:**
```bash
vulnetix vdb gcve-issuances --year <YYYY> --month <M> [flags]
```

**Flags:**

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--year` | int | **Yes** | — | 4-digit publication year |
| `--month` | int | **Yes** | — | Publication month (1–12) |
| `--limit` | int | No | `100` | Maximum results to return (max 500) |
| `--offset` | int | No | `0` | Results to skip (for pagination) |
| `-o, --output` | string | No | `pretty` | Output format: `json` or `pretty` |

**Examples:**
```bash
# List GCVE issuances for March 2025
vulnetix vdb gcve-issuances --year 2025 --month 3

# As JSON
vulnetix vdb gcve-issuances --year 2025 --month 3 --output json

# Paginate
vulnetix vdb gcve-issuances --year 2025 --month 3 --limit 50 --offset 100
```

---

### vdb ids

List distinct CVE identifiers published in a given calendar month.

**Usage:**
```bash
vulnetix vdb ids <year> <month> [flags]
```

**Positional arguments:**

| Argument | Description |
|----------|-------------|
| `year` | 4-digit year (e.g. `2024`) |
| `month` | Month number 1–12 (e.g. `3` for March) |

**Flags:**
- `--limit int`: Maximum results (default 100, max 500)
- `--offset int`: Results to skip (for pagination, default 0)
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List CVE IDs for March 2024
vulnetix vdb ids 2024 3

# With pagination
vulnetix vdb ids 2024 3 --limit 50

# As JSON
vulnetix vdb ids 2024 3 --output json
```

---

### vdb search

Search CVE identifiers by prefix (case-insensitive). The prefix must be between 3 and 50 characters.

**Usage:**
```bash
vulnetix vdb search <prefix> [flags]
```

**Flags:**
- `--limit int`: Maximum results (default 100, max 500)
- `--offset int`: Results to skip (for pagination, default 0)
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# Search for CVE IDs starting with CVE-2024-1
vulnetix vdb search CVE-2024-1

# With pagination and JSON output
vulnetix vdb search CVE-2024-1 --limit 50 --output json

# Next page
vulnetix vdb search CVE-2024-1 --limit 100 --offset 100
```

---

### vdb sources

List all vulnerability data sources tracked by the VDB.

**Usage:**
```bash
vulnetix vdb sources [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List all data sources
vulnetix vdb sources

# As JSON
vulnetix vdb sources --output json
```

---

### vdb metric-types

List all vulnerability metric and scoring types tracked by the VDB (e.g. CVSS v2, CVSS v3.1, CVSS v4, EPSS).

**Usage:**
```bash
vulnetix vdb metric-types [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List all metric types
vulnetix vdb metric-types

# As JSON
vulnetix vdb metric-types --output json
```

---

### vdb exploit-sources

List all exploit intelligence sources tracked by the VDB (e.g. ExploitDB, Metasploit, VulnCheck, Nuclei).

**Usage:**
```bash
vulnetix vdb exploit-sources [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List all exploit intelligence sources
vulnetix vdb exploit-sources

# As JSON
vulnetix vdb exploit-sources --output json
```

---

### vdb exploit-types

List all exploit type classifications tracked by the VDB.

**Usage:**
```bash
vulnetix vdb exploit-types [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List all exploit type classifications
vulnetix vdb exploit-types

# As JSON
vulnetix vdb exploit-types --output json
```

---

### vdb fix-distributions

List all supported Linux distributions for which fix advisory data is available in the VDB.

**Usage:**
```bash
vulnetix vdb fix-distributions [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# List supported distributions
vulnetix vdb fix-distributions

# As JSON
vulnetix vdb fix-distributions --output json
```

---

## API-Only Endpoints

The following VDB API endpoints are available via direct HTTP requests but do not yet have dedicated CLI subcommands. Use `vulnetix vdb spec` to retrieve the full OpenAPI specification.

### GET /v1/summary/{year}

Annual vulnerability statistics including severity distribution, top CWEs, affected vendors, and trends.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://api.vdb.vulnetix.com/v1/summary/2024
```

---

## Examples

### Look Up a Vulnerability by Any Identifier

```bash
# MITRE CVE (Log4Shell)
vulnetix vdb vuln CVE-2021-44228

# GitHub Security Advisory (same vulnerability)
vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9

# PyPI vulnerability
vulnetix vdb vuln PYSEC-2024-123

# Rust vulnerability
vulnetix vdb vuln RUSTSEC-2024-1234

# Red Hat advisory
vulnetix vdb vuln RHSA-2025:1730

# Debian security advisory
vulnetix vdb vuln DSA-4741-1

# Ubuntu security notice
vulnetix vdb vuln USN-7040-1
```

### Investigate Exploits and Fixes

```bash
# Check exploit intelligence
vulnetix vdb exploits CVE-2021-44228
vulnetix vdb exploits GHSA-jfh8-3a1q-hjz9

# Get available fixes
vulnetix vdb fixes CVE-2021-44228
vulnetix vdb fixes GHSA-jfh8-3a1q-hjz9
```

### Audit Package Vulnerabilities

```bash
# Check if Express.js has vulnerabilities
vulnetix vdb vulns express

# Check specific version
vulnetix vdb product express 4.16.0

# Check specific version in npm ecosystem
vulnetix vdb product express 4.16.0 npm
```

### Explore Available Data

```bash
# List all ecosystems
vulnetix vdb ecosystems

# Find all versions of a package
vulnetix vdb product react --limit 500

# List all package versions across ecosystems
vulnetix vdb versions react
```

### Export Data for Analysis

```bash
# Export vulnerability data (any identifier format)
vulnetix vdb vuln CVE-2021-44228 -o json > analysis/log4shell-cve.json
vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9 -o json > analysis/log4shell-ghsa.json

# Export all vulnerabilities for a package
vulnetix vdb vulns webpack -o json > reports/webpack-vulns.json

# Export API specification
vulnetix vdb spec -o json > docs/vdb-api-spec.json

# Export vulnerabilities for a date range
vulnetix vdb gcve --start 2024-01-01 --end 2024-01-31 -o json > jan-2024-vulns.json
```

### Combine with Other Tools

```bash
# Filter vulnerability data with jq
vulnetix vdb vuln CVE-2021-44228 -o json | jq '.[0].containers.cna.title'

# Count vulnerabilities
vulnetix vdb vulns lodash -o json | jq '.total'

# Extract severity levels
vulnetix vdb vulns express -o json | jq '.vulnerabilities[].severity' | sort | uniq -c
```

## Rate Limiting

The VDB API implements rate limiting to ensure fair usage:

### Per-Minute Rate Limit
- **Default**: 60 requests per minute
- Exceeded requests receive HTTP 429 status

### Weekly Quota
- **Default**: 1000 requests per week (configurable per organization)
- Resets every Sunday at 00:00 UTC
- Contact sales@vulnetix.com for higher quotas

### Rate Limit Headers

All responses include rate limit information:

```
RateLimit-MinuteLimit: 60
RateLimit-Remaining: 45
RateLimit-Reset: 28
RateLimit-WeekLimit: 10000
RateLimit-WeekRemaining: 8543
RateLimit-WeekReset: 172800
```

### Handling Rate Limits

The CLI automatically handles token expiration (15-minute JWT tokens).

For rate limit errors, the API returns:
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "details": "Too many requests. Limit: 60 requests per minute. Try again in 42 seconds."
}
```

**Best Practices:**
- Cache responses when possible
- Use pagination parameters to reduce request count
- Implement exponential backoff for retries
- Monitor rate limit headers
- Contact Vulnetix for production usage quotas

## Global Flags

All `vdb` commands support these global flags:

- `--org-id string`: Organization UUID (overrides env vars)
- `--api-key string`: Direct API key (overrides VULNETIX_API_KEY env var)
- `--secret string`: SigV4 secret key (overrides VVD_SECRET env var)
- `--method string`: Auth method: `apikey` or `sigv4` (auto-detected from flags if omitted)
- `--base-url string`: VDB API base URL (default "https://api.vdb.vulnetix.com/v1")
- `-o, --output string`: Output format (json, pretty) (default "pretty")

## Security Notes

1. **Never commit credentials** to version control
2. **Use environment variables** or secure configuration files
3. **Rotate secrets regularly** for production use
4. **Store secrets securely** using secrets managers in CI/CD
5. **Limit access** to credentials on shared systems

## Troubleshooting

### Authentication Errors

```bash
# Quickest fix — run interactive login
vulnetix auth login

# Check all credential sources
vulnetix auth status

# Or set environment variables (Direct API Key)
export VULNETIX_ORG_ID="your-uuid"
export VULNETIX_API_KEY="your-key"

# Or set environment variables (SigV4)
export VVD_ORG="your-uuid"
export VVD_SECRET="your-secret"

# Or create config file
mkdir -p ~/.vulnetix
cat > ~/.vulnetix/credentials.json << EOF
{
  "org_id": "your-uuid",
  "api_key": "your-key",
  "method": "apikey"
}
EOF
```

### Token Expiration

JWT tokens automatically expire after 15 minutes. The CLI handles token refresh automatically. If you encounter token errors, try:

```bash
# The CLI will automatically request a new token
vulnetix vdb ecosystems
```

### Rate Limiting

If you exceed rate limits:

1. Wait for the reset time indicated in the error message
2. Consider implementing caching
3. Use pagination to reduce request frequency
4. Contact Vulnetix for higher quotas

### Network Issues

```bash
# Test connectivity
curl -I https://api.vdb.vulnetix.com/v1/spec

# Use custom base URL if needed
vulnetix vdb ecosystems --base-url https://custom-endpoint.example.com/v1
```

## API Documentation

For complete API documentation, visit:
- OpenAPI Spec: https://api.vdb.vulnetix.com/v1/spec
- Interactive Docs: https://redocly.github.io/redoc/?url=https://api.vdb.vulnetix.com/v1/spec
- User Guide: Contact sales@vulnetix.com

## Support

For assistance:
- Email: sales@vulnetix.com
- Website: https://www.vulnetix.com
- GitHub Issues: https://github.com/vulnetix/cli/issues
