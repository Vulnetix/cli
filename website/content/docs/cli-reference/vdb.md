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
  - [vdb exploits search](#vdb-exploits-search)
  - [vdb exploits sources](#vdb-exploits-sources)
  - [vdb exploits types](#vdb-exploits-types)
  - [vdb fixes](#vdb-fixes)
  - [vdb fixes distributions](#vdb-fixes-distributions)
  - [vdb timeline](#vdb-timeline)
  - [vdb versions](#vdb-versions)
  - [vdb gcve](#vdb-gcve)
  - [vdb gcve issuances](#vdb-gcve-issuances)
  - [vdb purl](#vdb-purl)
  - [vdb ids](#vdb-ids)
  - [vdb search](#vdb-search)
  - [vdb sources](#vdb-sources)
  - [vdb metrics](#vdb-metrics)
  - [vdb metrics types](#vdb-metrics-types)
  - [vdb status](#vdb-status)
  - [vdb summary](#vdb-summary)
  - [vdb packages search](#vdb-packages-search)
  - [vdb ecosystem package](#vdb-ecosystem-package)
  - [vdb ecosystem group](#vdb-ecosystem-group)
- [V2 Commands](#v2-commands)
- [Output Management](#output-management)
  - [Output Formats](#output-formats)
  - [JSON Formatting Options](#json-formatting-options)
  - [Saving Output to a File](#saving-output-to-a-file)
  - [Separating Output and Logs](#separating-output-and-logs)
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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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

### vdb exploits search

Search for exploits across all vulnerabilities with filtering.

**Usage:**
```bash
vulnetix vdb exploits search [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ecosystem` | string | - | Filter by package ecosystem |
| `--source` | string | - | Filter by exploit source |
| `--severity` | string | - | Filter by severity level |
| `--in-kev` | bool | `false` | Only show exploits in CISA KEV |
| `--min-epss` | float | - | Minimum EPSS score threshold |
| `-q` | string | - | Free-text search query |
| `--sort` | string | - | Sort field |
| `--limit` | int | `100` | Maximum results |
| `--offset` | int | `0` | Results to skip |
| `-o, --output` | string | `pretty` | Output format: `json`, `yaml`, `pretty` |

**Examples:**
```bash
# Search for npm exploits
vulnetix vdb exploits search --ecosystem npm

# High-severity exploits in CISA KEV
vulnetix vdb exploits search --in-kev --severity critical

# Exploits with high EPSS scores
vulnetix vdb exploits search --min-epss 0.9 --limit 20

# Free-text search
vulnetix vdb exploits search -q "remote code execution" -o json
```

---

### vdb exploits sources

List all exploit intelligence sources tracked by the VDB (e.g. ExploitDB, Metasploit, VulnCheck, Nuclei).

> **Alias:** `vdb exploit-sources` still works as a hidden alias.

**Usage:**
```bash
vulnetix vdb exploits sources [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
# List all exploit intelligence sources
vulnetix vdb exploits sources

# As JSON
vulnetix vdb exploits sources --output json
```

---

### vdb exploits types

List all exploit type classifications tracked by the VDB.

> **Alias:** `vdb exploit-types` still works as a hidden alias.

**Usage:**
```bash
vulnetix vdb exploits types [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
# List all exploit type classifications
vulnetix vdb exploits types

# As JSON
vulnetix vdb exploits types --output json
```

---

### vdb fixes

Retrieve comprehensive fix data for a specific vulnerability.

**Usage:**
```bash
vulnetix vdb fixes <vuln-id> [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

> **V2 note:** When using API v2 (`-V v2`), fix data is fetched in parallel with other enrichment endpoints for faster response times.

**Examples:**
```bash
# CVE
vulnetix vdb fixes CVE-2021-44228

# GitHub Security Advisory
vulnetix vdb fixes GHSA-jfh8-3a1q-hjz9

# JSON output
vulnetix vdb fixes CVE-2021-44228 --output json
```

**Response includes:** Patches, advisories, workarounds, KEV required actions, AI-generated analysis, and exploitation maturity assessment.

**Registry fix objects** now include computed display fields:

| Field | Description | Example |
|-------|-------------|---------|
| `displayName` | Human-readable registry name | `"Kubernetes Registry"`, `"npm"`, `"PyPI"` |
| `registryKey` | Stable unique key for the registry | `"oci:kubernetes"`, `"npm"`, `"oci:ghcr"` |
| `ecosystem` | Raw ecosystem identifier | `"oci"`, `"npm"`, `"unknown"` |
| `purl` | Package URL for the fixed version | `"pkg:oci/kubernetes/ingress-nginx@1.12.0"` |

**Top-level `exploitationMaturity` object:**

```json
{
  "exploitationMaturity": {
    "score": 42,
    "level": "WEAPONIZED",
    "confidence": "MEDIUM",
    "reasoning": "2 public exploits available",
    "factors": {
      "epss": 0.12,
      "cess": 0.08,
      "kevPresence": false,
      "exploitDbCount": 2,
      "crowdSecSightings": 0
    }
  }
}
```

Levels: `NONE` (0–14) · `POC` (15–34) · `WEAPONIZED` (35–54) · `ACTIVE` (55–74) · `WIDESPREAD` (75+)

---

### vdb fixes distributions

List all supported Linux distributions for which fix advisory data is available in the VDB.

> **Alias:** `vdb fix-distributions` still works as a hidden alias.

**Usage:**
```bash
vulnetix vdb fixes distributions [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
# List supported distributions
vulnetix vdb fixes distributions

# As JSON
vulnetix vdb fixes distributions --output json
```

---

### vdb timeline

Retrieve the vulnerability lifecycle timeline — CVE dates, exploits, scoring history, patches, and advisories.

Works without `-V v2` (v1 default). With `-V v2`, also returns `sources{}` providing raw source transparency data.

**Usage:**
```bash
vulnetix vdb timeline <vuln-id> [flags]
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--include` | string | all | Comma-separated event types to include |
| `--exclude` | string | none | Comma-separated event types to exclude |
| `--dates` | string | all | CVE date fields: `published,modified,reserved` |
| `--scores-limit` | int | `30` | Max score-change events (max 365) |
| `-o, --output` | string | `pretty` | Output format: `json`, `yaml`, `pretty` |

**Event types:**

| Type | Description |
|------|-------------|
| `source` | CVE lifecycle dates (published, reserved, updated, GHSA, ADP reviews) |
| `exploit` | All exploit sources (CISA KEV, EU KEV, VulnCheck, Exploit-DB, Metasploit, Nuclei, CrowdSec, PoC) |
| `score-change` | EPSS and Coalition ESS score history (sampled by outlier detection + interval fill) |
| `patch` | Fix PRs, commits, distribution advisories, registry version releases |
| `advisory` | CERT/PSIRT/government security advisories |
| `scorecard` | OpenSSF Scorecard assessments |

**Examples:**
```bash
# Full timeline (v1, no sources{})
vulnetix vdb timeline CVE-2021-44228

# With source transparency (v2)
vulnetix vdb timeline CVE-2021-44228 -V v2

# Only exploit events
vulnetix vdb timeline CVE-2021-44228 --include exploit

# All except score-change, limit scores
vulnetix vdb timeline CVE-2021-44228 --exclude score-change

# Restrict CVE dates to published only, limit score history
vulnetix vdb timeline CVE-2021-44228 --dates published --scores-limit 10

# JSON output with v2 source transparency
vulnetix vdb timeline CVE-2021-44228 -V v2 --include exploit --output json
```

**Response (v1):**
```json
{
  "identifier": "CVE-2021-44228",
  "events": [
    { "time": 1638316800000, "type": "source", "label": "CVE Published", "sourceRef": "cve", ... },
    { "time": 1638403200000, "type": "exploit", "label": "CISA KEV Added", "kevCisa": true, ... },
    { "time": 1638230400000, "type": "score-change", "label": "EPSS Score", "epssScore": 0.97, ... }
  ],
  "meta": {
    "currentAgeDays": 1500, "lifecycleStage": "LEGACY",
    "publicationToKevDays": 1, "publicationToFirstExploitDays": 0,
    "insights": ["Exploit published on same day as disclosure (0-day)", "..."]
  }
}
```

**v2 adds** a `sources{}` section with raw data from each source (kev.cisa, kev.eu, epss, cess, vulncheck, crowdsec, scorecard, advisories, adp).

---

### vdb versions

List all known versions for a package across ecosystems.

**Usage:**
```bash
vulnetix vdb versions <package-name> [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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

### vdb gcve issuances

List GCVE issuance identifiers (GCVE-VVD-YYYY-NNNN) published in a given calendar month.

> **Alias:** `vdb gcve-issuances` still works as a hidden alias.

**Usage:**
```bash
vulnetix vdb gcve issuances --year <YYYY> --month <M> [flags]
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
vulnetix vdb gcve issuances --year 2025 --month 3

# As JSON
vulnetix vdb gcve issuances --year 2025 --month 3 --output json

# Paginate
vulnetix vdb gcve issuances --year 2025 --month 3 --limit 50 --offset 100
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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

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
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
# List all data sources
vulnetix vdb sources

# As JSON
vulnetix vdb sources --output json
```

---

### vdb metrics

Vulnerability metric intelligence.

**Usage:**
```bash
vulnetix vdb metrics <vuln-id> [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

---

### vdb metrics types

List all vulnerability metric and scoring types tracked by the VDB (e.g. CVSS v2, CVSS v3.1, CVSS v4, EPSS).

> **Alias:** `vdb metric-types` still works as a hidden alias.

**Usage:**
```bash
vulnetix vdb metrics types [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
# List all metric types
vulnetix vdb metrics types

# As JSON
vulnetix vdb metrics types --output json
```

---

### vdb status

Check API health and display CLI/auth metadata.

**Usage:**
```bash
vulnetix vdb status [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

---

### vdb summary

Retrieve all-time global statistics for the entire Vulnetix Vulnerability Database. Shows database coverage, severity distribution, enrichment rates, exploit and malware counts, and the top 10 CWEs and vendors by CVE volume.

**Usage:**
```bash
vulnetix vdb summary [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Response sections:**

| Section | Key fields |
|---------|-----------|
| `database` | `totalRows`, `distinctCveIds`, `totalExploits`, `malwareExploits`, `cvesWithExploits`, `totalReferences`, `distinctReferenceUrls`, `totalKev` |
| `severity` | `critical`, `high`, `medium`, `low`, `none` |
| `coverage` | `withCvss`, `withEpss`, `withCess`, `withCwe`, `withCapec`, `withSsvc`, `noReferences`, `averageEpss`, `highEpss` |
| `topCWEs` | Top 10 CWE IDs by distinct CVE count |
| `topVendors` | Top 10 vendors by distinct CVE count |

**Examples:**
```bash
# Human-readable summary
vulnetix vdb summary

# Full JSON response
vulnetix vdb summary --output json
```

---

### vdb packages search

Full-text search across packages in the VDB. Searches across multiple data sources including SBOM dependencies, package registries, CVE affected products, GitHub repositories, CISA/VulnCheck KEV entries, end-of-life databases, and CycloneDX metadata.

**Usage:**
```bash
vulnetix vdb packages search <query> [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ecosystem` | string | - | Filter by package ecosystem |
| `--limit` | int | `100` | Maximum results |
| `--offset` | int | `0` | Results to skip |
| `-o, --output` | string | `pretty` | Output format: `json`, `yaml`, `pretty` |

**Response Fields:**

Each package in the response includes:

| Field | Type | Description |
|-------|------|-------------|
| `packageName` | string | Lowercased package name |
| `matchSources` | string[] | Data sources where the package was found. Values: `dependency`, `package_version`, `cve_affected`, `github_repository`, `eol_product`, `kev`, `cyclonedx_info`, `depsdev` |
| `ecosystems` | string[] | Package ecosystems (npm, pypi, maven, etc.) |
| `versionCount` | int | Number of known versions |
| `versions` | array | Top 10 most recent versions with safe harbour scores |
| `vulnCount` | int | Number of associated CVEs |
| `vulnerabilities` | array | List of CVEs affecting this package. Each entry: `{ cveId, source, severity, score, metricType, vectorString, purl }` |
| `exploitationSignals` | object | CISA KEV, VulnCheck KEV, exploit count, XDB count, CrowdSec sightings |
| `safeHarbour` | object | Recommended versions and highest safety score |
| `vendor` | string? | Vendor name from CVE/KEV data |
| `product` | string? | Product name from CVE/KEV data |
| `repositoryUrl` | string? | GitHub repository URL |
| `eolStatus` | object? | End-of-life status: `{ productName, isEol }` |
| `scorecardScore` | float? | OpenSSF Scorecard score |
| `hasProvenance` | bool | Whether SLSA provenance exists |

**Examples:**
```bash
# Search for packages matching "express"
vulnetix vdb packages search express

# Search within npm ecosystem
vulnetix vdb packages search express --ecosystem npm

# JSON output with pagination
vulnetix vdb packages search log4j --limit 20 -o json
```

---

### vdb ecosystem package

Get package information within a specific ecosystem.

**Usage:**
```bash
vulnetix vdb ecosystem package <ecosystem> <package-name> [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--versions` | bool | `false` | Show version information instead of package info |
| `-o, --output` | string | `pretty` | Output format: `json`, `yaml`, `pretty` |

**Examples:**
```bash
# Get package info
vulnetix vdb ecosystem package npm express

# Get version information
vulnetix vdb ecosystem package npm express --versions

# JSON output
vulnetix vdb ecosystem package pypi requests -o json
```

---

### vdb ecosystem group

Get group/artifact information using Maven-style coordinates.

**Usage:**
```bash
vulnetix vdb ecosystem group <ecosystem> <group> <artifact> [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
# Look up a Maven artifact
vulnetix vdb ecosystem group maven org.apache.commons commons-lang3

# JSON output
vulnetix vdb ecosystem group maven org.springframework spring-core -o json
```

---

## V2 Commands

The following commands are available when using API v2 (`-V v2`). They provide additional vulnerability enrichment data.

<div class="vdb-v2-only">

### vdb workarounds

Get workaround information for a vulnerability.

**Usage:**
```bash
vulnetix vdb workarounds <vuln-id> -V v2 [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
vulnetix vdb workarounds CVE-2021-44228 -V v2
vulnetix vdb workarounds CVE-2021-44228 -V v2 -o json
```

---

### vdb advisories

Get advisory data for a vulnerability.

**Usage:**
```bash
vulnetix vdb advisories <vuln-id> -V v2 [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
vulnetix vdb advisories CVE-2021-44228 -V v2
vulnetix vdb advisories GHSA-jfh8-3a1q-hjz9 -V v2 -o json
```

---

### vdb cwe guidance

Get CWE-based guidance for a vulnerability.

**Usage:**
```bash
vulnetix vdb cwe guidance <vuln-id> -V v2 [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
vulnetix vdb cwe guidance CVE-2021-44228 -V v2
vulnetix vdb cwe guidance CVE-2021-44228 -V v2 -o json
```

---

### vdb kev

Get CISA KEV (Known Exploited Vulnerabilities) status for a vulnerability.

**Usage:**
```bash
vulnetix vdb kev <vuln-id> -V v2 [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
vulnetix vdb kev CVE-2021-44228 -V v2
vulnetix vdb kev CVE-2021-44228 -V v2 -o json
```

---

### vdb timeline

Get the vulnerability timeline showing key dates and events.

**Usage:**
```bash
vulnetix vdb timeline <vuln-id> -V v2 [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
vulnetix vdb timeline CVE-2021-44228 -V v2
vulnetix vdb timeline CVE-2021-44228 -V v2 -o json
```

---

### vdb affected

Get affected products and packages for a vulnerability.

**Usage:**
```bash
vulnetix vdb affected <vuln-id> -V v2 [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ecosystem` | string | - | Filter by package ecosystem |
| `--package-name` | string | - | Filter by package name |
| `-o, --output` | string | `pretty` | Output format: `json`, `yaml`, `pretty` |

**Examples:**
```bash
vulnetix vdb affected CVE-2021-44228 -V v2
vulnetix vdb affected CVE-2021-44228 -V v2 --ecosystem maven
vulnetix vdb affected CVE-2021-44228 -V v2 --ecosystem maven --package-name log4j-core -o json
```

---

### vdb scorecard

Get the OpenSSF Scorecard for a vulnerability's source repository, including security check results.

**Usage:**
```bash
vulnetix vdb scorecard <vuln-id> -V v2 [flags]
```

**Flags:**
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")

**Examples:**
```bash
vulnetix vdb scorecard CVE-2021-44228 -V v2
vulnetix vdb scorecard CVE-2021-44228 -V v2 -o json
```

#### vdb scorecard search

Search OpenSSF Scorecards by repository name.

**Usage:**
```bash
vulnetix vdb scorecard search <query> -V v2 [flags]
```

**Examples:**
```bash
vulnetix vdb scorecard search openssl -V v2
vulnetix vdb scorecard search github.com/openssl/openssl -V v2 -o json
```

---

### vdb remediation plan

Get a context-aware remediation plan for a vulnerability.

**Usage:**
```bash
vulnetix vdb remediation plan <vuln-id> -V v2 [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ecosystem` | string | - | Filter by package ecosystem |
| `--package-name` | string | - | Filter by package name |
| `--vendor` | string | - | Filter by vendor name |
| `--product` | string | - | Filter by product name |
| `--purl` | string | - | Package URL (overrides ecosystem + package-name) |
| `--current-version` | string | - | Current package version |
| `--package-manager` | string | - | Package manager (npm, pip, cargo, etc.) |
| `--container-image` | string | - | Container image reference |
| `--os` | string | - | OS identifier (e.g. `ubuntu:22.04`) |
| `--registry` | string | - | Registry URL |
| `--include-guidance` | bool | `false` | Include CWE-based guidance text |
| `--include-verification-steps` | bool | `false` | Include verification steps in actions |
| `-o, --output` | string | `pretty` | Output format: `json`, `yaml`, `pretty` |

**Examples:**
```bash
# Basic remediation plan
vulnetix vdb remediation plan CVE-2021-44228 -V v2

# With package context
vulnetix vdb remediation plan CVE-2021-44228 -V v2 \
  --ecosystem maven --package-name log4j-core --current-version 2.14.1

# Using PURL
vulnetix vdb remediation plan CVE-2021-44228 -V v2 \
  --purl "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

# With full context and guidance
vulnetix vdb remediation plan CVE-2021-44228 -V v2 \
  --ecosystem maven --package-name log4j-core \
  --current-version 2.14.1 --package-manager maven \
  --include-guidance --include-verification-steps -o json
```

### vdb cloud-locators

Derive cloud-native resource identifier templates from vendor/product pairs. Returns templates for AWS ARN, Azure Resource ID, GCP Resource Name, Cloudflare Locator, and Oracle OCID with placeholders for account-specific values.

**Usage:**
```bash
vulnetix vdb cloud-locators -V v2 [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--vendor` | string | - | Vendor name (e.g. amazon, microsoft, google, cloudflare, oracle) |
| `--product` | string | - | Product/service name (e.g. s3, ec2, cloudfront, workers) |
| `-o, --output` | string | `pretty` | Output format: `json`, `yaml`, `pretty` |

**Examples:**
```bash
# AWS S3 (regional service)
vulnetix vdb cloud-locators --vendor amazon --product s3 -V v2

# AWS CloudFront (global-only, region=us-east-1)
vulnetix vdb cloud-locators --vendor amazon --product cloudfront -V v2

# Azure Storage
vulnetix vdb cloud-locators --vendor microsoft --product storage -V v2

# GCP Compute Engine
vulnetix vdb cloud-locators --vendor google --product compute -V v2

# Cloudflare Workers
vulnetix vdb cloud-locators --vendor cloudflare --product workers -V v2

# Oracle Compute
vulnetix vdb cloud-locators --vendor oracle --product compute -V v2

# JSON output for automation
vulnetix vdb cloud-locators --vendor amazon --product lambda -V v2 -o json
```

**Response includes:**

| Field | Type | Description |
|-------|------|-------------|
| `vendor` | string | Input vendor name |
| `product` | string | Input product name |
| `generatedCpe` | string | CPE 2.3 string derived from vendor/product |
| `cloudLocators.matched` | bool | Whether a cloud mapping was found |
| `cloudLocators.provider` | string | Primary cloud provider |
| `cloudLocators.service` | string | Normalised service name |
| `cloudLocators.templates[]` | array | Resource identifier templates with `{placeholders}` |

</div>

---

## Output Management

The `--output` (`-o`) flag controls the format of command output. Additional flags provide fine-grained control over JSON formatting and syntax highlighting.

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| `pretty` | `-o pretty` | Human-readable indented JSON (default) |
| `json` | `-o json` | Machine-readable JSON with configurable indent and highlighting |
| `yaml` | `-o yaml` | YAML output for readability and config file integration |

```bash
# Default pretty output
vulnetix vdb vuln CVE-2021-44228

# JSON output
vulnetix vdb vuln CVE-2021-44228 -o json

# YAML output
vulnetix vdb vuln CVE-2021-44228 -o yaml
```

### JSON Formatting Options

These flags are only valid with `--output json`. Using them with other output formats produces an error.

#### Indent Presets

Three mutually exclusive indent presets control JSON indentation depth. Only one can be used at a time.

| Flag | Indent | Description |
|------|--------|-------------|
| *(default)* | 4 spaces | Comfortable — balanced readability (same as `--comfortable`) |
| `--comfortable` | 4 spaces | Explicitly request the default indent |
| `--compact` | 2 spaces | Denser output, less vertical space |
| `--sparse` | 8 spaces | Wide indent for maximum readability |

```bash
# Default 4-space indent
vulnetix vdb vuln CVE-2021-44228 -o json

# Compact 2-space indent
vulnetix vdb vuln CVE-2021-44228 -o json --compact

# Sparse 8-space indent
vulnetix vdb vuln CVE-2021-44228 -o json --sparse
```

#### Syntax Highlighting

The `--highlight` flag adds terminal color highlighting to JSON output. Available themes:

| Value | Description |
|-------|-------------|
| `none` | No highlighting (default) |
| `dark` | Monokai theme — optimized for dark terminal backgrounds |
| `light` | GitHub theme — optimized for light terminal backgrounds |

```bash
# Highlighted JSON for dark terminals
vulnetix vdb vuln CVE-2021-44228 -o json --highlight dark

# Highlighted JSON for light terminals
vulnetix vdb vuln CVE-2021-44228 -o json --highlight light
```

**Pipe safety:** Syntax highlighting is automatically disabled when stdout is not a terminal (e.g., when piping to another command or redirecting to a file). This ensures that ANSI escape codes never corrupt file output or downstream tools, even if `--highlight` is explicitly set.

```bash
# Highlighting is active (stdout is terminal)
vulnetix vdb vuln CVE-2021-44228 -o json --highlight dark

# Highlighting is auto-disabled (stdout is piped)
vulnetix vdb vuln CVE-2021-44228 -o json --highlight dark | jq .

# Highlighting is auto-disabled (stdout is redirected)
vulnetix vdb vuln CVE-2021-44228 -o json --highlight dark > output.json
```

### Saving Output to a File

Use shell redirection (`>`) to write command output to a file. The data stream (stdout) contains only the formatted output, making it safe for direct file capture.

```bash
# Save JSON to a file
vulnetix vdb vuln CVE-2021-44228 -o json > vuln.json

# Save compact JSON
vulnetix vdb vuln CVE-2021-44228 -o json --compact > vuln.json

# Save YAML to a file
vulnetix vdb vuln CVE-2021-44228 -o yaml > vuln.yaml

# Append to an existing file
vulnetix vdb vuln CVE-2021-44228 -o json >> all-vulns.json
```

### Separating Output and Logs

The CLI writes data output to **stdout** and diagnostic messages (progress, warnings, rate limit info) to **stderr**. This separation allows you to capture clean data output while still seeing — or independently capturing — log messages.

```bash
# Save data to file, logs print to terminal
vulnetix vdb vuln CVE-2021-44228 -o json > vuln.json

# Save data to file, logs to separate file
vulnetix vdb vuln CVE-2021-44228 -o json > vuln.json 2> vuln.log

# Save data to file, suppress logs entirely
vulnetix vdb vuln CVE-2021-44228 -o json > vuln.json 2>/dev/null

# Save both data and logs to the same file
vulnetix vdb vuln CVE-2021-44228 -o json > vuln.json 2>&1

# View logs only, discard data
vulnetix vdb vuln CVE-2021-44228 -o json > /dev/null
```

| Redirect | Effect |
|----------|--------|
| `> file` | Data output to file, logs to terminal |
| `2> file` | Logs to file, data to terminal |
| `> data 2> logs` | Data and logs to separate files |
| `2>/dev/null` | Suppress log messages |
| `> file 2>&1` | Everything to one file |

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

# Search exploits across all vulnerabilities
vulnetix vdb exploits search --ecosystem npm --in-kev
```

### Audit Package Vulnerabilities

```bash
# Check if Express.js has vulnerabilities
vulnetix vdb vulns express

# Check specific version
vulnetix vdb product express 4.16.0

# Check specific version in npm ecosystem
vulnetix vdb product express 4.16.0 npm

# Search for packages
vulnetix vdb packages search express --ecosystem npm

# Get ecosystem-scoped package info
vulnetix vdb ecosystem package npm express --versions
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
- `--base-url string`: VDB API base URL (default "https://api.vdb.vulnetix.com")
- `-V, --api-version string`: API version path (default "v1"; e.g. "v2")
- `-o, --output string`: Output format: `json`, `yaml`, `pretty` (default "pretty")
- `--compact`: 2-space JSON indent (`--output json` only)
- `--comfortable`: 4-space JSON indent, the default (`--output json` only)
- `--sparse`: 8-space JSON indent (`--output json` only)
- `--highlight string`: Syntax highlighting: `dark`, `light`, `none` (`--output json` only, default "none")

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
vulnetix vdb ecosystems --base-url https://custom-endpoint.example.com

# Target a different API version
vulnetix vdb ecosystems --api-version v2
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
