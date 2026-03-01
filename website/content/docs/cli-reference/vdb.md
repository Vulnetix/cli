---
title: "VDB Command Reference"
weight: 2
description: "Access the Vulnetix Vulnerability Database for CVE lookups, package vulnerabilities, and ecosystem data."
---

The `vdb` subcommand provides access to the Vulnetix Vulnerability Database (VDB) API, offering comprehensive vulnerability intelligence from multiple authoritative sources.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Commands](#commands)
  - [vdb cve](#vdb-cve)
  - [vdb ecosystems](#vdb-ecosystems)
  - [vdb product](#vdb-product)
  - [vdb vulns](#vdb-vulns)
  - [vdb spec](#vdb-spec)
- [Examples](#examples)
- [Rate Limiting](#rate-limiting)

## Overview

The VDB API aggregates vulnerability data from:

- **Primary Sources**: MITRE CVE, NIST NVD, CISA KEV
- **Enhanced Intelligence**: VulnCheck KEV/NVD++/XDB, CrowdSec
- **Ecosystem Sources**: GitHub Security Advisories, OSV, EUVD
- **Risk Scoring**: FIRST EPSS, Coalition CESS

## Authentication

### Environment Variables

The recommended approach is to set environment variables:

```bash
export VVD_ORG="your-organization-uuid"
export VVD_SECRET="your-secret-key"
```

### Configuration File

Alternatively, create `~/.vulnetix/vdb.json`:

```json
{
  "org_id": "your-organization-uuid",
  "secret_key": "your-secret-key"
}
```

### Command-Line Flags

You can also provide credentials via flags (not recommended for security):

```bash
vulnetix vdb ecosystems --org-id "your-uuid" --secret "your-secret"
```

### Obtaining Credentials

1. **Via Demo Request**: Visit https://www.vulnetix.com and complete the demo request form
2. **Via Email**: Send a request to sales@vulnetix.com with subject "VDB API Access Request"

## Commands

### vdb cve

Retrieve detailed information about a specific CVE.

**Usage:**
```bash
vulnetix vdb cve <CVE-ID> [flags]
```

**Flags:**
- `-o, --output string`: Output format (json, pretty) (default "pretty")

**Examples:**
```bash
# Get CVE information
vulnetix vdb cve CVE-2024-1234

# Get CVE in JSON format
vulnetix vdb cve CVE-2024-1234 --output json

# Save CVE to file
vulnetix vdb cve CVE-2024-1234 -o json > cve-2024-1234.json
```

**Response includes:**
- CVE identifier
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
vulnetix vdb product <product-name> [version] [flags]
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

# List with pagination
vulnetix vdb product express --limit 50 --offset 100

# Get all versions as JSON
vulnetix vdb product lodash --output json
```

**List response includes:**
- Package/product name
- Total number of versions
- Array of version strings
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
  - CVE identifiers
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

## Examples

### Check a Specific CVE

```bash
# Get information about Log4Shell
vulnetix vdb cve CVE-2021-44228
```

### Audit Package Vulnerabilities

```bash
# Check if Express.js has vulnerabilities
vulnetix vdb vulns express

# Check specific version
vulnetix vdb product express 4.16.0
```

### Explore Available Data

```bash
# List all ecosystems
vulnetix vdb ecosystems

# Find all versions of a package
vulnetix vdb product react --limit 500
```

### Export Data for Analysis

```bash
# Export all CVE data
vulnetix vdb cve CVE-2024-1234 -o json > analysis/cve-2024-1234.json

# Export all vulnerabilities for a package
vulnetix vdb vulns webpack -o json > reports/webpack-vulns.json

# Export API specification
vulnetix vdb spec -o json > docs/vdb-api-spec.json
```

### Combine with Other Tools

```bash
# Filter CVE data with jq
vulnetix vdb cve CVE-2024-1234 -o json | jq '.cvss.v3.baseScore'

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

- `--org-id string`: Organization UUID (overrides VVD_ORG env var)
- `--secret string`: Secret key (overrides VVD_SECRET env var)
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
# Error: credentials not found
# Solution: Set environment variables
export VVD_ORG="your-uuid"
export VVD_SECRET="your-secret"

# Or create config file
mkdir -p ~/.vulnetix
cat > ~/.vulnetix/vdb.json << EOF
{
  "org_id": "your-uuid",
  "secret_key": "your-secret"
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
