---
title: "CLI Reference"
weight: 2
description: "Complete reference for all Vulnetix CLI commands, flags, and usage patterns."
---

Complete reference for all Vulnetix CLI commands, flags, and usage patterns.

## Commands

### vulnetix (root command)

Run vulnerability management tasks against the Vulnetix backend.

```bash
vulnetix
```

The root command runs an authentication healthcheck.

| Task | Description |
|------|-------------|
| `info` (default) | Authentication healthcheck across all credential sources |

---

### vulnetix auth

Manage authentication credentials for the Vulnetix API.

```bash
vulnetix auth [login|status|verify|logout] [flags]
```

#### auth login

Authenticate with Vulnetix. Interactive by default when run in a terminal.

```bash
# Interactive login (prompts for method, org ID, secret, storage)
vulnetix auth login

# Non-interactive login with Direct API Key
vulnetix auth login --method apikey --org-id <UUID> --secret <KEY> --store home

# Non-interactive login with SigV4
vulnetix auth login --method sigv4 --org-id <UUID> --secret <KEY> --store project
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--method` | string | `apikey` | Authentication method: `apikey` or `sigv4` |
| `--org-id` | string | - | Organization ID (UUID) |
| `--secret` | string | - | API key (hex) or SigV4 secret key |
| `--store` | string | `home` | Credential storage location: `home`, `project` |

Running `vulnetix auth` without a subcommand also triggers login.

#### auth status

Show current authentication state, including the credential source, method, and masked key.

```bash
vulnetix auth status
```

#### auth verify

Verify that stored credentials can authenticate with the Vulnetix API. Does not modify credentials.

```bash
# Verify stored credentials
vulnetix auth verify

# Verify with explicit API endpoint
vulnetix auth verify --base-url https://app.vulnetix.com/api
```

#### auth logout

Remove stored credentials from all file-based stores.

```bash
vulnetix auth logout
```

---

### vulnetix upload

Upload a security artifact file (SBOM, SARIF, VEX, CSAF) to Vulnetix for processing.

```bash
vulnetix upload --file <path> [flags]
```

The file format is auto-detected from content and extension but can be overridden. Files larger than 10MB are uploaded using chunked transfer. Authentication uses stored credentials or environment variables.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--file` | string | - | Path to artifact file to upload (**required**) |
| `--org-id` | string | stored | Organization ID (UUID, uses stored credentials if not set) |
| `--base-url` | string | `https://app.vulnetix.com/api` | Base URL for Vulnetix API |
| `--format` | string | auto | Override auto-detected format: `cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex` |
| `--json` | bool | `false` | Output result as JSON |

**Examples:**
```bash
# Upload with stored credentials
vulnetix upload --file sbom.cdx.json

# Upload with explicit org ID
vulnetix upload --file report.sarif --org-id "123e4567-e89b-12d3-a456-426614174000"

# Override format detection
vulnetix upload --file report.json --format sarif

# JSON output for scripting
vulnetix upload --file sbom.cdx.json --json
```

---

### vulnetix gha

GitHub Actions artifact management. Designed for use within GitHub Actions workflows.

#### gha upload

Collect and upload all artifacts from the current GitHub Actions workflow run to Vulnetix.

```bash
vulnetix gha upload --org-id <UUID> [flags]
```

This command:
1. Collects all artifacts from the current workflow run via the GitHub API
2. Gathers GitHub Actions metadata from environment variables
3. Initiates a transaction with the Vulnetix API
4. Uploads each artifact with the transaction ID
5. Reports the transaction ID and artifact UUIDs

**Requires:** `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_RUN_ID` environment variables.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--base-url` | string | `https://app.vulnetix.com/api` | Base URL for Vulnetix API |
| `--json` | bool | `false` | Output results as JSON |

#### gha status

Check the processing status of uploaded artifacts by transaction ID or artifact UUID.

```bash
vulnetix gha status --org-id <UUID> --txnid <ID>
vulnetix gha status --org-id <UUID> --uuid <UUID>
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--txnid` | string | - | Transaction ID to check status |
| `--uuid` | string | - | Artifact UUID to check status |
| `--base-url` | string | `https://app.vulnetix.com/api` | Base URL for Vulnetix API |
| `--json` | bool | `false` | Output results as JSON |

---

### vulnetix vdb

Interact with the Vulnetix Vulnerability Database (VDB) API. See the full [VDB Command Reference](vdb/) for all subcommands and detailed usage.

```bash
vulnetix vdb <subcommand> [flags]
```

| Subcommand | Description |
|------------|-------------|
| `vuln <vuln-id>` | Get information about a vulnerability (CVE, GHSA, PYSEC, and 75+ formats) |
| `ecosystems` | List available package ecosystems |
| `product <name> [version] [ecosystem]` | Get product version information |
| `vulns <package>` | Get vulnerabilities for a package |
| `spec` | Get the OpenAPI specification |
| `exploits <vuln-id>` | Get exploit intelligence for a vulnerability |
| `fixes <vuln-id>` | Get fix data for a vulnerability |
| `versions <package>` | Get all versions of a package across ecosystems |
| `gcve` | Get vulnerabilities by date range |

---

### vulnetix version

Print the version number of Vulnetix CLI.

```bash
vulnetix version
```

---

### vulnetix completion

Generate shell autocompletion scripts.

```bash
vulnetix completion [bash|zsh|fish|powershell]
```

## Authentication

Vulnetix CLI supports two authentication methods:

### Direct API Key

Uses `VULNETIX_API_KEY` and `VULNETIX_ORG_ID` environment variables, or stored credentials with `--method apikey`.

### SigV4

Uses `VVD_ORG` and `VVD_SECRET` environment variables, or stored credentials with `--method sigv4`. SigV4 authenticates via a JWT token exchange with the VDB API.

### Credential Storage

Credentials are stored as JSON in one of two locations:

| Store | Path | Use Case |
|-------|------|----------|
| `home` (default) | `~/.vulnetix/credentials.json` | User-wide credentials |
| `project` | `.vulnetix/credentials.json` | Project-specific credentials |

### Credential Precedence

The CLI loads credentials in this order (first match wins):

1. Environment variables: `VULNETIX_API_KEY` + `VULNETIX_ORG_ID` (Direct API Key)
2. Environment variables: `VVD_ORG` + `VVD_SECRET` (SigV4)
3. Project dotfile: `.vulnetix/credentials.json`
4. Home directory: `~/.vulnetix/credentials.json`

## Global Flags

These flags are available on the root command and inherited by subcommands:

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--org-id` | string | **Yes** | - | Organization ID (UUID) for Vulnetix operations |
| `--help` | - | No | - | Help for any command |

## Environment Variables

| Variable | Description | Used By |
|----------|-------------|---------|
| `VULNETIX_API_KEY` | Direct API key (hex digest) | `auth`, `upload` |
| `VULNETIX_ORG_ID` | Organization ID for Direct API Key auth | `auth`, `upload` |
| `VVD_ORG` | Organization UUID for SigV4 auth | `vdb`, `auth` |
| `VVD_SECRET` | Secret key for SigV4 auth | `vdb`, `auth` |
| `GITHUB_TOKEN` | GitHub API token | `gha upload` |
| `GITHUB_REPOSITORY` | GitHub repository (owner/name) | `gha upload` |
| `GITHUB_RUN_ID` | GitHub Actions workflow run ID | `gha upload` |
| `GITHUB_API_URL` | GitHub API base URL (default: `https://api.github.com`) | `gha upload` |
| `GITHUB_ACTIONS` | Set to `true` in GitHub Actions | `gha upload` |

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | Authentication error |
| `4` | Network error |
| `5` | File not found |

## Common Usage Patterns

### Basic Usage
```bash
# Run authentication healthcheck
vulnetix
```

### Artifact Upload
```bash
# Upload an SBOM
vulnetix upload --file sbom.cdx.json

# Upload SARIF from a scanner
semgrep --sarif > results.sarif && vulnetix upload --file results.sarif

# Upload via the upload command with format override
vulnetix upload --file report.json --format sarif --json
```

### CI/CD Integration
```bash
# GitHub Actions
vulnetix gha upload --org-id "$VULNETIX_ORG_ID"

# GitLab CI
vulnetix upload --file results.sarif

# Jenkins
vulnetix upload --file results.sarif
```
