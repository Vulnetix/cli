---
title: "Containers Command Reference"
weight: 8
description: "Run only container file analysis — checks Dockerfiles and Containerfiles for security misconfigurations."
---

The `containers` command runs a focused scan that evaluates only container-security Rego rules (rules with `kind: oci`) against Dockerfile and Containerfile manifests. It is equivalent to running:

```bash
vulnetix scan --enable-containers --no-sast --no-sca --no-secrets --no-iac --no-licenses
```

Package vulnerability analysis, general SAST rules, license analysis, secret detection, and IaC analysis are all disabled. Only rules that analyse container build files run.

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

## Usage

```bash
vulnetix containers [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-o, --output` | stringArray | - | Output target: `json-sarif` for stdout; `.sarif` file path for file output |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--severity` | string | - | Exit `1` if any finding meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--results-only` | bool | `false` | Only output when findings exist |
| `--dry-run` | bool | `false` | Detect files and check memory — zero API calls |

## Detected File Types

The `containers` command scans files identified as container manifests:

| Filename | Language |
|----------|----------|
| `Dockerfile` | docker |
| `Containerfile` | docker |
| `*.dockerfile` | docker |
| `*.containerfile` | docker |

## What Gets Detected

Container security rules check for common Dockerfile misconfigurations:

| Rule ID | Severity | Name |
|---------|----------|------|
| VNX-DOCKER-001 | Medium | Missing USER directive (running as root) |
| VNX-DOCKER-002 | Medium | FROM with `:latest` tag (unpinned base image) |
| VNX-DOCKER-003 | Medium | Missing HEALTHCHECK instruction |
| VNX-DOCKER-004 | Medium | Package manager cache not cleared in same layer |
| VNX-DOCKER-005 | High | Secrets or credentials in ENV instruction |
| VNX-DOCKER-006 | Medium | Privileged port exposure (< 1024) |
| VNX-DOCKER-007 | Medium | ADD instruction used instead of COPY |
| VNX-DOCKER-008 | Medium | Multiple RUN instructions that could be combined |

See the [Docker rules](../sast-rules/#docker) section for full details.

## Examples

```bash
# Container scan of the current directory
vulnetix containers

# Scan a specific directory
vulnetix containers --path /path/to/project

# Break the build on any container finding
vulnetix containers --severity low

# Emit SARIF JSON to stdout
vulnetix containers --output json-sarif

# Write SARIF to a file
vulnetix containers --output containers.sarif

# Silent when no issues found
vulnetix containers --results-only
```

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from container analysis |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, finding counts, git context) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | A gate was breached (`--severity`), or a fatal error occurred |

## Related Commands

- [`vulnetix scan`](scan/) — Full scan with all features enabled
- [`vulnetix sca`](sca/) — SCA-only scan
- [`vulnetix sast`](sast/) — General SAST-only scan
- [`vulnetix secrets`](secrets/) — Secret detection only
- [`vulnetix iac`](iac/) — IaC file analysis only
- [Docker Rules Reference](../sast-rules/#docker) — All 8 built-in container rules
