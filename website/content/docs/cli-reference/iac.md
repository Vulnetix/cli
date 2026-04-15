---
title: "IaC Command Reference"
weight: 9
description: "Run only Infrastructure as Code analysis — checks Terraform HCL and Nix files for security misconfigurations."
---

The `iac` command runs a focused scan that evaluates only IaC Rego rules (rules with `kind: iac`) against Terraform HCL and Nix manifest files. It is equivalent to running:

```bash
vulnetix scan --evaluate-iac --no-sast --no-sca --no-secrets --no-containers --no-licenses
```

Package vulnerability analysis, general SAST rules, license analysis, secret detection, and container analysis are all disabled. Only rules that analyse Infrastructure as Code files run.

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

## Usage

```bash
vulnetix iac [flags]
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

The `iac` command scans files identified as IaC manifests:

| Filename / Pattern | Language |
|-------------------|----------|
| `*.tf` | hcl (Terraform) |
| `flake.nix` | nix |
| `flake.lock` | nix |

## What Gets Detected

IaC rules check for common Terraform misconfigurations:

| Rule ID | Severity | Name |
|---------|----------|------|
| VNX-TF-001 | High | S3 bucket with public access enabled |
| VNX-TF-002 | High | Security group with unrestricted ingress (0.0.0.0/0) |
| VNX-TF-003 | High | IAM policy with wildcard resource or action |
| VNX-TF-004 | Medium | RDS / Aurora instance not encrypted at rest |
| VNX-TF-005 | Medium | CloudTrail logging not enabled |
| VNX-TF-006 | Medium | EC2 instance metadata service v1 allowed (IMDSv1) |
| VNX-TF-007 | Medium | EBS volume not encrypted |
| VNX-TF-008 | High | Hardcoded secret or credential in Terraform resource |

See the [Terraform / IaC rules](../sast-rules/#terraform) section for full details.

## Examples

```bash
# IaC scan of the current directory
vulnetix iac

# Scan a specific Terraform project
vulnetix iac --path /path/to/terraform

# Break the build on high or critical IaC findings
vulnetix iac --severity high

# Emit SARIF JSON to stdout
vulnetix iac --output json-sarif

# Write SARIF to a file
vulnetix iac --output iac.sarif

# Silent when no issues found
vulnetix iac --results-only

# Exclude modules directory
vulnetix iac --exclude ".terraform/**"
```

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from IaC analysis |
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
- [`vulnetix containers`](containers/) — Container file analysis only
- [Terraform / IaC Rules Reference](../sast-rules/#terraform) — All 8 built-in IaC rules
