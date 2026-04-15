---
title: "Secrets Command Reference"
weight: 7
description: "Run only secret detection — identifies hardcoded credentials, API keys, tokens, and private keys in source code."
---

The `secrets` command runs a focused scan that evaluates only secret-detection Rego rules (rules with `kind: secrets`) against your source files. It is equivalent to running:

```bash
vulnetix scan --evaluate-secrets --no-sast --no-sca --no-containers --no-iac --no-licenses
```

Package vulnerability analysis, general SAST rules, license analysis, container analysis, and IaC analysis are all disabled. Only rules that detect hardcoded credentials, API keys, tokens, and private keys run.

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

## Usage

```bash
vulnetix secrets [flags]
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

## What Gets Detected

Secret-detection rules cover credentials across all major cloud providers and services:

| Category | Examples |
|----------|---------|
| Cloud providers | AWS access key IDs, Azure storage keys, GCP service account keys |
| Source control | GitHub tokens, GitLab personal access tokens |
| Communication | Slack tokens, Twilio auth tokens |
| Payment | Stripe secret keys, PayPal tokens |
| Private keys | RSA, DSA, EC, OpenSSH private keys, PGP keys |
| Generic patterns | Generic API keys, bearer tokens, OAuth secrets |

See the [Secrets / Credentials rules](../sast-rules/#secrets) section for the full list of 32 rules.

## Examples

```bash
# Secret scan of the current directory
vulnetix secrets

# Scan a specific directory
vulnetix secrets --path /path/to/project

# Break the build on any secret found (all secrets are high/critical)
vulnetix secrets --severity high

# Emit SARIF JSON to stdout
vulnetix secrets --output json-sarif

# Write SARIF to a file
vulnetix secrets --output secrets.sarif

# Silent when no secrets found
vulnetix secrets --results-only

# Exclude test fixtures
vulnetix secrets --exclude "test/**" --exclude "fixtures/**"
```

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from secret detection |
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
- [`vulnetix containers`](containers/) — Container file analysis only
- [`vulnetix iac`](iac/) — IaC file analysis only
- [Secrets Rules Reference](../sast-rules/#secrets) — All 32 built-in secret-detection rules
