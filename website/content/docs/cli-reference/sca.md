---
title: "SCA Command Reference"
weight: 5
description: "Run only Software Composition Analysis — vulnerability analysis on package manifests with no other scan categories enabled."
---

The `sca` command runs a focused scan that analyses only package dependency manifests for known vulnerabilities. It is equivalent to running:

```bash
vulnetix scan --evaluate-sca --no-sast --no-secrets --no-containers --no-iac --no-licenses
```

No SAST rules, license analysis, secret detection, container analysis, or IaC analysis runs. This makes it faster and less noisy when you only care about dependency vulnerabilities.

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

## Usage

```bash
vulnetix sca [flags]
```

## Flags

All flags from `vulnetix scan` are available except the feature-control flags (`--evaluate-*`, `--no-*`) — those are hard-coded for this command.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-o, --output` | stringArray | - | Output target: `json-cyclonedx` or `json-sarif` for stdout; file path for file output |
| `--concurrency` | int | `5` | Max concurrent VDB queries |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--paths` | bool | `false` | Show full transitive dependency paths |
| `--no-exploits` | bool | `false` | Suppress the exploit intelligence section |
| `--no-remediation` | bool | `false` | Suppress the remediation section |
| `--severity` | string | - | Exit `1` if any vulnerability meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--block-malware` | bool | `false` | Exit `1` when any dependency is a known malicious package |
| `--block-eol` | bool | `false` | Exit `1` when a runtime or package dependency is end-of-life |
| `--block-unpinned` | bool | `false` | Exit `1` when any direct dependency uses a version range instead of an exact pin |
| `--exploits` | string | - | Exit `1` when exploit maturity reaches threshold: `poc`, `active`, `weaponized` |
| `--results-only` | bool | `false` | Only output when findings exist |
| `--version-lag` | int | `0` | Exit `1` when any dep is within the N most recently published versions (0 = disabled) |
| `--cooldown` | int | `0` | Exit `1` when any dep was published within the last N days (0 = disabled) |
| `--dry-run` | bool | `false` | Detect files and parse packages locally, check memory, then exit — zero API calls |

## Examples

```bash
# SCA scan of the current directory
vulnetix sca

# Scan a specific project directory
vulnetix sca --path /path/to/project

# Break the build on high or critical vulnerabilities
vulnetix sca --severity high

# Exit 1 on known malicious packages
vulnetix sca --block-malware

# Emit CycloneDX JSON to stdout
vulnetix sca --output json-cyclonedx

# Write CycloneDX to a file
vulnetix sca --output sbom.cdx.json

# Silent when clean
vulnetix sca --results-only
```

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sbom.cdx.json` | CycloneDX 1.7 SBOM for all scanned packages |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, counts, git context) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | A gate was breached (`--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`), or a fatal error occurred |

## Related Commands

- [`vulnetix scan`](scan/) — Full scan with all features enabled
- [`vulnetix sast`](sast/) — SAST-only scan
- [`vulnetix secrets`](secrets/) — Secret detection only
- [`vulnetix containers`](containers/) — Container file analysis only
- [`vulnetix iac`](iac/) — IaC file analysis only
- [`vulnetix license`](license/) — Standalone license analysis
