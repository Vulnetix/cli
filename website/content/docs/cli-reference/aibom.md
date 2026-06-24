---
title: "AIBOM Command Reference"
weight: 8
description: "Discover AI coding agents and AI usage, and emit a CycloneDX AI Bill of Materials."
---

The `aibom` command discovers evidence of AI coding agents/assistants and AI usage in a project and produces an **AI Bill of Materials (AIBOM)** in CycloneDX 1.7 format. See [AIBOM](../aibom/) for what is detected and the catalog format.

## Usage

```bash
vulnetix aibom [path] [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan (a positional `[path]` argument overrides this) |
| `--depth` | int | `25` | Maximum recursion depth for file discovery |
| `--ignore` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-o, --output` | string | `cyclonedx-json` | Output format: `cyclonedx-json`, `json`, `table` |
| `--output-file` | string | - | Write output to this file instead of stdout |
| `--spec-version` | string | `1.7` | CycloneDX spec version: `1.6` or `1.7` |
| `--catalog` | string | - | Catalog file to merge over (or replace) the builtin catalog |
| `--no-builtin-catalog` | bool | `false` | Do not load the embedded catalog (use only `--catalog`) |
| `--no-env` | bool | `false` | Skip the environment-variable detection pass |
| `--include-home` | bool | `false` | Also probe the user's home directory for tool config dirs |
| `--no-source` | bool | `false` | Skip the source-code SDK / model detection pass |
| `--no-commits` | bool | `false` | Skip the git commit-history detection pass |
| `--commit-scan-max` | int | `2000` | Max commits (from HEAD) the commit-history pass inspects |

## Output

- `cyclonedx-json` (default) — a CycloneDX AIBOM. AI coding tools map to `application` components, AI SDKs to `library` components, and model names to `machine-learning-model` components (each with a `modelCard`). Evidence rides on component `properties` under the `vulnetix:ai/*` namespace. The document is schema-validated before it is written.
- `table` — a human-readable summary.
- `json` — the raw detection result.

## Examples

```bash
vulnetix aibom                                  # scan ., emit CycloneDX AIBOM to stdout
vulnetix aibom ./myproject -o table             # human-readable summary
vulnetix aibom --output-file aibom.cdx.json     # write the AIBOM to a file
vulnetix aibom --no-env --no-source             # filesystem evidence only
vulnetix aibom --catalog ./extra-rules.json     # extend the builtin catalog
```

## Privacy

The environment pass records only variable **names** and their presence — never their values. No source content is uploaded.
