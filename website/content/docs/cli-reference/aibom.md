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
| `--aibom-include-ignored` | bool | `false` | Include files matched by `.gitignore` (default: gitignored paths are skipped) |

## Output

- `cyclonedx-json` (default) — a CycloneDX AIBOM. AI coding tools map to `application` components, AI SDKs to `library` components, and model names to `machine-learning-model` components (each with a `modelCard`). Evidence rides on component `properties` under the `vulnetix:ai/*` namespace. The document is schema-validated before it is written.
- `table` — a human-readable summary.
- `json` — the raw detection result.

The document names its producer as `vulnetix-aibom` in `metadata.tools`, records
the organization running the scan as `metadata.manufacturer`, and claims the
`design` and `discovery` lifecycle phases — an AI inventory is read out of
source, configuration and commit history by observation rather than by resolving
a declared dependency set. See
[BOM authoring identity](../scan/#bom-authoring-identity).

## Examples

```bash
vulnetix aibom                                  # scan ., emit CycloneDX AIBOM to stdout
vulnetix aibom ./myproject -o table             # human-readable summary
vulnetix aibom --output-file aibom.cdx.json     # write the AIBOM to a file
vulnetix aibom --no-env --no-source             # filesystem evidence only
vulnetix aibom --catalog ./extra-rules.json     # extend the builtin catalog
```

## Inside a scan

`vulnetix scan` captures the AI inventory as one of its passes, and it calls this
command's pipeline — the same catalog, the same detection passes, the same memory
reconcile. The in-scan pass differs only in what it does with the result:

| | `vulnetix aibom` | pass inside `vulnetix scan` |
|---|---|---|
| Passes run | selected by `--no-env` / `--no-source` / `--no-commits` / `--no-iac` | all four |
| CycloneDX file written | yes (`.vulnetix/ai-bom.cdx.json` or `--output-file`) | no |
| Terminal output | yes (`-o pretty/json/cyclonedx-json`) | no |
| Memory reconcile | yes | yes |
| Submitted when authenticated | yes (unless `--no-upload`) | yes |

Turn the pass off with `vulnetix scan --no-aibom`. Run this command directly when
you want the file, the table, or control over which passes run.

## Privacy

The environment pass records only variable **names** and their presence — never their values. No source content is uploaded.
