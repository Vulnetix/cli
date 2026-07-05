---
title: "CBOM Command Reference"
weight: 9
description: "Discover cryptographic usage and emit a CycloneDX Cryptography Bill of Materials with post-quantum posture."
---

The `cbom` command discovers cryptographic algorithms, certificates and crypto libraries in a project and produces a **Cryptography Bill of Materials (CBOM)** in CycloneDX format. See [CBOM](../cbom/) for what is detected and the catalog format.

## Usage

```bash
vulnetix cbom [path] [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan (a positional `[path]` argument overrides this) |
| `--depth` | int | `25` | Maximum recursion depth for file discovery |
| `--ignore` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-o, --output` | string | `pretty` | Terminal output format: `pretty`, `json`, `cyclonedx-json` |
| `--output-file` | string | - | Path to write the CBOM (default: `<path>/.vulnetix/cbom.cdx.json`) |
| `--spec-version` | string | `1.7` | CycloneDX spec version: `1.6` or `1.7` |
| `--catalog` | string | - | Catalog file to merge over (or replace) the builtin catalog |
| `--no-builtin-catalog` | bool | `false` | Do not load the embedded catalog (use only `--catalog`) |
| `--no-source` | bool | `false` | Skip the source-code crypto API detection pass |
| `--no-config` | bool | `false` | Skip the config & protocol detection pass |
| `--no-certs` | bool | `false` | Skip the certificate / key detection pass |
| `--no-deps` | bool | `false` | Skip the crypto-library detection pass |
| `--fail-on` | string | `none` | Exit non-zero when crypto of these PQC statuses is found (e.g. `quantum-vulnerable`, `deprecated`) |
| `--no-upload` | bool | `false` | Do not submit the CBOM to Vulnetix (submitted automatically when authenticated) |
| `--cbom-include-ignored` | bool | `false` | Include files matched by `.gitignore` (default: gitignored paths are skipped) |

## Output

- `pretty` (default) — a human-readable summary with the PQC posture rollup and per-algorithm tables.
- `cyclonedx-json` — the CycloneDX CBOM. Algorithms map to `cryptographic-asset` components (with `cryptoProperties`), certificates to `cryptographic-asset` (`assetType: certificate`) plus a `related-crypto-material` key, and crypto libraries to `library` components. PQC posture and the standards matrix ride on `vulnetix:crypto/*` properties. The document is schema-validated before it is written.
- `json` — the raw detection result.

## Examples

```bash
vulnetix cbom                                   # pretty summary; writes .vulnetix/cbom.cdx.json
vulnetix cbom ./service -o cyclonedx-json        # print CycloneDX to stdout
vulnetix cbom --no-certs --no-deps              # source + config only
vulnetix cbom --fail-on quantum-vulnerable      # gate CI on quantum-vulnerable crypto
vulnetix cbom --catalog ./extra-algos.json      # extend the builtin catalog
```

## Privacy

The certificate pass reads only certificate/key **metadata** (algorithm, size, validity) — never key material. No source content is uploaded.
