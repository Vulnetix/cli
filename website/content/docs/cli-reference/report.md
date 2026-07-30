---
title: "Report Command Reference"
weight: 4
description: "Render the results of the last scan from .vulnetix/sbom.cdx.json, with optional targeted refreshes."
---

The `report` command renders what the last scan found. It reads the CycloneDX
document the scanners already wrote (`.vulnetix/sbom.cdx.json`) and prints the
same tables a scan prints.

Nothing is discovered, parsed or evaluated: `report` is not a scanner. That is why
it is its own command rather than a mode of `scan` — replaying results belongs to
no single scanner, and every scanner contributes findings to the file it reads.

By default it makes **no network calls at all**, which makes it the fast way to
look at findings again: in a shell, in a CI step after the scan, or on a machine
that cannot reach the API.

> `vulnetix scan --from-memory` still works and produces the same output, but is
> deprecated in favour of this command; the CLI prints a notice pointing here.

## Usage

```bash
vulnetix report [path] [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Project directory whose `.vulnetix/` results are rendered; positional `[path]` overrides |
| `--fresh-exploits` | bool | `false` | Re-fetch exploit intelligence (KEV, PoC, weaponisation) for the stored findings |
| `--fresh-advisories` | bool | `false` | Re-fetch remediation plans and fix availability |
| `--fresh-vulns` | bool | `false` | Re-check affected version ranges and current scoring |

Each `--fresh-*` flag refreshes exactly one class of data and leaves everything
else as stored, so you can bring exploit intelligence up to date without repeating
a full scan. Without them, `report` is entirely offline.

## Examples

```bash
# Replay the stored findings, offline
vulnetix report

# Replay another project's results
vulnetix report ./service
vulnetix report --path ./service

# Stored findings, current exploit intelligence
vulnetix report --fresh-exploits

# Re-check which versions are affected, and current scoring
vulnetix report --fresh-vulns

# Combine refreshes
vulnetix report --fresh-exploits --fresh-advisories
```

## What it reads

| Input | Written by |
|-------|-----------|
| `.vulnetix/sbom.cdx.json` | `scan`, `sca`, `containers`, `license`, `cdx` |

The document carries the components, the vulnerability entries and the VEX
analysis, which is everything the tables need. When the file does not exist,
`report` says so and exits non-zero rather than printing an empty report.

License findings recorded by `vulnetix license` live in the same document and are
rendered alongside the dependency findings. `vulnetix license --from-memory`
remains the license-specific replay.

## Related

- [Scan Command Reference](../scan/) — produces the results this command renders
- [SCA Command Reference](../sca/) — dependency findings
- [License Command Reference](../license/) — license findings and their own replay
