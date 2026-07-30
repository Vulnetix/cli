---
title: "Fix Command Reference"
weight: 6
description: "Apply validated dependency fixes with the project's package manager, then rescan to confirm the finding is gone."
---

The `fix` command resolves vulnerable dependencies to safe versions, applies the
change with the project's own package manager, and rescans to prove the finding is
gone.

It is the owner of remediation. Autofix used to exist only as `--sca-autofix` on
the scan family; `fix` is the command that owns it, and the flag remains as the
in-pipeline trigger for a wider scan.

Under the hood `fix` runs the SCA pipeline with remediation enabled — the same
discovery, the same VDB lookup, the same quality gates — so there is one
implementation rather than two.

`vulnetix autofix` is an alias.

## Usage

```bash
vulnetix fix [path] [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan; positional `[path]` overrides |
| `--strategy` | string | `stable` | Fix target strategy: `stable`, `safest` or `latest` |
| `--manifest` | string | - | Restrict edits to one manifest file |
| `--max-major-bump` | int | `0` | Refuse targets crossing more than N major versions (0 = no limit) |
| `--yes` | bool | `false` | Non-interactive: pick safe defaults, never prompt |
| `--dry-run` | bool | `false` | Show the fix plan and change nothing |
| `--depth` | int | `3` | Max recursion depth |
| `--exclude` | stringArray | - | Exclude paths matching glob (repeatable) |
| `--severity` | string | - | Exit `1` if any remaining vulnerability meets or exceeds this severity |
| `--exploits` | string | - | Exit `1` when exploit maturity reaches: `poc`, `active`, `weaponized` |
| `--block-eol` / `--block-malware` / `--block-unpinned` | bool | `false` | Quality gates, as on `scan` |
| `--version-lag` / `--cooldown` | int | `0` | Freshness gates, as on `scan` |
| `-o, --output` | stringArray | - | Output target: `json-cyclonedx`, `json-sarif`, or a file path |
| `--results-only` | bool | `false` | Only output when findings exist |

The scan-family spellings (`--sca-autofix`, `--sca-autofix-strategy`,
`--sca-autofix-manifest`, `--sca-autofix-max-major-bump`) are still accepted so a
pipeline can pass them verbatim; they are hidden from `--help` so each knob has one
advertised name.

## Examples

```bash
# Propose and apply fixes, prompting where a choice is needed
vulnetix fix

# Show the plan, change nothing
vulnetix fix --dry-run

# Non-interactive (CI): safe defaults, no prompts
vulnetix fix --yes

# Prefer the lowest safe version rather than the stable default
vulnetix fix --strategy safest

# Stay within one major version
vulnetix fix --max-major-bump 1

# Restrict edits to a single manifest in a monorepo
vulnetix fix --manifest services/api/package.json

# As part of a wider scan (the in-pipeline trigger)
vulnetix scan --sca-autofix
vulnetix sca --sca-autofix
```

## What it does

1. **Discover and resolve** — the SCA pipeline parses manifests and lockfiles and
   queries the VDB, so the fix plan is built from the same findings a scan reports.
2. **Plan** — for each vulnerable package a target version is chosen by strategy,
   bounded by `--max-major-bump`. Packages with no vulnerability-free version are
   kept in the report rather than dropped.
3. **Apply** — manifest edits are written and the project's package manager
   installs them (npm/yarn/pnpm/bun, pip/uv/poetry, go, cargo, composer, …),
   batched per manifest directory.
4. **Confirm** — a second SCA pass verifies the finding is gone. A fix that does
   not verify is reported as such.
5. **Attest** — applied fixes are recorded as CycloneDX VEX in
   `.vulnetix/sbom.cdx.json` and posted to the scan snapshot, so the next scan
   knows why the finding disappeared. Packages with no safe version are attested
   as risk-accepted instead of silently skipped.

`--dry-run` stops after step 2 and prints the proposal. It still queries the VDB —
knowing which versions are safe requires it — so unlike a scanner dry run this one
is not offline.

## Related

- [SCA Autofix](../sca-autofix/) — the in-pipeline `--sca-autofix` flag in depth
- [SCA Command Reference](../sca/) — the dependency scan the fix plan is built from
- [Report Command Reference](../report/) — replay the results after fixing
