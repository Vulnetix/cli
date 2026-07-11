---
title: "Analyze Command Reference"
weight: 10
description: "Build the org tech-stack graph and report evidence-backed repository metrics."
---

The `analyze` command builds a graph of the repository's tech stack — including the cross-repo
join keys that assemble an org-wide graph from independent single-repo scans — and reports
metrics whose every number opens into the evidence that produced it.

See [Analyze](../analyze/) for what it does, and
[Authentication](../analyze/authentication/) for the **GitHub credentials it requires**.

## Usage

```bash
vulnetix analyze [path] [flags]
```

## GitHub authentication is checked first

`analyze` verifies GitHub credentials **before it scans anything**, and stops if it cannot find
any:

```
GitHub authentication: ok (chrislangton via gh CLI, 4,987/5,000 requests remaining)
```

Credentials are taken from `GITHUB_TOKEN`, then `GH_TOKEN`, then the `gh` CLI's own store.
Inside GitHub Actions the first of those is already set for you.

Pass `--no-forge` to skip it — the pull-request, review and issue metrics are then reported as
`not measured` rather than zero. A repository whose remote is not GitHub skips the check
automatically.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--path` | `.` | Directory to analyze. May also be given as the positional argument. |
| `--window-days` | `365` | How far back to walk history. Everything derived from history is relative to this, and the window is stamped on every metric that used it. |
| `--max-commits` | `20000` | Cap on commits walked. When it is hit, the report **declares it** rather than presenting a partial count as a whole one. |
| `--complexity-threshold` | `15` | Cyclomatic complexity at which a file counts as highly complex. |
| `-o`, `--output` | `pretty` | Terminal output: `pretty` or `json`. |
| `--output-file` | `.vulnetix/analyze.report.json` | Where to write the report. |
| `--no-forge` | `false` | Skip GitHub entirely. |
| `--no-git` | `false` | Skip the history walk. Activity, contributor, ownership, coupling and trend metrics are then **absent, not zero**. |
| `--no-files` | `false` | Skip the file, complexity and symbol passes. |
| `--no-deps` | `false` | Skip dependencies — and therefore the cross-repo package edges. |
| `--no-trust` | `false` | Skip the open-source policy checks. |
| `--no-upload` | `false` | Do not submit the report. It is submitted automatically when you are authenticated to Vulnetix. |

## Examples

Analyze the current repository:

```bash
vulnetix analyze
```

In GitHub Actions, where `GITHUB_TOKEN` is already available:

```yaml
permissions:
  contents: read
  pull-requests: read
  issues: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    env:
      GITHUB_TOKEN: ${{ github.token }}
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
    steps:
      - uses: actions/checkout@v5
      - name: Analyze
        run: vulnetix analyze
```

A faster pass over recent history only:

```bash
vulnetix analyze --window-days 90 --max-commits 500
```

Without any forge access — the graph, complexity, coupling, dependencies, policy and secrets
still run:

```bash
vulnetix analyze --no-forge
```

Machine-readable output:

```bash
vulnetix analyze -o json | jq '.metrics[] | select(.family == "security")'
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The analysis completed. |
| `1` | The analysis could not run — most often, no GitHub credentials and no `--no-forge`. |

`analyze` does **not** fail on findings. A tool that fails your build by default is a tool that
gets removed from your build.

## The report

Written to `.vulnetix/analyze.report.json` and validated against
[the schema](https://vulnetix.com/schemas/vulnetix-analyze-report.schema.json) before it is
written — a report we would reject on the way in is one we cannot produce on the way out.

Uploads go to `/v2/cli.insights` when authenticated, and are **best-effort**: a network failure
does not fail the command, and the report on disk remains authoritative. The org graph in the
console at **/vdb-graph** is assembled from those uploads.
