---
title: "GHA Command"
weight: 32
description: "Publish a GitHub Actions workflow run's scanner reports to Vulnetix, and report what actually landed."
---

`vulnetix gha` publishes the reports a workflow run produced, and tells you what
was recorded. It reads the run's own artifacts through the GitHub API, so the
scanners do not need to know anything about Vulnetix. They upload their reports
as ordinary workflow artifacts and this collects them.

If you just want a scanner wired up, [Third-Party Scanners]({{< relref "third-party-scanners" >}})
writes the whole workflow for you in one command.

## `vulnetix gha upload`

Classifies every file in the run's artifacts, validates it, and publishes it to
the endpoint that matches what it is, attributed to the tool that produced it.

```sh
vulnetix gha upload --org-id "$VULNETIX_ORG_ID"
```

| Flag | Meaning |
|---|---|
| `--org-id` | Organisation uuid. Falls back to stored credentials. |
| `--json` | Machine-readable result, one entry per file. |
| `--dry-run` | Classify and validate everything without publishing. |
| `--strict` | Treat skipped files (unrecognised formats) as failures. |
| `--fail-on-empty` | Fail when the run produced nothing publishable. |
| `--no-github-api` | Do not call the REST API to enrich the CI context. |

### What it does with each file

| Format | Where it goes |
|---|---|
| SARIF | `/v2/cli.<category>-sarif`, category inferred from the report |
| CycloneDX | the SCA path, with the producing tool's attribution |
| SPDX | the SCA path, package URLs read from `externalRefs` |
| anything else | skipped, with the reason stated |

Reports produced by Vulnetix's own scanners are skipped. `vulnetix sast` and the
other scan subcommands publish themselves when they run, so republishing the
artifacts they leave behind would record every finding twice.

### It fails when publishing fails

`gha upload` exits non-zero if any file fails to publish. This matters more than
it sounds: the command used to swallow errors and return success, so a job in
which nothing at all was published still showed a green check.

A file that cannot be published says why. The most common cause is a scanner
that wrote its report through a shell redirect and failed:

```text
zizmor/zizmor.sarif  error: file is empty (0 bytes)
  hint: the scanner likely wrote to stdout and a shell redirect captured
        nothing. Use the tool's --output flag instead of '> file.sarif'
```

### Permissions

The publish job needs `actions: read` to list the run's artifacts, and
`GITHUB_TOKEN` in scope:

```yaml
permissions:
  contents: read
  actions: read
```
```yaml
      - name: Publish scanner reports
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: vulnetix gha upload --org-id "$VULNETIX_ORG_ID" --json
```

## `vulnetix gha status`

Reports what a workflow run published. One publish job fans out into a separate
scanner run per tool, and this is what ties them back together.

```sh
vulnetix gha status                       # the current run, inside a workflow
vulnetix gha status --run-id 30178087483  # any run
vulnetix gha status --attempt 2           # one attempt of a re-run
vulnetix gha status --uuid <snapshot>     # a single submission
vulnetix gha status --json
```

Output names each tool, its version, the category it was filed under and what it
contributed:

```text
8 scan result(s) from 8 tool(s), 114 finding(s) ingested

zizmor 1.28.0  [SAST]
   findings: 43 ingested (crit 0, high 26, med 17, low 0, info 0)
   repo:     Vulnetix/vdb-cyclonedx
   snapshot: https://www.vulnetix.com/resolve/scanner-results/b52c9dc5-…
```

A tool you set up that is missing from that list did not publish. That is the
check worth running after a pipeline change. A green workflow is not evidence
that anything was recorded.

## Re-runs

Each report is published under a key identifying the workflow run, the attempt
and the tool. Re-running a publish job reuses the existing scan rather than
recording it twice, so `if: always()` and manual re-runs are safe. A new run
*attempt* is a genuinely new scan and is recorded as one.

## Example

A scanner job and the publish job that collects it. `vulnetix gha setup` writes
this for you, but the shape is worth knowing:

```yaml
name: Third-Party Scanners

on:
  push:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  gosec:
    name: gosec (Go SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run gosec
        continue-on-error: true
        uses: securego/gosec@v2.28.0
        with:
          args: -no-fail -fmt sarif -out gosec.sarif ./...
      - uses: actions/upload-artifact@v6
        with:
          name: gosec
          path: gosec.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

  publish:
    name: Publish to Vulnetix
    runs-on: ubuntu-latest
    needs: [gosec]
    if: always()
    permissions:
      contents: read
      actions: read
    env:
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
    steps:
      - uses: actions/checkout@v5
      - name: Install Vulnetix CLI
        run: |
          curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir "$HOME/.local/bin"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Publish scanner reports
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: vulnetix gha upload --org-id "$VULNETIX_ORG_ID" --json --no-banner --no-progress
```

`needs: [gosec]` and `if: always()` are both load-bearing. A scanner missing from
`needs` is never published, and without `always()` one failing scanner suppresses
every other scanner's results.

## Troubleshooting

**Nothing was published, but the job passed.** On any CLI before v3.73.0 that was
the default behaviour. The upload went to an endpoint that returned an error and
the command reported success anyway. Install the current CLI; it fails the job.

**`GITHUB_TOKEN environment variable is required`.** Add it to the step's `env`.
It is not in scope automatically.

**`no artifacts found in this workflow run`.** The publish job ran before the
scanners finished, or they are missing from `needs`.

**A tool is missing from `gha status`.** Its artifact was absent, empty, or not a
format Vulnetix accepts. `gha upload --json` names the file and the reason.
