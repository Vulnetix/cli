# GitHub Actions

This documentation has moved to **[docs.vulnetix.com/cli/ci-cd/github-actions](https://docs.vulnetix.com/cli/ci-cd/github-actions/)**.

## Quick Start

```yaml
name: Vulnetix
on: [push, pull_request]
permissions:
  contents: read
jobs:
  vulnetix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Vulnetix/cli@v4
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
```

Without `org-id` and a credential the CLI runs in community mode.

## Credentials

Credentials are passed to the CLI only as step environment variables
(`VULNETIX_ORG_ID`, `VULNETIX_API_KEY`, `VULNETIX_API_TOKEN`),
which `pkg/auth/credentials.go` reads before any stored file. The action never runs
`auth login`, so no `.vulnetix/credentials.json` is written into the workspace, and no
credential appears on a command line or in an uploaded artifact.

Every input reaches the action's scripts as an environment variable, never as a
`${{ }}` expression inside a script, and commands are built as argv arrays, never with
`eval`, so an input value containing quotes or `$(...)` stays data.

## Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `org-id` | Organization ID (UUID); needed with `api-key` | No | - |
| `api-key` | Direct API Key for authentication | No | - |
| `api-token` | Vulnetix API token; the server resolves the organization | No | - |
| `task` | Task to perform: `info`, `upload`, `gha`, `tea-release`, `config-plan`, `config-apply` | No | `info` |
| `version` | CLI release to install: an exact tag (`v4.0.0`), a major channel (`v4`, the newest v4 release) or `latest` | No | `v4` |
| `binary-path` | Use this already-built binary instead of downloading a release | No | - |
| `verify-provenance` | Install cosign and require the release's signed SLSA provenance to verify for the downloaded binary (`install.sh --require-provenance`). Every v4 release is signed; set `false` for a v3 release without `provenance.sigstore.json`. The SHA-256 checksum is checked either way | No | `true` |
| `upload-file` | Artifact file path (with `task: upload`) | No | - |
| `upload-format` | Override format (`cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex`) | No | - |

## Action Outputs

| Output | Description |
|--------|-------------|
| `result` | Result of the CLI execution |
| `summary` | Summary of vulnerabilities processed |
| `upload-uuid` | Pipeline UUID of uploaded artifact (with `task: upload`) |

See the [full documentation](https://docs.vulnetix.com/cli/ci-cd/github-actions/) for advanced configuration, matrix strategies, and troubleshooting.

## One action per command

Each CLI command also has its own composite action in a subdirectory of this repository, used as
`Vulnetix/cli/<name>@v4`: `setup`, `sca`, `sast`, `secrets`, `iac`, `containers`, `license`,
`malscan`, `analyze`, `cbom`, `aibom`, `sbom`, `upload`, `gha-upload`, `tea-release`,
`config-plan`, `config-apply`, `attest`, `jail`, `vex` and `github-publish`. Their inputs,
outputs, permissions and examples are in [`github-actions/`](github-actions/README.md).

`analyze` reads pull requests, issues and commit reviews from GitHub with the job token, several
requests per pull request. That token's hourly quota (1,000 requests) belongs to the whole
repository, and every other job shares it, including CodeQL's SARIF upload and a workflow
dispatch. So the GitHub pass stops while half the token's hourly limit is still left, and the
report declares what it did not fetch. The workflow `vulnetix gha init` writes passes
`--no-forge` on a pull request and `--forge-window-days=7` on a push or a release. Only a manual
run (`workflow_dispatch`) reads the full `--window-days` window from GitHub. The git history
window stays at 365 days in every case.

The scanners that resolve licences (`sca`, `license`, `sbom`, `containers` and `scan`) ask
GitHub for a repository's licence when the Vulnetix store, the package registry and deps.dev
cannot name it, with the same job token. Those lookups spend from the same quota:

- **A name GitHub cannot hold is never asked about.** That includes a workflow's `uses: $/sbom`,
  a glob and a template placeholder.
- **The lookup chain is short.** The repository answers first. A 404 there ends the chain;
  otherwise the next steps are GitHub's own licence detection, then the licence files that
  the root listing names, so a repository costs one to four requests.
- **Inside GitHub Actions the lookups keep 80% of the token's hourly limit for everything
  else.** They stop at 4,000 left of 5,000, above the half that analyze's forge pass keeps.
  Every job of a run sees the same remaining count, so the floor holds for the whole run.
- **They also stop as soon as GitHub answers with a rate limit.** A licence they did not
  check stays `UNKNOWN`, and a warning names how many repositories went unchecked.
- **Each job logs what it spent.** In Actions, every batch of lookups prints a line such as
  `GitHub licence lookups: 31 requests for 26 repositories (4880 of 5000 left)`.

`vulnetix gha init` passes the token to a scanner only off pull requests. It passes no token
to a scanner that runs as an extra's `prior` step, because that step only writes the file the
extra reads.

They are generated, not hand-written: `tools/actiongen/spec.go` is the table, and
`go generate ./tools/actiongen` writes every `<name>/action.yml`, every
`docs/github-actions/<name>.md` and `action-lib/commands.sh`. `TestGeneratedFilesAreCurrent`
fails when they drift. The shared shell is in `action-lib/` and is called as
`$GITHUB_ACTION_PATH/../action-lib/*.sh`, because a relative `uses:` does not resolve from a
remote action:

| Script | Job |
|---|---|
| `install.sh` | Major channel, `binary-path`, `verify-provenance`, skips a second install in the same job |
| `run.sh` | Builds the argv from `VX_*` env (through `commands.sh`), runs it with an artifact manifest, sets the outputs |
| `config.sh`, `config-plan-comment.sh` | `config-plan` and `config-apply`, and the pull request plan comment |
| `publish.sh` | `gha publish` after a command that does not publish itself, and the `github-publish` action |
| `release-assets.sh` | Attaches the manifest's files to a release |
| `finish.sh` | Re-raises the command's exit code when `fail-on-findings` is set |

The root action's `task` input takes the same names and runs the same `run.sh`.

The `actions-e2e` job in `test.yml` runs the root action and `sca`, `sast`, `sbom` and
`config-plan` against the binary the branch built (`binary-path`) on
`testdata/action-fixture/`, checks the outputs, the SARIF and the dependency graph snapshot
(with `--dry-run`), and that no credentials file was written. It also runs actionlint and
shellcheck. Third-party actions are pinned by commit SHA in `tools/actiongen/spec.go`.
