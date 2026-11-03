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
(`VULNETIX_ORG_ID`, `VULNETIX_API_KEY`, `VULNETIX_API_TOKEN`, `VULNETIX_CONFIG_TOKEN`),
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
| `version` | CLI release to install: an exact tag (`v3.158.0`), a major channel (`v3`, the newest v3 release) or `latest` | No | `v3` |
| `binary-path` | Use this already-built binary instead of downloading a release | No | - |
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

They are generated, not hand-written: `tools/actiongen/spec.go` is the table, and
`go generate ./tools/actiongen` writes every `<name>/action.yml`, every
`docs/github-actions/<name>.md` and `action-lib/commands.sh`. `TestGeneratedFilesAreCurrent`
fails when they drift. The shared shell is in `action-lib/` and is called as
`$GITHUB_ACTION_PATH/../action-lib/*.sh`, because a relative `uses:` does not resolve from a
remote action:

| Script | Job |
|---|---|
| `install.sh` | Major channel, `binary-path`, skips a second install in the same job |
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
