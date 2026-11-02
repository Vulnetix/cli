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
      - uses: Vulnetix/cli@v3
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
| `version` | CLI version to use | No | `latest` |
| `upload-file` | Artifact file path (with `task: upload`) | No | - |
| `upload-format` | Override format (`cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex`) | No | - |

## Action Outputs

| Output | Description |
|--------|-------------|
| `result` | Result of the CLI execution |
| `summary` | Summary of vulnerabilities processed |
| `upload-uuid` | Pipeline UUID of uploaded artifact (with `task: upload`) |

See the [full documentation](https://docs.vulnetix.com/cli/ci-cd/github-actions/) for advanced configuration, matrix strategies, and troubleshooting.
