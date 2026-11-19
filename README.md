<p align="center">
  <img src="pix.svg" alt="Pix, the Vulnesis AI coding assistant" width="140">
</p>

# Vulnesis CLI and GitHub Action

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Vulnesis/cli)

Vulnesis scans a repository for vulnerable dependencies, code flaws, secrets, IaC and container
misconfigurations, licence conflicts and malware, then tells you which findings affect the
version you run and the lowest version that fixes them. It is for developers who want that
answer on their own machine, and for teams who run the same scan in CI and track the results in
the Resolve Platform.

## Contents

- [Install](#install)
- [First scan](#first-scan)
- [GitHub Action](#github-action)
- [Other CI/CD platforms](#other-cicd-platforms)
- [Pix for coding agents](#pix-for-coding-agents)
- [Configuration](#configuration)
- [Development](#development)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [License](#license)

## Install

| Method | Platforms | Command |
|--------|-----------|---------|
| [Install script](./docs/curl.md) | Linux, macOS | `curl -fsSL https://cli.vulnes.is/install.sh \| sh` |
| [Homebrew](./docs/homebrew.md) | Linux, macOS | `brew install vulnetix/tap/vulnetix` |
| [Scoop](./docs/scoop.md) | Windows | `scoop bucket add vulnetix https://github.com/Vulnesis/scoop-bucket; scoop install vulnetix/vulnetix` |
| [Nix](./docs/nix.md) | Linux, macOS | `nix profile install github:Vulnesis/cli` |
| [Go install](./docs/go-install.md) | All | `go install github.com/vulnetix/cli/v4@latest` |
| [Binary download](./docs/curl.md) | All | [GitHub Releases](https://github.com/Vulnesis/cli/releases/latest) |
| [From source](./docs/from-source.md) | All | `go build -o vulnetix .` |

Architectures: AMD64, ARM64, ARM and 386.

The install script installs the binary only when its SHA-256 matches the release's
`checksums.txt`, and stops when it cannot check. With `cosign` on `PATH` it also verifies the
release's signed SLSA provenance; `--require-provenance` makes that mandatory. See
[docs/curl.md](./docs/curl.md) for the flags and for verifying a manual download.

**Analytics.** After a successful install, the install script sends one anonymous event to
Google Analytics with the OS, architecture, CLI version and a random id made for that install.
The CLI sends anonymous usage events too. Set `VULNETIX_NO_ANALYTICS=1` or `DO_NOT_TRACK=1` to
turn both off, or pass `--no-analytics` to a single command.

## First scan

```bash
vulnetix auth login && vulnetix scan
```

`vulnetix auth login` opens a browser to sign in. It is optional: without it, scans run in
community mode on a shared quota. `vulnetix scan` scans the current directory. On a project
whose `requirements.txt` pins `requests==2.25.0` and `jinja2==2.11.2`:

```text
Querying VDB via /v2/cli.sca: 2 unique package(s) in 1 batch(es)...
vulnetix scan: FINDINGS  9 advisories, 2 packages, 2 need action

NEEDS ACTION
  CRITICAL  jinja2 2.11.2 -> 3.1.6      CVE-2024-34064 +4   PoC-exploit   ./requirements.txt
  CRITICAL  requests 2.25.0 -> 2.33.0   CVE-2026-25645 +3   PoC-exploit   ./requirements.txt

vulnetix scan: CLEAN  no sast findings
  [OK] BOM:      ./.vulnetix/sbom.cdx.json
  [OK] Memory:   ./.vulnetix/memory.yaml
```

Each row is one package: the version to move to clears every advisory on it. `vulnetix fix`
applies those upgrades and rescans, and `vulnetix --help` lists every command by group.

## GitHub Action

```yaml
name: Security scan
on: [pull_request]
permissions:
  contents: read

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Vulnesis/cli@v4
        with:
          task: sca
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
```

`@v4` installs the newest v4 release. The action checks the binary's SHA-256 and, by default,
installs cosign and verifies the release's signed provenance (`verify-provenance: true`).

To upload a report you already have:

```yaml
- uses: Vulnesis/cli@v4
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    api-key: ${{ secrets.VULNETIX_API_KEY }}
    task: upload
    upload-file: ./reports/results.sarif
```

The `task` input takes:

| Task | What it runs |
|------|--------------|
| `info` | Authentication healthcheck (the default) |
| `sca` | Scan dependencies for known vulnerabilities |
| `sast` | Scan source code with the SAST rules |
| `secrets` | Scan for committed secrets |
| `iac` | Scan infrastructure as code |
| `containers` | Scan container files and images |
| `license` | Evaluate dependency licences against the licence policy |
| `malscan` | Scan installed dependencies for malicious code |
| `analyze` | Report the repository's tech stack, ownership and risk |
| `sbom` | Write a CycloneDX SBOM |
| `cbom` | Write a cryptography bill of materials |
| `aibom` | Write an AI bill of materials |
| `jail` | Assess the repository against the organisation's jail policy |
| `upload` | Upload one artifact file to Vulnesis |
| `gha` | Upload every artifact of this workflow run to Vulnesis |
| `tea-release` | Publish a release and its artifacts to the Transparency Exchange API |
| `config-plan` | Plan Platform IaC documents and comment the plan on the pull request |
| `config-apply` | Apply Platform IaC documents |

Most tasks also have their own action, such as `Vulnesis/cli/sca@v4`, with artifact, attestation and
release steps. See [docs/github-actions.md](./docs/github-actions.md) for every input and
[docs/GHA_COMMAND.md](./docs/GHA_COMMAND.md) for uploading workflow artifacts.

## Other CI/CD platforms

| Platform | Guide |
|----------|-------|
| GitLab CI | [docs/gitlab-ci.md](./docs/gitlab-ci.md) |
| Azure DevOps | [docs/azure-devops.md](./docs/azure-devops.md) |
| Bitbucket | [docs/bitbucket.md](./docs/bitbucket.md) |

## Pix for coding agents

Pix wires Vulnesis into the coding agents on your machine (Claude Code, Codex and others): hooks
that check a dependency before it lands and a commit before it records a credential, and skills
for work that needs your working tree, such as fixing a finding and checking the fix landed.

```bash
vulnetix agent install
```

It detects the agents, writes each one's hook config and skills, and configures the Vulnesis MCP
server where the agent speaks MCP. In Claude Code you can install the plugin instead:

```
/plugin marketplace add Vulnesis/pix-ai-coding-assistant
/plugin install vulnetix@vulnetix-plugins
```

See the [Pix documentation](https://docs.vulnes.is/pix/) and the
[Pix repository](https://github.com/Vulnesis/pix-ai-coding-assistant).

## Configuration

| Where | What |
|-------|------|
| `~/.vulnetix/credentials.json` | Credentials from `vulnetix auth login` (the default `--store home`) |
| `.vulnetix/credentials.json` | Project credentials, with `vulnetix auth login --store project` |
| `.vulnetix/config/` | Platform IaC documents for `vulnetix config plan` and `apply`, VEX sources and licence exceptions ([docs/platform-iac.md](./docs/platform-iac.md)) |
| `.vulnetix/memory.yaml`, `.vulnetix/sbom.cdx.json` | What the last scan found; `vulnetix report` reads them without rescanning |
| `VULNETIX_ORG_ID`, `VULNETIX_API_KEY`, `VULNETIX_API_TOKEN` | Credentials from the environment, read before any file |
| `VULNETIX_NO_ANALYTICS`, `DO_NOT_TRACK` | Turn off anonymous usage analytics |
| `VULNETIX_BRAND` (alias `VULNESIS_BRAND`) | Which brand's hosts the CLI talks to and links: `vulnetix` (default) or `vulnesis`. See [Brand selection](#brand-selection) |

### Brand selection

The CLI serves two brands: Vulnetix (`vulnetix.com`, the default) and Vulnesis (`vulnes.is`).
Set `VULNETIX_BRAND=vulnesis` (or `VULNESIS_BRAND=vulnesis`; the value is case-insensitive) to
point every default endpoint and printed link at `vulnes.is`. Unset, empty or any other value
keeps Vulnetix, so nothing changes unless you opt in. `VULNETIX_BRAND` wins when both are set.

Under Vulnesis only `vulnetix.com` hosts change, and only the host:

| Vulnetix | Vulnesis |
|----------|----------|
| `vulnetix.com` | `vulnes.is` |
| `www.vulnetix.com`, `packages.vulnetix.com`, `docs.vulnetix.com` | `www.vulnes.is`, `packages.vulnes.is`, `docs.vulnes.is` |
| `api.vdb.vulnetix.com` | `api-vdb.vulnes.is` |

The Package Firewall netrc machine follows the brand (`packages.vulnes.is`). Explicit overrides
(`--base-url`, `--proxy-url`, `--gateway-url`, `--server`, `VULNETIX_API_URL`, `VULNETIX_WEB_URL`,
`VULNETIX_SIEM_URL`, `VULNETIX_ENDPOINT`) still win over the brand's default. Identifiers are not
rebranded: config `apiVersion: vulnetix.com/v1`, TEI identifiers, schema `$id`s, SPDX namespaces,
SARIF tool names and the `vulnetix` command itself stay as they are.

## Development

```bash
go build -o vulnetix .
just test
```

`just test` runs `go test ./...`. Go 1.25 or newer is required (see `go.mod`). The `justfile`
lists the other recipes, including the generators for docs and actions.

`just mutation` runs mutation testing with gremlins (pinned at v0.6.0): it changes the code of a
package (negated conditions, moved boundaries, swapped operators) and reruns that package's tests,
and fails when fewer than 80% of the mutants are caught. CI runs the default, `./internal/purl`, in
the "Mutation testing" job. Pass another package and threshold to survey it, for example
`just mutation ./internal/versions 0`.

## Contributing

Open an issue or a pull request at [github.com/Vulnetix/cli](https://github.com/Vulnesis/cli).
Run `just test` before you send a change, and regenerate any generated file you touch (the
`justfile` and [AGENTS.md](./AGENTS.md) say which).

## Documentation

- [CLI documentation](https://docs.vulnes.is/cli/)
- [Pix documentation](https://docs.vulnes.is/pix/)
- [VDB API](https://docs.vulnes.is/vdb-api/)
- [Installation guides](./docs/README.md)
- [Distribution](./docs/PUBLISHING.md)
- [GitHub App](https://github.com/marketplace/vulnetix)

## License

[AGPL-3.0](./LICENSE.md)
<!-- ci-touch: 2026-08-24T13:13:32Z -->
