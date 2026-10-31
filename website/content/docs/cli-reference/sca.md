---
title: "SCA Command Reference"
weight: 5
description: "Run only Software Composition Analysis — vulnerability analysis on package manifests with no other scan categories enabled."
---

The `sca` command runs a focused scan that analyses package dependencies for known vulnerabilities. It is equivalent to running:

```bash
vulnetix scan --evaluate-sca --no-sast --no-secrets --no-containers --no-iac --no-licenses
```

No SAST rules, license analysis, secret detection, container analysis, or IaC analysis runs. This makes it faster and less noisy when you only care about dependency vulnerabilities.

Dependency discovery includes package manifests and lock files plus package-manager install commands found in CI/CD pipeline files, shell scripts, Makefiles and task recipes. This catches packages installed directly by pipelines or scripts when no package manifest exists. The full file and vendor coverage is listed under [CI/CD coverage](../cdx/#cicd-coverage) and [Shell and recipe coverage](../cdx/#shell-and-recipe-coverage).

> **Credentials are optional.** When no credentials are configured the [community fallback](https://www.vulnetix.com/features/community) is used automatically.

For JavaScript projects, lock files remain the preferred source of truth: `package-lock.json` (and `npm-shrinkwrap.json`), `yarn.lock` (Classic and Berry), `pnpm-lock.yaml` (lockfile v5 through v9) and `bun.lock`. In a monorepo the lock lives at the workspace root, so a member's `package.json` is resolved from the root's lock: the root is the nearest ancestor whose `package.json` `workspaces`, `lerna.json` `packages` or `pnpm-workspace.yaml` `packages` globs include the member. Every dependency a workspace declares is reported as direct. See [JavaScript / TypeScript](../scan/#javascript--typescript) for the details.

If a `package.json` has no lock beside it and no workspace root's lock covers it, `vulnetix sca` resolves from installed `node_modules/` instead: it verifies every direct dependency is installed, uses the installed versions for `/v2/cli.sca`, and reads package manifests in `node_modules/` to build a best-effort transitive tree. If `node_modules/` is absent or incomplete, the manifest is skipped with a note saying how to make it scannable, and the rest of the scan continues.

## Usage

```bash
vulnetix sca [flags]
```

## Flags

All flags from `vulnetix scan` are available except the feature-control flags (`--evaluate-*`, `--no-*`) — those are hard-coded for this command.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-o, --output` | stringArray | - | Output target: `json-cyclonedx` or `json-sarif` for stdout; file path for file output |
| `--concurrency` | int | - | **Deprecated, no-op.** It never had any effect; set `VULNETIX_SCA_CONCURRENCY` (default `6`) to change SCA fan-out |
| `--reachability` | string | `both` | Tree-sitter reachability mode for the CVEs this scan produces: `direct`, `transitive`, `both`, or `off` |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--paths` | bool | `false` | Show full transitive dependency paths |
| `--no-exploits` | bool | `false` | Suppress the exploit intelligence section |
| `--no-remediation` | bool | `false` | Suppress the remediation section |
| `--severity` | string | - | Exit `1` if any vulnerability meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--block-malware` | bool | `false` | Exit `1` when any dependency is a known malicious package |
| `--block-eol` | bool | `false` | Exit `1` when a runtime or package dependency is end-of-life |
| `--block-unpinned` | bool | `false` | Exit `1` when any direct dependency uses a version range instead of an exact pin |
| `--exploits` | string | - | Exit `1` when exploit maturity reaches threshold: `poc`, `active`, `weaponized` |
| `--results-only` | bool | `false` | Only output when findings exist |
| `--no-ci-package-analysis` | bool | `false` | Skip dependency extraction from CI/CD pipeline files, including GitHub Actions workflows |
| `--no-shell-package-analysis` | bool | `false` | Skip dependency extraction from shell scripts, Makefiles and task recipes |
| `--version-lag` | int | `0` | Exit `1` when any dep is within the N most recently published versions (0 = disabled) |
| `--cooldown` | int | `0` | Exit `1` when any dep was published within the last N days (0 = disabled) |
| `--sca-autofix` | bool | `false` | Apply validated SCA fixes with the project package manager, then rescan to confirm |
| `--sca-autofix-strategy` | string | `stable` | Target strategy: `safest`, `stable`, `latest` or `rolling` ([definitions](/docs/cli-reference/sca-autofix/#strategies)) |
| `--sca-autofix-manifest` | string | - | Restrict autofix edits to one manifest file |
| `--sca-autofix-max-major-bump` | int | `0` | Refuse targets crossing more than N major versions. `0` stays on the current major; a negative value lifts the cap |
| `--yes` | bool | `false` | Non-interactive autofix mode: auto-pick safe defaults and never prompt |
| `--dry-run` | bool | `false` | Parse packages locally, replay stored results, then exit — zero API calls |

## Examples

```bash
# SCA scan of the current directory
vulnetix sca

# Scan a specific project directory
vulnetix sca --path /path/to/project

# Break the build on high or critical vulnerabilities
vulnetix sca --severity high

# Exit 1 on known malicious packages
vulnetix sca --block-malware

# Emit CycloneDX JSON to stdout
vulnetix sca --output json-cyclonedx

# Write CycloneDX to a file
vulnetix sca --output sbom.cdx.json

# Skip packages installed only by pipelines or shell scripts
vulnetix sca --no-ci-package-analysis --no-shell-package-analysis

# Silent when clean
vulnetix sca --results-only

# Preview vetted dependency fixes without editing files
vulnetix sca --sca-autofix --dry-run

# Apply stable Safe-Harbour fixes in CI
vulnetix sca --sca-autofix --yes
```

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sbom.cdx.json` | CycloneDX 1.7 SBOM for all scanned packages |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, counts, git context) |

## Performance and Local Caches

A scan is mostly round trips to the VDB API, so the CLI keeps as few of them as possible on the critical path:

- **One token exchange per credential.** The exchanged API token is shared by every request the scan makes and persisted (mode `0600`) under `~/.vulnetix/cache/tokens/`, keyed by a hash of the endpoint and credential (the secret itself is never written). The next scan within the token's lifetime makes no exchange at all. If the server rejects a cached token, the CLI drops it and exchanges once more. Set `VULNETIX_NO_TOKEN_CACHE=1` to keep tokens in memory only.
- **The last uploads do not hold the exit.** `cli.sca-reachability`, `cli.finalize` and the graph-insights upload (`cli.insights`) only record what the scan decided; the scan asks the API to save them after answering (`X-Vulnetix-Deferred`), so it exits without waiting for those writes.
- **Version checks go in one request.** A finding whose affected range cannot be compared with the installed version (a git-commit range, typically) is settled by reading the advisory's own record. Each wave of those reads is sent as one `POST /v2/cli.affected-batch` request, which the API answers item by item exactly as `GET /v2/vuln/{id}/affected`; a read it could not answer is retried on its own.
- **No lookup that cannot answer.** A Maven package named without its group (BUCK and some sbt manifests) is not looked up on deps.dev, which names every Maven package `group:artifact`.
- **Licences other scans resolved come from the API.** After local detection (manifests, installed files, the embedded catalogue), the scan asks `POST /v2/cli.licenses` once for every package still unknown; the API answers with the licence earlier Vulnetix scans stored for that package. Registries, deps.dev and GitHub are only asked about what it does not know. Those licences are labelled with source `vulnetix`.
- **Licences found are remembered.** Licences resolved from package registries, deps.dev and GitHub are stored under `~/.vulnetix/cache/licenses/` for seven days. Lookups that found nothing are asked again next run, with one exception: a GitHub repository whose every `gh` lookup answered or returned HTTP 404 is remembered as having no licence for a day. A miss after a timeout, an auth or rate-limit failure, or a lookup through a personal access token is never remembered. A version deps.dev answers 404 for is likewise remembered for a day. npm and JSR scopes such as `@std/path` are never looked up on GitHub. Set `VULNETIX_NO_LICENSE_CACHE=1` to disable the store.
- **Work the scan does not read runs in the background.** The raw manifest archive, reachability evidence and graph insights upload alongside the rest of the scan. The org's suppression rules are fetched while local parsing runs. The CLI waits for all of them before it exits.
- **Advisory checks run in parallel and are reused.** Up to 24 version checks against advisory records (`/v2/vuln/{id}/affected`) run at once. An answer is reused from the local response cache for ten minutes, the same window the API keeps it. That cache is keyed by credential as well as request, so one organisation's answers (or community answers) never serve another.
- **The repository is read once, and it is the one scanned.** Every request a scan sends (quality gate, suppressions, licences, ...) carries the git context of the `--path` repository, read once per run, not of the directory the CLI was started in. Scanning another directory from inside a large repository no longer runs `git status` over that repository first.
- **Package-manager versions are asked once.** The installed package managers the manifests imply (`gradle`, `poetry`, `npm`, ...) are asked their versions in parallel. Each answer is stored under `~/.vulnetix/cache/binaries/`, keyed by the binary file's path, size and modification time, so an upgrade is picked up. Set `VULNETIX_NO_BINARY_CACHE=1` to disable the store.

Set `VULNETIX_HTTP_TRACE=1` to print one stderr line per HTTP request: start offset, duration, status and URL path, with no headers or bodies. Use it to see where a slow scan spends its time.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | A gate was breached (`--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`), or a fatal error occurred |

## Related Commands

- [`vulnetix scan`](scan/) — Full scan with all features enabled
- [`vulnetix sast`](sast/) — SAST-only scan
- [`vulnetix secrets`](secrets/) — Secret detection only
- [`vulnetix containers`](containers/) — Container file analysis only
- [`vulnetix iac`](iac/) — IaC file analysis only
- [`vulnetix license`](license/) — Standalone license analysis
- [`vulnetix fix`](fix/) — Apply the dependency fixes this scan proposes
- [`vulnetix report`](report/) — Replay the stored results without rescanning
