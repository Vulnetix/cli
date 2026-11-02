# Publishing into GitHub

The CLI publishes its results to GitHub in GitHub's own formats, independently of
sending them to Vulnetix. Public documentation lives at
[docs.vulnetix.com](https://docs.vulnetix.com/cli/ci-cd/github-actions/); this page is the
in-repository reference for how it works.

## GitHub-compatible SARIF

Every SARIF file the CLI writes carries what code scanning reads beyond the SARIF 2.1.0
schema (`internal/sast/github.go`):

| Field | Value | Why |
|---|---|---|
| rule `properties.security-severity` | critical 9.5, high 8.0, medium 5.5, low 2.0; SCA uses the advisory's CVSS score | Sorts the alert into Critical, High, Medium or Low |
| rule `properties.tags` | adds `security` and `external/cwe/cwe-N` | Makes it a security alert, filterable by CWE |
| run `automationDetails.id` | `vulnetix/<kind>/` (`sast`, `secrets`, `iac`, `containers`, `sca`, `license`) | One category per kind, so one kind's upload never closes another kind's alerts |
| result `partialFingerprints.primaryLocationLineHash` | codeql-action's rolling line hash (`internal/sast/linehash.go`) | Keeps an alert the same alert when its line moves |

`linehash.go` is a port of `hash()` in github/codeql-action `src/fingerprints.ts`, and its
test vectors are codeql-action's own, so a value computed here equals the one codeql-action's
upload step would compute.

A run with one kind of rule gets its category in `sast.BuildSARIF`. `scan` writes every rule
kind into one `.vulnetix/sast.sarif`; `sast.SplitByKind` splits such a file into one log per
kind before it is published. Code scanning accepts at most 25,000 results per run, so
`sast.PrepareForGitHub` keeps the most severe 25,000.

### SCA and licence SARIF

| File | Written by | Builder |
|---|---|---|
| `.vulnetix/sca.sarif` | every scan that runs SCA, clean or not | `report.BuildSARIF` |
| `.vulnetix/license.sarif` | `vulnetix license` | `license.BuildLog` |

Both are written even when clean, so a publish closes alerts that are fixed. A result sits on
the manifest line that declares the package (`sast.ManifestLines`). Its fingerprint hashes the
ecosystem, package, advisory (or licence rule) and manifest, never the version: a bump that
leaves the advisory open is the same alert, and a bump that fixes it closes it.

## The shared client (`internal/github`)

| File | Purpose |
|---|---|
| `client.go` | JSON requests, `Link` pagination (`GetAll`), rate limits waited out within 90 seconds (`Retry-After`, then `X-RateLimit-Reset`), `GITHUB_API_URL` for GitHub Enterprise Server |
| `token.go` | `ResolveToken`: `GITHUB_TOKEN`, then `GH_TOKEN`, then `gh auth token` (also used by `internal/triage`) |
| `target.go` | `ResolveTarget`: repository, commit and ref from flags, then `GITHUB_REPOSITORY`/`GITHUB_SHA`/`GITHUB_REF`, then the git checkout |
| `codescanning.go` | `UploadSARIF` (gzip, base64, `POST /repos/{o}/{r}/code-scanning/sarifs`) and `WaitSARIF` |

A 401, 403 or 404 (`IsPermission`) is reported with the permission the token is missing; a
pull request from a fork has a read-only token, so its publish warns and the job goes on.

## `vulnetix gha publish code-scanning`

Uploads every `.vulnetix/*.sarif` under `--path` (or each `--sarif`), merged and split into one
upload per kind, and writes what it uploaded to `.vulnetix/code-scanning/<kind>.sarif`. It waits
up to `--wait` (2 minutes) for GitHub to process each upload. Permissions:
`security-events: write`, plus `actions: read` on a private repository.

### `--github-publish` on scans

Every scan-family command takes `--github-publish code-scanning`. At the end of the scan it
uploads the scan's own results, with an empty upload for each kind that ran clean, so fixed
alerts close. It forces `--no-cache`: a cached run must never close an alert that is still
real. A failure only warns; the scan's exit code and its Vulnetix upload are unaffected, and a
community run (no Vulnetix credentials) still publishes to GitHub.

## `vulnetix gha publish dependency-graph`

Builds a dependency graph snapshot from a CycloneDX SBOM (`--sbom`, default
`.vulnetix/sbom.cdx.json`) and posts it to `POST /repos/{o}/{r}/dependency-graph/snapshots`
(`internal/github/depgraph.go`). Permission: `contents: write`.

| Snapshot field | From |
|---|---|
| manifests | grouped by each component's `vulnetix:source-file` property; components without it go under the SBOM's own path |
| `scope` | `vulnetix:scope` (or the CycloneDX scope): anything development or test is `development`, the rest `runtime` |
| `relationship` | `direct` when the root component's dependencies name it, else `indirect`; omitted when the SBOM has no root dependencies |
| `dependencies` | the component's own `dependsOn`, as purls |
| `job.correlator` | `vulnetix/<workflow>/<job>` (`--correlator`), so the next run replaces this snapshot |

Components without a purl cannot be named to the dependency graph and are skipped. Scans take
`--github-publish dependency-graph` to submit the SBOM they just wrote.

## The artifact manifest (`internal/artifacts`)

`--artifact-manifest <file>` (a root flag) or `VULNETIX_ARTIFACT_MANIFEST` names a JSON Lines
file to which every file the CLI writes is appended: path, kind (`sarif`, `cyclonedx`, `vex`,
`signature`, `certificate`, `attestation`, `report`), SHA-256, size and command. Writers go
through `artifacts.WriteFile` or record after writing: `sast.WriteSARIF` (every SARIF, including
`sca.sarif`, `license.sarif` and `.vulnetix/code-scanning/`), `writeBOMToFile` (the scan SBOM),
`cdx`, `cbom`, `aibom`, `malscan`, `jail`, `vex`, `analyze`, and the cdxsign `.sig`, `.pem` and
`.intoto.jsonl` sidecars. Appends use `O_APPEND`, so several commands in one job share one
manifest; `artifacts.Read` keeps the last entry per path and drops files that no longer exist.
An unwritable manifest never fails the write it records.

## `vulnetix gha publish release-assets`

Attaches the named files, or with none every file in the artifact manifest, to the release for
`--tag` (default: the tag of a tag push), through `Client.EnsureRelease` and
`Client.UploadAsset` (`internal/github/release.go`). A missing release is an error unless
`--create`, which creates a draft. An existing asset of the same name is an error unless
`--clobber`. The upload host comes from the release's `upload_url`, so GitHub Enterprise Server
works. Permission: `contents: write`.

## `vulnetix gha publish advisories`

Drafts GitHub repository security advisories (`POST /repos/{o}/{r}/security-advisories`) for
this repository's own SAST findings (`cmd/gha_publish_advisories.go`,
`internal/github/advisories.go`).

| Rule | Detail |
|---|---|
| Scope | Findings of kind `sast` at or above `--min-severity` (default `high`), read from `--sarif` (default `.vulnetix/sast.sarif`). Suppressed findings, test-suite findings (`vulnetix/test-suite`) and confidence-gap findings are excluded |
| Grouping | One advisory per rule and CWE set, worst severity first, then most locations, capped at `--max` (default 10) |
| Fields | `summary` `[Vulnetix] <rule>`, a description listing up to 25 locations, `cwe_ids`, `severity`; never a CVSS vector. The package is the repository's own, from `package.json`, `go.mod`, `Cargo.toml`, `pyproject.toml` or `composer.json`, else ecosystem `other` with the repository name |
| Dedupe | The description ends with `<!-- vulnetix-advisory:<hash> -->` (hash of rule and CWEs). A later run updates the matching draft with `PATCH` and leaves a published or closed one alone |
| Lifecycle | Never published: the update body has no `state`. Publishing stays a maintainer's decision |
| Token | Repository advisories write: a fine-grained PAT or a GitHub App token. The workflow `GITHUB_TOKEN` cannot create advisories |

`--dry-run` prints what would be drafted and calls nothing.
