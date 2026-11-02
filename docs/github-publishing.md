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
