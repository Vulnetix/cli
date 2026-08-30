---
title: "License Command Reference"
weight: 5
description: "Analyze package licenses for conflicts, policy compliance, and risk — entirely local with multi-source resolution."
---

The `license` command walks your project directory, parses package manifests, resolves licenses from multiple sources, and evaluates them against compatibility rules and optional policy constraints. **All analysis runs locally.** License findings are merged into the CycloneDX SBOM alongside vulnerability findings — neither overwrites the other.

> License analysis also runs automatically as part of `vulnetix scan` unless `--no-licenses` is passed.

## Usage

```bash
vulnetix license [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `--mode` | string | `inclusive` | Analysis mode: `inclusive` (all packages as one unit) or `individual` (per-manifest conflict detection) |
| `--allow` | string | - | Comma-separated allow list of SPDX license IDs |
| `--allow-file` | string | - | Path to YAML allow list file |
| `--policy-file` | string | discovered | [Licence policy](#licence-policy) document (default `.vulnetix/license-policy.yaml` when present) |
| `--exceptions-file` | string | discovered | [Approved exceptions](#exceptions) (default `.vulnetix/license-exceptions.yaml` when present) |
| `--project` | string | - | Select per-project policy overrides |
| `--severity` | string | - | Exit with code `1` if any finding meets or exceeds this level: `low`, `medium`, `high`, `critical` |
| `-o, --output` | string | pretty summary | Output format: `json` (CycloneDX), `json-spdx` (SPDX 2.3); omit for a human-readable summary |
| `--results-only` | bool | `false` | Only show output when there are findings or conflicts (summary + issues, no full package table) |
| `--no-progress` | bool | `false` | Suppress progress indicators |
| `--from-memory` | bool | `false` | Reconstruct license output from `.vulnetix/memory.yaml` without re-scanning |
| `--dry-run` | bool | `false` | Detect files and parse packages only — no license evaluation or API calls |

## Output Files

License findings are merged into the same artifacts used by `vulnetix scan`:

| Path | Description |
|------|-------------|
| `.vulnetix/sbom.cdx.json` | CycloneDX BOM with license findings in the `vulnerabilities` section (source: `vulnetix-license-analyzer`) |
| `.vulnetix/memory.yaml` | License finding records alongside vulnerability findings |

The merge is keyed by source name — running `vulnetix scan` and `vulnetix license` independently will not overwrite each other's findings in the BOM.

The licence pass adds findings to a document another pass usually authored, so
it appends `vulnetix-license-analyzer` to `metadata.tools` — CycloneDX's own
description of that member is "the tool(s) used in the creation, **enrichment**,
and validation of the BOM" — and leaves the author's `serialNumber`, `timestamp`
and `manufacturer` untouched. The entry now carries the version that ran; it
previously carried none, which made it impossible to tell which release produced
a licence verdict. See [BOM authoring identity](../scan/#bom-authoring-identity).

## License Resolution

Licenses are resolved through a multi-source pipeline. Each step only runs for packages not yet resolved by a previous step.

### Resolution Priority

| Priority | Source | Description |
|----------|--------|-------------|
| 1 | **Manifests** | License fields declared in package manager files (`package.json`, `Cargo.toml`, `pyproject.toml`, `composer.json`) |
| 2 | **Filesystem** | LICENSE/COPYING files in the Go module cache (`~/go/pkg/mod/`), classified by text content |
| 3 | **Container / IaC** | OCI image labels, well-known Docker images, Terraform Registry, Nix CLI |
| 4 | **Embedded DB** | Curated mapping of popular packages to SPDX IDs |
| 5 | **deps.dev** | Google's Open Source Insights API for package version metadata |
| 6 | **GitHub** | Repository license via `gh` CLI (if authenticated) or GitHub REST API |

### Manifest License Fields

| Manifest | Field |
|----------|-------|
| `package.json` | `license` (string or `{type: "MIT"}` object) |
| `Cargo.toml` | `[package] license = "MIT"` |
| `pyproject.toml` | `[project] license = "MIT"` or `license = {text = "MIT"}` |
| `composer.json` | `license` (string or array) |

### Filesystem Detection

For Go modules, LICENSE files are read from the local module cache at `~/go/pkg/mod/`. The text classifier recognizes these license families:

MIT, Apache (1.1, 2.0), BSD (2-Clause, 3-Clause), GPL (2.0, 3.0), LGPL (2.0, 2.1, 3.0), AGPL (3.0), MPL (1.1, 2.0), EPL (1.0, 2.0), ISC, Unlicense, CC0, WTFPL, Boost (BSL-1.0), Zlib

Files checked (in order): `LICENSE`, `LICENSE.txt`, `LICENSE.md`, `LICENCE`, `LICENCE.txt`, `LICENCE.md`, `License`, `License.txt`, `COPYING`, `COPYING.txt`, `COPYING.md`

SPDX-License-Identifier headers in file content are also detected and parsed.

### Container and Infrastructure-as-Code

| Ecosystem | Resolution Method |
|-----------|-------------------|
| Docker / OCI | `podman inspect` or `docker inspect` for `org.opencontainers.image.licenses` label, then `org.opencontainers.image.source` annotation to resolve via GitHub, then well-known image mapping, then Docker Hub API description |
| Terraform | Terraform Registry API `source` field to GitHub repo, with fallback to `{namespace}/terraform-provider-{name}` convention |
| Nix | `nix eval nixpkgs#{name}.meta.license.spdxId` if CLI available, then well-known Nix packages |

### deps.dev API

Packages are queried via the [deps.dev API](https://docs.deps.dev/api/v3/) for ecosystems: Go, npm, PyPI, Cargo, Maven, NuGet. The `licenses` field from the package version response is used. For Go modules that are GitHub repositories, the project endpoint is also tried.

### GitHub Resolution

For packages hosted on GitHub, license resolution uses multiple strategies in order:

1. Repository API `.license.spdx_id` field
2. Dedicated `/repos/{owner}/{repo}/license` endpoint (includes file content)
3. Fetch known license file names from the repo and classify text content
4. Discover license files via directory listing (regex match on filenames)

The `gh` CLI is used when authenticated locally. If unavailable, the GitHub REST API is called using a token from the `GITHUB_TOKEN` or `GH_TOKEN` environment variable (if set).

> GitHub resolution handles multiple naming conventions: `github.com/owner/repo` (Go modules), `owner/repo` (GitHub Actions, Terraform providers).

## Evaluation Rules

Each package is evaluated against these rules. Findings include evidence chains showing which rule triggered and why.

| Rule | Severity | Description |
|------|----------|-------------|
| `unknown-license` | medium | No license could be detected from any source |
| `non-standard-license` | low | deps.dev reports a license exists but it is not an SPDX-recognized identifier |
| `deprecated-license` | low | License uses an SPDX-deprecated identifier |
| `not-osi-approved` | low | License is not OSI-approved (public domain licenses are exempt) |
| `copyleft-in-production` | policy | A category the [policy](#licence-policy) assigns a severity to, in a production-scope dependency. Defaults to `high` for strong copyleft |
| `license-conflict` | critical / high | Two licenses in the project are incompatible |
| `not-in-allowlist` | high | License is not in the configured allow list |

### License Categories

Licenses are classified into these categories for compatibility checking:

| Category | Examples | Color |
|----------|----------|-------|
| Permissive | MIT, Apache-2.0, BSD-3-Clause, ISC | Green |
| Weak Copyleft | LGPL-2.1, MPL-2.0, EPL-2.0, CDDL-1.0 | Yellow |
| Strong Copyleft | GPL-3.0, AGPL-3.0, EUPL-1.2 | Orange |
| Proprietary | BUSL-1.1, PolyForm, CC-BY-NC | Red |
| Public Domain | CC0-1.0, Unlicense, 0BSD | Blue |
| Unknown | Unresolved licenses | Grey |

### Conflict Detection

The compatibility matrix checks category pairs and specific SPDX ID pairs:

| Conflict | Severity |
|----------|----------|
| Strong Copyleft + Proprietary | critical |
| Proprietary + Weak Copyleft | high |
| Apache-2.0 + GPL-2.0-only | high |
| GPL-2.0-only + GPL-3.0-only | high |
| AGPL-3.0-only + GPL-2.0-only | high |

In **inclusive mode** (default), all packages across all manifests are checked as one unit. In **individual mode**, conflicts are only detected between packages within the same manifest file.

## Allow List

An allow list restricts which SPDX license IDs are permitted. Packages with licenses not in the list generate `not-in-allowlist` findings (severity: high).

### Via Flag

```bash
vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause
```

### Via YAML File

```yaml
# .vulnetix/license-allow.yaml
licenses:
  - MIT
  - Apache-2.0
  - BSD-3-Clause
  - ISC
  - BSD-2-Clause
```

```bash
vulnetix license --allow-file .vulnetix/license-allow.yaml
```

An allow list is the right answer for most projects. It stops being one when it
is a hundred entries long and nobody can say why MPL-2.0 is on it and EPL-2.0 is
not — and it says nothing at all about a licence nobody has enumerated yet. For
that, use a policy.

## Licence policy

A policy classifies licences **by category** and attaches a severity to each,
which is how the decision is actually made. Unlike a flat allow list it stays
correct when a dependency introduces a licence you have never seen.

```bash
vulnetix license policy init        # write a recommended starting policy
vulnetix license policy show        # the policy in effect, defaults filled in
vulnetix license policy validate    # check a policy document
```

```yaml
# .vulnetix/license-policy.yaml
apiVersion: vulnetix.com/v1
kind: LicensePolicy

# Reassign SPDX ids, overriding the built-in classification. The embedded
# database is a reasonable default, not an authority on what your organisation
# decided about a particular licence.
categories:
  strong-copyleft:
    - AGPL-3.0-only
    - AGPL-3.0-or-later
    - SSPL-1.0

severity:
  permissive: none
  public-domain: none
  weak-copyleft: low
  strong-copyleft: high
  proprietary: high
  unknown: medium

# warn | fail | ignore
unknown: warn

# evaluate | ignore
scopes:
  development: ignore
  dev: ignore
  test: ignore
  optional: ignore

# Per-project overrides, keyed on --project
projects:
  payment-service:
    severity:
      weak-copyleft: high
```

### The built-in default is deliberately looser

When no policy file exists, the built-in default reproduces **exactly** what the
evaluator did before policies existed: only strong copyleft carries a severity,
and no scope is ignored. Adopting a policy is a change you make deliberately,
not one that arrives with an upgrade and turns your build red for a decision
nobody made.

`license policy init` writes the stricter policy most teams adopting one
actually want — proprietary flagged, AGPL and SSPL treated as strong copyleft
(their obligation triggers on network use rather than distribution, which the
embedded database does not separate out), and unshipped dependencies out of
scope.

```bash
vulnetix license policy show
```

```
Category            Severity
permissive          none (not a finding)
public-domain       none (not a finding)
weak-copyleft       low
strong-copyleft     high
proprietary         high
unknown             medium

Unresolved licences: warn
Scopes ignored:      dev, development, optional, test
```

`show` prints the **resolved** policy — absent sections shown with the values
they inherit — so what you read is what the evaluator will do.

## Exceptions

Every real policy has exceptions: a vendored MPL-2.0 utility counsel signed off,
a GPL build tool that never ships. What matters is whether the exception is
recorded, or whether somebody quietly widened the allow list.

```bash
vulnetix license exceptions add --license MPL-2.0 \
  --reason "file-level copyleft, unmodified" --approver security@example.com

vulnetix license exceptions add --purl 'pkg:golang/github.com/hashicorp/*' \
  --license MPL-2.0 --reason "vendored, unmodified" --expires 2027-08-01

vulnetix license exceptions ls       # what is recorded, and whether it still applies
vulnetix license exceptions check    # what lapses soon; exits 1 on anything expired
```

```yaml
# .vulnetix/license-exceptions.yaml
apiVersion: vulnetix.com/v1
kind: LicenseExceptions

blanket:
  - license: MPL-2.0
    reason: file-level copyleft, unmodified, dynamically linked
    approver: security@example.com
    approvedDate: 2026-08-01
    expires: 2027-08-01

packages:
  - purl: pkg:golang/github.com/hashicorp/*
    license: MPL-2.0
    scope: vendored, unmodified
    reason: widely used, reviewed 2026-08
    approver: security@example.com
    expires: 2027-08-01
    projects: [payment-service]   # omit to apply everywhere
```

| Field | Required | Notes |
|-------|----------|-------|
| `license` | blanket only | Prefix-matched: `MPL-2.0` also covers `MPL-2.0-no-copyleft-exception` |
| `purl` / `name` | one, package only | `purl` accepts `*` globs; the **version is stripped** so an exception does not lapse on the next bump |
| `reason` | **yes** | An exception nobody can explain is indistinguishable from a mistake |
| `approver`, `approvedDate`, `scope` | no | Attribution |
| `expires` | no | `YYYY-MM-DD`, inclusive |
| `projects` | no | Limit to named projects |

### Name matching is segment-anchored

`name: gpl-lib` matches `gpl-lib`, `github.com/acme/gpl-lib` and
`@acme/gpl-lib` — but **not** `agpl-lib`, which is a different and stricter
licence. An exception that quietly covers more than it names is the worst
failure this file can have, so matching is anchored at `/` boundaries rather
than being a substring test.

### Expiry is enforced

An expired exception **stops applying**, and the finding says so rather than
reappearing unexplained:

```
high  LICENSE:copyl...  github.com/cyphar/fil...  strong-copyleft GPL-3.0-only  EXPIRED
    exception github.com/cyphar/filepath-securejoin: package exception,
      exc-2026-08-001, approved by security@example.com, expires 2026-01-01
      — EXPIRED — build-time only, not linked into the shipped binary
```

Run `license exceptions check` on a schedule to turn the expiry into a review
cadence instead of a trap:

```bash
vulnetix license exceptions check --expiring-within 90d
```

### Exempted findings are retained

An exempted finding keeps its row, is badged `exempted`, carries its
attribution, and is counted separately:

```
239 packages | 7 licenses | 0 conflicts | 8 findings (2 exempted)
```

A violation count that fell because somebody wrote an exception is a different
fact from one that fell because the dependency was removed, and a report that
cannot tell them apart is not an audit trail.

Only the **gate** ignores them — an approved exception that still failed the
build would be no exception at all.

## Output Formats

### Pretty (default)

Human-readable summary with:
- Package count, license distribution, category breakdown
- OSI/FSF/deprecated status badges
- Full package table grouped by manifest file
- Conflicts table (if any)
- Findings table sorted by severity
- Artifact paths

### CycloneDX JSON (`-o json`)

License findings are merged into `.vulnetix/sbom.cdx.json` and the full BOM is written to stdout. Each license finding becomes a CycloneDX `Vulnerability` entry with source `vulnetix-license-analyzer` and properties:

- `vulnetix:license-category` — the evaluation rule that triggered
- `vulnetix:license-spdx-id` — the resolved SPDX ID
- `vulnetix:license-severity` — finding severity
- `vulnetix:source-file` — manifest file path
- `vulnetix:evidence-N:rule` / `vulnetix:evidence-N:result` — evidence chain

### SPDX 2.3 JSON (`-o json-spdx`)

Generates a standalone SPDX 2.3 document with:
- `packages[]` with `licenseConcluded` and `licenseDeclared`
- `relationships[]` (DESCRIBES)
- `extractedLicensingInfos[]` for non-standard licenses
- Package URLs as external references

## Integration with `vulnetix scan`

License analysis runs automatically during `vulnetix scan`, and it runs **this**
pipeline: `scan` delegates to the same detect → policy → suppression → memory
reconcile path this command uses, so both reach the same verdict. License findings
are:
- Appended to the CycloneDX BOM in the `vulnerabilities` section
- Written to `.vulnetix/memory.yaml`
- Included in the pretty output after the vulnerability summary
- Resolved and attested as CycloneDX VEX when they disappear

Because it is the same pipeline, the policy flags work identically on the scan
family:

```bash
# These two apply the same policy and produce the same findings
vulnetix license --allow MIT,Apache-2.0 --mode individual
vulnetix scan --allow MIT,Apache-2.0 --license-mode individual
```

| `license` flag | Scan-family flag |
|----------------|------------------|
| `--allow` | `--allow` |
| `--allow-file` | `--allow-file` |
| `--mode` | `--license-mode` |

> Earlier releases ran a fixed permissive policy inside `scan` (no allow list,
> always `inclusive`), so a scan could pass while `vulnetix license` failed. That
> divergence is gone.

To skip license analysis during a scan:

```bash
vulnetix scan --no-licenses
```

Note that license evaluation needs the packages the SCA pass resolves, so
`--evaluate-licenses` on its own resolves nothing — pair it with `--evaluate-sca`:

```bash
vulnetix scan --evaluate-sca --evaluate-licenses --allow MIT
```

## Examples

### Scan the current directory

```bash
vulnetix license
```

### Scan a specific project

```bash
vulnetix license --path /path/to/project --depth 5
```

### Only show issues

```bash
vulnetix license --results-only
```

### Enforce an allow list

```bash
vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause,ISC
```

### Break the build on high-severity license issues

```bash
# Exit 1 if any high or critical finding (copyleft in production, conflicts, policy violations)
vulnetix license --severity high
```

### Per-manifest conflict detection

```bash
vulnetix license --mode individual
```

### CycloneDX output for CI pipelines

```bash
vulnetix license -o json > license-findings.cdx.json
```

### SPDX output

```bash
vulnetix license -o json-spdx > license-report.spdx.json
```

### Dry run (no evaluation, no API calls)

```bash
vulnetix license --dry-run
```

### Reconstruct from previous results

```bash
vulnetix license --from-memory
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Analysis completed successfully (no threshold breach) |
| `1` | `--severity` threshold was breached, or a fatal error occurred |
