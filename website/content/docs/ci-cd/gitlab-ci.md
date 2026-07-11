---
title: "GitLab CI/CD"
weight: 2
description: "Integrate Vulnetix CLI into GitLab CI/CD, from a single-file quickstart to a CI/CD Component every project inherits."
---

This page builds up from the smallest working `.gitlab-ci.yml` to an organization-wide CI/CD Component that every project includes in four lines. Each level adds one idea to the previous one.

{{< callout type="warning" >}}
**Versions in this page are current as of writing** (Vulnetix CLI `v3.59.4`, GitLab 18.x).

Every YAML example is validated against GitLab's published CI schema before release — the sources live in [`examples/gitlab/`](https://github.com/Vulnetix/cli/tree/main/examples/gitlab) and are checked by `examples/gitlab/validate.sh`. Schema validation cannot catch semantic errors; see [Verifying These Examples](#verifying-these-examples) to lint against your own project.

If a snippet no longer works, [open an issue](https://github.com/Vulnetix/cli/issues/new) with the GitLab and CLI versions you are on, and we will correct the documentation.
{{< /callout >}}

## Before You Start

Add two variables under **Settings → CI/CD → Variables**. Mark both **Masked** and **Protected**.

| Variable | Value |
|----------|-------|
| `VULNETIX_ORG_ID` | Organization UUID |
| `VULNETIX_API_KEY` | ApiKey hex digest |

A value is maskable when it is a single line, contains no spaces, and is at least 8 characters. A UUID qualifies. **Protected** restricts the variable to pipelines on protected branches and tags — set it, then keep release pipelines on protected tags.

{{< callout type="error" >}}
Do **not** name the ApiKey `VULNETIX_API_TOKEN`. That variable holds a **Bearer token** and sits at the top of the [credential precedence chain](/docs/authentication/precedence/). An ApiKey stored under that name is sent as `Authorization: Bearer <apikey>` and rejected, and because environment credentials outrank everything else, nothing else will be tried.
{{< /callout >}}

### No `auth login` Step

None of these examples run `vulnetix auth login`. Environment variables authenticate on their own, persist nothing, and disappear with the job. A login step on an ephemeral runner writes a plaintext `.vulnetix/credentials.json` into the workspace for no benefit. See [Authentication in CI/CD](/docs/authentication/ci-cd/).

Use `vulnetix auth verify` instead. It reads the credential, calls the API, exits non-zero on failure, and writes nothing.

---

## Level 1 — Quick Start

One file, one job. Install the CLI, prove the credential works, scan.

```yaml
stages:
  - security

vulnetix:
  stage: security
  image: alpine:3.20
  variables:
    VULNETIX_VERSION: v3.59.4
  before_script:
    - apk add --no-cache bash ca-certificates curl tar
    - curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /usr/local/bin --version "$VULNETIX_VERSION"
  script:
    - vulnetix auth verify
    - vulnetix scan --severity high
```

`vulnetix auth verify` on line one means a bad credential fails immediately rather than halfway through a scan.

### The CLI Already Knows It Is in GitLab

You do not need to pass any pipeline context. The CLI detects GitLab from `GITLAB_CI` / `CI_JOB_ID` and reads the predefined variables itself:

| Read automatically | Used for |
|---|---|
| `CI_PROJECT_PATH`, `CI_PROJECT_NAMESPACE` | Project attribution |
| `CI_PIPELINE_ID`, `CI_PIPELINE_IID`, `CI_JOB_ID` | Pipeline correlation |
| `CI_COMMIT_SHA`, `CI_COMMIT_REF_NAME`, `CI_COMMIT_TAG` | Commit attribution |
| `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` | Merge-request diffs |
| `CI_SERVER_URL`, `CI_API_V4_URL`, `CI_SERVER_VERSION` | Instance identification |

This is the same normalised context the CLI builds on GitHub Actions, so findings correlate across both.

---

## Level 2 — One Job Per Scan Subcommand

Each subcommand runs standalone and uploads its findings to Vulnetix automatically whenever the two credential variables are present.

### What Each Subcommand Writes

Results land under `.vulnetix/` in the scanned directory whether or not you ask for a copy elsewhere.

| Command | Default result file | Format | Exits `1` when |
|---------|--------------------|--------|----------------|
| `vulnetix sca` | `.vulnetix/sbom.cdx.json` | CycloneDX | a gate flag is passed and breached |
| `vulnetix sast` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix secrets` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix containers` | `.vulnetix/containers.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix iac` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix license` | `.vulnetix/sbom.cdx.json` | CycloneDX | `--severity` is met or exceeded |
| `vulnetix cbom` | `.vulnetix/cbom.cdx.json` | CycloneDX (CBOM) | `--fail-on` status is found |
| `vulnetix aibom` | `.vulnetix/ai-bom.cdx.json` | CycloneDX (AIBOM) | never |
| `vulnetix malscan` | `.vulnetix/malscan.sarif` | SARIF | any malware finding |
| `vulnetix scan` | `.vulnetix/sbom.cdx.json` + `.vulnetix/sast.sarif` | both | any passed gate is breached |

{{< callout type="info" >}}
The SARIF-producing scans write their file **only when there are findings**. A clean scan deliberately leaves no empty artifact behind. Guard downstream steps accordingly — see Level 3.
{{< /callout >}}

### A Shared Base

`extends:` keeps the install in one place.

```yaml
stages:
  - security

.vulnetix:
  stage: security
  image: alpine:3.20
  variables:
    VULNETIX_VERSION: v3.59.4
  before_script:
    - apk add --no-cache bash ca-certificates curl tar
    - curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /usr/local/bin --version "$VULNETIX_VERSION"
    - vulnetix auth verify
```

A job name beginning with `.` is a hidden job: GitLab never runs it, it exists to be extended.

### The Jobs

```yaml
# Dependency vulnerabilities.
sca:
  extends: .vulnetix
  script:
    - vulnetix sca --severity high

# Source code analysis.
sast:
  extends: .vulnetix
  script:
    - vulnetix sast --severity high

# Hardcoded credentials.
secrets:
  extends: .vulnetix
  script:
    - vulnetix secrets

# Dockerfile and image layers.
containers:
  extends: .vulnetix
  script:
    - vulnetix containers

# Terraform, OpenTofu, Nix, Kubernetes manifests.
iac:
  extends: .vulnetix
  script:
    - vulnetix iac

# SPDX policy compliance.
license:
  extends: .vulnetix
  script:
    - vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause --severity high

# Cryptographic inventory and post-quantum posture.
cbom:
  extends: .vulnetix
  script:
    - vulnetix cbom --fail-on quantum-vulnerable

# AI coding agents, SDKs, and model usage.
aibom:
  extends: .vulnetix
  script:
    - vulnetix aibom
```

`--fail-on` defaults to `none`, which never fails the job. It accepts a comma-separated list of PQC statuses (`quantum-vulnerable`, `deprecated`).

### Malscan Needs Installed Dependencies

`malscan` reads the bytes of your installed dependencies, so install them first and use an image that can.

```yaml
malscan:
  extends: .vulnetix
  image: node:20-alpine
  script:
    - npm ci
    - vulnetix malscan
```

---

## Level 3 — Publish the Result File

Each command can write its result to a path you choose. Which flag does it depends on the command.

| Flag | Commands | Behaviour |
|------|----------|-----------|
| `-o` / `--output` | `sca`, `sast`, `secrets`, `containers`, `iac`, `scan` | Repeatable. Accepts a path ending `.cdx.json` or `.sarif`, or the literals `json-cyclonedx` / `json-sarif` for stdout |
| `--output-file` | `cbom`, `aibom`, `malscan` | Single path. `-o` on these selects the **terminal** format only |
| *(neither)* | `license` | Writes `.vulnetix/sbom.cdx.json`. `-o json-spdx` prints SPDX 2.3 to stdout. Copy the file out to publish it |

Every job below writes into `dist/`, so the shared base from Level 2 gains one line:

```yaml
.vulnetix:
  stage: security
  image: alpine:3.20
  variables:
    VULNETIX_VERSION: v3.59.4
  before_script:
    - apk add --no-cache bash ca-certificates curl tar
    - curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /usr/local/bin --version "$VULNETIX_VERSION"
    - vulnetix auth verify
    - mkdir -p dist
```

### `artifacts:when: always` Is Not Optional

A breached `--severity` gate fails the job. Without `when: always`, GitLab discards the artifacts of a failed job — throwing away the exact evidence you wanted.

```yaml
sca:
  extends: .vulnetix
  script:
    - vulnetix sca --severity high -o dist/sbom.cdx.json
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - dist/sbom.cdx.json
```

This is the GitLab analogue of `if: always()` on a GitHub `upload-artifact` step.

### Feeding the Security Dashboard

{{< callout type="warning" >}}
`artifacts:reports:cyclonedx` and `artifacts:reports:sarif` both require **GitLab Ultimate**. On Free and Premium they are silently ignored: the pipeline passes, the findings simply never reach the Security Dashboard. Always declare `artifacts:paths` as well — that works on every tier.

Note also that `artifacts:reports:sast` is Free-tier but expects **GitLab's own report schema**, not SARIF. Do not point it at a Vulnetix SARIF file.
{{< /callout >}}

CycloneDX outputs (`sca`, `license`, `cbom`, `aibom`) go to `reports:cyclonedx`:

```yaml
sca:
  extends: .vulnetix
  script:
    - vulnetix sca --severity high -o dist/sbom.cdx.json
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - dist/sbom.cdx.json
    reports:
      cyclonedx:
        - dist/sbom.cdx.json
```

SARIF outputs (`sast`, `secrets`, `containers`, `iac`, `malscan`) go to `reports:sarif`:

```yaml
sast:
  extends: .vulnetix
  script:
    - vulnetix sast --severity high -o dist/sast.sarif
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - dist/sast.sarif
    reports:
      sarif: dist/sast.sarif
```

### License Needs Two Commands

`license` has no `--output-file`. Copy its CycloneDX out of `.vulnetix/`, and redirect stdout for the SPDX view.

```yaml
license:
  extends: .vulnetix
  script:
    - vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause
    - cp .vulnetix/sbom.cdx.json dist/licenses.cdx.json
    - vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause -o json-spdx > dist/licenses.spdx.json
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - dist/licenses.cdx.json
      - dist/licenses.spdx.json
    reports:
      cyclonedx:
        - dist/licenses.cdx.json
```

### CBOM, AIBOM, and Malscan Take `--output-file`

```yaml
cbom:
  extends: .vulnetix
  script:
    - vulnetix cbom --output-file dist/cbom.cdx.json --fail-on quantum-vulnerable
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - dist/cbom.cdx.json
    reports:
      cyclonedx:
        - dist/cbom.cdx.json
```

A clean `secrets`, `sast`, `containers`, `iac`, or `malscan` run writes no SARIF. GitLab warns that the artifact path matched nothing; it does not fail the job.

The full set of jobs is in [`examples/gitlab/03-publish-artifacts.gitlab-ci.yml`](https://github.com/Vulnetix/cli/blob/main/examples/gitlab/03-publish-artifacts.gitlab-ci.yml).

---

## Level 4 — Run Them in Parallel

`parallel:matrix` is GitLab's analogue of the GitHub Actions job matrix: each combination becomes its own job with its own log.

There is no `fail-fast` to disable. GitLab already lets sibling matrix jobs run to completion when one fails.

```yaml
stages:
  - security

vulnetix:
  stage: security
  image: alpine:3.20
  variables:
    VULNETIX_VERSION: v3.59.4
  parallel:
    matrix:
      - SCAN: sca
        OUT: dist/sbom.cdx.json
        OUT_FLAG: '-o'
      - SCAN: secrets
        OUT: dist/secrets.sarif
        OUT_FLAG: '-o'
      - SCAN: cbom
        OUT: dist/cbom.cdx.json
        OUT_FLAG: '--output-file'
      - SCAN: aibom
        OUT: dist/aibom.cdx.json
        OUT_FLAG: '--output-file'
      # license accepts neither flag; the script special-cases it.
      - SCAN: license
        OUT: dist/licenses.cdx.json
        OUT_FLAG: ''
  before_script:
    - apk add --no-cache bash ca-certificates curl tar
    - curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /usr/local/bin --version "$VULNETIX_VERSION"
    - vulnetix auth verify
    - mkdir -p dist
  script:
    - |
      if [ -z "$OUT_FLAG" ]; then
        vulnetix "$SCAN"
        cp .vulnetix/sbom.cdx.json "$OUT"
      else
        vulnetix "$SCAN" "$OUT_FLAG" "$OUT"
      fi
  artifacts:
    when: always
    expire_in: 7 days
    name: "vulnetix-$SCAN-$CI_COMMIT_SHORT_SHA"
    paths:
      - dist/
```

The three-flag split from Level 3 is why the matrix carries an `OUT_FLAG` and the script has a branch. It is honest about the CLI's surface rather than pretending one flag fits all.

### There Is No `task: gha` Equivalent

On GitHub, `task: gha` collects every artifact of a workflow run and uploads it to Vulnetix in one step. GitLab has no such command — the CLI's `gha` subcommand is GitHub-only, gated on `GITHUB_ACTIONS=true`.

On GitLab, each scan uploads its own findings automatically when authenticated. To push a **third-party** artifact (a Semgrep SARIF, a Syft SBOM) into Vulnetix, upload it explicitly:

```yaml
upload-external:
  extends: .vulnetix
  script:
    - vulnetix upload --file reports/semgrep.sarif --format sarif
```

---

## Level 5 — Ship the Artifacts with a GitLab Release

This is where GitLab and GitHub genuinely differ, and the difference dictates the shape of the pipeline.

| | GitHub | GitLab |
|---|--------|--------|
| Attach a file to a release | `gh release upload <tag> <file>` | Not possible directly |
| `release:assets:links` | — | Takes a **URL**, never a local path |

So the artifacts must be published somewhere addressable first. The built-in answer is the **generic package registry**, authenticated with `CI_JOB_TOKEN`, which every job already has.

{{< callout type="info" >}}
`release-cli` is **deprecated as of GitLab 18.0** and planned for removal in 20.0. The examples below use `registry.gitlab.com/gitlab-org/cli:latest` (the `glab` image), which is the supported path.
{{< /callout >}}

### Three Stages

```yaml
stages:
  - security
  - publish
  - release

variables:
  VULNETIX_VERSION: v3.59.4
  PACKAGE_NAME: vulnetix-artifacts
```

**Generate**, on tags only, in parallel:

```yaml
analyze:
  extends: .vulnetix
  stage: security
  rules:
    - if: $CI_COMMIT_TAG
  parallel:
    matrix:
      - SCAN: sca
        OUT: dist/sbom.cdx.json
        OUT_FLAG: '-o'
      - SCAN: cbom
        OUT: dist/cbom.cdx.json
        OUT_FLAG: '--output-file'
      - SCAN: aibom
        OUT: dist/aibom.cdx.json
        OUT_FLAG: '--output-file'
      - SCAN: license
        OUT: dist/licenses.cdx.json
        OUT_FLAG: ''
      - SCAN: secrets
        OUT: dist/secrets.sarif
        OUT_FLAG: '-o'
  script:
    - |
      if [ -z "$OUT_FLAG" ]; then
        vulnetix "$SCAN"
        cp .vulnetix/sbom.cdx.json "$OUT"
      else
        # A clean secrets scan writes no SARIF. Do not fail the release for it.
        vulnetix "$SCAN" "$OUT_FLAG" "$OUT" || [ "$SCAN" = secrets ]
      fi
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - dist/
```

**Publish** each file to the generic package registry:

```yaml
publish:
  stage: publish
  image: alpine:3.20
  rules:
    - if: $CI_COMMIT_TAG
  needs:
    - job: analyze
      artifacts: true
  before_script:
    - apk add --no-cache curl ca-certificates
  script:
    - |
      for f in dist/*; do
        [ -e "$f" ] || continue
        echo "Publishing $(basename "$f")"
        curl --fail-with-body --location \
          --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
          --upload-file "$f" \
          "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${CI_COMMIT_TAG}/$(basename "$f")"
      done
```

**Release**, linking each uploaded file by URL:

```yaml
release:
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  rules:
    - if: $CI_COMMIT_TAG
  needs:
    - job: publish
  script:
    - echo "Creating release $CI_COMMIT_TAG"
  release:
    tag_name: $CI_COMMIT_TAG
    name: "Release $CI_COMMIT_TAG"
    description: "Security artifacts for $CI_COMMIT_TAG. SBOM, CBOM, AIBOM, licenses, secret scan."
    assets:
      links:
        - name: sbom.cdx.json
          url: "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${CI_COMMIT_TAG}/sbom.cdx.json"
          link_type: package
        - name: cbom.cdx.json
          url: "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${CI_COMMIT_TAG}/cbom.cdx.json"
          link_type: package
        - name: aibom.cdx.json
          url: "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${CI_COMMIT_TAG}/aibom.cdx.json"
          link_type: package
        - name: licenses.cdx.json
          url: "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${CI_COMMIT_TAG}/licenses.cdx.json"
          link_type: package
```

Notes on this pipeline:

- `link_type` is one of `other`, `runbook`, `image`, or `package`. Only `name` and `url` are required.
- The `release` job's `script` must still exist and succeed. The release itself is created from the `release:` keyword, not from the script.
- `rules: - if: $CI_COMMIT_TAG` on every job keeps the release path off branch pipelines.
- Package names and versions accept letters, digits, and `. _ - + ~ @ /`.

Full file: [`examples/gitlab/05-release.gitlab-ci.yml`](https://github.com/Vulnetix/cli/blob/main/examples/gitlab/05-release.gitlab-ci.yml).

---

## Level 6 — One Base Setup, Inherited by Every Project

The level GitHub Actions has no direct answer to. Instead of copying a `.gitlab-ci.yml` into forty repositories, publish the pipeline once and include it.

### CI/CD Components (Recommended)

[CI/CD Components](https://docs.gitlab.com/ci/components/) went generally available in **GitLab 17.0**. A component is a versioned, catalog-published pipeline unit with typed inputs.

A consuming project's entire `.gitlab-ci.yml`:

```yaml
include:
  - component: $CI_SERVER_FQDN/myorg/vulnetix-ci/scan@1.0.0
    inputs:
      stage: test
      severity: high
```

`$CI_SERVER_FQDN` resolves to your instance, so the same include works on `gitlab.com` and self-managed.

{{< callout type="warning" >}}
Pin an exact version. `@main` re-resolves on every pipeline, so a change to the component silently changes every downstream pipeline that references it.
{{< /callout >}}

The component project itself needs `templates/` at the repository root:

```
vulnetix-ci/
├── templates/
│   ├── scan.yml
│   ├── bom.yml
│   └── release.yml
├── .gitlab-ci.yml
└── README.md
```

A template is two YAML documents: a `spec:` header declaring inputs, then the configuration.

```yaml
spec:
  inputs:
    stage:
      default: test
      description: Pipeline stage the scan job runs in.
    severity:
      default: ''
      description: >-
        Fail the job when a finding meets or exceeds this severity
        (low, medium, high, critical). Empty disables the gate.
    version:
      default: v3.59.4
      description: Vulnetix CLI release to install. Pin an exact tag.
    path:
      default: .
      description: Directory to scan.
    image:
      default: alpine:3.20
      description: Base image the job runs in.
---
vulnetix-scan:
  stage: $[[ inputs.stage ]]
  image: $[[ inputs.image ]]
  variables:
    VULNETIX_VERSION: $[[ inputs.version ]]
    VULNETIX_PATH: $[[ inputs.path ]]
    VULNETIX_SEVERITY: $[[ inputs.severity ]]
  before_script:
    - apk add --no-cache bash ca-certificates curl tar || true
    - curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /usr/local/bin --version "$VULNETIX_VERSION"
    - vulnetix auth verify
  script:
    # ${VAR:+--flag "$VAR"} expands to nothing when the input is empty, so the
    # gate is opt-in without needing a second job definition.
    - vulnetix scan --path "$VULNETIX_PATH" ${VULNETIX_SEVERITY:+--severity "$VULNETIX_SEVERITY"}
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - .vulnetix/sbom.cdx.json
      - .vulnetix/sast.sarif
```

Publish it by pushing a semver tag; a `release:` job in the component's own `.gitlab-ci.yml` registers the version with the catalog.

{{< callout type="error" >}}
**An input is interpolated as a whole value.** `$[[ inputs.foo ]]` cannot be spliced into a longer string, and an **array input cannot be interpolated into a string at all**.

That is why the `bom.yml` template assigns each input to a variable and writes `rules: - if: $VULNETIX_CBOM_ENABLED == "true"` rather than testing the input inline. Getting this wrong produces a pipeline that fails to create, with an error that does not name the offending line.
{{< /callout >}}

A component project **must live on GitLab**. The CI/CD Catalog is GitLab-side only, so a component hosted on GitHub cannot be resolved by `include: component:`. Copy [`examples/gitlab/component/`](https://github.com/Vulnetix/cli/tree/main/examples/gitlab/component) into a GitLab project, or set up a pull mirror.

### `include: project:` (Fallback)

For self-managed instances below 17.0, or teams not using the catalog, `include: project:` with `extends:` and `!reference` does the same job with no catalog and no version resolution.

The template project holds a base:

```yaml
variables:
  VULNETIX_VERSION: v3.59.4
  VULNETIX_IMAGE: alpine:3.20

.vulnetix-install:
  - apk add --no-cache bash ca-certificates curl tar
  - curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /usr/local/bin --version "$VULNETIX_VERSION"
  - vulnetix auth verify

.vulnetix-base:
  image: $VULNETIX_IMAGE
  before_script:
    # !reference splices the list above in, so the install steps live in
    # exactly one place even when a job overrides before_script.
    - !reference [.vulnetix-install]
    - mkdir -p dist
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - dist/
```

and the jobs:

```yaml
stages:
  - security

variables:
  VULNETIX_SEVERITY: high

vulnetix-sca:
  extends: .vulnetix-base
  stage: security
  script:
    - vulnetix sca --severity "$VULNETIX_SEVERITY" -o dist/sbom.cdx.json

vulnetix-secrets:
  extends: .vulnetix-base
  stage: security
  script:
    - vulnetix secrets -o dist/secrets.sarif

vulnetix-license:
  extends: .vulnetix-base
  stage: security
  script:
    - vulnetix license
    - cp .vulnetix/sbom.cdx.json dist/licenses.cdx.json
```

A consuming project:

```yaml
include:
  - project: myorg/ci-templates
    ref: v1.0.0
    file:
      - /vulnetix/base.yml
      - /vulnetix/scan.yml

variables:
  VULNETIX_SEVERITY: critical   # tighten the gate for this project only

vulnetix-sca:
  stage: verify                 # or move the job to another stage
```

Two rules that save pain later:

- **`ref:` must be a tag, never `main`.** Including a branch means every downstream pipeline changes the moment someone merges to it.
- **Redeclaring a job merges into it, it does not replace it.** The `vulnetix-sca` override above changes only `stage`; the `script`, `image`, and `artifacts` from the template remain.

---

## Quality Gates

Any scan can fail the pipeline. Gates are opt-in — without a gate flag the command reports and exits `0`.

```yaml
gate:
  extends: .vulnetix
  script:
    - vulnetix scan --severity high --block-eol --block-malware --exploits active --version-lag 1 --cooldown 3
```

Available gates: `--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`. See the [Scan Command Reference]({{< relref "scan" >}}).

`--block-malware` gates on the known-malicious-package verdict **and** the in-process [malscan]({{< relref "malscan" >}}) pass over the installed dependency bytes.

To report a gate breach without blocking the merge request, use `allow_failure: true`. The job shows a warning and the pipeline still passes.

```yaml
gate:
  extends: .vulnetix
  allow_failure: true
  script:
    - vulnetix scan --severity high
```

## Custom SAST Rules

Load additional Rego rule packs from a repository. See [Custom Rule Repositories](../sast-rules/custom-rules/) for private repos and SSH access.

```yaml
sast-custom:
  extends: .vulnetix
  script:
    - vulnetix scan --severity high --rule myorg/security-rules -o dist/results.sarif
```

## Verifying These Examples

Schema validation catches unknown keywords, wrong types, and bad enums. It cannot catch a `needs:` naming a job that does not exist, an `include:` that resolves to nothing, or a `rules:` expression that never matches.

For that, lint against a real project with the [CI Lint API](https://docs.gitlab.com/api/lint/). It requires authentication and a project ID.

```sh
jq -Rs '{content: ., include_jobs: true}' < .gitlab-ci.yml \
  | curl --fail-with-body --silent --request POST \
      --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
      --header "Content-Type: application/json" \
      --url "https://gitlab.com/api/v4/projects/$PROJECT_ID/ci/lint" \
      --data @- \
  | jq '{valid, errors, warnings}'
```

Pass `"dry_run": true` to simulate pipeline creation for a ref, which resolves `include:` and `needs:` for real:

```sh
jq -Rs '{content: ., dry_run: true, dry_run_ref: "main"}' < .gitlab-ci.yml | ...
```

To lint the configuration already committed to a project, `GET` the same path. Note that the `sha` and `ref` query parameters were deprecated in GitLab 16.10 in favour of `content_ref` and `dry_run_ref`.

For local, offline checking of the examples in this repository:

```sh
bash examples/gitlab/validate.sh
```

## Troubleshooting

**Every scan reports community rate limits** — the credential variables are not reaching the job. Protected variables are only exposed to pipelines on protected branches and tags. Confirm with `vulnetix auth status`, and fail loudly rather than degrading silently:

```yaml
  script:
    - vulnetix auth status | grep -q 'environment' || { echo "no credential"; exit 1; }
```

**`Authorization: Bearer` rejected** — the ApiKey is stored under `VULNETIX_API_TOKEN`. Rename it to `VULNETIX_API_KEY`. See [Before You Start](#before-you-start).

**Artifacts vanish when the gate fails** — add `artifacts: when: always`.

**Findings never appear in the Security Dashboard** — `artifacts:reports:cyclonedx` and `artifacts:reports:sarif` require Ultimate. On Free and Premium the key is ignored without error.

**`this GitLab CI configuration is invalid` after adding a component** — an input was interpolated into a string, or an array input was interpolated at all. Both are forbidden. Assign the input to a variable first.

**A matrix leg fails on a clean scan** — the SARIF-producing scans write no file when there are no findings. Tolerate the missing file (`|| true`) or use `artifacts: when: always` with `paths:` on a directory.

**`no such file or directory: curl`** — `alpine` images ship without `curl`, `bash`, `tar`, or CA certificates. Install them in `before_script`, as every example here does.

## Keeping This Page Honest

Everything above was validated against GitLab's published CI schema and checked against the GitLab documentation for CI/CD Components, `artifacts:reports`, the generic package registry, and the CI Lint API. The examples live in [`examples/gitlab/`](https://github.com/Vulnetix/cli/tree/main/examples/gitlab) and are re-validated on every release.

Flags, default output paths, GitLab tier requirements, and deprecations change. If a snippet no longer works, [open an issue](https://github.com/Vulnetix/cli/issues/new) with the GitLab and CLI versions you are on and we will correct the documentation.
