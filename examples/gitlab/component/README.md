# Vulnetix CI/CD Component

A working [CI/CD Component](https://docs.gitlab.com/ci/components/) that gives every project in your organization
the same Vulnetix setup from a four-line include.

CI/CD Components went generally available in **GitLab 17.0** (experimental in 16.0). For older self-managed
instances, use the `include: project:` pattern in [`../templates/`](../templates/) instead.

## This directory is not the component

A component must live in **its own GitLab project**, with `templates/` at the repository root. The CI/CD Catalog is
GitLab-side only: a component hosted on GitHub cannot be resolved by `include: component:`. To use this, copy the
directory into a new GitLab project (or set up a pull mirror), then tag it.

```
your-gitlab-project/
├── templates/
│   ├── scan.yml
│   ├── bom.yml
│   └── release.yml
├── .gitlab-ci.yml      # lints and integration-tests the templates
└── README.md
```

Publish it by pushing a semver tag. The `create-release` job in `.gitlab-ci.yml` registers the version with the
catalog.

```sh
git tag 1.0.0 && git push origin 1.0.0
```

## Using it

```yaml
include:
  - component: $CI_SERVER_FQDN/myorg/vulnetix-ci/scan@1.0.0
    inputs:
      stage: test
      severity: high
```

`$CI_SERVER_FQDN` resolves to your instance, so the same include works on `gitlab.com` and on a self-managed host.

Pin an exact version. `@main` re-resolves on every pipeline, which means a change to the component silently changes
every downstream pipeline that references it.

## Templates

### `scan.yml`

One job, `vulnetix-scan`, running `vulnetix scan` (SCA + SAST + secrets + licenses).

| Input | Default | Description |
|-------|---------|-------------|
| `stage` | `test` | Stage the job runs in |
| `severity` | `''` | Fail on findings at or above this severity. Empty disables the gate |
| `version` | `v3.55.2` | CLI release to install |
| `path` | `.` | Directory to scan |
| `image` | `alpine:3.20` | Base image |

### `bom.yml`

Two jobs, `vulnetix-cbom` and `vulnetix-aibom`, each gated by an input.

| Input | Default | Description |
|-------|---------|-------------|
| `stage` | `test` | Stage the jobs run in |
| `cbom` | `'true'` | Emit a Cryptography Bill of Materials |
| `aibom` | `'true'` | Emit an AI Bill of Materials |
| `fail_on` | `none` | cbom only: `none`, `quantum-vulnerable`, or `deprecated` |
| `version`, `path`, `image` | as above | |

### `release.yml`

Two jobs, `vulnetix-publish` and `vulnetix-release`. Uploads the artifacts to the generic package registry, then
attaches them to a GitLab Release as asset links.

| Input | Default | Description |
|-------|---------|-------------|
| `publish_stage` | `publish` | Stage for the package upload |
| `release_stage` | `release` | Stage for the release |
| `package_name` | `vulnetix-artifacts` | Generic package registry package name |
| `artifact_dir` | `dist` | Directory holding artifacts from earlier jobs |
| `needs_job` | `vulnetix-scan` | Job whose artifacts are downloaded |

## Two constraints worth knowing

**An input is interpolated as a whole value.** `$[[ inputs.foo ]]` cannot be spliced into a longer string, and an
array input cannot be interpolated into a string at all. That is why `bom.yml` assigns each input to a variable and
writes `rules: - if: $VULNETIX_CBOM_ENABLED == "true"` rather than testing the input directly.

**`release:assets:links` takes a URL, not a path.** There is no GitLab equivalent of `gh release upload <file>`.
Artifacts must be published somewhere addressable first; `release.yml` uses the generic package registry with
`CI_JOB_TOKEN`.

## Credentials

The component reads `VULNETIX_ORG_ID` and `VULNETIX_API_KEY` from the consuming project's CI/CD variables. It never
runs `vulnetix auth login`. See [Authentication in CI/CD](https://docs.cli.vulnetix.com/docs/authentication/ci-cd/).
