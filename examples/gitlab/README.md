# GitLab CI examples

Every YAML file here is validated against GitLab's own CI schema before it ships, and the documentation at
[docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci](https://docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci/) quotes these files
directly. If you change one, run the validator.

```sh
bash examples/gitlab/validate.sh
```

## Layout

| Path | Level | What it shows |
|------|-------|---------------|
| `01-quickstart.gitlab-ci.yml` | 1 | Smallest working pipeline: install, verify, scan |
| `02-subcommands.gitlab-ci.yml` | 2 | One job per scan subcommand |
| `03-publish-artifacts.gitlab-ci.yml` | 3 | `artifacts:paths` and `artifacts:reports` per command |
| `04-parallel-matrix.gitlab-ci.yml` | 4 | `parallel:matrix` across subcommands |
| `05-release.gitlab-ci.yml` | 5 | Generic package registry, then a GitLab Release |
| `component/` | 6 | A CI/CD Component, the modern reuse mechanism |
| `templates/` | 6 | `include: project:` fallback for GitLab < 17.0 |

## Required CI/CD variables

Set both under **Settings → CI/CD → Variables**, Masked and Protected.

| Variable | Value |
|----------|-------|
| `VULNETIX_ORG_ID` | Organization UUID |
| `VULNETIX_API_KEY` | ApiKey hex digest |

Both are maskable: a value need only be a single line, contain no spaces, and be at least 8 characters. A UUID
qualifies.

Do **not** name the ApiKey `VULNETIX_API_TOKEN`. That variable holds a *Bearer token* and sits at the top of the
credential precedence chain, so an ApiKey stored under that name is sent as a bearer credential and rejected.

None of these examples run `vulnetix auth login`. Environment variables authenticate on their own and persist
nothing; a login step on an ephemeral runner writes a plaintext credentials file into the workspace for no benefit.

## What the validator does and does not check

`validate.sh` normalises each file (splitting the component `spec:` header, flattening `!reference` tags) and runs
it through GitLab's published JSON schema. That catches unknown keywords, wrong types, and bad enum values.

It cannot catch semantic errors: a `needs:` naming a job that does not exist, an `include:` that resolves to
nothing, or a `rules:` expression that never matches. For those, lint against a real project:

```sh
jq -Rs '{content: ., include_jobs: true}' < examples/gitlab/01-quickstart.gitlab-ci.yml \
  | curl --fail-with-body --silent --request POST \
      --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
      --header "Content-Type: application/json" \
      --url "https://gitlab.com/api/v4/projects/$PROJECT_ID/ci/lint" \
      --data @- \
  | jq '{valid, errors, warnings}'
```

## Tier requirements

`artifacts:reports:cyclonedx` and `artifacts:reports:sarif` both require **GitLab Ultimate**. On Free and Premium
they are silently ignored — the pipeline still passes, the findings simply never reach the Security Dashboard. Every
example therefore also declares `artifacts:paths`, which works on every tier.
