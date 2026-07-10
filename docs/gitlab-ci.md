# GitLab CI

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci](https://docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci/)**.

Runnable, schema-validated examples live in [`examples/gitlab/`](../examples/gitlab/).

## Quick Start

Set `VULNETIX_ORG_ID` and `VULNETIX_API_KEY` under **Settings → CI/CD → Variables** (Masked + Protected). Environment variables authenticate on their own; no `auth login` step is needed.

```yaml
stages:
  - security

vulnetix:
  stage: security
  image: alpine:3.20
  variables:
    VULNETIX_VERSION: v3.55.2
  before_script:
    - apk add --no-cache bash ca-certificates curl tar
    - curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /usr/local/bin --version "$VULNETIX_VERSION"
  script:
    - vulnetix auth verify
    - vulnetix scan --severity high
```

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci/) for one job per scan subcommand, publishing artifacts, `parallel:matrix`, GitLab Releases, and the CI/CD Component every project can inherit.
