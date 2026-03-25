# GitLab CI

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci](https://docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci/)**.

## Quick Start

```yaml
vulnetix:
  stage: test
  image: golang:latest
  script:
    - go install github.com/vulnetix/cli@latest
    - vulnetix auth login --method apikey --org-id "$VULNETIX_ORG_ID" --secret "$VULNETIX_API_KEY" --store project
    - vulnetix
  variables:
    VULNETIX_ORG_ID: $VULNETIX_ORG_ID
    VULNETIX_API_KEY: $VULNETIX_API_KEY
```

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/gitlab-ci/) for pipeline templates and advanced configuration.
