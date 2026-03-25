# Bitbucket Pipelines

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/bitbucket](https://docs.cli.vulnetix.com/docs/ci-cd/bitbucket/)**.

## Quick Start

```yaml
pipelines:
  default:
    - step:
        name: Vulnetix Security Scan
        image: golang:latest
        script:
          - go install github.com/vulnetix/cli@latest
          - vulnetix auth login --method apikey --org-id "$VULNETIX_ORG_ID" --secret "$VULNETIX_API_KEY" --store project
          - vulnetix
```

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/bitbucket/) for pipeline templates and advanced configuration.
