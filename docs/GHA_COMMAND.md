# GHA Command Reference

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/gha-command](https://docs.cli.vulnetix.com/docs/ci-cd/gha-command/)**.

## Overview

The `vulnetix gha` subcommand provides seamless integration with GitHub Actions workflows for uploading artifacts to Vulnetix.

### Upload all workflow artifacts

```bash
vulnetix gha upload --org-id "$VULNETIX_ORG_ID" --json
```

### Check upload status

```bash
vulnetix gha status --txnid <transaction-id>
vulnetix gha status --uuid <artifact-uuid>
```

### Workflow example

```yaml
permissions:
  contents: read
  actions: read

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - name: Upload artifacts to Vulnetix
        uses: Vulnetix/cli@v3.59.3
        with:
          task: gha
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
        env:
          GITHUB_TOKEN: ${{ github.token }}
```

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/gha-command/) for detailed usage and examples.
