# CLI Reference

This documentation has moved to **[docs.cli.vulnetix.com/docs/cli-reference](https://docs.cli.vulnetix.com/docs/cli-reference/)**.

## Commands

| Command | Description |
|---------|-------------|
| `vulnetix` | Authentication healthcheck (default) |
| `vulnetix auth login` | Authenticate with Vulnetix |
| `vulnetix auth status` | Show authentication state |
| `vulnetix auth verify` | Verify stored credentials |
| `vulnetix auth logout` | Remove stored credentials |
| `vulnetix upload --file <path>` | Upload a security artifact (SBOM, SARIF, VEX, CSAF) |
| `vulnetix gha upload` | Upload GitHub Actions workflow artifacts |
| `vulnetix gha status` | Check artifact processing status |
| `vulnetix scan` | Auto-discover and scan manifests for vulnerabilities |
| `vulnetix vdb <subcommand>` | Vulnerability Database queries |
| `vulnetix version` | Print version and check for updates |
| `vulnetix update` | Update CLI to latest release |
| `vulnetix completion` | Generate shell autocompletion scripts |

See the [full CLI reference](https://docs.cli.vulnetix.com/docs/cli-reference/) for all flags, options, and usage patterns.
