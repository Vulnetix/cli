# Publishing & Distribution

This documentation has moved to **[docs.cli.vulnetix.com/docs/enterprise/publishing](https://docs.cli.vulnetix.com/docs/enterprise/publishing/)**.

## Distribution Channels

| Method | Automation | Installation |
|--------|-----------|-------------|
| GitHub Releases | Automated on tags | Direct binary download |
| Go Install | Automated | `go install github.com/vulnetix/cli@latest` |
| Homebrew Tap | Automated on release | `brew install vulnetix/tap/vulnetix` |
| Scoop Bucket | Automated on release | `scoop install vulnetix` |
| Nix Flake | Automated on release | `nix profile install github:Vulnetix/cli` |
| GitHub Actions | In-repo | `uses: Vulnetix/cli@v1` |

See the [full documentation](https://docs.cli.vulnetix.com/docs/enterprise/publishing/) for release processes and repository details.
