# Publishing & Distribution

This documentation has moved to **[docs.cli.vulnetix.com/docs/enterprise/publishing](https://docs.cli.vulnetix.com/docs/enterprise/publishing/)**.

## Distribution Channels

| Method | Automation | Installation |
|--------|-----------|-------------|
| GitHub Releases | Automated on tags | Direct binary download |
| Go Install | Automated | `go install github.com/vulnetix/cli/v3@latest` |
| Homebrew Tap | Automated on release | `brew install vulnetix/tap/vulnetix` |
| Scoop Bucket | Automated on release | `scoop install vulnetix` |
| Nix Flake | Automated on release | `nix profile install github:Vulnetix/cli` |
| GitHub Actions | In-repo | `uses: Vulnetix/cli@v3.59.3` (pin an exact tag; no moving major tag exists) |

See the [full documentation](https://docs.cli.vulnetix.com/docs/enterprise/publishing/) for release processes and repository details.

## Recovering a tag with no Release

`auto-version.yml` creates the tag and then dispatches `release.yml`, because a
tag pushed with `GITHUB_TOKEN` does not itself trigger another workflow. If the
`release` job then fails — most often *"The job was not acquired by Runner of
type hosted"*, a GitHub runner-allocation flake — the tag exists but no Release
is published, and `test-go-install` and `update-packages` are skipped. Homebrew,
Scoop and Nix stay on the previous version.

Re-dispatch for that exact tag. The "Create or update Release" step is
idempotent: it creates the tag if missing, and uploads with `--clobber` when the
release already exists.

```sh
gh workflow run release.yml -f version=vX.Y.Z
gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId -q '.[0].databaseId')"
gh release view vX.Y.Z --json assets -q '.assets[].name'
```

If only the package-manager fan-out failed, mirror it locally instead — this is
what the `update-packages` job does:

```sh
just update-packages vX.Y.Z
```

Every job now carries a `timeout-minutes`, so a stuck runner fails in minutes
rather than blocking a release for forty.
