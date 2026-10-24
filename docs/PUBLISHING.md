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
| GitHub Actions | In-repo | `uses: Vulnetix/cli@v3.59.4` (pin an exact tag; no moving major tag exists) |

See the [full documentation](https://docs.cli.vulnetix.com/docs/enterprise/publishing/) for release processes and repository details.

## Build provenance and TEA

Every release carries signed SLSA v1 provenance, `provenance.sigstore.json`,
and is published to the Transparency Exchange API. The `provenance` job calls
`.github/workflows/slsa-provenance.yml`, which belai's release workflow calls
too. It signs one statement whose subjects are every line of the release's
`checksums.txt` plus `checksums.txt` itself, verifies the bundle, and uploads it
to the release. `publish-tea` then attaches it to the TEA release as an
attestation, beside the SBOM and the distributions.

Both repositories are public, so the bundle carries a Rekor entry. The signing
identity is the reusable workflow, not the caller. The statement is signed
provenance of the build workflow on this organisation's runners (the
`runner_environment` field says so); it is not an isolated builder, so it is not
SLSA Build L3.

A provenance failure does not stop the TEA publish: the release is published
without the bundle and the job warns. A public TEA product cannot be
unpublished, so preview a release first. Do not re-dispatch an existing tag for
that: it rebuilds the binaries and replaces the release assets. Run the CLI
locally against the release's own checksums instead; `--dry-run` publishes
nothing:

```sh
gh release download vX.Y.Z --repo Vulnetix/cli --pattern checksums.txt
vulnetix tea release vulnetix.cdx.json provenance.sigstore.json --dry-run \
  --version vX.Y.Z --product Vulnetix/cli \
  --checksums checksums.txt --exclude checksums.txt \
  --base-url https://github.com/Vulnetix/cli/releases/download/vX.Y.Z
```

Verify a downloaded binary against the bundle (use `Vulnetix/belai` for belai):

```sh
gh release download vX.Y.Z --repo Vulnetix/cli --pattern provenance.sigstore.json --pattern 'vulnetix-linux-amd64'
cosign verify-blob-attestation \
  --bundle provenance.sigstore.json --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/Vulnetix/cli/\.github/workflows/slsa-provenance\.yml@' \
  --digest "$(sha256sum vulnetix-linux-amd64 | cut -d' ' -f1)" --digestAlg sha256
```

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
