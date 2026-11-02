# Vulnetix CLI Documentation

Documentation has moved to **[docs.vulnetix.com/cli/get-started/overview](https://docs.vulnetix.com/cli/get-started/overview/)**.

Their source is the [Vulnetix/platform-docs](https://github.com/Vulnetix/platform-docs) repository.

[`generated/`](generated/) holds pages this repository renders from its own catalogs, because the
platform docs generators read them from here:

| Path | Written by | Read by (platform-docs) |
|---|---|---|
| `generated/github-rules/` | `GHRULES_UPDATE=1 go test ./internal/ghtasks/` | `migration/generators/github-rules.mjs` |
| `generated/ci-cd/third-party-scanners.md` | `just gen-gha-setup` | `migration/generators/gha-scanners.mjs` |
| `generated/aibom/`, `generated/cbom/` | `just gen-aibom`, `just gen-cbom` | `migration/generators/sbom-catalog-pages.py` |

The hand-written SAST rule prose is in [`internal/sast/docs/`](../internal/sast/docs/), read by
`migration/generators/sast-rules.mjs`.

In-repository references:

| Page | Covers |
|---|---|
| [`github-publishing.md`](github-publishing.md) | GitHub-compatible SARIF and `vulnetix gha publish` |
| [`platform-iac.md`](platform-iac.md) | What a Platform IaC document is, and where the CLI finds them |
| [`github-actions.md`](github-actions.md) | The root action and the generated subdirectory actions |
