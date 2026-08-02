# TEA release publishing across every Vulnetix repository

Date: 2026-08-03
Status: approved, not yet implemented

## Problem

`vulnetix tea release` publishes a product, a release, its component, its
collection, every artifact and every distribution to the Transparency Exchange
API in one idempotent call. Exactly one repository uses it: `cli`, in
`.github/workflows/release.yml`, job `publish-tea`.

The other 25 repositories generate CycloneDX evidence on every push.
`vulnetix.yml` runs `sca`, `cbom` and `aibom` and uploads `sbom.cdx.json`,
`cbom.cdx.json` and `ai-bom.cdx.json` as GitHub artifacts, and then publishes
none of it to TEA. The evidence exists and is thrown away after seven days.

This spec covers publishing that evidence from every repository, on every event
that produces it: a branch push, a tag push, and a GitHub release.

## Decisions

These were settled before design and are not open questions.

**Every push publishes, not only tags.** A branch push produces BOMs, so a
branch push produces a TEA release. The transparency log gets the full history,
not only the tagged points in it.

**Non-tag runs are versioned by `git describe --tags --always`.** That yields
`v3.75.0-12-gabc1234`: it sorts after the release it descends from, states how
far past it the commit is, and resolves back to that commit. A repository with
no tags falls back to a bare short SHA. Non-tag runs are marked `--pre-release`.

**Visibility mirrors GitHub visibility.** The eight public repositories publish
with `--visibility public`. The seventeen private ones pass no visibility flag
at all, so their TEA objects stay private to the organisation and can be opened
later by hand. `tea release`'s own documentation states that public cannot be
undone, and a private repository's SBOM enumerates an internal dependency tree.

**One reusable workflow, called from each repository.** The publish logic lives
in a single `workflow_call` workflow in the public `cli` repository. Each
repository's existing `vulnetix.yml` gains a small caller job. Changing how
publishing works later means editing one file rather than twenty-five.

**Tag runs also publish distributions, and repositories may declare channels.**
On a tag, the job looks for a `checksums*` asset on the GitHub release and, if
one exists, passes `--checksums` so every published asset becomes a distribution
carrying the digest the project itself published. A `channels` input lets a
repository declare install channels that have no single file to fetch.

## Architecture

Two files per unit of work, one of them shared:

```
Vulnetix/cli/.github/workflows/tea-release.yml     (new, workflow_call)
<each repo>/.github/workflows/vulnetix.yml         (edited: +1 job, +1 trigger)
```

The reusable workflow owns everything about publishing. The caller job owns only
what differs per repository: visibility, channels, and runner. No repository
contains a copy of the publish logic.

### Why the caller lives in `vulnetix.yml` rather than a new file

`vulnetix.yml` is where the BOMs are produced. Its `analyze` job uploads them as
run-scoped artifacts, and a reusable workflow invoked from the same run can
download them with `actions/download-artifact`. A standalone workflow could not
reach those artifacts without regenerating them, which would run the SCA, CBOM
and AIBOM passes a second time on every push across twenty-five repositories.

### Trigger coverage

`vulnetix.yml` is currently `on: push` with no branch or tag filter, which fires
on branch pushes *and* tag pushes. Adding `release: types: [published]` covers
the third case: a release cut from a tag that already existed, which produces no
push event.

A conventional release fires both the tag push and the release-published event,
so the workflow runs twice for one version. This is accepted rather than
prevented. `tea release` is idempotent on the identity it derives, so the second
run republishes rather than duplicating, and the concurrency group serialises the
two so they cannot race each other's collection publish.

## The reusable workflow

`Vulnetix/cli/.github/workflows/tea-release.yml`

```yaml
name: TEA Release

on:
  workflow_call:
    inputs:
      visibility:
        description: 'public, shared, or empty to leave the objects private'
        type: string
        default: ''
      channels:
        description: 'newline-separated --channel specs, one per line'
        type: string
        default: ''
      runs-on:
        description: 'runner label expression'
        type: string
        default: 'ubuntu-latest'
      cli-version:
        description: 'Vulnetix CLI version to install; empty installs latest'
        type: string
        default: ''
```

Permissions: `contents: read` (checkout, and `gh release download` on tag runs),
`actions: read` (download the calling run's artifacts).

Concurrency: group `tea-${{ github.repository }}-${{ github.ref }}`,
`cancel-in-progress: false`.

Steps, in order:

1. **Checkout at `fetch-depth: 0`.** `git describe` needs tags, and a shallow
   checkout has none.
2. **Install the CLI** with the same `install.sh` invocation every repository's
   `vulnetix.yml` already uses. Pin to `cli-version` when given.
3. **Download the BOM artifacts** from the calling run with
   `actions/download-artifact@v6`, `pattern: '{sca,cbom,aibom}'` and
   `merge-multiple: true`, producing a flat directory. Version 6 pairs with the
   `upload-artifact@v6` that wrote them, and `pattern`/`merge-multiple` have
   existed since v4.1. Any v4-or-later download works; a v3 one does not, since
   v4 changed the artifact backend. This step is `continue-on-error: true`,
   because `pattern` with no match is an error and a repository whose scans
   produced nothing should still publish its release object.
4. **Resolve the version.** If `GITHUB_REF_TYPE` is `tag`, use `GITHUB_REF_NAME`
   verbatim, keeping any leading `v`, and do not pass `--pre-release`. Otherwise
   use `git describe --tags --always` and pass `--pre-release`.
5. **On tag runs only, fetch the checksums manifest**:
   `gh release download "$GITHUB_REF_NAME" -p 'checksums*'`, allowed to fail.
   If a readable `checksums.txt` results, add `--checksums checksums.txt
   --exclude checksums.txt`. `tea release` derives the download base URL from
   `GITHUB_SERVER_URL` and the repository, so no base URL is passed.
6. **Publish**: `vulnetix tea release <downloaded *.cdx.json>` plus the resolved
   version, the pre-release flag when applicable, the checksums arguments when
   present, one `--channel` per non-empty line of the `channels` input, and
   `--visibility` when the input is non-empty.

### Identity and credentials

The product name, the download base URL and the GitHub token all come from the
caller's context. A reusable workflow runs inside the calling repository's run,
so `GITHUB_REPOSITORY` names the calling repository and not `cli`. Product
identity therefore needs no input.

Authentication is environment-only. `VULNETIX_API_KEY` together with
`VULNETIX_ORG_ID` selects `DirectAPIKey` in `pkg/auth/credentials.go:112`, which
is what `teaClient` loads. There is no `auth login` step and therefore no
exposure to the `<org>:` API-key prefix that only `auth login` strips. Callers
pass `secrets: inherit`; every repository already defines both secrets for its
existing `vulnetix.yml` jobs.

## The caller job

Added to each repository's `vulnetix.yml`:

```yaml
  publish-tea:
    name: TEA
    needs: analyze
    continue-on-error: true
    uses: Vulnetix/cli/.github/workflows/tea-release.yml@main
    with:
      visibility: public      # present on public repositories only
    secrets: inherit
```

`continue-on-error: true` because the transparency log being unreachable is not
a reason to fail a repository's CI. The publish is a record of what was built,
not a gate on building it.

`needs: analyze` and not `needs: publish`: the existing `publish` job uploads to
Vulnetix over a different path, and the two have no ordering relationship.

## Per-repository configuration

Twenty-five repositories have a `vulnetix.yml` and receive the caller job.
`tea-spec` is excluded: its remote is `0x73746F66/transparency-exchange-api`, a
fork of a third-party specification, and it has no `vulnetix.yml`.

`visibility: public` on the eight repositories that are public on GitHub:

| Repository |
|---|
| `cli` |
| `homebrew-tap` |
| `scoop-bucket` |
| `pix-ai-coding-assistant` |
| `vdb-cyclonedx` |
| `ietf-crit-spec` |
| `transparency-exchange-api` |
| `malscan-engine` |

The remaining seventeen (`ai-firewall`, `github-runner-aws`, `mcp-server`,
`osm-submitter`, `package-firewall`, `pkgregistry`, `s3-queue-gui`, `saas`,
`vdb-api`, `vdb-api-cyclonedx-uploads`, `vdb-manager`, `vdb-sca-match`,
`vdb-sca-monitor`, `vdb-site`, `vulnetix-authentic-aws`, `vulnetix-vscode`,
`website`) pass no `visibility` input.

Runner: every caller uses the `ubuntu-latest` default. The self-hosted
`vulnetix-local` pool queues silently when nothing is started, and a publish
that never runs is a worse outcome than one that consumes GitHub minutes. The
`runs-on` input exists to override this per repository if the trade-off changes.

Channels: no repository passes any. The input is wired for future use.

## `cli` is a special case

`cli/.github/workflows/release.yml` already contains a `publish-tea` job. It is
kept as it is, for two reasons the shared workflow cannot reproduce:

- It runs `needs: [release, update-packages]`, so the Homebrew and Scoop
  channels it advertises are not published until the tap and bucket actually
  carry the version. Advertising `brew install` for a version the tap does not
  have yet is a link that 404s for machine consumers.
- It publishes using the binary that release just built, so a `tea` regression
  fails the release that introduced it rather than the next one.

`cli`'s `vulnetix.yml` still gains the caller job, gated with
`if: github.ref_type != 'tag'` so that on a tag only `release.yml` publishes.

## Failure handling

| Situation | Behaviour |
|---|---|
| No BOM artifacts produced | Download step is `continue-on-error`; `tea release` warns about an empty collection and publishes the release object. |
| No `checksums*` asset on a tag release | `gh release download` is allowed to fail; the release publishes evidence without distributions. |
| Repository has no tags | `git describe --tags --always` returns a short SHA, which is used as the version. |
| TEA server unreachable, or credentials rejected | `publish-tea` fails; `continue-on-error: true` keeps the calling workflow green. |
| Tag push and release-published both fire | Both runs publish the same identity. `tea release` is idempotent, and the concurrency group serialises them. |
| Two pushes to the same ref in quick succession | Concurrency group queues the second; `cancel-in-progress: false` means neither is dropped. |

## Testing

The reusable workflow cannot be unit tested. Verification is staged:

1. **Dry run locally.** `vulnetix tea release .vulnetix/*.cdx.json --dry-run
   --version "$(git describe --tags --always)" --pre-release --product
   Vulnetix/cli` confirms file expansion, media types and derived identity
   without publishing.
2. **One repository first.** Wire `vdb-cyclonedx`'s caller job. It is public,
   low blast radius, and produces real BOMs. Confirm with
   `vulnetix tea product <uuid>` that the release, component release and
   collection all appear.
3. **One tag run.** Cut a tag on that repository and confirm the distributions
   land, and that the tag run is not marked pre-release.
4. **Then the remaining twenty-three.**

Rollback is deleting the caller job. Nothing already published is removed by
that, and nothing published privately was ever visible outside the organisation.

## Out of scope

- Signing artifacts with cosign before publishing.
- Publishing VEX or SARIF alongside the BOMs. `tea release` accepts any file and
  types it by name, so this is a later argument change, not a redesign.
- Changing `cli/release.yml`.
- Any repository outside `~/GitHub/Vulnetix`, including the fixture and
  vulnerable-app repositories in the GitHub organisation.
