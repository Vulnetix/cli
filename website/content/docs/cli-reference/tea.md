---
title: tea
weight: 24
description: "Publish to and read from the OWASP Transparency Exchange API: discovery, catalogue search, resolution, publication, distributions, sharing, and the one-shot `tea release` for pipelines."
---

`vulnetix tea` speaks the [OWASP Transparency Exchange API](../../tea/). Two halves of one API: the consumption operations read any conformant server, ours or a supplier's, and the publication operations create the objects those consumers read.

Reading a public catalogue needs no login. Publishing does, and always targets your own organisation.

```sh
vulnetix tea products
vulnetix tea --catalogue public products --search pixi
vulnetix tea --server https://tea.example.com/v1 products
```

`--server` defaults to Vulnetix's own server and applies to every subcommand. `--catalogue` picks one of the two built-in roots instead (see below). `--json` emits raw JSON instead of a table.

## Catalogues and credentials

Vulnetix serves two catalogues, each at its own root.

| `--catalogue` | Root | What it holds | Credential |
|---|---|---|---|
| `first-party` (default) | `https://www.vulnetix.com/tea/v1.0.0` | Vulnetix's own products and components, plus whatever your organisation has published | None needed for the public records |
| `public` | `https://www.vulnetix.com/tea/public/v1.0.0` | The open source catalogue: the most starred GitHub projects | Required by the server; the CLI supplies one for you |

Without a login, the default root returns the public records only. Sign in with `vulnetix auth login` and it also returns what your organisation has published or has had shared with it.

The open source catalogue rejects anonymous requests but has no plan gate: any valid API key reads all of it, including a community-tier key. You do not need an account. When no stored credentials are found, the CLI sends the shared community credential, the same one the `vdb` commands fall back to. The rules:

- Stored credentials always win (environment variables, then the credentials files, then netrc, as for every other command).
- The community credential is only ever sent to the open source root, selected with `--catalogue public` or with `--server` set to that exact URL. It is never sent to the first party root or to any other `--server`, because on the first party root it would return the community organisation's own catalogue instead of the public records.
- With `-v`, the CLI prints `tea: using the community credential` on stderr. Nothing extra goes to stdout.
- `--server` and `--catalogue` together are an error. Choose one.
- A `401` is explained in the error: for the open source root it says whether your stored key or the built-in credential was rejected and to run `vulnetix auth login`; for any other server it says the server requires credentials.
- `--catalogue public` is read only. The publishing commands refuse it.

## Reading

| Command | What it does |
|---|---|
| `tea discover <domain\|url\|tei>` | Follow DNS to `/.well-known/tea` and report the endpoints and the root a client should use |
| `tea products` | List or search the products a server publishes |
| `tea components` | List or search the components a server publishes |
| `tea product <uuid>` | One product and its releases |
| `tea collection <release-uuid>` | The artifacts published for a release |
| `tea distribution list <component-release-uuid>` | Where a release can be obtained |
| `tea resolve <tei\|purl>` | Resolve a TEI or a Package URL to the product release it names, and the servers that serve it |

```sh
vulnetix tea discover vulnetix.com
vulnetix tea resolve tei://vulnetix.com/uuid/54e8820d-0803-5a4f-858d-88a279486564
vulnetix tea resolve pkg:github/prefix-dev/pixi
```

A TEI can be written either way, `tei://<domain>/<type>/<id>` (TEA 1.0.0) or `urn:tei:<type>:<domain>:<id>` (TEA 0.x). The CLI sends it in the spelling the server's version speaks, taken from the version in the root, so either works against either. A root that names no version, such as the stable alias `/tea/v1`, gets it as typed. A Package URL needs a 1.0.0 server.

The CLI reads TEA 1.0.0 and 0.4.0. To read the older shapes, point `--server` at `https://www.vulnetix.com/tea/v0.4.0`. Publishing always goes to `/tea/v1`, because publication is not part of any TEA version and is not served at the version path.

`tea product`, `tea collection`, `tea resolve` and `tea distribution list` read from whichever root `--catalogue` or `--server` selects.

## Finding a product or component

`tea products` and `tea components` take the same flags and print one `uuid  name` line per item.

| Flag | Meaning |
|---|---|
| `--purl <purl>` | Exact filter on a Package URL, done by the server |
| `--tei <tei>` | Exact filter on a TEI, done by the server |
| `--id-type <type>`, `--id-value <value>` | The raw pair behind the two above. The type is one of `CPE`, `TEI`, `PURL`, `COMPLIANCE_DOCUMENT`; both flags are required together |
| `--search <text>` | Case-insensitive substring match over the name and every identifier value, done by the CLI |
| `--limit <n>` | Most rows to print. Default 50 |
| `--page-token <token>` | Continue from the token an earlier call printed |
| `--all` | Follow every page. With no `--limit`, prints everything it reads |

`--purl`, `--tei`, `--id-type`/`--id-value` and `--search` are mutually exclusive. The exact filters match the whole identifier: no wildcards, no case folding.

```sh
# Find by name (client side search)
vulnetix tea --catalogue public products --search pixi

# Exact match on a PURL or a TEI (server side, fast)
vulnetix tea --catalogue public products --purl pkg:github/prefix-dev/pixi
vulnetix tea --catalogue public products --tei urn:tei:uuid:vulnetix.com:<uuid>
vulnetix tea --catalogue public components --purl pkg:github/prefix-dev/pixi

# Everything, as JSON
vulnetix tea --catalogue public products --all --json
```

### Paging

A table that stops before the end of the catalogue finishes with the token for the next page:

```text
more available; continue with --page-token tea1:50
```

```sh
vulnetix tea --catalogue public products --page-token tea1:50
```

`--json` prints one object, with the same keys as the API's page envelope:

```json
{
  "results": [{ "uuid": "...", "name": "...", "identifiers": [{ "idType": "PURL", "idValue": "pkg:github/..." }] }],
  "hasNext": true,
  "nextPageToken": "tea1:50"
}
```

`--all` reads up to 20 pages of 100. If the catalogue is longer, the CLI says so on stderr and gives the token to continue from.

### Limits

- **Name search is client side.** The server has no name or free-text search. `--search` reads pages of 100, up to 20 pages (2,000 items), and keeps the matches. If the cap stops it, stderr says `searched the first N items; use --purl or --tei for an exact match`. Search stops early once `--limit` matches are found.
- **Only GitHub PURLs.** Open source products and components carry a TEI and a `pkg:github/owner/repo` PURL, nothing else. A `pkg:npm/...` or `pkg:pypi/...` PURL finds nothing there.
- **The open source catalogue is capped.** It holds at most the top 1,500 projects by stars.
- **The default root is the public subset.** Without a login, `tea products` on the first party root shows Vulnetix's public records, not the open source catalogue. Use `--catalogue public` for that.

## Publishing

The object graph is not incidental: a product holds releases, a release has exactly one collection, and a collection holds the artifacts. Each command takes the parent it belongs to.

| Command | What it does |
|---|---|
| `tea publish product <name>` | Register a product |
| `tea publish release <product-uuid> <version>` | Publish a release |
| `tea publish collection <release-uuid>` | Publish the next collection version (an update reason is required) |
| `tea publish artifact <collection-uuid> <file>` | Register an artifact and upload its bytes |
| `tea publish list` | What your organisation has published, and who can read it |
| `tea publish delete <kind> <uuid>` | Withdraw an object |

The file's SHA-256 is computed locally and sent as `Content-Digest`. The server verifies it before storing anything, so a truncated upload fails loudly rather than being published under a checksum claiming it arrived intact.

## Distributions

An artifact is evidence *about* a release. A distribution is the release as somebody installs it. A consumer asking "how do I get this on macOS" wants the second, and an SBOM is not an answer to it.

```sh
# One download at a time
vulnetix tea distribution add $REL \
  --url https://example.com/tool-linux-amd64 \
  --description "Linux x86-64 binary" \
  --sha256 b9f62ff7...

# Or a whole release's assets, from the checksums file it already publishes
vulnetix tea distribution add $REL \
  --checksums checksums.txt \
  --base-url https://github.com/owner/repo/releases/download/v1.2.3

# A channel with nothing to fetch is a description with no URL
vulnetix tea distribution add $REL \
  --description "Homebrew: brew install owner/tap/tool"
```

Taking digests from the checksums file rather than recomputing them means the checksum a consumer reads through TEA is the same string your users verify against.

Each is idempotent on its URL, or on its description where there is no URL, so re-running a release job updates the links instead of listing each of them twice.

## Sharing

```sh
vulnetix tea share <uuid>                                   # report the policy in force
vulnetix tea share <uuid> --visibility public               # anyone, unauthenticated
vulnetix tea share <uuid> --visibility shared --org <uuid>  # named organisations
vulnetix tea share <uuid> --visibility private              # your organisation only
```

With no flags it reports what the object *declares* against what is *effectively* enforced, including what it inherits and from where. The gap between the two is where accidental disclosure hides.

An object may only ever narrow what it inherits. Trying to widen it is refused with `ACCESS_WIDENS_PARENT`. Otherwise marking a product private would guarantee nothing, because any artifact beneath it could be made public on its own.

{{< callout type="warning" >}}
Public cannot be undone. Setting an object back to private later stops new readers; it does not recall anything already fetched.
{{< /callout >}}

## `tea release`, the one for pipelines

After a release is cut, one command publishes everything about it: the product, the release, the component and its release, the collection, every artifact, and every download link.

```yaml
- name: Publish transparency data
  run: |
    vulnetix tea release dist/*.cdx.json \
      --checksums checksums.txt \
      --exclude checksums.txt \
      --channel "name=Homebrew: brew install owner/tap/tool,url=https://github.com/owner/homebrew-tap" \
      --channel "name=Scoop: scoop bucket add tool https://github.com/owner/scoop-bucket,url=https://github.com/owner/scoop-bucket" \
      --visibility public
  env:
    VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
    VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
```

Inside GitHub Actions the product name, version and asset base URL are read from the environment (`GITHUB_REPOSITORY`, `GITHUB_REF_NAME`, `GITHUB_SERVER_URL`) unless given explicitly. Each file's name decides its media type and TEA artifact type.

Every step is idempotent on the identity it derives, so re-running a failed job republishes rather than duplicating, which matters because the alternative is a duplicate that a consumer finds rather than you.

`--dry-run` prints what would be published, download links included, and exits.

{{< callout type="info" >}}
A release spans **two roots**: the product holds the evidence, the component holds the distributions. `--visibility` sets both. Setting only one by hand leaves a public SBOM describing a release nobody can reach.
{{< /callout >}}

### Flags

| Flag | Meaning |
|---|---|
| `--product` | Product name; defaults to `GITHUB_REPOSITORY` |
| `--purl` | Package URL identifying the product; defaults to `pkg:github/<product>` when the product is `owner/repo`. Set it when the product is not a GitHub repository |
| `--version` | Release version; defaults to the tag |
| `--date` | Release date (RFC3339); defaults to now |
| `--pre-release` | Mark the release as a pre-release |
| `--checksums` | sha256sum manifest whose files become distributions |
| `--base-url` | Where those files are served; derived in GitHub Actions |
| `--exclude` | File name in `--checksums` to skip (repeatable) |
| `--channel` | Install channel as `name=…[,url=…][,purl=…]` (repeatable) |
| `--visibility` | `private`, `shared` or `public`, applied to both roots |
| `--org` | Organisation UUID to share with, with `--visibility shared` |
| `--dry-run` | Print what would be published and exit |
