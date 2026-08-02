---
title: tea
weight: 24
description: "Publish to and read from the OWASP Transparency Exchange API: discovery, resolution, publication, distributions, sharing, and the one-shot `tea release` for pipelines."
---

`vulnetix tea` speaks the [OWASP Transparency Exchange API](../../tea/). Two halves of one API: the consumption operations read any conformant server — ours or a supplier's — and the publication operations create the objects those consumers read.

Reading a public catalogue needs no credentials. Publishing does, and always targets your own organisation.

```sh
vulnetix tea --server https://www.vulnetix.com/tea/v1 products
```

`--server` defaults to Vulnetix and applies to every subcommand. `--json` emits raw JSON instead of a table.

## Reading

| Command | What it does |
|---|---|
| `tea discover <domain\|url\|tei>` | Follow DNS to `/.well-known/tea` and report the endpoints and the root a client should use |
| `tea products` | List the products a server publishes |
| `tea product <uuid>` | One product and its releases |
| `tea collection <release-uuid>` | The artifacts published for a release |
| `tea distribution list <component-release-uuid>` | Where a release can be obtained |
| `tea resolve <tei>` | Resolve a TEI to the object it names |

```sh
vulnetix tea discover vulnetix.com
vulnetix tea resolve urn:tei:uuid:vulnetix.com:54e8820d-0803-5a4f-858d-88a279486564
```

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

Each is idempotent on its URL — or on its description where there is no URL — so re-running a release job updates the links instead of listing each of them twice.

## Sharing

```sh
vulnetix tea share <uuid>                                   # report the policy in force
vulnetix tea share <uuid> --visibility public               # anyone, unauthenticated
vulnetix tea share <uuid> --visibility shared --org <uuid>  # named organisations
vulnetix tea share <uuid> --visibility private              # your organisation only
```

With no flags it reports what the object *declares* against what is *effectively* enforced, including what it inherits and from where. The gap between the two is where accidental disclosure hides.

An object may only ever narrow what it inherits. Trying to widen it is refused with `ACCESS_WIDENS_PARENT` — otherwise marking a product private would guarantee nothing, because any artifact beneath it could be made public on its own.

{{< callout type="warning" >}}
Public cannot be undone. Setting an object back to private later stops new readers; it does not recall anything already fetched.
{{< /callout >}}

## `tea release` — the one for pipelines

After a release is cut, one command publishes everything about it: the product, the release, the component and its release, the collection, every artifact, and every download link.

```yaml
- name: Publish transparency data
  run: |
    vulnetix tea release dist/*.cdx.json \
      --checksums checksums.txt \
      --exclude checksums.txt \
      --channel "name=Homebrew — brew install owner/tap/tool,url=https://github.com/owner/homebrew-tap" \
      --channel "name=Scoop — scoop bucket add tool https://github.com/owner/scoop-bucket,url=https://github.com/owner/scoop-bucket" \
      --visibility public
  env:
    VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
    VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
```

Inside GitHub Actions the product name, version and asset base URL are read from the environment (`GITHUB_REPOSITORY`, `GITHUB_REF_NAME`, `GITHUB_SERVER_URL`) unless given explicitly. Each file's name decides its media type and TEA artifact type.

Every step is idempotent on the identity it derives, so re-running a failed job republishes rather than duplicating — which matters, because the alternative is a duplicate that a consumer finds rather than you.

`--dry-run` prints what would be published, download links included, and exits.

{{< callout type="info" >}}
A release spans **two roots**: the product holds the evidence, the component holds the distributions. `--visibility` sets both. Setting only one by hand leaves a public SBOM describing a release nobody can reach.
{{< /callout >}}

### Flags

| Flag | Meaning |
|---|---|
| `--product` | Product name; defaults to `GITHUB_REPOSITORY` |
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
