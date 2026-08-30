---
title: "BOM Command Reference"
weight: 5
description: "Read, validate, diff, merge, query and enrich SBOM documents — including ones this CLI did not produce."
---

The `bom` command consumes SBOM documents. Where [`cdx`](../cdx/) (alias `sbom`)
**generates** a CycloneDX document from a working tree, `bom` **reads** documents
back in — including ones produced by Syft, Trivy, cdxgen, BuildKit or anything
else.

Two nouns, deliberately: `vulnetix sbom` produces, `vulnetix bom` inspects.

## Formats it reads

| Format | Versions | Notes |
|--------|----------|-------|
| CycloneDX JSON | 1.0 – 1.7 | 1.0/1.1 predate `bomFormat` and are detected by `specVersion` plus a components array |
| SPDX JSON | 2.2, 2.3 | Package identity comes from `externalRefs` purl locators |
| in-toto attestation | DSSE or bare statement | The SBOM is unwrapped from `predicate` |

The attestation case is the one a plain `bomFormat` check misses entirely, and
it is the shape Syft and BuildKit emit for container SBOMs:

```bash
# All three work identically
vulnetix bom import sbom.cdx.json
vulnetix bom import sbom.spdx.json
vulnetix bom import image.att.intoto.jsonl
```

Unwrapping is parsing, not trust. Reading a document never implies believing
it — see [`--verify-attestation`](#verifying-before-trusting).

## One canonical model

Everything parsed becomes a CycloneDX document in memory. SPDX in, CycloneDX
model out. That is why an SPDX file and a CycloneDX file diff against each
other, validate the same way, and appear side by side in a corpus query.

Normalisation is lossy by construction, so what the document originally was is
stamped into `metadata.properties`:

| Property | Meaning |
|----------|---------|
| `vulnetix:bom/source-format` | `cyclonedx` or `spdx` |
| `vulnetix:bom/source-spec-version` | e.g. `SPDX-2.3` |
| `vulnetix:bom/source-envelope` | `dsse`, `in-toto`, or absent |
| `vulnetix:bom/source-digest` | SHA-256 of the exact bytes supplied |
| `vulnetix:bom/source-path` | Where it was read from |

## Subcommands

### Single document

```bash
vulnetix bom import <file|->      # parse and report; --out re-emits as CycloneDX
vulnetix bom validate <file>      # structure plus per-field completeness
vulnetix bom diff <before> <after>
vulnetix bom merge <file> <file...>
vulnetix bom tree <file>
vulnetix bom enrich <file> --out <file>
```

### Across a corpus

```bash
vulnetix bom ls --from ./sboms/
vulnetix bom where <package> --from ./sboms/
vulnetix bom skew --from ./sboms/
vulnetix bom search <query> --from ./sboms/
```

---

## bom import

Parse a document and report its inventory. Pass `-` to read stdin.

```bash
vulnetix bom import sbom.spdx.json
vulnetix bom import sbom.spdx.json --out sbom.cdx.json    # convert
syft . -o spdx-json | vulnetix bom import - --out sbom.cdx.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | - | Write the normalised CycloneDX document here |
| `-o, --output` | `pretty` | `pretty` (alias `table`), `json` |
| `--verify-attestation` | `false` | Verify the signature before trusting the document |

Plus the [deployment-context flags](#deployment-context) and the
[verification flags](../attest/#flags).

### Verifying before trusting

Verification is opt-in. Reading a document is not believing it, and most SBOMs
are unsigned — making every parse a trust decision would break the common case.

```bash
vulnetix bom import image.att.intoto.jsonl --verify-attestation
vulnetix bom import sbom.cdx.json --verify-attestation --strict
```

A failed check aborts the import. Returning a document alongside a failed
verification would leave the caller holding something it has no way to know it
should not trust. See [`attest verify`](../attest/) for the checks and their
defaults.

---

## bom validate

Two independent checks: can the document be parsed at its declared spec version,
and does it actually carry the fields a consumer needs.

```bash
vulnetix bom validate sbom.cdx.json
vulnetix bom validate sbom.cdx.json --min-score 70
```

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `pretty` | `pretty`, `json` |
| `--min-score` | `0` | Exit `1` when the completeness score falls below this (`0` disables) |

The output is a per-field breakdown, not a badge:

```
[OK]    Unique document identifier               1/1
[OK]    Creation timestamp                       1/1
[OK]    Dependency graph                         1/1
[OK]    Component version                        3/3
[WARN]  Cryptographic hash                       1/3  missing from 2 of 3
[WARN]  Supplier                                 1/3  missing from 2 of 3
Completeness score: 88/100
```

The score exists to sort documents against each other. The **breakdown** is the
actionable part — a single number would hide which field is missing, and the
missing field is what you go and fix. Framework-branded scoring (NTIA, CISA) is
deliberately absent; the mechanical field check is not.

---

## bom diff

Compare two documents. This is the change-review gate.

```bash
vulnetix bom diff before.cdx.json after.cdx.json
vulnetix bom diff v1.cdx.json v2.spdx.json -o markdown
vulnetix bom diff base.cdx.json head.cdx.json --fail-on vuln-added
```

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `pretty` | `pretty`, `json`, `markdown` |
| `--fail-on` | `none` | `none`, `any`, `added`, `removed`, `downgraded`, `vuln-added`, `license-regression` (comma-separated) |

Either side may be CycloneDX or SPDX — comparing across formats is supported and
useful, because both normalise to the same model.

```
Change           Component             Version               Licence         Direct
removed          left-pad              1.3.0                 WTFPL           transitive
downgraded       express               4.18.2 → 4.18.1       —               direct
license-changed  express               4.18.2 → 4.18.1       MIT → Apache-2.0  direct
upgraded         lodash                4.17.20 → 4.17.21     —               direct
added            chalk                 5.3.0                 MIT             direct

1 added · 1 removed · 1 upgraded · 1 downgraded · 1 licence · 1 vulns in · 1 vulns out
```

**Matching** follows the cascade the CycloneDX merge already uses: versionless
purl, then `bom-ref`, then `name@version`. That is what makes a dependency bump
read as one upgrade rather than an add plus a remove, even when the two
documents came from different tools.

**Version movement is ordered semantically**, so an accidental `1.2.10 → 1.2.9`
reads as a *downgrade* rather than an undifferentiated change. A version pair
semver cannot order — a git sha replacing a tag, a distro epoch — is reported as
movement without a direction rather than guessed at.

---

## bom merge

Combine documents into one CycloneDX file. Inputs may mix formats.

```bash
vulnetix bom merge app.cdx.json image.spdx.json --out combined.cdx.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | stdout | Write the merged document here |
| `-o, --output` | `pretty` | `pretty`, `json` |

Purl-keyed and non-destructive: components in an earlier document are kept
verbatim, later documents fill gaps and contribute new components, tools,
vulnerabilities and dependency edges.

---

## bom tree

The CycloneDX `dependencies` array is a flat edge set — the right shape to
store, the wrong shape to read. This walks it.

```bash
vulnetix bom tree sbom.cdx.json
vulnetix bom tree sbom.cdx.json --component lodash --invert
vulnetix bom tree sbom.cdx.json --depth 3
```

| Flag | Default | Description |
|------|---------|-------------|
| `--component` | document subject | Root the tree here (purl, bom-ref, name, or substring) |
| `--invert` | `false` | Show what depends on the component instead of what it depends on |
| `--depth` | `0` | Maximum depth (`0` = unlimited) |
| `-o, --output` | `pretty` | `pretty`, `json` |

`--invert` is the direction triage actually asks — *what pulls this in*:

```
left-pad@1.3.0
└── express@4.18.2
    └── payment-service@2.3.0
```

Cycles are marked and elided rather than followed. Go modules and Maven both
permit them, so this is a real input rather than a hypothetical.

---

## Corpus queries

A repository scan holds one document. These answer questions about a *set* of
them — which services carry a package, where a component sits at four different
versions. Point `--from` at files, directories or globs.

```bash
--from ./sboms/            # a directory
--from 'releases/*.json'   # a glob
--from a.cdx.json --from b.spdx.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--from` | - | File, directory or glob to read (repeatable, **required**) |
| `--recursive` | `false` | Walk directories to any depth |
| `--depth` | `0` | Maximum directory depth when recursive |
| `-o, --output` | `pretty` | `pretty`, `json` |

There is no store and no server. Documents are collected and indexed in memory
per invocation, because the questions are about files already on disk. Object
storage is deliberately absent — ingesting a bucket of a thousand SBOMs is a
server's job, and the [deployment labels](#deployment-context) exist so the
backend can answer at that scale.

A document that could not be read is **always** surfaced. Silently answering
from fewer documents than you pointed at is how "no results" becomes a wrong
answer.

### bom ls

```bash
vulnetix bom ls --from ./sboms/
```

```
Document              Subject           Version  Format          Components  Vulns  Deployment
payments.cdx.json     payment-service   2.4.0    cyclonedx 1.6            3      1  cluster=prod-eu
checkout.cdx.json     checkout-service  1.9.0    cyclonedx 1.6            2      0  cluster=prod-us
docs.spdx.json        docs-site         3.0.0    spdx SPDX-2.3            1      0  —
```

### bom where

Blast radius: which documents contain a package, at what version, and whether
the dependency is **direct** there — which is where the version can actually be
changed.

```bash
vulnetix bom where lodash --from ./sboms/
vulnetix bom where pkg:golang/github.com/hashicorp/golang-lru --from ./sboms/
vulnetix bom where log4j-core --from ./sboms/ --fail-on-found
```

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on-found` | `false` | Exit `1` when the package is present at all |

Accepts a purl (with or without a version), a bare name, or a substring.

Directness is reported as **unknown**, never false, when a document has no
dependency graph to answer from. A confident wrong answer about where a package
can be fixed is worse than an admitted gap.

### bom skew

Packages present at more than one version across the corpus — usually four
upgrades nobody sequenced rather than four deliberate pins.

```bash
vulnetix bom skew --from ./sboms/
vulnetix bom skew --from ./sboms/ --min-versions 3
vulnetix bom skew --from ./sboms/ --fail-on-count 0
```

| Flag | Default | Description |
|------|---------|-------------|
| `--min-versions` | `2` | Only report packages at this many versions or more |
| `--fail-on-count` | `-1` | Exit `1` above this many skewed packages (`-1` disables) |

Most-divergent first, with a count of how many documents carry each version as a
direct dependency.

### bom search

Four facets, counted and limited independently, so a query matching a thousand
components still shows the one document it also matched.

```bash
vulnetix bom search lodash --from ./sboms/
vulnetix bom search log4shell --from ./sboms/
vulnetix bom search AGPL --from ./sboms/ --limit 50
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `25` | Maximum results per facet |

Vulnerabilities match on **identifier and description** — "log4shell" is how
people refer to CVE-2021-44228, and an id-only search finds nothing for it.

Minimum query length is 2; a single character matches most of a corpus, which is
not a search result.

---

## bom enrich

Take an SBOM somebody else produced and give it back better: licences resolved,
vulnerabilities attached, VEX applied — and still a standards-valid CycloneDX
document rather than a Vulnetix report.

```bash
vulnetix bom enrich sbom.spdx.json --out enriched.cdx.json
vulnetix bom enrich sbom.cdx.json --out enriched.cdx.json --vex vendor.openvex.json
vulnetix bom enrich sbom.cdx.json --out enriched.cdx.json --keep-original --sign
```

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | - | **Required.** Write the enriched document here |
| `--vex` | - | VEX file or directory to apply (repeatable) |
| `--no-licenses` | `false` | Skip licence resolution |
| `--no-vulns` | `false` | Skip the vulnerability lookup |
| `--no-vex` | `false` | Skip VEX application |
| `--keep-original` | `false` | Write the input document beside the output |
| `--sign` | `false` | Sign the result with this machine's own OIDC identity |
| `-o, --output` | `pretty` | `pretty`, `json` |

Three passes, each independently skippable:

- **licences** — components whose licence is absent or `NOASSERTION` are
  resolved through deps.dev, the ecosystem registries and GitHub: the same
  resolvers `vulnetix license` uses, so an enriched document agrees with a scan
  of the same tree. A component that already states a licence is left alone —
  the document's own claim is better evidence than a registry lookup.
- **vulns** — known vulnerabilities from the VDB as CycloneDX `vulnerabilities`
  entries, with ratings, EPSS and KEV context. Best-effort: an unreachable or
  unauthenticated VDB degrades to a warning rather than failing the command.
- **vex** — statements from `--vex` folded into each entry's `analysis` block.

A companion OpenVEX file is written beside the output when VEX was applied, for
consumers that want the statements separately.

### Fidelity and attribution

Enrichment rewrites a document somebody else may have signed. Two properties are
preserved:

**Fidelity.** The input's digest is always recorded on the output as
`vulnetix:bom/enriched-from`, and `--keep-original` writes the input beside it.
A transformation that cannot be traced back is indistinguishable from a
substitution.

**Attribution.** `--sign` signs with **this** machine's identity, because this
machine made these claims. Any signature on the input is preserved as
`vulnetix:bom/original-signature` rather than discarded — it attests the input,
which is still a fact worth carrying. The VDB request also names the input's own
generator, so the backend records "syft found these packages, Vulnetix enriched
them" rather than claiming the discovery.

### Attribution when enriching

Enriching a document does not make us its author, and the output says so.

CycloneDX describes `metadata.tools` as "the tool(s) used in the **creation,
enrichment, and validation** of the BOM", so an enricher belongs in that list —
appended, after whoever created the document. `metadata.manufacturer` and
`metadata.authors` say who *created* it, and those are left exactly as found.

Enriching a Syft SBOM produces:

```json
"metadata": {
  "manufacturer": { "name": "Anchore" },
  "lifecycles": [{ "phase": "post-build" }],
  "tools": { "components": [
    { "name": "syft", "version": "1.2.3", "group": "Anchore" },
    { "name": "vulnetix-bom-enrich", "version": "3.98.0", "group": "Vulnetix" }
  ]}
}
```

Because the result is written to a new path it is a new artefact, so it gets a
fresh `serialNumber` and records the one it came from as
`vulnetix:bom/derived-from`. Enriching the same document twice leaves **one**
entry per tool — `metadata.tools.components` is a unique set from CycloneDX 1.5,
so a duplicate would make the document fail its own schema.

[`bom import`](#bom-import) behaves the same way when converting SPDX: the SPDX
document's creators become the CycloneDX `tools` and `authors` entries and stay
there, `vulnetix-bom-import` is appended, and no manufacturer is claimed. The
SPDX `documentNamespace` becomes the `serialNumber`, normalised to the `urn:uuid`
form the schema requires from 1.6 — deterministically, so the same input file
always converts to the same identity.

The full model is described under
[BOM authoring identity](../scan/#bom-authoring-identity).

---

## Deployment context

Registered on `bom import`, on [`cdx`](../cdx/), on `upload`, and family-wide on
the [scan family](../scan/).

| Flag | Description |
|------|-------------|
| `--project` | What the artefact is and who owns it |
| `--cluster` | Where it is deployed |
| `--namespace` | Namespace within the cluster |
| `--environment` | Deployment stage, e.g. `production` |
| `--tag` | Additional `key=value` label (repeatable) |

Cluster and project are **separate, orthogonal** dimensions. A scan belongs to
cluster `prod-eu` **and** project `payment-service` at the same time; collapsing
them into one field makes either query impossible to answer.

| Dimension | Answers | Cardinality | Owned by |
|-----------|---------|-------------|----------|
| `cluster` / `namespace` / `environment` | Where is it deployed? | Low | Platform team |
| `project` | What is it, who owns it? | High | Dev teams |

Unset values are inferred from `VULNETIX_CLUSTER`, `VULNETIX_PROJECT`,
`VULNETIX_NAMESPACE`, `VULNETIX_ENVIRONMENT`, `CI_ENVIRONMENT_NAME`,
`POD_NAMESPACE` and `CI_PROJECT_NAME`. **Nothing is inferred from a branch
name** — "main means production" is a convention this CLI has no business
assuming, and a wrong environment label is worse than an absent one.

The labels land in `metadata.properties` as `vulnetix:deployment/*`, in
`.vulnetix/memory.yaml`, and in the `cli.*` upload envelope — so the backend can
answer fleet-scale questions a single repository cannot.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | A `--fail-on` gate breached, a document failed validation or verification |
| `2` | Usage or configuration error |

## See also

- [`cdx`](../cdx/) — generate a CycloneDX document
- [`vex`](../vex/) — read and apply VEX statements
- [`attest`](../attest/) — verify signatures and provenance
- [`license`](../license/) — licence policy and exceptions
