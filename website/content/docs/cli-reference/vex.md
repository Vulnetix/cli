---
title: "VEX Command Reference"
weight: 6
description: "Read, validate, merge and apply VEX statements — OpenVEX, CycloneDX VEX and CSAF VEX — including ones this CLI did not write."
---

The `vex` command consumes VEX documents. The CLI has always *generated* VEX from
its own triage decisions ([`triage`](../../cli-reference/#vulnetix-triage),
`reconcile`, `jail`); `vex` reads them back in, and reads anyone else's.

That is the case VEX exists for: an upstream publishing *"this CVE does not
affect the configuration we ship"* reaching your scan.

## Formats

| Format | Version | Notes |
|--------|---------|-------|
| OpenVEX | 0.2.0 | The native format; `vex merge` emits it |
| CycloneDX VEX | 1.4+ | Read from `vulnerabilities[].analysis` |
| CSAF VEX | 2.0 | `document.category: csaf_vex` |

All three normalise to one statement model, so matching and application are
written once rather than once per format. Each hides the same assertion
somewhere different:

- **CSAF** scatters the justification into a `flags` entry and the prose into a
  `threats` entry, both keyed by an opaque `product_id` whose purl is defined in
  a nested product tree elsewhere in the document.
- **CycloneDX** puts it in `analysis` — and an entry with **no** analysis block
  is a *finding*, not an assertion. Reading those as VEX would turn every SBOM's
  vulnerability list into statements asserting nothing.

## Matching

Not exact equality on `(vulnerability, purl)`. Exact equality is why VEX so
often appears to do nothing, and it fails **silently** — the statement is simply
never applied, with no error:

| Case | Exact equality | Here |
|------|----------------|------|
| Statement for `pkg:npm/foo@1.2.3`, scan finds `1.2.4` | misses | matched if the statement scopes a range |
| Statement names a package with **no** version | misses everything | covers **every** version — which is what it means |
| Identifier written as `https://nvd.nist.gov/.../CVE-2021-44228` | never equals `CVE-2021-44228` | reduced to the bare id first |
| Finding reported as `GHSA-…`, statement written against the CVE | misses | matched via aliases |

The cascade, most-specific first:

| Basis | Meaning |
|-------|---------|
| `exact-purl` | The statement names this exact purl, version included |
| `purl-version-listed` | The version appears in the statement's version list |
| `purl-version-range` | The version falls inside a range the statement scopes |
| `subcomponent` | Named as a subcomponent of the product |
| `name-version` | Neither side carried a purl |
| `purl-any-version` | The package with no version scope |
| `document-wide` | The statement names no product at all |

Ties break on the newer timestamp — VEX is a running assertion, and a later
statement supersedes an earlier one about the same thing.

Every match records **why** it matched and **which document** asserted it.

---

## vex apply

Apply statements to an SBOM.

```bash
vulnetix vex apply --vex vendor.openvex.json --bom sbom.cdx.json
vulnetix vex apply --vex ./vex/ --bom sbom.cdx.json --out annotated.cdx.json
vulnetix vex apply --vex ./vex/ --bom sbom.cdx.json --fail-on-effective 0
```

| Flag | Default | Description |
|------|---------|-------------|
| `--vex` | - | VEX file or directory (repeatable, **required**) |
| `--bom` | - | **Required.** The SBOM to apply statements to |
| `--out` | - | Write the annotated CycloneDX document here |
| `--fail-on-effective` | `-1` | Exit `1` above this many surviving vulnerabilities (`-1` disables) |
| `-o, --output` | `pretty` | `pretty`, `json` |

`--bom` goes through the same loader as [`bom import`](../bom/), so an SPDX or
attestation-wrapped document works identically.

### Nothing is deleted

A suppressed finding keeps its entry, gains a CycloneDX `analysis` block, and
carries namespaced provenance:

| Property | Meaning |
|----------|---------|
| `vulnetix:vex/source` | The document that asserted it |
| `vulnetix:vex/author` | Who published it |
| `vulnetix:vex/match-basis` | Which basis matched, from the table above |
| `vulnetix:vex/explain` | A sentence saying why |
| `vulnetix:vex/document-id` | The document's own identifier |

Counts are reported three ways:

```
Vulnerabilities  Count  Meaning
Total                4  every entry in the document
Suppressed           2  closed by a not_affected or fixed statement
Annotated            1  statement attached, still live
Effective            2  what remains to act on
```

A count that silently went down cannot be audited, cannot be re-evaluated when
the statement expires, and cannot be explained to a reviewer.

Only `not_affected` and `fixed` suppress. An `affected` statement adds an action
statement — useful, but it does not close anything, and treating it as a
suppression would be the exact opposite of what the publisher said.

Statements that matched **nothing** are surfaced. That is the single most common
reason VEX appears not to work — the documents describe a different product.

---

## vex ls

List statements and what they assert, so a set of documents can be reviewed
before it is trusted to suppress anything.

```bash
vulnetix vex ls --vex ./vex/
vulnetix vex ls --vex ./vex/ --status not_affected
```

| Flag | Default | Description |
|------|---------|-------------|
| `--vex` | - | VEX file or directory (repeatable, **required**) |
| `--status` | - | Filter: `not_affected`, `affected`, `fixed`, `under_investigation` |
| `-o, --output` | `pretty` | `pretty`, `json` |

---

## vex validate

Structural validity is not enough for VEX. A document can parse cleanly and
still assert nothing usable.

```bash
vulnetix vex validate --vex vendor.openvex.json
vulnetix vex validate --vex ./vex/ -o json
```

| Problem | Fatal | Why |
|---------|-------|-----|
| `not_affected` with no justification or impact statement | yes | Invalid per OpenVEX — the argument is the whole point of the status |
| Status outside the vocabulary | yes | Cannot be acted on |
| Statement names no vulnerability | yes | Nothing to match |
| `affected` with no action statement | no | Tells a consumer nothing to do |
| Statement names no product | no | Applies to everything the document describes |

Exits `1` when any problem is fatal.

---

## vex merge

Combine documents into one OpenVEX file.

```bash
vulnetix vex merge --vex vendor.openvex.json --vex ours.json --out merged.openvex.json
vulnetix vex merge --vex ./vex/ --out merged.openvex.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | stdout | Write the merged document here |

Keyed by `(vulnerability, product)`; the newer timestamp wins. A vendor who
published `under_investigation` in March and `not_affected` in June has said the
second thing, and a merge that kept both would leave the consumer to guess.

Inputs may mix all three formats; the output is always OpenVEX 0.2.0.

---

## In a scan

`--vex-file` and `--no-vex` are registered **family-wide** on `scan`, `sca`,
`sast`, `secrets`, `containers` and `iac`.

```bash
vulnetix sca --vex-file vendor.openvex.json
vulnetix scan --vex-file ./vex/ --severity high
vulnetix sca --vex-file ./vex/ --no-vex     # --no-vex wins
```

| Flag | Default | Description |
|------|---------|-------------|
| `--vex-file` | - | VEX file or directory to apply before gates are evaluated (repeatable) |
| `--no-vex` | `false` | Ignore `--vex-file` and apply no third-party VEX |

Statements are applied in **one place, immediately before the quality gates**.
Every gate therefore honours VEX by construction — filtering per gate would
leave one that could be forgotten, and the forgotten one fails a build over a
finding the vendor already excluded.

The summary line names the suppressed count, because `0 vulnerabilities` on its
own reads as *"nothing was found"* when what happened is that somebody asserted
the findings do not apply:

```
VEX: 12 statement(s) from 1 document(s) — 12 suppressed, 0 effective
  CVE-2021-23337       not_affected (vendor.openvex.json)
  …

  1 packages | 0 vulnerabilities (12 suppressed by VEX)
```

A malformed VEX document fails the scan rather than silently widening the gate.

## Files this CLI writes

Generated VEX still lands where it always has:

| Path | Contents |
|------|----------|
| `.vulnetix/vex.openvex.json` | SAST, secrets, IaC, container resolutions |
| `.vulnetix/vex-malscan.openvex.json` | Malware findings |
| `.vulnetix/vex-cbom.openvex.json` | Crypto asset resolutions |
| `.vulnetix/vex-aibom.openvex.json` | AI inventory resolutions |
| `.vulnetix/vex-risk-accepted.json` | Risk accepted during autofix |
| `.vulnetix/jail.vex.json` | Jail verdict attestation |

`vex apply --vex .vulnetix/` reads all of them; non-VEX files in that directory
are skipped rather than fatal.

### Who asserted it

A VEX statement is an assertion by somebody, and a document that does not say
who asserted it is worth less than one that does. CycloneDX VEX this CLI writes
carries `metadata.authors` naming Vulnetix, and a `metadata.tools` entry of
`vulnetix-vex` at the version that produced it — previously the version was the
literal string `cli`, which told a consumer nothing.

It also claims the `operations` lifecycle phase, because a VEX statement is
about software that exists and is deployed. Documents written before this
carried no `lifecycles` at all, leaving a reader unable to tell a statement
about a running system from one about a design proposal. See
[BOM authoring identity](../scan/#bom-authoring-identity).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | `--fail-on-effective` breached, or a document has a fatal validation problem |
| `2` | Usage error |

## See also

- [`bom`](../bom/) — read, diff and query SBOM documents
- [`triage`](../../cli-reference/#vulnetix-triage) — generate VEX from triage decisions
- [`jail`](../jail/) — policy gate with VEX attestation
