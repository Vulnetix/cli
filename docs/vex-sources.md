# VEX in scans and in config

A scan applies VEX before any gate is evaluated, so a finding a statement closes
(`not_affected`, `fixed`) cannot fail a build. The finding stays in the SBOM,
annotated, and in the total / suppressed / effective counts.

## Where a scan reads VEX from

| Source | How |
|---|---|
| `--vex-file <path>` | A file or a directory (one level of `.json` files). Repeatable. |
| `--vex <path\|dir\|https URL>` | The same, and an `https://` URL is downloaded for the run (8 MiB cap, 30 s). Plain `http://` is refused. A `--vex` URL that cannot be fetched fails the scan: it was asked for, and a quiet gap would widen the gate. |
| `VexSource` documents in `.vulnetix/config` | A `path` source is read from disk (relative to the repository root, then `.vulnetix/config`) and a `urls` source is fetched. A source that cannot be read is a warning. |
| Vulnetix console | When the scan is authenticated, the statements the console holds for the repository as rules (see below). Community mode asks for nothing. |
| `--no-vex` | Turns all of it off, the console's statements included. |

`tea`, `s3` and `git` sources are fetched by the console, not by the CLI, so a scan
reads what the console made of them (next section). An unauthenticated scan cannot, and prints
a note naming each such source; to have it honour their documents, pass the same documents with
`--vex`.

A declared source keeps the limits it was declared with: `scope.repos` applies it
only to the listed repositories (matched against the scanned repository's
`owner/name`), and `trust.allowedAuthors` drops a document whose author is not on
the list. The CLI never applies a source more widely than declared.

Matching is by package URL and vulnerability id, the same as `--vex-file`
(`internal/vex`). OpenVEX, CycloneDX VEX and CSAF VEX are read.

## `config apply` and a `path` source

The console cannot read a path, so for a `VexSource` with `spec.path`,
`config apply` uploads a snapshot of the documents after the apply
(`POST /config/vex-sources/{name}/snapshot`): each document base64 encoded with the
hex sha256 of its bytes, at most 10 documents of at most 8 MiB. The snapshot
replaces the source's last one, so a statement that left the files leaves the
console too. It is uploaded even when the plan has nothing to apply, since the
files can change when the document does not, and a failed upload makes `apply`
exit non-zero.

## Statements the console holds

A `VexSource` of type `tea`, `s3` or `git` is fetched by the console on its refresh. Each
statement that is a decision (not affected, or a decision not to fix) becomes a `Suppression`
rule keyed by the vulnerability and the product. `cli.suppressions-get` returns those rules with
the statement behind them (`vulnerabilityId`, `productPurl`, `justification`, `status`, `source`,
`sourceType`, `sourceRef`, `sourceDocumentId`, `statementTimestamp`; see vdb-api
`docs/cli-suppressions-vex.md`), and an authenticated scan applies them in the same VEX pass as
`--vex` documents: the same matching, the same annotation (`vulnetix:vex/source` reads
`Vulnetix VexSource/<name>`), the same total / suppressed / effective counts.

| | |
|---|---|
| What is applied | Every active rule with `sourceKind` `vex` for the scanned repository and branch, or for none. That is the statements of every `VexSource` type, and VEX documents ingested from earlier scans and uploads. A rule scoped to another repository or branch is not applied, and a scan that does not know its repository applies only unscoped rules. |
| Statuses | `not_affected` closes a finding. A decision not to fix is `affected`: the finding is annotated and stays open, exactly as for a `--vex` document. A fixed statement is triage evidence on the console, not a rule, so it is not returned. |
| Product | The narrowest the console recorded: the purl with its version when the statement had one. A statement about one version does not reach another. |
| When it applies | Authenticated, VEX on (no `--no-vex`), SCA run. It is the request the scan already makes for ignore rules, so it adds none. |
| Unmatched | Console statements are not counted in the "matched no finding" note: most of an organisation's statements are about other products. |

### De-duplication

A console statement is dropped when a `--vex` document, a `path` or `urls` `VexSource`, or
another console rule already says the same: the same vulnerability (or an alias of it), the same
status, and the same product, or the same package with no version, which speaks about every
version. A local statement about one version does not cover a console statement about all of them.
Documents sent to Vulnetix (`cli.vex-ingest`) are the local ones only; the console's statements are
never sent back.

### Ownership

A rule a `VexSource` made belongs to that source: its refresh writes and removes it. So
`vulnetix ignore remove --uuid <rule>` refuses it and names the source, `ignore remove` by
vulnerability id never reaches it, `ignore sync` leaves it out of `.vulnetix/memory.yaml`, and
`ignore list` shows it as `VexSource/<name>` against its vulnerability and product. The server
refuses a deactivation of such a rule as well (409). Change or remove the statement at the source,
or the `VexSource`.

Reply sizes: ordinary rules are bounded at 1000 and VexSource rules at 5000 per request. A scan
that hit the second bound says so and applies what it was given.
