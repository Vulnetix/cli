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
| `--no-vex` | Turns all of it off. |

`tea`, `s3` and `git` sources are fetched by the console, not by the CLI. A scan
prints a note naming them; to have a CI gate honour their documents, pass the same
documents with `--vex`.

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

## Not yet

Suppressions that a console-fetched source (`tea`, `s3`, `git`) created are
`Suppression` rows keyed by vulnerability id and product purl. `cli.suppressions-get`
does not return those columns, so the CLI cannot apply them on its own; that needs
the API to return them.
