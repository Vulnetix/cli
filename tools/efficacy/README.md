# Scan efficacy tools

Both need network access and are not part of `go test`.

## `just efficacy`

Clones popular open-source repos, runs `vulnetix scan --only sca` on each, and compares
**every package in the SBOM** (not only the ones with findings) with OSV. It fails when
the scan makes more than `MAX_WRONG` false "affected" claims (default 2) or recall
against OSV falls below `MIN_RECALL` (default 95).

```
just efficacy                          # the default corpus
ONLY=flask,fastapi just efficacy       # a subset
REPOS=vuln-apps.json just efficacy     # extra repos: [{"Name":"x","URL":"https://github.com/..."}]
```

Read the classes in this order:

| Class | Meaning |
|---|---|
| `FP-REAL` | The scan said **affected** and OSV's own record excludes the version. A wrong claim; this is what the gate counts. |
| `FP-flagged-unverified` | The scan said **unverified** where OSV excludes the version. It counts toward gates but does not claim anything false. |
| `FN-missed` | OSV lists an advisory for the package that the scan did not report. Usually the database has no affected-package data for it. |
| `FIX-too-low` | The recommended upgrade does not clear an advisory OSV lists for the install's release line. |
| `ID-mislabel` | The right package and fix, reported under an id OSV does not use (server alias groups). |
| `FP-unverifiable`, `FP-unknown-to-osv` | OSV has no record to compare against. Neither confirms nor refutes. |
| `C-*` | Consistency checks that need no oracle (the same package must not be both fixed and vulnerable). |

Precision against OSV understates quality: most of the gap is advisories OSV does not
list for the package, not scan errors.

## `just vdb-smoke`

For each `vdb` command and a set of well-known vulnerabilities, checks that the pretty
output renders what `-o json` returns: no header with a blank identifier, no "No X found"
when the JSON has data, no output far smaller than its data. A vulnerability the database
has no record of (a 404 "Vulnerability not found") is a valid answer, not a failure.
