---
title: "Usage"
weight: 1
description: "Invocation patterns for tree-sitter reachability — flag reference, pretty + JSON output, and the .vulnetix/memory.yaml schema."
---

This page documents every way to invoke reachability and every output it produces.

## The `--reachability` flag

Registered as a persistent flag on `vdb`, so every subcommand that produces vulnerability data inherits it.

```
--reachability {direct|transitive|both|off}     (default: both)
```

| Value | Direct scan | Transitive scan | Fetches queries |
|-------|-------------|-----------------|-----------------|
| `direct` | ✅ | ❌ | Yes |
| `transitive` | ❌ | ✅ | Yes |
| `both` *(default)* | ✅ | ✅ | Yes |
| `off` | ❌ | ❌ | **No** — no API request, no scan, no output block |

The `off` value is the only setting that skips the `GET /vuln/{id}/tree-sitter` call. Use it when:

- The CLI is running in a sandbox without filesystem access to dependencies.
- You want a strictly offline `vdb vuln` lookup.
- A CI job has already produced reachability evidence and you only want to render the rest of the vuln detail in a different stage.

Aliases accepted on input: `off` / `none` / `false` / `0` all map to `off`. The empty string maps to `both` (the default).

### Performance tuning

Direct mode walks the install folder of a single package — even on a deep monorepo this completes in well under a second.

Transitive mode walks the entire project root excluding standard build dirs. On a ~10k-file Node monorepo it typically completes in ~2–5 seconds; on a ~200k-file mixed-language monorepo it can take 30+ seconds. If you need to gate CI on reachability and the transitive sweep is too slow, run with `--reachability=direct` in CI and re-run with `both` locally during triage.

The scanner caps any individual file at 4 MiB (`reachability.MaxFileSize`) and silently skips larger files. This keeps memory bounded on minified bundles and generated source.

---

## Commands that produce reachability

### `vulnetix vdb vuln <id>`

The primary user-facing command. Always runs reachability when the mode is non-`off`, the API version is v2 (the default), and queries exist for the named identifier.

```bash
# Default: direct + transitive
vulnetix vdb vuln CVE-2021-23337

# JSON output for automation
vulnetix vdb vuln CVE-2021-23337 --output json

# Skip transitive (faster for CI)
vulnetix vdb vuln CVE-2021-23337 --reachability=direct

# Pure offline lookup
vulnetix vdb vuln CVE-2021-23337 --reachability=off
```

### `vulnetix vdb remediation plan <id>`

The remediation plan endpoint surfaces fix candidates. Reachability evidence helps prioritise between them (a CVE with no reachable code paths might warrant a deferred upgrade rather than an emergency patch). When run with v2, reachability is fetched and rendered on the same flow as `vdb vuln`.

### `vulnetix scan`

The repo-wide scan flow produces a stream of findings rather than a single-vuln view. Reachability fans out across the produced CVEs — each finding gets its own direct + transitive scan recorded into `.vulnetix/memory.yaml`. Disable globally with `--reachability=off` when scanning large monorepos where you don't need per-CVE source-evidence.

---

## Pretty output

The reachability block renders below the standard vuln detail. Example annotated:

```
Reachability: 2 direct, 1 transitive (1 queries)
│  └ Per-mode counts                  └ Number of distinct queries executed
  direct       node_modules/lodash/template.js  142:158  (prototype-pollution)
  │            │                                │       └ Query name (TreeSitterQuery.name)
  │            │                                └ start_line:end_line, 1-indexed inclusive
  │            └ Path relative to project root
  └ Match mode (direct = inside install dir; transitive = elsewhere)
  direct       node_modules/lodash/template.js  201:204  (prototype-pollution)
  transitive   src/render.ts                    88:97    (prototype-pollution)
```

When a mode was requested but couldn't run, a muted "skipped" line replaces the matches:

```
Reachability: 0 direct, 1 transitive (1 queries)
  transitive   src/render.ts  88:97  (prototype-pollution)
  direct skipped: install directory for npm/lodash not found
```

---

## JSON output

Reachability is attached to the response as `x_reachability`. The CLI uses an `x_`-prefixed key because the vuln payload is the CVE 5.0 JSON shape; `x_` extensions are the documented way to attach non-CVE-spec data.

```json
{
  "cveMetadata": { "cveId": "CVE-2021-23337", ... },
  "containers": { ... },
  "x_reachability": {
    "queries_run": 1,
    "direct": [
      {
        "file": "node_modules/lodash/template.js",
        "start_line": 142,
        "end_line": 158,
        "query": "prototype-pollution",
        "language": "javascript",
        "captures": {
          "callee": "_.template",
          "arg": "userInput"
        }
      },
      {
        "file": "node_modules/lodash/template.js",
        "start_line": 201,
        "end_line": 204,
        "query": "prototype-pollution",
        "language": "javascript"
      }
    ],
    "transitive": [
      {
        "file": "src/render.ts",
        "start_line": 88,
        "end_line": 97,
        "query": "prototype-pollution",
        "language": "javascript"
      }
    ]
  }
}
```

### Field reference

| Field | Type | Notes |
|-------|------|-------|
| `queries_run` | int | Distinct `(language, queryHash)` pairs executed. Always non-zero when the block is present. |
| `direct` | `Match[]` | Matches inside the installed-package folder. Empty/omitted if mode skipped direct. |
| `transitive` | `Match[]` | Matches elsewhere in the project tree. Empty/omitted if mode skipped transitive. |
| `skipped_direct` | string | Set when direct was requested but couldn't run (e.g. install folder not found). |
| `skipped_transitive` | string | Set when transitive was requested but couldn't run (rare; no project root). |

### Match object

| Field | Type | Notes |
|-------|------|-------|
| `file` | string | Path relative to the project root (or absolute if outside it). |
| `start_line` | int | 1-indexed, inclusive. The earliest source line touched by any capture. |
| `end_line` | int | 1-indexed, inclusive. The latest source line touched by any capture. |
| `query` | string | The `TreeSitterQuery.name` field for the query that matched. |
| `language` | string | Canonical language ID — see [Languages](../languages/). |
| `captures` | object | Map of capture name → matched source text. Truncated by tree-sitter to the captured node's literal source. |

---

## `.vulnetix/memory.yaml` integration

Every reachability run appends evidence to the corresponding finding under `threat_model.reachability_evidence`. Existing `memory.yaml` files without this field continue to load (it's `omitempty` on the Go struct).

```yaml
findings:
  CVE-2021-23337:
    package: lodash
    ecosystem: npm
    status: under_investigation
    severity: HIGH
    threat_model:
      attack_vector: Network
      attack_complexity: Low
      reachability: Network         # CVSS-derived attack-vector reachability
      reachability_evidence:        # tree-sitter-derived code reachability
        direct:
          - file: node_modules/lodash/template.js
            range: "142:158"
            query: prototype-pollution
          - file: node_modules/lodash/template.js
            range: "201:204"
            query: prototype-pollution
        transitive:
          - file: src/render.ts
            range: "88:97"
            query: prototype-pollution
    history:
      - date: 2026-05-17T09:14:32Z
        event: vdb-lookup
        detail: Queried VDB for vulnerability details
      - date: 2026-05-17T09:14:34Z
        event: reachability-scan
        detail: "2 direct, 1 transitive"
```

### How downstream tooling consumes it

| Consumer | What it reads | Why |
|----------|---------------|-----|
| `vdb vex publish` | `reachability_evidence` + `decision.choice` | Generates OpenVEX/CycloneDX VEX attestations citing specific file:line evidence for `not_affected` claims. |
| `vulnetix:dashboard` skill | `reachability_evidence` counts | Surfaces "vulns with reachable code" as a priority tier above "vulns with no reachable code". |
| Compliance bundle (`vdb compliance`) | Full reachability block | Embeds match locations into the audit deliverable so reviewers can verify the triage rationale. |
| Triage agents | `reachability_evidence` | Auto-suggest `not_affected` when both direct and transitive arrays are empty for a CVE with reliable queries. |

### Range syntax

The `range` field is rendered as `start_line:end_line` using `n:n` for single-line matches — matching the rest of the CLI's location format. Tools consuming the file can split on `:` to get the two integers.

### Clearing stale evidence

Re-running reachability overwrites the `reachability_evidence` for the same CVE — it never appends or merges with a previous run, so evidence always reflects the most recent scan. To wipe reachability without re-scanning, edit `memory.yaml` directly or use the dashboard skill.
