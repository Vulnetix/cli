---
title: "Reachability Analysis"
weight: 3
description: "Static-analysis reachability for vulnerabilities. Uses tree-sitter S-expression queries derived from CVE data to confirm whether the vulnerable code pattern is present in the installed package, and whether first-party code (or other dependencies) actually reaches it."
---

Vulnetix reachability analysis turns the question *"is this CVE present in our dependencies?"* into the much sharper question *"is the vulnerable code actually reached from anywhere in this repository?"*. It runs locally on the developer machine or in CI, using tree-sitter S-expression queries derived from each CVE's published data — there is no network round-trip during the scan itself, only the initial fetch of the queries from the Vulnetix VDB.

This page is the conceptual overview. Once you've read this, see:

- [Usage](usage/) — invocation patterns, flag reference, output schemas, memory.yaml integration.
- [Languages](languages/) — language coverage matrix, file extensions, ecosystem mapping, support tiers.
- [Troubleshooting](troubleshooting/) — empty results, missing install folders, false positives, performance.
- [Internals](internals/) — how the engine is built (smacker/go-tree-sitter, CGo grammars, cross-compile via zig cc).

---

## What is reachability analysis?

A vulnerability scanner that only checks package names and versions answers a *necessary* condition for being affected, never a *sufficient* one. A repository can pull in `lodash@4.17.20` (vulnerable to CVE-2021-23337 prototype pollution) and never call the function that contains the bug — in which case patching is still good hygiene, but the urgency is dramatically lower. Conversely, the package may not even appear at the top level of a manifest yet still be pulled in transitively by a framework, and may still be called indirectly through that framework — in which case the urgency is higher than the version-match implies.

Tree-sitter reachability collapses that distance. It parses your source files (and the installed-package source) into syntax trees, runs CVE-specific queries against those trees, and reports the exact `file:line:line` location of every match. The outputs feed three consumers:

1. **The human reading `vulnetix vdb vuln`** — pretty-printed inline with the rest of the vuln detail.
2. **Automation reading `--output json`** — a structured `x_reachability` block on the response.
3. **The Vulnetix triage memory in `.vulnetix/memory.yaml`** — recorded under `threat_model.reachability_evidence` so subsequent triage decisions, VEX attestations, and reports can cite specific match locations.

### How it differs from CVSS attack-vector reachability

The CVSS vector includes an `AV:` attribute (Network, Adjacent, Local, Physical) and the older Vulnetix memory schema stored that as `threat_model.reachability`. That field describes the *attacker's* path into the vulnerability assuming it is reachable. Tree-sitter reachability describes the *defender's* code path *to* the vulnerability. The two answers different questions; both are kept on the finding record.

| Question | Answered by |
|----------|-------------|
| Could a network attacker exploit this if it were reachable? | CVSS `AV:N` (existing `threat_model.reachability`) |
| Does our codebase actually call the vulnerable symbol? | Tree-sitter (`threat_model.reachability_evidence`) |

---

## How Vulnetix derives the queries

Vulnetix's VDB ingests CVE 5.0 records, OSV entries, GHSA advisories, vendor advisories, distribution patches, and Red Hat security data. From these, the backend (`vdb-manager`) extracts the vulnerable symbol set — function name, method receiver, decorator, attribute access pattern — and synthesises a tree-sitter S-expression query for each affected language. The queries are normalised, deduplicated by SHA-1, and stored against the CVE as `CVETreeSitterQuery` rows. The CLI fetches them via:

```
GET /vuln/{identifier}/tree-sitter
```

Each query object exposes:

| Field | Purpose |
|-------|---------|
| `language` | Canonical language ID — see [Languages](languages/) for the full set |
| `name` | Short human label (e.g. `prototype-pollution`, `unsafe-deserialization`) |
| `description` | Optional longer description |
| `queryText` | Raw S-expression executed against parsed source |
| `queryHash` | Content hash for caching and deduplication |
| `derivedBy` | Generator identifier — useful for support |
| `captures` | Named captures the query exposes (`@callee`, `@arg`, etc.) |
| `predicates` | `#eq?`/`#match?`/`#any-of?` clauses constraining matches |
| `directives` | `#set!`/other directives attached to the query |
| `ecosystems` | Which package ecosystems this query targets (npm, pypi, …) |

The CLI never modifies the query — it compiles it directly with the bundled grammar for the named language and runs it through `tree-sitter`'s query cursor against each candidate file.

---

## Direct vs transitive modes

Reachability runs in one of four modes, controlled by `--reachability` (default `both`).

### Direct mode

**Question answered:** *"Is the vulnerable pattern present in the installed copy of the package?"*

The scanner locates the on-disk install folder for the affected package and walks every source file inside it. The install-folder resolver knows how each ecosystem lays out dependencies — `node_modules/<pkg>`, `vendor/<pkg>` (Go, Composer, Cargo), `vendor/bundle/ruby/<ver>/gems/<pkg>-*` (Bundler), `.venv/lib/pythonX.Y/site-packages/<pkg>` (Python), `target/dependency/*` (Maven) — and falls back to common alternates.

A direct match is strong evidence: the literal vulnerable code, in the exact version your `node_modules`/`vendor`/`site-packages` directory holds, contains the pattern. If a CVE's affected version range says `< 4.17.21` and your installed `lodash` is `4.17.20`, the direct mode either confirms or refutes that the vulnerable function is present — sometimes a backported patch lands in a version the CVE database hasn't caught up to.

**Worked example** — CVE-2021-23337 (lodash `_.template` prototype pollution), repository has `node_modules/lodash@4.17.20`:

```
$ vulnetix vdb vuln CVE-2021-23337
…
Reachability: 2 direct, 0 transitive (1 queries)
  direct     node_modules/lodash/template.js  142:158  (prototype-pollution)
  direct     node_modules/lodash/template.js  201:204  (prototype-pollution)
```

### Transitive mode

**Question answered:** *"Does any other code in this repository — first-party source, other dependencies, generated code — reach the vulnerable symbol?"*

The scanner walks the entire project tree starting from the current working directory (or the resolved Vulnetix project root). It skips the install folder already covered by direct mode (so matches aren't double-counted) and standard build/cache directories: `.git`, `node_modules`, `vendor`, `.venv`/`venv`/`env`, `__pycache__`, `.tox`, `dist`, `build`, `target`, `.gradle`, `.idea`, `.vscode`, `.next`, `.nuxt`, `coverage`, `.cache`.

The queries that fire here are the *same* queries derived from the CVE — they describe the vulnerable pattern, and a transitive match means *something else in your tree exhibits that pattern*. For a function-call CVE that typically means a call to the vulnerable function (e.g. `lodash.template(userInput)`). For a sink-pattern CVE (deserialization, unsafe-eval, taint) it can mean usage that re-implements the vulnerable behaviour.

**Worked example** — same CVE, with `src/render.ts` using `_.template`:

```
Reachability: 2 direct, 1 transitive (1 queries)
  direct       node_modules/lodash/template.js  142:158  (prototype-pollution)
  direct       node_modules/lodash/template.js  201:204  (prototype-pollution)
  transitive   src/render.ts                    88:97    (prototype-pollution)
```

### When the affected package is transitive

This is the case the user's question called out specifically: the CVE names a package, but that package doesn't appear in the top-level manifest — a framework or other dependency pulled it in. Reachability of *first-party* code to that package is, statistically, less likely than for a direct dep. Transitive mode still runs because it's cheap to be sure, and a single match in `src/` against a transitively-pulled vuln is a high-signal finding worth surfacing.

Heuristically:

- **Affected pkg is a direct dep + transitive match found** → high confidence the vuln is reachable; treat as **affected**.
- **Affected pkg is a direct dep + no transitive match** → tree-sitter says it isn't called from your code; defensible **not_affected** triage (but verify the affected-symbol set in [Troubleshooting](troubleshooting/) — type-aware patterns can evade pure-syntactic matching).
- **Affected pkg is transitive + transitive match found** → unusual; investigate the calling intermediate, the match is probably in another dep's code rather than first-party.
- **Affected pkg is transitive + no transitive match** → strong **not_affected** signal; the vuln is in a dep you never reach.

### Mode summary

| Mode | Scans installed-package folder | Scans rest of project | When to use |
|------|--------------------------------|-----------------------|-------------|
| `direct` | ✅ | ❌ | Confirming the vulnerable code is present in the installed version. Fast. |
| `transitive` | ❌ | ✅ | Finding callers of the vulnerable symbol across your repo. Slower on large monorepos. |
| `both` *(default)* | ✅ | ✅ | The full picture. |
| `off` | ❌ | ❌ | Skip reachability entirely. No `/vuln/{id}/tree-sitter` request is made. |

---

## What a match means — and what it doesn't

Tree-sitter is **syntactic**, not semantic, not type-aware, and never executes code. That has two consequences:

**Matches are not a proof of exploitability.** A query that matches `foo.template(x)` for the lodash CVE will match every call shaped that way, including calls on objects called `foo` that happen to have a method named `template` — your own utility, a different vendor module, anything. The CLI surfaces the match so you can inspect it, not so you can mark the finding `affected` blindly.

**Absence of matches is a strong signal, not a guarantee.** Reflection (`obj[methodName](...)`), dynamic dispatch, code generation, and metaprogramming can all reach a vulnerable symbol in ways the query won't catch. For CVEs in widely-used libraries where dynamic invocation is rare, "no matches" is defensible evidence for `not_affected`. For framework code (Spring, Rails, Django) where reflective invocation is routine, treat "no matches" with appropriate skepticism.

Triage workflow:

1. `vdb vuln <id>` produces direct + transitive matches.
2. Review each match line — the file path and `start:end` range opens directly in an editor.
3. For each match: is this a real call to the vulnerable symbol, or a false positive? Annotate the finding in `.vulnetix/memory.yaml`.
4. The recorded `reachability_evidence` is consumed downstream by `vdb vex publish`, compliance bundles, and audit exports.

---

## Requirements and where this runs

- **API version** — Reachability requires the v2 VDB surface, which is now the **default**. If you've pinned `-V v1`, drop the override. The CLI still produces vuln output with `-V v1` but silently skips reachability since the queries aren't published on v1.
- **CGo** — The bundled tree-sitter grammars are C source compiled into the binary via CGo. Cross-compile builds use `zig cc` (see [Internals](internals/) for build details). Pre-built release binaries already include all 17 grammars.
- **Network** — One additional `GET /vuln/{id}/tree-sitter` request per vuln. Queries are cached on disk under the standard VDB cache; subsequent runs against the same CVE re-use them. Disable with `--reachability=off` if you want to keep `vdb vuln` strictly offline.
- **Memory** — The scanner caps individual files at 4 MiB; larger files are skipped. Parser instances are pooled per language. A full transitive sweep on a typical mid-size Node monorepo (~200 MB of source) finishes in seconds.
