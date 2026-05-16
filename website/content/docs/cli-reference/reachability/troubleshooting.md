---
title: "Troubleshooting"
weight: 3
description: "Common reachability scenarios — empty results, missing install folders, false positives, performance issues."
---

## `Reachability: 0 direct, 0 transitive (0 queries)`

Three causes, distinguishable by the `queries_run` number:

**`queries_run = 0`** — The CVE has no tree-sitter queries derived yet. The backend produces queries from the published affected-symbol set in CVE 5.0 data; very recent CVEs and some advisory-only sources (e.g. distribution-only advisories) may not have them yet. This is not an error; the rest of the vuln output is unaffected.

**`queries_run > 0` but no matches** — Queries ran cleanly and found nothing. This is the desirable case for `not_affected` triage: the vulnerable pattern is genuinely absent from your install folder and the project tree. Verify against [What a match means](../#what-a-match-means--and-what-it-doesnt) before marking the finding closed — reflection and dynamic dispatch can still reach a symbol invisibly.

**`skipped_direct: ...` or `skipped_transitive: ...`** — A requested mode couldn't run. See the next sections.

## `skipped_direct: install directory for npm/lodash not found`

The ecosystem-aware resolver couldn't find the on-disk install folder. Common causes:

- **Dependencies not installed locally.** Run `npm install` / `pnpm install` / `pip install -r requirements.txt` / `bundle install` / `cargo vendor` first. Reachability needs the files on disk.
- **Non-standard layout.** The resolver checks the canonical locations per ecosystem (`node_modules/<pkg>`, `vendor/<pkg>`, `.venv/lib/pythonX.Y/site-packages/<pkg>`, `vendor/bundle/ruby/<ver>/gems/<pkg>-*`, `target/dependency`, etc.). Custom monorepo layouts (`packages/foo/node_modules`) aren't probed today. Workaround: `cd` into the inner project root before running reachability.
- **Bundler-style hoisting (pnpm/Yarn PnP).** pnpm hoists scoped packages under `node_modules/.pnpm/...` and surfaces top-level symlinks. The resolver follows the top-level symlink and works for most pnpm layouts. Yarn PnP (no `node_modules` at all) is not supported — switch to `nodeLinker: node-modules` in `.yarnrc.yml` for reachability.
- **Module cache lookups intentionally skipped.** Go's `$GOPATH/pkg/mod/...` cache is not probed — version resolution is non-trivial and the cache layout is shared across projects. Add `vendor/` (run `go mod vendor`) for direct-mode Go reachability.

Even when direct is skipped, transitive still runs. A transitive match in this case is high-signal because you're seeing code that *would* call the vulnerable symbol regardless of which package version is installed.

## `skipped_transitive: project root unknown`

Rare — the CLI couldn't determine a project root. Happens when reachability is invoked from a directory that isn't inside a recognised project (no git root, no Vulnetix project marker). Workaround: `cd` into the project root before running, or pass `--git-local-dir <path>`.

## `query compile failed` in verbose logs

A specific query couldn't be compiled against the bundled grammar version. This is logged at debug level and the scanner continues with the next query — a single failed query never aborts the run.

Causes:

- **Grammar drift.** The backend generated the query against a newer grammar version than the CLI bundles. Rare but possible during a coordinated upgrade; update the CLI.
- **Backend regression.** A malformed query slipped through generation. Report the offending `(CVE, language, queryHash)` triple to Vulnetix support; the backend will regenerate.

The remaining queries for the same CVE still execute. A run with all queries failing produces `queries_run: N` but empty arrays — distinguishable from "no queries published" by `queries_run > 0`.

## False-positive matches

A direct match in `node_modules/lodash/template.js` for the lodash CVE is unambiguous — the file is the vulnerable code. A transitive match in `src/render.ts` for the same query needs human review: does the call go to `_.template`, or to a same-named method on a different object?

The match's `captures` field surfaces the matched source text for each named capture (`@callee`, `@arg`, etc.). When `captures.callee = "lodash.template"` or `"_.template"` the match is almost certainly real; when `captures.callee = "myUtil.template"` it's a syntactic collision worth dismissing.

Triage workflow for a confirmed false positive:

1. Open `.vulnetix/memory.yaml`.
2. Set the finding's `decision.choice = not_affected` with a `reason` citing the false positive (`"transitive match in src/render.ts is a same-named method on a different object, verified by code review"`).
3. The match is preserved in `reachability_evidence` as audit trail — the decision overrides it.

The CLI doesn't have a "suppress this match" primitive today. The pattern of capturing the *decision* with reasoning (rather than nuking the evidence) keeps the audit trail intact for compliance.

## Slow transitive sweeps on large monorepos

Transitive mode walks the project tree minus the skipped directories. On very large repos (~1M+ source files, vendored OS images, generated TS bundles) this can take 30+ seconds.

Tactics:

- **Run direct-only in CI.** `--reachability=direct` skips the transitive sweep entirely and finishes in <1 second. Pair with a periodic `--reachability=both` run (cron, weekly) for the full picture.
- **Ensure build outputs are in the skip list.** The default skip list covers `node_modules`, `vendor`, `.venv`/`venv`/`env`, `__pycache__`, `.tox`, `dist`, `build`, `target`, `.gradle`, `.idea`, `.vscode`, `.next`, `.nuxt`, `coverage`, `.cache`. If your repo has additional generated trees (e.g. `gen/`, `out/`), the scanner walks them today — file an issue to extend the skip list.
- **Profile the slow paths.** With `--verbose` the scanner emits one line per file scanned at debug level; piping to `awk` quickly identifies generated-file hot spots.
- **MaxFileSize.** Files over 4 MiB are skipped silently, which keeps generated bundles from blowing up memory. If you have legitimate source files larger than 4 MiB you'll see them missed; file an issue.

## Memory pressure

Parsers and queries are short-lived in the smacker/go-tree-sitter binding — both `Close()` on the tree and the query cursor are deferred in the engine's `Run` path, so per-file allocations don't accumulate. Parser instances themselves are pooled per language via `sync.Pool`, which keeps allocator pressure low for repeated runs.

If you observe a memory leak in long-running reachability runs (uncommon), capture a heap profile (`vulnetix --pprof-heap …`) and file an issue with the dump.

## Reachability runs even though I passed `-V v1`

It doesn't — the CLI silently skips reachability on v1 because the tree-sitter endpoint isn't part of the v1 surface. If you see reachability output on what you think is v1, check the resolved API version: `vulnetix vdb status -V v1` echoes the version actually in use. The most likely explanation is the v2 default winning over an environment variable that's no longer in effect.

## I want to re-run reachability without re-fetching everything else

Today reachability is a side-effect of `vdb vuln`, `vdb remediation plan`, and `scan` — there's no standalone `vdb reachability <id>` subcommand. Re-run the parent command; the CVE response is served from cache when fresh, so only the `/vuln/{id}/tree-sitter` and the local scan execute.

If you need to clear and re-run from scratch:

```bash
vulnetix vdb cache clear --identifier CVE-2021-23337
vulnetix vdb vuln CVE-2021-23337
```
