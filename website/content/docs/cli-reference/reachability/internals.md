---
title: "Internals"
weight: 4
description: "How tree-sitter reachability is implemented — grammar bundling, CGo build, cross-compile, parser pooling, query execution."
---

This page is for engineers vetting the implementation, packaging the CLI into a custom binary, or extending the language set.

## Components

```
cmd/vdb.go               — registers --reachability flag, hooks into `vdb vuln`
cmd/vdb_reachability.go  — orchestration: API call, scan, memory write, output attach
internal/treesitter/     — language registry (ID → *sitter.Language, ext → ID)
internal/reachability/   — engine (parser pool), scanner (file walk), discovery (install path resolver), types
pkg/vdb/api_v2.go        — V2TreeSitterQueries API method and TreeSitterQuery types
internal/memory/         — ReachabilityEvidence on ThreatModel struct
internal/display/        — renderReachability for pretty output
```

## Tree-sitter binding choice

The CLI uses [`github.com/smacker/go-tree-sitter`](https://github.com/smacker/go-tree-sitter) — a CGo binding that bundles each language as a Go sub-package containing the upstream C grammar source.

Alternatives considered:

- **`github.com/tree-sitter/go-tree-sitter` (upstream)** — also CGo, grammars added one-by-one as separate Go modules. Functionally equivalent; the smacker fork was chosen for its single-import grammar story (`import _ "github.com/smacker/go-tree-sitter/python"`).
- **WASM grammars via `wasmtime-go`** — would preserve pure-Go cross-compile, but there is no maintained Go implementation of the tree-sitter WASM host shim (the host-side memory layout and callback ABI that `web-tree-sitter` provides for the browser). Writing one is a multi-week project we judged not worth the savings.
- **Calling tree-sitter as a subprocess** — works but adds ~100ms per parse for process startup, and doesn't compose with the query cursor's streaming API. Rejected on performance grounds.

## CGo and cross-compile

CGo is enabled (`CGO_ENABLED=1`) on every release target. The C grammar source compiles once per target; the resulting `.a` archives are static-linked into the binary. There are no runtime shared-library dependencies — the CLI binary still runs on any Linux/macOS/Windows host without installing tree-sitter or any language toolchain.

Cross-compile uses [`zig cc`](https://andrewkelley.me/post/zig-cc-powerful-drop-in-replacement-gcc-clang.html) as the C cross-compiler. The justfile recipe template:

```make
GOOS=linux GOARCH=amd64 \
  CC="zig cc -target x86_64-linux-musl" \
  CXX="zig c++ -target x86_64-linux-musl" \
  CGO_ENABLED=1 \
  go build -trimpath -ldflags="..." -o bin/vulnetix-linux-amd64 ./
```

Zig is installed locally via `just install-zig` and on CI runners via the release workflow. The CI image bundles zig 0.13+; older versions may not support all targets cleanly.

### Supported targets

| Target | CGo verified | Notes |
|--------|--------------|-------|
| `linux/amd64` (musl) | ✅ | Primary CI build. |
| `linux/arm64` (musl) | ✅ | Built with `zig cc -target aarch64-linux-musl`. |
| `darwin/amd64` | ✅ | Built with `zig cc -target x86_64-macos`. |
| `darwin/arm64` | ✅ | Built with `zig cc -target aarch64-macos`. |
| `windows/amd64` | ✅ | Built with `zig cc -target x86_64-windows-gnu`. |
| `windows/arm64` | ⚠️ | Builds; not exercised by CI integration tests. |
| `linux/arm` | ⚠️ | Builds via `zig cc -target arm-linux-musleabihf`; not exercised by CI. |
| `linux/386` | ⚠️ | Builds; not exercised by CI. |
| `windows/386` | ❌ | Dropped — zig-cc 32-bit Windows + CGo combination is unstable in our matrix. |
| `windows/arm` | ❌ | Dropped — no upstream demand. |

If you need a dropped target, the CLI is open source: open an issue or build from source. Reachability is not the only CGo-touching part of the CLI (cache compression also uses CGo paths in some configurations), so the dropped 32-bit Windows variants predate this feature.

## Engine

`reachability.Engine` is a thin pool of `*sitter.Parser` instances keyed by language ID. The first request for a language compiles the parser lazily; subsequent requests reuse pooled instances via `sync.Pool.Get`/`Put`. Parsers are not safe for concurrent use, but the pool serialises access per goroutine; the engine itself is safe for concurrent use.

Per `Engine.Run`:

1. Acquire a parser from the language's pool (or create one).
2. `ParseCtx(ctx, nil, source)` — produces a `*Tree`, deferred `Close()`.
3. `NewQuery([]byte(queryText), language)` — compiles the S-expression, deferred `Close()`. A compile error here causes the query to be skipped for that file; the run continues.
4. `NewQueryCursor()` + `Exec(query, tree.RootNode())` — primes the cursor.
5. Loop `NextMatch()` + `FilterPredicates(match, source)` — the second call applies `#eq?`/`#match?`/`#any-of?` semantics that the cursor doesn't enforce on its own.
6. For each surviving match: compute `(min(captures.StartRow), max(captures.EndRow))` and convert to 1-indexed line numbers.

`Match.Captures` is built by mapping each capture's `Index` through `Query.CaptureNameForId` and storing the literal source slice at the captured node. Captures are useful for human review (identifying same-named-method false positives, see [Troubleshooting](../troubleshooting/#false-positive-matches)).

## Scanner

`reachability.Scan` orchestrates a full run:

1. Group queries by language ID using `treesitter.Normalise`. Queries whose language isn't bundled drop out silently.
2. If `Mode.Includes(ModeDirect)`: resolve the install path via `InstallPath(projectRoot, ecosystem, package)` and run `scanRoot` against it. A nil install path is recorded as `SkippedDirect`.
3. If `Mode.Includes(ModeTransitive)`: run `scanRoot` against the project root with an exclusion that strips the install path (when known) plus the standard `skipDirs()` list.
4. Render all match file paths relative to project root for friendlier output.

`scanRoot` walks the tree with `filepath.WalkDir`, skips directories on the exclusion list at the dirent level (so the entire subtree is pruned, not just filtered file-by-file), and dispatches each file to the engine for the language registered for its extension. Files >4 MiB are skipped.

Errors from the engine (parse failure, query compile failure) are non-fatal at the file level. The scanner continues. File-system permission errors are similarly swallowed — a reachability run that hits a couple of unreadable files still produces useful output for the rest.

## Install-path discovery

`reachability.InstallPath` is purely filesystem-based — it never invokes the package manager. The ecosystem branches handle:

- **npm/yarn/pnpm/node** — `node_modules/<pkg>` (relies on pnpm's top-level hoisting; Yarn PnP is unsupported).
- **pypi/python/pip** — `.venv|venv|env/lib/pythonX.Y/site-packages/<pkg|pkg_with_underscores>`. Walks the lib dir to find any `pythonX.Y` subdir.
- **go/golang** — `vendor/<pkg>`. Module cache is intentionally not probed.
- **maven/gradle/java** — `target/dependency` (Maven Copy-Dependencies) or `build/dependencies` (Gradle).
- **composer/php** — `vendor/<pkg>`.
- **gem/rubygems/ruby** — `vendor/bundle/ruby/<ver>/gems/<pkg>-*` (walks to find the versioned dir).
- **cargo/rust** — `vendor/<pkg>` (cargo vendor).
- **nuget/dotnet** — not probed (per-user cache, project-local restore is rare).

A return of `""` means no plausible install dir was found; the caller surfaces `SkippedDirect`.

## Data flow

```
vdb vuln CVE-X
   │
   ├─→ client.GetCVE("CVE-X")            ← v1 or v2
   │   memory.RecordVulnLookup(...)
   │
   ├─→ extractEcoPkg(response)            ← determines pkg + ecosystem from CVE
   │
   ├─→ client.V2TreeSitterQueries("CVE-X")  ← v2-only; silent skip on v1
   │   ↓
   │   []TreeSitterQuery
   │   ↓
   ├─→ reachability.Scan(ctx, engine, ScanRequest{...})
   │   ↓
   │   *Result{Direct, Transitive, SkippedDirect, SkippedTransitive, QueriesRun}
   │   ↓
   ├─→ reachabilityToEvidence → memory.RecordReachability(CVE-X, evidence)
   │   reachabilityToOutputMap → attachReachability(&data, block)
   │
   └─→ pretty render OR json print
```

## Testing

Unit tests live at `internal/reachability/engine_test.go` and exercise the engine against fixture grammars. The integration test in `cmd/vdb_reachability_test.go` runs against a fixture lodash repo (`testdata/fixtures/lodash-cve-2021-23337/`) and asserts the expected direct + transitive match counts.

Adding a new fixture: drop a representative source tree under `testdata/fixtures/<name>/`, write a test that calls `runReachability` with the fixture as project root, and assert the match shape. Tests run in normal `just test` and are exercised against every release target via the cross-compile matrix smoke test.

## Performance notes

- **Parser pooling.** `sync.Pool` is keyed per language. A run that hits 1,000 JS files reuses the same handful of parsers; allocator pressure is minimal.
- **Query compilation** is per-(query, language) and not cached across files today. Most CVEs publish 1–3 queries, so compile cost is small. If profiling shows compile time dominating on huge sweeps, a per-Engine query cache keyed on `queryHash` is the obvious extension.
- **No goroutine fan-out per file.** The scanner is single-goroutine. Parallelism is a future optimisation; the bottleneck on transitive sweeps is filesystem I/O more than CPU.
