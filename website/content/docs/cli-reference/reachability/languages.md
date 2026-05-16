---
title: "Language Coverage"
weight: 2
description: "Every tree-sitter grammar bundled with the CLI, the file extensions it covers, the ecosystems that map onto it, and its support tier."
---

The CLI bundles 17 tree-sitter grammars covering the major source languages used in software supply chains. Grammars compile from C into the release binary at build time — there are no separate downloads at runtime, and reachability works against every language below without configuration.

## Coverage matrix

| Language ID | File extensions | Ecosystems | Tier |
|-------------|-----------------|------------|------|
| `javascript` | `.js`, `.mjs`, `.cjs`, `.jsx` | npm, yarn, pnpm, deno (JS source), bower, jspm | 1 |
| `typescript` | `.ts`, `.mts`, `.cts` | npm, yarn, pnpm, deno (TS source) | 1 |
| `tsx` | `.tsx` | npm, yarn, pnpm (React + TypeScript) | 1 |
| `python` | `.py`, `.pyi` | PyPI (pip, poetry, uv, pdm, hatch, pipenv) | 1 |
| `go` | `.go` | Go modules, `go.mod` / `vendor/` | 1 |
| `java` | `.java` | Maven Central, Gradle, JCenter (mirror) | 1 |
| `ruby` | `.rb`, `.rake`, `.gemspec` | RubyGems, Bundler | 1 |
| `rust` | `.rs` | crates.io (Cargo) | 1 |
| `c` | `.c`, `.h` | system / Conan / vcpkg / nix / autotools / CMake | 1 |
| `cpp` | `.cpp`, `.cxx`, `.cc`, `.hpp`, `.hxx`, `.hh` | system / Conan / vcpkg / nix / vcpkg | 1 |
| `c-sharp` | `.cs` | NuGet (.NET / dotnet) | 1 |
| `php` | `.php`, `.phtml` | Composer (Packagist) | 1 |
| `swift` | `.swift` | SwiftPM, CocoaPods (Swift sources), Carthage | 2 |
| `kotlin` | `.kt`, `.kts` | Maven Central, Gradle (`build.gradle.kts`) | 2 |
| `scala` | `.scala`, `.sc` | Maven Central via sbt / Mill / Gradle | 2 |
| `bash` | `.sh`, `.bash` | n/a — surfaces shell-script CVEs (Bash, BusyBox shell scripts) | 2 |
| `lua` | `.lua` | LuaRocks, Neovim plugins, OpenResty bundles | 2 |

**Tier 1 (production-grade):** The grammar is mature upstream, the Vulnetix backend generates queries actively, and CI exercises end-to-end reachability tests against fixture vulns. Expect reliable matching.

**Tier 2 (supported, lower volume):** Grammar is bundled and queries run, but the backend may have fewer per-CVE queries today. False-negative rate is higher simply because fewer CVEs in these ecosystems have published tree-sitter patterns yet. Reachability still runs; absence of matches is just lower-signal than a tier-1 absence.

### Why these and not others?

The bundled set matches the `language` enum that `vdb-manager` emits in `TreeSitterQuery.language`. Adding a new language requires both ends — a query generator on the backend and a bundled grammar on the CLI — so the set evolves in lockstep.

Notable absences:

- **Dart / Flutter** — Tree-sitter grammar is available upstream but the backend doesn't generate Dart queries yet.
- **Elixir / Erlang** — Backend coverage is sparse; not bundled.
- **HCL / Terraform** — Reachability isn't the right model (configuration, not code). Use `vulnetix iac` for IaC misconfiguration scanning instead.
- **YAML / JSON / TOML** — Configuration formats; structural validation lives in other commands (`vulnetix sca`, `vulnetix sast`).
- **Shell variants other than Bash** — fish, zsh, ksh syntax differences mean Bash queries don't fire reliably against them; intentional gap.

### File extension precedence

When a path's extension is ambiguous (`.h` could be C or C++; `.kt` matches Kotlin only) the resolver picks the first matching language in declaration order: C wins over C++ for `.h`. If your project has C++ headers as `.h`, force the recogniser by renaming to `.hpp` or running `--reachability=off` and inspecting `x_treeSitterQueries` manually.

The mapping is one-to-one in the registry, so a `.ts` file is parsed only with the TypeScript grammar (not TSX). Files containing JSX must be named `.tsx` to be picked up by the TSX grammar.

---

## Language ID normalisation

The CLI accepts the common spellings used in the wild and maps them to the canonical ID emitted by the backend. This matters for `--language` filters and when reading raw `x_treeSitterQueries` output.

| You type | Canonical |
|----------|-----------|
| `js`, `ecmascript`, `JavaScript` | `javascript` |
| `ts`, `TypeScript` | `typescript` |
| `py`, `Python` | `python` |
| `go`, `golang` | `go` |
| `rs`, `Rust` | `rust` |
| `c#`, `csharp`, `c-sharp` | `c-sharp` |
| `c++`, `cxx`, `cpp` | `cpp` |
| `kt`, `Kotlin` | `kotlin` |
| `sh`, `shell`, `Bash` | `bash` |

Case is insensitive. Whitespace is trimmed.

---

## Requesting a new language

If you have a CVE in an ecosystem the matrix doesn't cover and you'd like reachability for it, the path is:

1. Confirm a tree-sitter grammar exists upstream and is reasonably mature. The smacker/go-tree-sitter umbrella module is the easiest path; pure upstream tree-sitter grammars also work but require a vendoring step.
2. Open an issue on the Vulnetix CLI repository titled `language: add <language>` listing the file extensions, common ecosystems, a representative CVE, and a link to the grammar.
3. The Vulnetix backend team coordinates: backend query generation is added in `vdb-manager`, and the CLI bundles the grammar in the next release. The CGo binary size grows by 1–3 MB per added language.

Backend-only additions (queries emitted by `vdb-manager` for an unbundled language) flow through the API but are skipped silently by the CLI scanner — they appear in the raw `/vuln/{id}/tree-sitter` response but produce no matches because the grammar isn't bundled. The CLI logs a debug message identifying the unsupported language so future builds can prioritise additions.

---

## Binary-size impact

The bundled grammars add roughly 25–35 MB to each release binary (varies by target — Windows builds are slightly larger, macOS arm64 smaller after strip). This is intentional: shipping every supported grammar in every binary means reachability works without runtime grammar downloads, sandboxed environments, or per-machine installation. The trade-off is binary size; we judged that acceptable for a security tool that runs primarily on developer machines and CI runners.

If binary size is a hard constraint for your deployment, the CLI can be built with a subset of grammars by editing `internal/treesitter/languages.go` to remove unused imports and rebuilding. This is unsupported outside the official release stream but the codebase is structured to allow it cleanly.
