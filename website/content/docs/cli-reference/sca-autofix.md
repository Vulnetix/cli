---
title: "SCA Autofix"
weight: 6
description: "Apply validated dependency fixes with your package manager, rescan to confirm, and emit VEX for resolved vulnerabilities."
---

`--sca-autofix` turns SCA remediation into an applied workflow:

```bash
vulnetix sca --sca-autofix
vulnetix scan --evaluate-sca --sca-autofix
```

The CLI requests ranked Safe-Harbour versions from `/v2/cli.sca`, plans direct and transitive fixes, edits supported manifests, runs the project package manager, then runs SCA again to confirm the result. For resolved candidates it writes an OpenVEX document to:

```text
.vulnetix/vex-autofix.json
```

## Strategies

| Strategy | Meaning |
|----------|---------|
| `stable` | Default. Pick the smallest Safe-Harbour version greater than or equal to the installed version. No downgrades. |
| `safest` | Pick the newest highest-scoring Safe-Harbour version, preferring vulnerability-, exploit-, and malware-free versions. |
| `latest` | Pick the newest registry version when available, falling back to Safe-Harbour data. No downgrades. |

Use `--sca-autofix-max-major-bump N` to refuse targets crossing more than `N` major versions. The default is `0`.

## Direct and Transitive Fixes

For direct dependencies, the CLI preserves the original version style where possible. A declaration like `^1.2.0` is updated to `^1.2.3`; an exact pin stays exact.

For transitive dependencies, the CLI walks the manifest and lockfile graph to resolve every chain it can, in order of least blast radius:

1. **Parent update** — when a Safe-Harbour child already satisfies the parent's declared range, the lockfile is re-resolved (`npm update <parent>`); no manifest edit needed.
2. **Parent upgrade** — when the parent is a *direct* dependency, its declared range is edited in place to a version whose range admits the safe child.
3. **Override** — otherwise the safe child is pinned deterministically through the package manager's override mechanism (`overrides`, `pnpm.overrides`, or `resolutions`).

| Ecosystem | Autofix depth |
|-----------|---------------|
| npm | Full npm-first graph from `package-lock.json` or installed `node_modules`: parent-update, direct-parent upgrade, and deterministic child `overrides`. |
| pnpm, yarn, bun | Direct upgrades plus transitive pinning via `pnpm.overrides` / `resolutions` / `overrides`. |
| Go, Cargo, PyPI (`requirements.txt`, `pyproject.toml`), RubyGems, Composer, Maven (`pom.xml`) | In-place manifest edits for direct dependencies, then a package-manager re-resolve. |
| Other ecosystems | Command guidance and manual remediation fallback where in-place editing is not yet reliable. |

The report prints proof-of-work counts:

- direct fixes
- transitive fixes via parent update
- transitive fixes via parent upgrade
- transitive fixes via override
- unresolved deep chains

Every finding also gets a copy-and-run command, including skipped or manual items.

## Dry Run

```bash
vulnetix sca --sca-autofix --dry-run
```

This queries VDB for vetted targets and prints proposed edits, commands, transitive chain decisions, and proof counts. It does not edit manifests, run install, rescan, or write VEX.

## CI Usage

Use `--yes` in CI so the command never prompts:

```bash
vulnetix sca --sca-autofix --yes
```

Restrict a monorepo run to one manifest with:

```bash
vulnetix sca --sca-autofix --sca-autofix-manifest apps/api/package.json --yes
```

## How This Differs

Tools such as Socket, Dependabot, and `cve-lite-cli` commonly focus on one ecosystem or direct dependency updates. `--sca-autofix` applies validated direct fixes and, where the manifest or lockfile supports it, follows the parent-child range graph to resolve transitive chains, then rescans to prove the fix landed.
