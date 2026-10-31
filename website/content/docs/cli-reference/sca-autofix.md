---
title: "SCA Autofix"
weight: 7
description: "Apply validated dependency fixes with your package manager, rescan to confirm, and emit VEX for resolved vulnerabilities."
---

Remediation is owned by [`vulnetix fix`](../fix/). `--sca-autofix` is the same
workflow triggered inside a wider scan, and this page documents the mechanics both
share.

```bash
vulnetix fix                             # the command that owns remediation
vulnetix sca --sca-autofix               # the same workflow, inside an SCA scan
vulnetix scan --evaluate-sca --sca-autofix
```

The `fix` command exposes the knobs under shorter names (`--strategy`,
`--manifest`, `--max-major-bump`); the `--sca-autofix-*` spellings below keep
working everywhere, including on `fix`.

The CLI requests ranked Safe-Harbour versions from `/v2/cli.sca`, plans direct and transitive fixes, edits supported manifests, runs the project package manager, then runs SCA again to confirm the result. For resolved candidates it writes an OpenVEX document to:

```text
.vulnetix/vex-autofix.json
```

## Strategies

| Strategy | Meaning |
|----------|---------|
| `safest` | The highest stable release that Safe Harbour clears (no known vulnerability, exploit or malware report). Chosen by version order. A pre-release is never picked. |
| `stable` | Default. The stable release closest to the one you run (major, then minor, then patch, a tie goes to the higher). It can be lower than the one you run. |
| `latest` | The highest stable release by the ecosystem's own version rules. A pre-release is never picked. For SemVer ecosystems it is the highest version whatever its date. Where versions cannot be ordered by number it is the most recent release by date. A point release on an old branch is newer by date but is not the latest. |
| `rolling` | The safer rolling: take every version published on the release day of the highest version (UTC; the most recent day when versions cannot be ordered) that is not malware, pre-releases and versions with known vulnerabilities included, and pick the one closest to the version you run. |

Malware is removed before any strategy picks. `safest`, `stable` and `latest` are then drawn from versions Safe Harbour clears (no known vulnerability or exploit). `rolling` is the exception: it follows the release day of the highest version and so can land on a version with a known vulnerability, which the plan output and the advisory data still report. `safest` and `latest` are computed separately and can differ in future; today they usually agree.

The server makes the pick: the VDB returns `safest`, `stable`, `latest` and `rolling` for each package, and the CLI reads them without recomputing. Against an older server that does not return picks, the CLI derives them from the ranked Safe-Harbour versions, and `rolling` falls back to `stable` with a note in the plan. Whatever the strategy, a plan never downgrades a package and never targets the version you already run, so a `stable` pick below your version is dropped from the plan.

Use `--sca-autofix-max-major-bump N` to refuse targets crossing more than `N` major versions. The default is `0`, which keeps every target on the major version you run: a package whose only cleared versions are in a new major is listed as manual. A negative value lifts the cap.

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

The package manager is the one that wrote the lock: `package-lock.json` and `npm-shrinkwrap.json` mean npm, `yarn.lock` yarn (Berry when the lock or `packageManager` says so), `pnpm-lock.yaml` pnpm, and `bun.lock` or `bun.lockb` bun. When it is not on `PATH`, another installed resolver for the ecosystem is used, and with none the fix is marked manual rather than run.

**Workspaces.** In a JavaScript monorepo the lock is at the workspace root. A fix found in the root's lock installs at the root, and a member `package.json` with no lock of its own inherits the root's package manager instead of defaulting to npm (which would write a second, competing lockfile). A direct dependency is usually declared by a member, not the root, so a direct bump or a parent upgrade edits every member manifest that declares the package, and the root then only re-resolves (`bun install`): running `bun add express@4.22.3` at the root would also make `express` a new root dependency. A transitive pin goes into the root `package.json`, where npm, pnpm, yarn and bun read overrides. The dependency edges come from `bun.lock` even when `node_modules/` exists, because Bun installs a workspace in isolated mode and a member's dependencies are not under the root's `node_modules/`.

**One version per parent.** When several vulnerable children share a parent, each can need a different parent version (for `express` 4.17.1: 4.22.0 for `send`, 4.21.2 for `path-to-regexp`, 4.22.3 for `qs`). The installs run in turn, so every parent upgrade of one parent in one manifest is raised to the highest of them, and to a direct bump of the parent when there is one; a lower one would undo a higher one. The plan says when a target was raised.

**The major-version cap covers the parent.** `--max-major-bump` applies to every version a plan installs. A parent upgrade the server recommends that crosses the cap (`express` 4 to 5 to clear a `debug` advisory) is not applied; the plan falls back to a parent update or an override, or is left manual with the reason (`the fix needs express 5.1.0, a new major version from 4.17.1, and the major-version cap is 0`).

A fix left manual is suggested in the project's own package manager (`bun add cookie`, not `npm install cookie`).

### How an override lands in the manifest

When a transitive package has to be pinned, the CLI writes the pin into the manifest section its package manager reads. What is written depends on the ecosystem:

| Ecosystem | Where the pin goes |
|-----------|--------------------|
| npm, bun | `overrides` in `package.json` |
| pnpm | `pnpm.overrides` in `package.json` |
| yarn | `resolutions` in `package.json` |
| PyPI | A pinned line in `requirements.txt` (or `.in`), appended when the package is not already declared. `pyproject.toml` is edited only where the package is already listed. |
| Maven | A pinned entry in `<dependencyManagement>` in `pom.xml` |
| Composer | The package added to `require` in `composer.json` |
| RubyGems | A pinned entry in the `Gemfile` |
| Go, Cargo | No manifest section is written. `go get <module>@<version>` with `go mod tidy`, or `cargo update -p <crate> --precise <version>`, moves the pin in `go.mod` or `Cargo.lock`. |

For the `package.json` sections the file is rewritten as indented JSON, so the order of keys can change. Edits to the other manifests are text edits that leave the rest of the file as it was.

Lockfiles are never edited by hand. After the manifest edit the CLI runs the project's package manager (`npm install`, `pnpm install`, `go mod tidy` and so on), which regenerates the lockfile, and the rescan then confirms the result. The `--dry-run` plan lists the override and the command without touching either file.

The command runs in the manifest's own directory. For Python, a lockfile beside the manifest picks the manager: `uv.lock` runs `uv sync`, `poetry.lock` runs `poetry update <package>`, `pdm.lock` runs `pdm update <package>` and `Pipfile.lock` runs `pipenv update <package>`. Without one, a requirements file (`requirements.txt`, `requirements-dev.txt`, `requirements.in`) runs `pip install -r <file>`, a `pyproject.toml`, `setup.py` or `setup.cfg` project is reinstalled with `pip install .`, and a `Pipfile` runs `pipenv install`.

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
