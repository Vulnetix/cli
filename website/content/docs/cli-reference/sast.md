---
title: "SAST Command Reference"
weight: 6
description: "Run only Static Application Security Testing — evaluates Rego-based rules for code-level security issues with no other scan categories enabled."
---

The `sast` command runs a focused scan that evaluates only SAST (sast-kind) Rego rules against your source files. It is equivalent to running:

```bash
vulnetix scan --evaluate-sast --no-sca --no-secrets --no-containers --no-iac --no-licenses
```

Package vulnerability analysis, license analysis, secret detection, container analysis, and IaC analysis are all disabled. Only general static analysis rules run (not secrets, container, or IaC rules — use `vulnetix scan` or the relevant specialized command for those).

> **Credentials are optional.** When no credentials are configured the [community fallback](https://www.vulnetix.com/features/community) is used automatically.

## Usage

```bash
vulnetix sast [flags]
```

## Flags

All flags from `vulnetix scan` are available except the feature-control flags (`--evaluate-*`, `--no-*`). SAST-specific flags are also available:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-o, --output` | stringArray | - | Output target: `json-sarif` for stdout; `.sarif` file path for file output |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--severity` | string | - | Exit `1` if any SAST finding meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--results-only` | bool | `false` | Only output when findings exist |
| `--disable-default-rules` | bool | `false` | Skip built-in default SAST rules (external `--rule` repos still loaded) |
| `--list-default-rules` | bool | `false` | Print the built-in rule table and exit |
| `-R, --rule` | stringArray | - | External SAST rule repo in `org/repo` format (repeatable) — see [Custom Rule Repositories](../sast-rules/custom-rules/) |
| `--rule-registry` | string | `https://github.com` | Override default registry URL for `--rule` repos |
| `--dry-run` | bool | `false` | Report what this command would scan — rule kinds, external rule packs, discovered files — then replay stored results. Zero API calls. |
| `--snippet-context` | int | `-1` | Source lines captured around each SARIF finding (`-1` = dynamic, `0` disables) |
| `--sast-include-ignored` | bool | `false` | Include files matched by `.gitignore` (default: gitignored paths are skipped) |
| `--suppress-test-code` | bool | `false` | Suppress findings located in the project's test suite (see [Test-suite detection](#test-suite-detection)) |
| `--no-cache` | bool | `false` | Evaluate every file, not reusing rule results kept for unchanged files (see [Result cache](#result-cache)) |

## What is read

- **Text files** in the scan path, up to 1 MiB each. Larger files are listed as "not content-scanned" in the scan's degradations, never as clean.
- **Binary files are not read.** Printable-strings and EXIF extraction feeds the secret rules only, so `sast` skips it. `vulnetix scan` with secrets enabled still extracts them, and no SAST rule sees that synthetic content (`__binary_strings__/`, `__exif__/`, `__git_history__/`, `__k8s_secret__/`).

## Parallelism and memory

Rules are evaluated on a pool of workers, one per core up to 16. A rule that judges one file at a time, most of them, is evaluated a batch of files at a time, so a large project spreads across every worker. A rule that reads more than one file (a configuration value used in code, a constant declared elsewhere) runs once over the files in its scope. Set `VULNETIX_SAST_WORKERS` to change the number of workers; fewer workers use less memory.

## Result cache

A rule that judges one file's text and nothing else gives the same findings for the same text, so a scan keeps those findings and reuses them for files that have not changed. A file is reused when its path and the SHA-256 of its text match the earlier run's. The cache is keyed by the CLI build and by every rule evaluated, so a new release, an edited rule, an added `--rule` pack or a language new to the project starts afresh. Rules that read more than one file, or the file list, are always evaluated. Nosec comments, ignore rules and the org policy apply to every finding on every run, cached or not.

The cache lives in your user cache directory (`~/.cache/vulnetix/sast` on Linux), one file per scanned directory and rule set, with the three newest kept. It holds finding text, which includes the matched source line. Set `VULNETIX_SAST_CACHE_DIR` to move it (for example into a CI cache step), or pass `--no-cache` to evaluate every file. `--explain` never uses it.

A scan sets a soft Go memory limit of 75% of the machine's memory, or of its cgroup's `memory.max` when that is lower, so the runtime collects garbage harder before the kernel would kill the process. Set `GOMEMLIMIT` to choose your own limit; the scan then leaves it alone.

## Examples

```bash
# SAST scan of the current directory
vulnetix sast

# Scan a specific directory
vulnetix sast --path /path/to/project

# Break the build on high or critical SAST findings
vulnetix sast --severity high

# List all built-in rules and exit
vulnetix sast --list-default-rules

# Skip built-in rules and load custom rules from GitHub
vulnetix sast --disable-default-rules --rule myorg/custom-rules

# Load additional rules on top of the built-in set
vulnetix sast --rule myorg/extra-rules

# Use a self-hosted registry for custom rules
vulnetix sast --rule myorg/rules --rule-registry https://git.example.com

# Emit SARIF JSON to stdout
vulnetix sast --output json-sarif

# Write SARIF to a file
vulnetix sast --output results.sarif

# Silent when clean
vulnetix sast --results-only

# Suppress findings that live in the test suite
vulnetix sast --suppress-test-code
```

## Reading the output

The terminal report is organised by **rule**, the way the dependency report is
organised by package. Each rule appears once, with how many places it fired and in
how many files, followed by its top files and their line numbers:

```text
 ✖ SAST 1068 findings in 325 files          150 need action · 846 can wait · 65 in tests · 7 vendored
   12 rules need action · 774 of 2865 rules ran

 NEEDS ACTION · 12 rules · 150 places · production code
 ────────────────────────────────────────────────────────────────────────────────────────────────
 ● HIGH      VNX-GO-014    Lock() without a deferred Unlock()                       69 in 20 files
             internal/lsp/server.go          23   172 184 251 268 287 322 351 +16
             internal/lsp/sca.go             10   231 247 252 260 359 394 534 +3
             internal/display/progress.go     7   68 100 122 150 177 192 199
             + 17 more files

 CAN WAIT · 21 rules · 846 places · medium and low
 ────────────────────────────────────────────────────────────────────────────────────────────────
 ● MEDIUM    VNX-GO-039    Login handler without rate limiting                      37 in 13 files

 IN TESTS · 65 high-severity places · listed, not ranked
 VENDORED · 7 places · third-party files in the tree

 NEXT
   vulnetix sast --explain VNX-GO-014  the rule, and all 69 places with the matched code
   vulnetix sast -v                    one snippet per rule, and every rule that can wait
   vulnetix sast --show tests          rank test code with the rest
```

The groups say what to do, not only how severe:

| Group | What is in it |
|-------|---------------|
| **NEEDS ACTION** | Critical and high findings in production code. |
| **CAN WAIT** | Medium and low findings, one line per rule. The default view shows seven; `-v` lists every rule. |
| **IN TESTS** | Critical and high findings in [test code](#test-suite-detection). They are counted and listed, not ranked. `--show tests` moves them into NEEDS ACTION. |
| **VENDORED** | Critical and high findings under a `third_party/`, `third-party/`, `vendor/`, `vendored/`, `node_modules/` or `bower_components/` directory: code you did not write. The NEXT block names the `--exclude` that stops scanning it. |

These groups only change the terminal view. Every finding stays in SARIF, JSON, the
snapshot upload and the GitHub annotations, and `--severity`/`--fail-on` gate on
severity exactly as before.

`--explain <rule-id>` shows the rule's description and CWE, then every place it fired:
production code first, grouped by file with three matched lines each (all of them at
`-v`), then test code. `--explain <file-path>` explains each rule that fired in that
file. A rule-id query evaluates only that rule. The suggested command adds the `--rule`
pack that supplied it, so a rule from a pack is still explained, and it repeats the run's
`--path`, `--exclude` and other input flags. An explain run writes and uploads nothing
(see [Explaining one finding](../scan/#explaining-one-finding)). [`secrets`](../secrets/), [`iac`](../iac/), [`containers`](../containers/) and
[`malscan`](../malscan/) keep this frame (a verdict line, groups that say what to do, a
NEXT block of commands that exist) but group by the thing you fix: a credential, a
resource, an image, a package.

## Test-suite detection

Because the CLI runs inside your repository, it can tell whether a finding lives in
**test code** rather than production code — and does so with far more confidence than a
filename guess. Each finding's file is classified against an exhaustive table of test
naming conventions across every supported language (`*.test.ts`, `*_test.py`, `*_test.go`,
`*Test.java`, `*_spec.rb`, `*Tests.cs`, `*_test.rs`, `*_test.exs`, `*Spec.scala`, …), and
the guess is **corroborated** with two repo-local signals:

- **Test-runner configuration files** present on disk — `jest.config.js`, `pytest.ini`,
  `pyproject.toml [tool.pytest]`, `phpunit.xml`, `.rspec`, `Cargo.toml [dev-dependencies]`,
  `build.gradle` (junit/testng), and many more.
- **Test frameworks declared as dev-dependencies** in your package-manager manifests
  (`jest` in `devDependencies`, `pytest` in `requirements-dev.txt`, `rspec` in the
  `Gemfile`, …).

A path match **plus** a present config or a declared dependency is recorded as a
**confirmed** attribution. Test-suite findings are:

- tagged in the SARIF result properties (`vulnetix/test-suite`, `vulnetix/test-framework`,
  `vulnetix/test-confidence`, `vulnetix/test-matched-pattern`, `vulnetix/test-evidence`);
- **deprioritized to LOW** in the backend's SSVC prioritization (test code is rarely a
  production attack surface); and
- shown in the Vulnetix app with a **TEST** badge, an "In test code" metric filter, and a
  test-suite evidence panel on the finding detail page.

The detected config files are also uploaded as scan environment metadata (path, framework,
language, size, SHA-256 — **not** their contents) and surfaced on the scan's **Test runners
detected** card.

Pass `--suppress-test-code` to actively suppress test-suite findings instead of just
tagging them — this records an auditable suppression (see
[Ignore / Suppress](../ignore/)) rather than a silent mute.

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from SAST analysis |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, finding counts, git context) |

## SAST Rule Sub-categories

The `sast` command runs only rules with `kind: sast`. For other Rego-based analysis categories:

| Sub-category | Command | Rule kind |
|---|---|---|
| Secret detection | `vulnetix secrets` | `secrets` |
| Container analysis | `vulnetix containers` | `oci` |
| IaC analysis | `vulnetix iac` | `iac` |
| All SAST rules | `vulnetix scan` (default) | all kinds |

The rule kind travels in the SARIF result's property bag as `vulnetix/kind`.
It is not written to SARIF's own `result.kind`, which is a fixed enum
(`notApplicable`, `pass`, `fail`, `review`, `open`, `informational`) and is
left at its default of `fail` for every reported finding.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | A gate was breached (`--severity`), or a fatal error occurred |

## Related Commands

- [`vulnetix scan`](scan/) — Full scan with all features enabled
- [`vulnetix sca`](sca/) — SCA-only scan
- [`vulnetix secrets`](secrets/) — Secret detection only
- [`vulnetix containers`](containers/) — Container file analysis only
- [`vulnetix iac`](iac/) — IaC file analysis only
- [SAST Rules Reference](../sast-rules/) — All built-in rule documentation
