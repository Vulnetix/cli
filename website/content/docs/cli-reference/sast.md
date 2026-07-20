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

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

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
| `--list-default-rules` | bool | `false` | Print built-in SAST rules and exit |
| `-R, --rule` | stringArray | - | External SAST rule repo in `org/repo` format (repeatable) — see [Custom Rule Repositories](../sast-rules/custom-rules/) |
| `--rule-registry` | string | `https://github.com` | Override default registry URL for `--rule` repos |
| `--dry-run` | bool | `false` | Detect files and check memory — zero API calls |
| `--sast-include-ignored` | bool | `false` | Include files matched by `.gitignore` (default: gitignored paths are skipped) |
| `--suppress-test-code` | bool | `false` | Suppress findings located in the project's test suite (see [Test-suite detection](#test-suite-detection)) |

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
