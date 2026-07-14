# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vulnetix is a CLI tool for automated vulnerability management that focuses on remediation over discovery. It's designed as both a standalone Go CLI and a GitHub Action. The tool supports multiple operational modes including authentication healthchecks, artifact uploads, and vulnerability database queries.

## Architecture

This is a Go-based CLI application with the following key components:

- **Main CLI entry point**: `main.go` - Simple entry point that delegates to the cmd package
- **Command structure**: `cmd/root.go` - Uses Cobra CLI framework with comprehensive flag handling
- **Configuration management**: `internal/config/config.go` - Handles all configuration, GitHub context, and task validation
- **Task types**: The root command runs an info healthcheck; subcommands provide auth, upload, gha, scan, and vdb operations
- **GitHub integration**: Deep integration with GitHub Actions environment variables and artifact handling

### VDB Subcommands

The `vdb` command queries the Vulnetix Vulnerability Database API. Commands default to `-V v2`; pass `-V v1` only when the legacy surface is specifically required. `-o json` selects JSON output. v1 is retained for backwards compatibility and will be removed in a future release.

**V1+V2 commands**: `vuln`, `exploits`, `info`, `gcve`, `product`, `packages`, `ecosystems`, `sources`, `summary`, `identifiers`, `eol`, `purl`
**V2-only commands** (require v2, which is now the default — do not pass `-V v1`): `scorecard` (+ `search` subcommand), `timeline`, `affected`, `kev`, `advisories`, `workarounds`, `cwe` (+ `guidance`), `remediation` (+ `plan`), `cloud-locators`, `fixes` (V2 fetches registry/distributions/source in parallel), tree-sitter reachability (`x_treeSitterQueries`)
**Utility**: `status`, `cache` (+ `clear`)

### AIBOM Subcommand

The `aibom` command discovers AI coding agents/assistants and AI usage in a project and emits a CycloneDX AI Bill of Materials. It has four passes — environment (tool/provider env-var *names* only; values are never read), filesystem (tool config dirs, instructions, ignore files, skills, hooks, plugins, steering, memory, prompts, agents, commands, marketplace manifests), source code (AI SDK usage + model-name literals extracted by anchoring on the SDK parameter, so unknown/future models are captured), and commit history (commits authored by an AI agent, via `commit_patterns` matched against author/committer identity + message — Co-Authored-By trailers, session markers, agent bot authors; catches agents like Devin/Jules that leave no working-tree trace). Flags: `--no-env`, `--no-source`, `--no-commits` (default on), `--commit-scan-max`, `--include-home`, `--catalog`.

All detection is driven by the catalog in `internal/aibom/catalog/*.json` (`tools.json`, `libraries.json`, `families.json`) — the single source of truth. After editing the catalog, run `just gen-aibom` to regenerate the docs under `website/content/docs/aibom/`. The catalog is embedded and overridable at runtime with `--catalog`. Output maps tools→`application`, SDKs→`library`, models→`machine-learning-model` (+`modelCard`) components, validated against the bundled CycloneDX schema.

### CBOM Subcommand

The `cbom` command discovers cryptographic usage in code and config and emits a CycloneDX Cryptography Bill of Materials (CBOM, `cryptographic-asset` components, spec 1.6+), classifying each algorithm for post-quantum posture (`quantum-safe`/`quantum-vulnerable`/`deprecated`/`hybrid`) with `nistQuantumSecurityLevel` and a per-country approval matrix. Four passes: source code (per-language crypto API usage + generic call extractors), config (TLS cipher suites/versions, SSH Ciphers/Kex/MACs, JWT `alg`, OpenSSL/IPsec), certificates (X.509 certs/keys on disk via `crypto/x509` — metadata only, never key bytes), and dependencies (declared crypto libraries). Algorithm spellings are **case/separator-insensitive and stored under the canonical SPDX name** — `SHA256`/`Sha256`/`sha256`/`SHA_256` collapse to one asset (see `internal/cbom/normalize.go`). Flags: `--no-source`, `--no-config`, `--no-certs`, `--no-deps`, `--fail-on` (opt-in CI gate on a PQC status; default `none`/exit 0), `--catalog`, `--no-builtin-catalog`, `--spec-version`, `--output-file` (default `.vulnetix/cbom.cdx.json`), `-o {pretty,json,cyclonedx-json}`, `--no-upload`.

Detection is driven by the catalog in `internal/cbom/catalog/*.json` (`algorithms.json` with aliases/primitive/`pqc_status`/`standards`/`source_patterns`/`config_patterns` + top-level `call_extractors`; `libraries.json`) — the single source of truth, validated (regex + CycloneDX enum ranges) by `Compile()`. After editing, run `just gen-cbom` to regenerate docs under `website/content/docs/cbom/`. The `CryptoDetections` types + `BuildCBOM`/`ParseCBOM` builder live in the shared `vdb-cyclonedx` module (parity with `BuildAIBOM`); the CLI calls `cyclonedx.BuildCBOM`. Authenticated runs upload to `/v2/cli.cbom` (best-effort; backend endpoint is a follow-up).

### AI Firewall Subcommand

The `ai-firewall` command wires local AI clients to the hosted OpenAI-compatible gateway at `https://guardrails.vulnetix.com/{providerSlug}/{orgUuid}/v1` (org is a **URL path component**, unlike the Package Firewall which carries it as the HTTP Basic username), and manages the org policy the gateway enforces. Two keys: the client sends `Authorization: Bearer $VULNETIX_API_KEY`; the org's *provider* key is held server-side (BYOK, KMS-encrypted, write-only) and swapped in by the gateway.

Command tree: `install [client...]` / `uninstall [--all|--except]` / `status [--strict]` / `policy {provider,model,guardrail}` / `key {set,remove}` / `settings` / `get` / `apply` / `export` / `baseline` / `snippet`. `config set|get ai-firewall` still works — the same constructors in `cmd/config_ai_firewall.go` are registered under both parents (delegate, not alias: a `*cobra.Command` cannot live in two trees).

Clients (`pkg/aifirewall/clients.go`): `shell`, `env` (project `.env`/`.envrc`/`Makefile`, existing files only), `claude-code` (JSON merge into `settings.json` `env`), `codex` (textual TOML block — never a `toml.Marshal` round-trip, which drops comments), `continue` (YAML Node API + the unavoidable literal key in `~/.continue/.env`), `aider`, and `cursor`/`windsurf` (**detect-and-instruct only** — their base URL lives in app state, so writing a file would be a lie).

Three facts drive the design and must not be "fixed": (1) only `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `ANTHROPIC_BASE_URL` (and probably `GROQ_BASE_URL`) are read by real SDKs — `MISTRAL_BASE_URL` etc. **do not exist**, so those providers get a snippet, not an invented env var; (2) Anthropic needs `ANTHROPIC_AUTH_TOKEN`, not `ANTHROPIC_API_KEY` (the latter is sent as `x-api-key`); (3) Codex requires `wire_api = "responses"` and Claude Code speaks `/v1/messages`, so both are gated on the server's `gateway.wireApis` advertisement and **skipped with a reason** when it is absent.

File writing goes through `internal/managedfile` (extracted from `cmd/package_firewall.go`, shared by both firewalls): `Markers` are a **parameter**, so `package-firewall uninstall` cannot strip the AI Firewall's block from the same `~/.zshrc`. Whole-file writes (Structured/Merge) always back up to `<path>.vulnetix.bak`; managed blocks are reverted surgically and never restore a stale backup.

Declarative policy lives in `.vulnetix/ai-firewall.yaml` (`apiVersion: vulnetix.com/v1`, `kind: AiFirewallPolicy`); `apply` plans in the order **guardrails → models → providers → keys → settings** so tightening never opens a window, reports unmanaged server objects as drift (deletes only with `--prune`), and composes in the server's recommended guardrail baseline (`cli.ai-firewall-baseline`, soft-fails on 404 unless `--baseline-required`). Guardrails reconcile by **name**, so names must be unique. Patterns are Go RE2 — no lookaround — and an uncompilable pattern is *skipped by the gateway*, so `status` compiles every one and warns.

Backend follow-ups (not yet implemented): `cli.ai-firewall-get` must return `hasKey`/`keyUpdatedAt`/`logsEnabled`/`gateway.wireApis`; new endpoints `cli.ai-firewall-key`, `cli.ai-firewall-settings`, `cli.ai-firewall-baseline`. The CLI ships first and tolerates their absence. Docs: `website/content/docs/ai-firewall/` (hand-written, not generated).

### Malscan Subcommand

The `malscan` command runs the `malscan-engine` (module `github.com/vulnetix/malscan-engine`, consumed like `vdb-cyclonedx`) **in-process** against the project's locally-installed dependencies — unlike `--block-malware` on the `sca` path, which defers to the backend's periodic pipelines. It runs the full engine over each resolved ecosystem target: `iocscan.Scan` (STIX IOC filesystem scan — known-bad domains/IPs/URLs in text + extracted binary strings, with file+line+context), `detect.Detect` (manifest/install-script pattern + shell-obfuscation detectors), `ioc.ExtractIOCs`, and `badhash` (known-bad artifact-hash blocklist over declared/candidate hashes).

Scan targets are resolved per ecosystem by `internal/ecosystems/locations.go` — the single source of truth mapping each ecosystem to its engine slug + project-local install dirs (npm `node_modules`, python `site-packages`/`.venv`, go `vendor`, rust/cargo, ruby, php, java, dotnet, dart, elixir) and user-scoped/home caches (`~/.npm`, `~/go/pkg/mod`, `~/.cargo`, `~/.m2`, …). Home caches are scanned only with `--include-home`. Findings are SARIF (with code samples, evidence context and host env), always written to `.vulnetix/malscan.sarif` (override with `--output-file`), pretty-printed unless `-o {json,sarif}`, and uploaded to `/v2/cli.malscan` when authenticated. Flags: `--path`, `--include-home`, `-o`, `--output-file`, `--no-binary-analysis`, `--scan-depth`, `--max-file-size`, `--no-ioc-feeds`, `--catalog`, `--no-upload`.

Exit status is non-zero when malware is found on direct `malscan` usage. The pass is also hooked into `scan` (runs by default; `--no-malscan` disables) and `sca` (runs only when `--block-malware` is passed or org policy `blockMalware` is enforced); in those, it contributes a `malware` quality-gate breach only when block-malware is in effect. The backend endpoint persists a `MALWARE` ScannerRun + IngestionSnapshot + Finding/Triage/OpenVEX plus `MalwareIoc` rows with offending-file samples stored to S3 (ecosystem-attributed `{ecosystem}/files/{sha256}/{filename}`).

## Build and Development Commands

Use the justfile for all development tasks:

```bash
# Build for development
just dev

# Build production binary
just build

# Run tests
just test

# Format code
just fmt

# Lint code (uses golangci-lint if available, falls back to go vet)
just lint

# Build for all platforms
just build-all

# Clean build artifacts
just clean

# Download and tidy dependencies
just deps

# Run with test UUID
just run
```

## Key Configuration Patterns

The application uses a centralized configuration system (`VulnetixConfig`) that:

- Validates all inputs including UUID format for org-id
- Loads complete GitHub context from environment variables
- Supports YAML parsing for complex inputs (tools, tags)
- Provides artifact naming conventions for GitHub Actions workflows
- Handles different task types with specific validation rules

## Testing

Tests are minimal currently (`cmd/root_test.go`). Run with:
```bash
just test
```

## Important Development Notes

- The CLI requires a valid UUID for `--org-id` parameter
- Version is injected at build time via ldflags
- GitHub context is automatically loaded from environment variables
- Tool configurations use YAML format for complex artifact specifications
- The application is designed primarily for CI/CD environments, particularly GitHub Actions