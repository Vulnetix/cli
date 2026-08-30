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

**V1+V2 commands**: `vuln`, `exploits`, `gcve`, `product`, `packages`, `ecosystems`, `sources`, `summary`, `ids`, `eol` (+ `product`/`release`), `purl`
**V2-only commands** (require v2, which is now the default — do not pass `-V v1`): `scorecard` (+ `search` subcommand), `timeline`, `affected`, `kev`, `advisories`, `workarounds`, `cwe` (+ `guidance`), `remediation` (+ `plan`), `cloud-locators`, `fixes` (V2 fetches registry/distributions/source in parallel), tree-sitter reachability (`x_treeSitterQueries`)
**Utility**: `status`, `cache` (+ `clear`)

### `scan` Is An Orchestrator — Do Not Give It Private Logic

`scan` composes the scanner subcommands; it owns no analysis of its own. All five specialized scanners (`sca`, `sast`, `secrets`, `containers`, `iac`) call the same `runScanWithFeatures`, and the engine branches on **feature booleans, not `cmd.Name()`**. Three name-keyed exceptions are deliberate and documented: rule-kind lock (`specializedRuleKinds`), manifest `.gitignore` policy (`respectGitignoreManifest`, only `containers`/`iac` prune), and the malscan trigger (`shouldRunMalscanPass`: always for `scan`, `--block-malware`-gated for `sca`).

Every capability has exactly one owner, reached through one options-struct entry function that both the owner's subcommand and the scan engine call:

| Capability | Owner entry point | File |
|---|---|---|
| License policy | `runLicensePipeline(LicenseRunOptions)` | `cmd/license.go` |
| License policy/exception documents | `loadLicenseGovernance` | `cmd/license_policy.go` |
| AI inventory | `runAIBOMPass(AIBOMPassOptions)` | `cmd/aibom.go` |
| Crypto inventory | `runCBOMPass(CBOMPassOptions)` | `cmd/cbom.go` |
| Built-in rule listing | `handleSASTRuleListing` / `listBuiltinSASTRules` | `cmd/sast_rules.go` |
| Local malware | `runMalscanForGate` | `cmd/malscan.go` |
| Remediation (autofix) | `fixCmd` + helpers | `cmd/fix.go`, `cmd/fix_autofix.go` |
| Report replay | `renderStoredReport` → `LoadFromMemory` | `cmd/report.go`, `cmd/from_memory.go` |
| SBOM reading | `runBOMImport(BOMImportOptions)` | `cmd/bom.go` |
| SBOM corpus queries | `runBOMCorpus(BOMCorpusOptions)` | `cmd/bom_corpus.go` |
| SBOM enrichment | `runBOMEnrichPass(BOMEnrichOptions)` | `cmd/bom_enrich.go` |
| VEX consumption | `runVEXPass(VEXPassOptions)` | `cmd/vex.go` |
| Attestation verification | `runAttestVerify(AttestVerifyOptions)` | `cmd/attest.go` |
| BOM authoring identity | `Authoring` / `Participating` / `ResolveManufacturer` / `DerivePhases` | `internal/cdx/authorship.go` |

When adding a capability: put it behind such a function in its owner's file and have `scan` call it. Do not inline a second implementation into `cmd/scan.go` — that is how the license stage came to run a weaker fixed-policy fork of `vulnetix license`.

Flags registered family-wide by `addScanFlags`/`addSASTFlags` must be **honoured** family-wide. `--dry-run` and `--list-default-rules` are handled inside `runScanWithFeatures` (before any network work) precisely so every subcommand honours them; `--snippet-context` lives in `addSASTFlags` because it shapes SARIF for every rego command. `cmd/scan_flag_ownership_test.go` locks this in.

`--from-memory`/`--fresh-*` on `scan` are deprecated aliases delegating to `report`; `--sca-autofix` is the in-pipeline trigger for `fix`. Keep both working.

### `cdx` Writes SBOMs, `bom` Reads Them

Two nouns, deliberately. `cdx` (alias `sbom`) generates a CycloneDX document from
a working tree. `bom` consumes documents this CLI did not necessarily write —
CycloneDX 1.0–1.7 and SPDX 2.2/2.3, bare or inside an in-toto attestation
envelope (DSSE or plain). That envelope case is the one a `bomFormat` check
misses entirely, and it is the shape Syft and BuildKit emit for container SBOMs.

Everything parsed normalises into one canonical model, `cdx.BOM`. SPDX in,
CycloneDX model out, so diff, validate, licence evaluation and VEX application
are written once instead of once per serialisation. What the document originally
was is stamped into `metadata.properties` (`vulnetix:bom/source-format`,
`-spec-version`, `-envelope`, `-digest`, `-path`) — normalisation is lossy, and
the stamp is what keeps it honest.

Single-document: `import`, `validate`, `diff`, `merge`, `tree`. Corpus (`--from`
a file, directory or glob): `ls`, `where`, `skew`, `search`. The corpus layer has
no store and no server — it indexes in memory per invocation, because the
questions it answers are about documents already on disk. The bigger version of
the same question, across every repository and over time, is what the deployment
labels push to the backend instead.

`bom diff` matches components by versionless purl, then bom-ref, then
name@version — the cascade `internal/cdx/merge.go` already proved — so a bump
reads as one upgrade rather than an add plus a remove. Versions are ordered
through `internal/versions`, so a downgrade says downgrade. `purlWithoutVersion`
splits on the **last** `@` after the final `/`: splitting on the first collapses
every scoped npm package to `pkg:npm/` and pairs unrelated components.

**Deployment context** (`--project`/`--cluster`/`--namespace`/`--environment`/
`--tag`) is registered family-wide by `addScanFlags` and read in exactly one
place, `scanopts.DeploymentFromCommand`. Cluster and project are separate
dimensions on purpose: a scan belongs to `prod-eu` AND `payment-service` at once,
and collapsing them makes either query impossible. Nothing is inferred from a
branch name — a wrong environment label is worse than an absent one. The labels
travel into CycloneDX metadata, memory and the `cli.*` upload envelope, because
a repository scan cannot know where its artefacts run and the pipeline that
deployed them can.

### The Document Model Lives In `vdb-cyclonedx`, Not Here

`cdx.BOM` is a **type alias** for `cyclonedx.Document`, not a local declaration.
This package used to declare the model itself, and the cost was not the
duplication — it was that two declarations are two sets of omissions, and they
did not match. The local one had no `metadata.manufacturer` and no
`metadata.supplier`, which is most of what CycloneDX uses to say who produced a
document. It was also lossy: decoding a third-party BOM into it dropped every
member it did not declare, which is why `internal/scanopts` carried a **third**,
map-based implementation of deployment labelling rather than reuse
`ApplyDeploymentContext`.

The shared model round-trips unmodelled members through an `Extra` map, so a
command asked only to label a document no longer narrows it. Do not add fields
to a local copy of the model — add them upstream and let the alias carry them.
`TestStampDeploymentJSONPreservesUnknownFields` and the library's
`document_extra_test.go` are what keep this true.

### BOM Authoring Identity: Author, Transformer, Reader

CycloneDX has no "authoring" field. It splits the idea across `metadata`:
`manufacturer` is "the organization that **created the BOM**" (automated
processes), `authors` is the same for manual ones, `tools` is "the tool(s) used
in the **creation, enrichment, and validation** of the BOM", `supplier` is
subject-level, and `lifecycles` is "the stage(s) in which **data in the BOM was
captured**". Three tiers follow, and every emitting path is one of them:

- **Author** — creates a document. Owns `serialNumber`, `version`,
  `metadata.timestamp`, `manufacturer`, `lifecycles`, and the first
  `metadata.tools` entry. `scan`/`sca`/`containers`, `cdx`, `aibom`, `cbom`, VEX.
- **Transformer** — enriches, converts or validates a document it did not
  create. **Appends** itself to `metadata.tools` and touches nothing else;
  `NextRevision` re-identifies the output only when it is written to a new path.
  `bom enrich`, `bom import`, the licence pass.
- **Reader** — `diff`, `tree`, `ls`, `where`, `skew`, `search`, `attest verify`.
  Stamps nothing.

Two rules that are easy to get wrong and were:

**`manufacturer` is the org running the scan, not Vulnetix.** Vulnetix is the
tool and belongs in `metadata.tools`. It is resolved by one function,
`cdx.ResolveManufacturer`, and returns **nil rather than guessing** — an absent
manufacturer costs a reader one unknown, an invented one is a false claim.
Enriching syft's SBOM must not overwrite `manufacturer: Anchore`.

**Authorship is spec-version-conditional.** `metadata` carries
`"additionalProperties": false` from 1.4, `manufacturer` exists only in 1.6+,
`lifecycles` in 1.5+, and the object form of `tools` in 1.5+ — so emitting
`manufacturer` into the 1.5 document the VEX path produces is a hard validation
failure. `Document.MarshalJSON` projects members away for versions that cannot
carry them (`specversion.go`); callers never do this themselves. 2.0 additionally
renames `bomFormat` to `specFormat` and closes the document root.

`metadata.tools.components` carries `uniqueItems: true` from 1.5, so dedupe on
append is a validity requirement, not tidiness — enriching one document twice
would otherwise produce a document that fails its own schema.

The tool entry is built in exactly one place (`cdx.Authoring` /
`cdx.Participating`) and carries a real version from `internal/buildinfo` — four
builders used to default it to the literal string `"cli"`. `--lifecycle` and
`--bom-manufacturer` are registered by `addScanFlags` and on `cdx`, and are
**not** registered on transformer-tier commands, which have no manufacturer to
claim. `cmd/bom_authoring_ownership_test.go` locks all of this in.

### VEX Is Consumed As Well As Emitted

`internal/triage` writes VEX from this CLI's own triage decisions;
`internal/vex` reads VEX that somebody else wrote. Both directions matter, and
only the read side lets an upstream's "this CVE does not affect the
configuration we ship" reach a scan.

OpenVEX 0.2.0, CycloneDX VEX and CSAF 2.0 VEX normalise to one statement model.
Each hides the same assertion somewhere different: CSAF scatters the
justification into a `flags` entry and the prose into a `threats` entry, both
keyed by an opaque `product_id` defined in a nested product tree; CycloneDX puts
it in `analysis`, and **an entry with no analysis block is a finding, not an
assertion** — reading those as VEX would turn every SBOM into statements
asserting nothing.

Matching is a cascade, not exact equality on (vulnerability, purl). Exact
equality is why VEX so often appears to do nothing, and it fails **silently**:
a statement against `pkg:npm/foo@1.2.3` misses 1.2.4, a statement naming a
package with no version matches nothing though it means every version, and an
identifier written as a URL never compares equal to a bare id. So:
versionless-purl and range matching, alias matching, URL identifiers reduced to
bare ids, most-specific basis winning with newest timestamp breaking ties.
Every match records its basis and source.

**Nothing is deleted.** A suppressed finding keeps its entry, gains an analysis
block and `vulnetix:vex/*` provenance properties, and is counted separately —
total, suppressed, effective. `--vex-file`/`--no-vex` are family-wide and applied
in **one place immediately before the gates** (`filterVEXSuppressed`), so every
gate honours VEX by construction; filtering per gate would leave one that could
be forgotten, and the forgotten one fails a build over a finding the vendor
already excluded.

### Attestation Verification: Do The Work, Then Be Exact About It

`internal/cdxsign` signs; `internal/attest` verifies. Two rules pull against
each other and both matter. A green tick for a check that did not run converts
an unknown into a false assurance. But a verifier that answers every question
with "you did not tell me what to trust" is not careful either — it is making
the user do its job and calling that honesty.

The first version got this wrong and it is worth not repeating. It skipped chain
validation unless given `--trusted-root`, listed the identity and issuer as
"skipped" whenever no expectation was supplied, and printed six rows of which
four said skipped. A non-expert read that as having failed at something, with no
indication of what.

What it does now:

- **The Sigstore public-good root is embedded** (`internal/attest/roots/`) and
  used by default, exactly as cosign does. `--trusted-root` is an override for a
  private deployment, not a prerequisite. A chain that does not anchor there
  *fails* and says to pass `--trusted-root` — it does not shrug.
- **`parseCertificate` reads the whole PEM bundle.** Fulcio returns leaf +
  intermediate + root and the signer stores all of it; decoding only the first
  block threw the intermediates away and made every chain check unable to build
  a path. That single bug is why chain validation looked impossible without user
  input when the material was in the file already.
- **The identity is a fact, not a check.** It is always read and always
  reported. Comparing it against an expectation is the check, and only runs when
  one is given.
- **What is genuinely not done becomes a `Suggestion`** carrying a complete,
  pre-filled command — never a fragment with an ellipsis, which a reader can
  only complete if they already knew the answer. Ordered most-actionable first;
  the cosign invocation for transparency-log inclusion goes last.
- `--require <check>` turns "did not run" into a failure, for a pipeline needing
  a specific assurance rather than the default set.

The embedded root is pinned rather than fetched over TUF. `TestEmbeddedRootIsUsable`
fails once it expires, so the day the pin goes stale is loud rather than a
mystery chain error.

An expired certificate **passes** with a caveat. Fulcio certificates live ten
minutes, so failing every signature older than that would make the verifier
useless; what an expiry cannot tell you without a log entry is whether the
signature predates it, and the detail says so.

`Predicate` reads SLSA v0.2 and v1 provenance but deliberately reports **fields
present, not a SLSA level**. A level is a property of the build platform, which
no consumer can determine by reading a document that build produced.

`bom enrich` resolves licences, attaches VDB vulnerabilities and applies VEX to
a supplied document, and must not lose two things. Fidelity: the input's digest
is stamped on the output and `--keep-original` writes the input beside it, so a
transformation is always traceable. Attribution: `--sign` signs with **this**
machine's identity, because this machine made these claims; a signature on the
input attests the input and is preserved as a property rather than discarded.
The VDB request carries a `CliToolAttribution` naming the input's own generator,
so the server records "syft found these, Vulnetix enriched them" rather than
claiming the discovery.

### Licence Policy And Exceptions

`.vulnetix/license-policy.yaml` classifies by category and attaches a severity;
`.vulnetix/license-exceptions.yaml` records approved exceptions with approver,
date, grounds and expiry. Both are loaded by `loadLicenseGovernance` and reach
the evaluator only through `runLicensePipeline`, so `scan --evaluate-licenses`
and `license` cannot disagree about the same repository.

`DefaultPolicy()` reproduces **exactly** what the evaluator did before policies
existed — only strong copyleft carries a severity, no scope is ignored — so an
upgrade never turns a build red for a decision nobody made. `RecommendedPolicy()`
is the stricter one `license policy init` writes.

Exception name matching is anchored at path-segment boundaries, **not
substring**: a substring test makes an exception for `gpl-lib` silently cover
`agpl-lib`, a different and stricter licence. Purl matching strips the version so
an exception does not lapse on the next dependency bump. An expired exception
stops applying and says so; exempted findings are retained, badged and counted
separately, and only the gate ignores them.

### SBOM/CDX Subcommand

The `cdx` command (alias `sbom`, implemented in `cmd/cdx.go`) writes one offline CycloneDX document — no VDB lookup, upload, memory write, quality gate or container daemon. Discovery passes: manifests/lockfiles, installed package trees (`internal/ecosystems`), container package DBs (dpkg/apk/pacman), Dockerfile/compose/k8s/Helm, CI/CD pipeline files, shell scripts + Makefile/justfile recipes, and **compiled artefacts** via `internal/binpkg`. AIBOM and CBOM components are merged into the same file.

`internal/binpkg` is the binary→package reader: Go build info (`debug/buildinfo`, so ELF/PE/Mach-O/XCOFF — main module, every linked module with its H1 sum, and the toolchain as `stdlib` in ecosystem `golang`), Rust `cargo auditable` (zlib JSON in the ELF `.dep-v0` section, including crate edges), and JVM archives (`META-INF/maven/**/pom.properties` → `MANIFEST.MF` → filename, plus jars nested one level inside a fat jar). `ownership.go` reads dpkg/apk/pacman **file lists** so each artefact is attributed to its installing package (RPM is unreadable without a native lib — never report those images' binaries as `unpackaged`).

Parity with `sca` is a requirement, not a nice-to-have: components carry purl/ecosystem/scope/environment/direct-ness/source-file/source-type/installed-path/checksums/signatures **plus** the `cdx.BuildDependencies` graph and `license.DetectLicenses` results (SPDX ids land in `license.id` via `SBOMOptions.CanonicalSPDXID`). Every component's `bom-ref` is assigned in `dedupeCDXPackages` (purl when there is one) because the graph references components by ref — `file` components are excluded from that name→ref index or a package edge resolves to a binary. Evidence confidence is graded by source: manifest/installed/container-db = high, pinned install command = medium, unpinned = low.

The default output path is the same `.vulnetix/sbom.cdx.json` that `scan`/`sca` use as memory, so `preserveCDXVulnerabilities` carries existing `vulnerabilities` (and any component they reference, marked `vulnetix:sbom/carried-over`) into the new document. Do not "simplify" that away.

CI/CD and shell coverage is driven by `internal/scan/detector.go` (`ciPipelineDirs`, `ciPipelineNameSuffixes`, `looksLikeGitHubActionsPath`, `IsCIPipelineFile`) plus the command-key list in `vdb-sca-match/parse` (`isCICommandKey`, multi-document YAML decode). `parseCIFileScoped` runs the YAML walk **and** the line-oriented shell pass on every CI file — Kotlin/Groovy/TOML pipelines parse as YAML scalars without error, so "did it parse as YAML" is not a usable fallback test. Note that a bare package name equal to a package-manager binary (`npm i -g pnpm`) is treated as a command boundary, not a package — pick fixtures accordingly. GitHub Actions files count as CI for `--no-ci`/`--no-ci-package-analysis`. After changing detection, update `website/content/docs/cli-reference/cdx.md` — its coverage tables are hand-maintained.

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

### Binary Inventory (`containers` ELF pass)

`containers` runs a second, internal pass after the Rego one: `runBinaryScan`
walks the filesystem for ELF binaries and posts them to `/v2/cli.analyze` as
`ContainerBinary` rows — hashes, ELF header, hardening weaknesses, capabilities,
strings, EXIF, the CIRCL hashlookup correlation and the malware-corpus verdict.

Two rules keep it honest, and both are load-bearing:

  - It does **no** CVE matching. Packages compiled into binaries already travel
    as real purls (`internal/binpkg` → the SBOM → `/v2/cli.sca`). A hashlookup
    package *name* carries no ecosystem, so matching it against advisories is
    string-matching "openssl" across every source in the database.
  - It creates **no** findings. Malware raises its finding through
    `/v2/cli.malscan`, which owns the Finding/Triage/OpenVEX chain; this pass
    marks the verdict on the row and counts it.

`findingsCreated` and `cveMatches` in the response are therefore structurally 0.
They are kept in the shape rather than removed so a client does not break if
either ever gains a source it can substantiate.

The pass attaches to the container scan's snapshot via
`lastContainerSnapshotUuid` (set by `runLocalScan`, consumed by
`runBinaryScanPath`) so one invocation records one snapshot. It runs after
`runScanWithFeatures` has returned, which is why the value travels in a package
var rather than an argument.

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