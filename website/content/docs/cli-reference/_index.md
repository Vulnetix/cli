---
title: "CLI Reference"
weight: 3
description: "Complete reference for all Vulnetix CLI commands, flags, and usage patterns."
---

Complete reference for all Vulnetix CLI commands, flags, and usage patterns.

## Commands

### vulnetix (root command)

Run vulnerability management tasks against the Vulnetix backend.

```bash
vulnetix
```

The root command runs an authentication healthcheck.

| Task | Description |
|------|-------------|
| `info` (default) | Authentication healthcheck across all credential sources |

**Global Flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--org-id` | string | Organization ID (UUID) |
| `--api-key` | string | Direct API key (overrides VULNETIX_API_KEY) |
| `--help` | - | Help for any command |

---

### vulnetix auth

Manage authentication credentials for the Vulnetix API.

```bash
vulnetix auth [login|status|verify|logout] [flags]
```

#### auth login

Authenticate with Vulnetix. Interactive by default when run in a terminal.

```bash
# Interactive browser device flow (prompts for storage)
vulnetix auth login --store keyring

# Non-interactive login with an ApiKey
vulnetix auth login --api-key <KEY> --org-id <UUID> --store keyring

# Non-interactive login with a SigV4 secret
vulnetix auth login --secret <SECRET> --org-id <UUID> --store keyring

# Non-interactive login with a Bearer token (org resolved server-side)
vulnetix auth login --token <TOKEN> --store keyring
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--org-id` | string | - | Organization ID (UUID). Required by `--api-key` and `--secret`; ignored by `--token` |
| `--api-key` | string | - | ApiKey hex digest |
| `--secret` | string | - | SigV4 HMAC secret — **not** an alias for `--api-key` |
| `--token` | string | - | Bearer token |
| `--store` | string | `home` | Credential storage location: `home`, `project`, `keyring` |
| `--store-dir` | string | - | Directory for home/keyring metadata instead of `$HOME/.vulnetix` |
| `--noninteractive` | bool | `false` | Require an ApiKey from flags or environment; never launch a browser |
| `--method` | string | - | **Deprecated.** The credential flag now selects the method |

`--api-key`, `--secret`, and `--token` are mutually exclusive. Running `vulnetix auth` without a subcommand also triggers login.

See [Authentication](/docs/authentication/) for storage backends, precedence, file permissions, and rotation.

#### auth status

Show current authentication state, including the credential source, method, masked key, and Package Firewall `.netrc` status.

```bash
vulnetix auth status
```

#### auth verify

Verify that stored credentials can authenticate with the Vulnetix API. Does not modify credentials.

```bash
# Verify stored credentials
vulnetix auth verify

# Verify with explicit API endpoint
vulnetix auth verify --base-url https://api.vdb.vulnetix.com/v1
```

#### auth logout

Remove stored credentials from all file-based stores.

```bash
vulnetix auth logout
```

---

### vulnetix package-firewall

Configure package managers to use the Vulnetix Package Firewall.

```bash
vulnetix package-firewall go [flags]
```

#### package-firewall go

Configure Go to use `https://packages.vulnetix.com` with `.netrc` authentication.

```bash
vulnetix package-firewall go
vulnetix package-firewall go --dry-run
```

This command writes a `machine packages.vulnetix.com` entry to `.netrc`, persists `GOPROXY` and `GOAUTH=netrc` in your shell configuration, and updates detected project files at the git root (`.env`, `.envrc`, `Makefile`).

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--base-url` | string | `https://api.vdb.vulnetix.com` | VDB API base URL |
| `--proxy-url` | string | `https://packages.vulnetix.com` | Package Firewall Go proxy URL |
| `--dry-run` | bool | `false` | Show planned changes without writing files |

#### package-firewall uninstall

Remove the configuration written for one, some, or every ecosystem. Needs no authentication — it operates on local files only. See [Uninstall](/docs/enterprise/package-firewall/uninstall/).

```bash
vulnetix package-firewall uninstall npm pypi        # named ecosystems
vulnetix package-firewall uninstall --all            # every supported ecosystem
vulnetix package-firewall uninstall --except aur     # all but the named ones
vulnetix package-firewall uninstall --purge          # every ecosystem + the shared netrc credential
```

Exactly one selector is required: positional ecosystem(s), `--all`, or `--except`. The shared `~/.netrc` credential is kept unless `--remove-credentials` or `--purge` is given.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Unconfigure every supported ecosystem |
| `--except` | strings | — | Unconfigure all supported ecosystems except these |
| `--remove-credentials` | bool | `false` | Also remove the shared netrc credential (`machine packages.vulnetix.com`) |
| `--purge` | bool | `false` | Remove the shared netrc credential and every supported ecosystem |
| `--proxy-url` | string | `https://packages.vulnetix.com` | Package Firewall proxy URL (host to detect and strip) |
| `--dry-run` | bool | `false` | Show planned changes without writing files |

---

### vulnetix config

Manage Vulnetix configuration. This manages the [Package Firewall](/docs/enterprise/package-firewall/policies/) per-organization policy and ecosystem mirrors, the org-wide [Quality Gate](/docs/enterprise/quality-gates/) scan-enforcement policy, and the Quality Gate end-of-life severity buckets. The organization is resolved from your authenticated session (`vulnetix auth login`).

```bash
vulnetix config set package-firewall [ecosystem] [url] [flags]
vulnetix config get package-firewall [flags]
vulnetix config set quality-gate [flags]
vulnetix config get quality-gate [flags]
vulnetix config set eol-policy [flags]
vulnetix config get eol-policy [flags]
```

#### config set package-firewall

Two forms, distinguished by positional arguments.

**Policy form** (no positionals) — updates the org-wide policy. Each call is a partial update; only the flags you pass change.

```bash
vulnetix config set package-firewall --cvss-threshold 8.0 --block-malware true --cooldown-days 7
```

| Flag | Type | Value | Description |
|------|------|-------|-------------|
| `--cvss-threshold` | float | `0`–`10` | Block when max CVSS ≥ value (`0` disables) |
| `--epss-threshold` | float | `0`–`1` | Block when EPSS probability ≥ value |
| `--cess-threshold` | float | `0`–`10` | Block when Vulnetix CESS ≥ value |
| `--block-malware` | bool | `true\|false` | Block known-malicious packages |
| `--block-eol` | bool | `true\|false` | Block end-of-life versions |
| `--block-kev` | bool | `true\|false` | Block CISA KEV / VulnCheck KEV CVEs |
| `--block-weaponized-exploits` | bool | `true\|false` | Block weaponized exploitation |
| `--block-active-exploits` | bool | `true\|false` | Block active exploitation sightings |
| `--block-poc-exploits` | bool | `true\|false` | Block public PoC / exploit records |
| `--block-bad-actors` | bool | `true\|false` | Block CVEs linked to malicious actors |
| `--cooldown-days` | int | `≥ 0` | Quarantine versions published within the last *n* days |
| `--version-lag` | int | `≥ 0` | Require *n* newer versions before a version is allowed |

**Mirror form** (`<ecosystem> <url>`) — adds, updates, enables, or disables one upstream mirror.

```bash
# Add a mirror; priority auto-increments per ecosystem when omitted
vulnetix config set package-firewall npm https://registry.npmjs.org

# Pin a priority, or toggle a mirror by ecosystem + url
vulnetix config set package-firewall npm https://npm.internal.example --priority 0
vulnetix config set package-firewall npm https://registry.npmjs.org --disable
```

| Argument / Flag | Type | Description |
|------|------|-------------|
| `<ecosystem>` | string | Ecosystem id (`go`, `npm`, `pypi`, …) |
| `<url>` | string | Absolute upstream mirror URL |
| `--priority` | int | Order within the ecosystem (auto `max+1` if omitted) |
| `--enable` / `--disable` | bool | Toggle `isActive` on the mirror matched by ecosystem + url |

Both forms share `--base-url` (default `https://api.vdb.vulnetix.com`) and `-o, --output` (`pretty`, `json`).

#### config get package-firewall

Print the org-wide policy and every mirror across all ecosystems.

```bash
vulnetix config get package-firewall
vulnetix config get package-firewall -o json
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--base-url` | string | `https://api.vdb.vulnetix.com` | VDB API base URL |
| `-o, --output` | string | `pretty` | Output format: `pretty`, `json` |

#### config set quality-gate

Set the org-wide [Quality Gate](/docs/enterprise/quality-gates/) scan-enforcement policy. When a member runs `vulnetix scan` (or `sca`, `sast`, …) while authenticated, every value you set here **overrides** the equivalent scan flag — **org policy always wins**, even over an explicitly-passed flag. Settings you leave unset fall back to the caller's flag or the builtin default.

Each call is a **partial update** — only the flags you pass change; everything else keeps its current value. To clear a setting back to "not enforced", pass `null` as the flag's value (e.g. `--severity null`) — members then fall back to their own scan flag or the builtin default.

```bash
vulnetix config set quality-gate --severity high --block-malware true --cooldown 3
```

| Flag | Value | Description |
|------|-------|-------------|
| `--block-eol` | `true\|false\|null` | Exit `1` when a runtime or package dependency is end-of-life |
| `--block-malware` | `true\|false\|null` | Exit `1` when any dependency is a known malicious package |
| `--block-unpinned` | `true\|false\|null` | Exit `1` when any direct dependency uses a version range instead of an exact pin |
| `--cooldown` | `≥ 0 \| null` | Exit `1` when any dependency version was published within the last *n* days (`0` disables) |
| `--version-lag` | `≥ 0 \| null` | Exit `1` when any dependency is within the *n* most recently published versions (`0` disables) |
| `--sca-autofix-max-major-bump` | `≥ 0 \| null` | Refuse autofix targets crossing more than *n* major versions |
| `--exploits` | `poc\|active\|weaponized\|null` | Exit `1` when exploit maturity reaches the threshold |
| `--severity` | `low\|medium\|high\|critical\|null` | Exit `1` when any vulnerability or SAST finding meets or exceeds this level |
| `--sca-autofix-strategy` | `latest\|safest\|stable\|null` | Target strategy for `--sca-autofix` |

Every flag takes a value (e.g. `--block-malware true`). Pass **`null`** to unset a setting entirely for the org — the value is cleared and members fall back to their own scan flag or the builtin default:

```bash
vulnetix config set quality-gate --severity null --cooldown null
```

Omitting a flag leaves its stored value unchanged. Both this command and `config get quality-gate` share `--base-url` (default `https://api.vdb.vulnetix.com`) and `-o, --output` (`pretty`, `json`).

#### config get quality-gate

Print the org-wide Quality Gate enforcement policy. Settings the organization never configured render as **not set** (the caller's flag or builtin default applies for those).

```bash
vulnetix config get quality-gate
vulnetix config get quality-gate -o json
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--base-url` | string | `https://api.vdb.vulnetix.com` | VDB API base URL |
| `-o, --output` | string | `pretty` | Output format: `pretty`, `json` |

#### config set eol-policy

Set the four end-of-life **calendar-quarter severity buckets** of the Quality Gate. These map an upcoming or past EOL date to a synthetic finding severity during `vulnetix scan` (opt-in via the org policy). The buckets are literal calendar quarters (Q1 Jan–Mar, Q2 Apr–Jun, Q3 Jul–Sep, Q4 Oct–Dec); a date is classified by which quarter it lands in. This is **not** a per-product mapping — it is the four shared time buckets.

Each call is a **partial update**.

```bash
vulnetix config set eol-policy \
  --next-quarter-severity low \
  --this-quarter-severity medium \
  --within-30-days-severity high \
  --retired-severity critical
```

| Flag | Type | Value | Description |
|------|------|-------|-------------|
| `--next-quarter-severity` | string | `skip\|low\|medium\|high\|critical` | Severity for products reaching EOL in the next calendar quarter |
| `--this-quarter-severity` | string | `skip\|low\|medium\|high\|critical` | Severity for products reaching EOL in the current calendar quarter |
| `--within-30-days-severity` | string | `skip\|low\|medium\|high\|critical` | Severity for products reaching EOL within the next 30 days |
| `--retired-severity` | string | `skip\|low\|medium\|high\|critical` | Severity for products already past EOL (retired) |

Use `skip` to suppress findings for a bucket entirely. Both this command and `config get eol-policy` share `--base-url` (default `https://api.vdb.vulnetix.com`) and `-o, --output` (`pretty`, `json`).

#### config get eol-policy

Print the four EOL calendar-quarter severity buckets.

```bash
vulnetix config get eol-policy
vulnetix config get eol-policy -o json
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--base-url` | string | `https://api.vdb.vulnetix.com` | VDB API base URL |
| `-o, --output` | string | `pretty` | Output format: `pretty`, `json` |

---

### vulnetix upload

Upload a security artifact file (SBOM, SARIF, VEX, CSAF) to Vulnetix for processing.

```bash
vulnetix upload --file <path> [flags]
```

The file format is auto-detected from content and extension but can be overridden. Files larger than 10MB are uploaded using chunked transfer. Authentication uses stored credentials or environment variables.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--file` | string | - | Path to artifact file to upload (**required**) |
| `--org-id` | string | stored | Organization ID (UUID, uses stored credentials if not set) |
| `--base-url` | string | `https://api.vdb.vulnetix.com/v1` | Base URL for the Vulnetix VDB API |
| `--format` | string | auto | Override auto-detected format: `cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex` |
| `--json` | bool | `false` | Output result as JSON |

**Examples:**
```bash
# Upload with stored credentials
vulnetix upload --file sbom.cdx.json

# Upload with explicit org ID
vulnetix upload --file report.sarif --org-id "123e4567-e89b-12d3-a456-426614174000"

# Override format detection
vulnetix upload --file report.json --format sarif

# JSON output for scripting
vulnetix upload --file sbom.cdx.json --json
```

---

### vulnetix gha

GitHub Actions artifact management. Designed for use within GitHub Actions workflows.

#### gha upload

Collect and upload all artifacts from the current GitHub Actions workflow run to Vulnetix.

```bash
vulnetix gha upload [flags]
```

This command:
1. Collects all artifacts from the current workflow run via the GitHub API
2. Downloads and extracts each artifact
3. Uploads each file to Vulnetix using the standard upload API
4. Reports pipeline UUIDs for each uploaded file

**Requires:** `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_RUN_ID` environment variables.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--dry-run` | bool | `false` | Classify and validate every file without publishing anything |
| `--fail-on-empty` | bool | `false` | Fail when the run produced no publishable artifact |
| `--no-github-api` | bool | `false` | Do not call the GitHub REST API to enrich the CI context |
| `--strict` | bool | `false` | Treat skipped files (unrecognised formats) as failures |
| `--json` | bool | `false` | Output results as JSON |

The API base URL is not a flag on `gha`; both subcommands go through the shared
client, so use `VULNETIX_API_URL` if you need to point them elsewhere.

#### gha status

Report on the ingestion snapshots produced by a workflow run, or on a single
snapshot by UUID.

```bash
vulnetix gha status                    # current run (GITHUB_RUN_ID)
vulnetix gha status --run-id <RUN_ID>
vulnetix gha status --uuid <UUID>
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--run-id` | string | `GITHUB_RUN_ID` | Workflow run id to report on |
| `--attempt` | int | `GITHUB_RUN_ATTEMPT` | Limit to one run attempt |
| `--uuid` | string | - | Report on a single ingestion snapshot instead of a whole run |
| `--json` | bool | `false` | Output results as JSON |

---

### vulnetix license

Analyze package licenses for conflicts, policy compliance, and risk. See the full [License Command Reference](license/) for details.

```bash
vulnetix license [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Directory to scan |
| `--depth` | `3` | Max recursion depth |
| `--exclude` | - | Exclude paths matching glob (repeatable) |
| `--mode` | `inclusive` | Analysis mode: `inclusive` or `individual` |
| `--allow` | - | Comma-separated allow list of SPDX IDs |
| `--allow-file` | - | Path to YAML allow list file |
| `--policy-file` | discovered | Category-based licence policy (default `.vulnetix/license-policy.yaml`) |
| `--exceptions-file` | discovered | Approved exceptions (default `.vulnetix/license-exceptions.yaml`) |
| `-o, --output` | pretty | Output format: `json` (CycloneDX), `json-spdx` (SPDX 2.3) |
| `--results-only` | `false` | Only show output when there are findings or conflicts |
| `--severity` | - | Exit `1` if any finding meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--from-memory` | `false` | Reconstruct from `.vulnetix/memory.yaml` without re-scanning |
| `--dry-run` | `false` | Detect files and parse packages only — no evaluation |

**Subcommands:**

```bash
vulnetix license policy init|show|validate      # category-based policy
vulnetix license exceptions add|ls|check        # approved exceptions
```

A policy classifies licences by category and attaches a severity to each, which
stays correct when a dependency introduces a licence nobody enumerated. The
built-in default reproduces exactly what the evaluator did before policies
existed, so adopting one is deliberate rather than something an upgrade does to
your build. Exceptions carry approver, grounds and expiry; an expired one stops
applying and says so.

> License analysis also runs automatically during `vulnetix scan` (disable with `--no-licenses`).

---

### vulnetix aibom

Discover AI coding agents/assistants and AI usage, and emit a CycloneDX AI Bill of Materials. See the full [AIBOM Command Reference](aibom/) and the [AIBOM](../aibom/) overview.

```bash
vulnetix aibom [path] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Directory to scan (positional `[path]` overrides) |
| `--depth` | `25` | Max recursion depth |
| `-o, --output` | `cyclonedx-json` | Output format: `cyclonedx-json`, `json`, `table` |
| `--output-file` | - | Write output to a file instead of stdout |
| `--spec-version` | `1.7` | CycloneDX spec version: `1.6` or `1.7` |
| `--catalog` | - | Catalog file to merge over (or replace) the builtin catalog |
| `--no-builtin-catalog` | `false` | Use only `--catalog`, not the embedded catalog |
| `--no-env` | `false` | Skip the environment-variable detection pass |
| `--include-home` | `false` | Also probe the home directory for tool config dirs |
| `--no-source` | `false` | Skip the source-code SDK / model detection pass |

> Detection is catalog-driven (42+ tools, AI SDKs, model-name extraction). The environment pass records variable **names** only — never their values.

---

### vulnetix cbom

Discover cryptographic usage in code and config and emit a CycloneDX Cryptography Bill of Materials (CBOM) with post-quantum posture. See the full [CBOM Command Reference](cbom/) and the [CBOM](../cbom/) overview.

```bash
vulnetix cbom [path] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Directory to scan (positional `[path]` overrides) |
| `--depth` | `25` | Max recursion depth |
| `-o, --output` | `pretty` | Output format: `pretty`, `json`, `cyclonedx-json` |
| `--output-file` | - | Path to write the CBOM (default `.vulnetix/cbom.cdx.json`) |
| `--spec-version` | `1.7` | CycloneDX spec version: `1.6` or `1.7` |
| `--catalog` | - | Catalog file to merge over (or replace) the builtin catalog |
| `--no-builtin-catalog` | `false` | Use only `--catalog`, not the embedded catalog |
| `--no-source` | `false` | Skip the source-code crypto API pass |
| `--no-config` | `false` | Skip the config & protocol pass |
| `--no-certs` | `false` | Skip the certificate / key pass |
| `--no-deps` | `false` | Skip the crypto-library pass |
| `--fail-on` | `none` | Exit non-zero when crypto of these PQC statuses is found (e.g. `quantum-vulnerable`, `deprecated`) |

> Detection is catalog-driven across source, config, certificates and crypto libraries. Algorithm spellings are case/separator-insensitive (`SHA256`/`Sha256`/`SHA_256` → one SPDX algorithm); each is classified quantum-safe / quantum-vulnerable / deprecated / hybrid with a per-country approval matrix.

---

### vulnetix cdx

Generate one standalone CycloneDX document containing package SBOM inventory, AIBOM components and CBOM components. The command is offline: no VDB lookup, upload, memory update, quality gate, image pull or container daemon is used. Discovery spans manifests and lockfiles, installed package trees, container package databases, Dockerfiles, CI/CD pipeline files, shell scripts and recipes, and the packages compiled into binaries (Go build info, Rust `cargo auditable`, JVM archives). Each component carries the same metadata `sca` records, including the dependency graph and licenses.

`vulnetix sbom` is an alias for this command — CycloneDX is the preferred format, and a future SPDX generator will be its own command. See the full [CDX Command Reference](cdx/).

```bash
vulnetix cdx [path] [flags]
vulnetix sbom [path] [flags]   # alias
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Directory to scan (positional `[path]` overrides) |
| `--depth` | `25` | Maximum recursion depth |
| `-o, --output` | `pretty` | Terminal output: `pretty`, `json`, `cyclonedx-json` |
| `--output-file` | - | Path to write the CycloneDX file (default `.vulnetix/sbom.cdx.json`) |
| `--spec-version` | `1.7` | CycloneDX spec version: `1.6` or `1.7` |
| `--container-rootfs` | - | Inspect a container root filesystem directory (repeatable) |
| `--container-archive` | - | Inspect a Docker/OCI/rootfs tar archive (repeatable) |
| `--no-ci` / `--no-shell` | `false` | Skip CI/CD pipeline or shell/recipe package discovery |
| `--no-binary-analysis` / `--no-binary-packages` | `false` | Skip binary analysis, or keep it but omit the packages embedded in binaries |
| `--no-licenses` | `false` | Skip license detection |
| `--no-aibom` / `--no-cbom` | `false` | Omit AI or cryptographic components |
| `--sign` | `false` | Sign with this machine's own OIDC identity; verifies with stock `cosign` |
| `--project` / `--cluster` / `--namespace` / `--environment` / `--tag` | inferred | [Deployment context](scan/#deployment-context) |

---

### vulnetix bom

Read SBOM documents, including ones this CLI did not produce. Where `cdx` **generates** a CycloneDX document from a working tree, `bom` **reads** documents back in: CycloneDX 1.0–1.7, SPDX 2.2/2.3, and in-toto attestation envelopes — the shape Syft and BuildKit emit for container SBOMs, which a plain `bomFormat` check misses entirely.

Everything parsed normalises into one CycloneDX model, so an SPDX file and a CycloneDX file diff against each other and appear side by side in a corpus query. See the full [BOM Command Reference](bom/).

```bash
vulnetix bom import <file|->              # parse and report; --out re-emits as CycloneDX
vulnetix bom validate <file>              # structure plus per-field completeness
vulnetix bom diff <before> <after>        # the change-review gate
vulnetix bom merge <file> <file...>
vulnetix bom tree <file>                  # --invert answers "what pulls this in"
vulnetix bom enrich <file> --out <file>   # resolve licences, attach vulns, apply VEX

vulnetix bom ls     --from ./sboms/       # corpus inventory
vulnetix bom where  <pkg> --from ./sboms/ # blast radius, direct vs transitive
vulnetix bom skew   --from ./sboms/       # inconsistent versions across services
vulnetix bom search <query> --from ./sboms/
```

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | - | Where `import`, `merge` and `enrich` write their document |
| `--from` | - | File, directory or glob for the corpus queries (repeatable) |
| `--fail-on` | `none` | `diff` gate: `any`, `added`, `removed`, `downgraded`, `vuln-added`, `license-regression` |
| `--fail-on-found` | `false` | `where` gate: exit `1` when the package is present |
| `--fail-on-count` | `-1` | `skew` gate: exit `1` above this many skewed packages |
| `--min-score` | `0` | `validate` gate on the completeness score |
| `--verify-attestation` | `false` | `import`: verify the signature before trusting the document |
| `-o, --output` | `pretty` | `pretty`, `json`; `diff` also accepts `markdown` |

---

### vulnetix vex

Read, validate, merge and apply VEX statements — OpenVEX 0.2.0, CycloneDX VEX and CSAF 2.0 VEX — including ones this CLI did not write. That is the case VEX exists for: an upstream publishing "this CVE does not affect the configuration we ship" reaching your scan. See the full [VEX Command Reference](vex/).

```bash
vulnetix vex apply --vex vendor.openvex.json --bom sbom.cdx.json
vulnetix vex ls --vex ./vex/
vulnetix vex validate --vex ./vex/
vulnetix vex merge --vex ./vex/ --out merged.openvex.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--vex` | - | VEX file or directory (repeatable, required) |
| `--bom` | - | `apply`: the SBOM to apply statements to |
| `--out` | - | Where `apply` and `merge` write |
| `--fail-on-effective` | `-1` | Exit `1` above this many vulnerabilities surviving VEX |
| `--status` | - | `ls`: filter by `not_affected`, `affected`, `fixed`, `under_investigation` |

Matching is not exact equality on `(vulnerability, purl)` — that is why VEX so often appears to do nothing, and it fails silently. Version ranges, unversioned products, aliases and URL-form identifiers are all handled, and every match records why it matched.

`--vex-file` and `--no-vex` apply the same statements during a [scan](scan/#third-party-vex), in one place before the gates, so every gate honours VEX by construction. Suppressed findings are annotated, never deleted, and counted separately.

---

### vulnetix attest

Verify signatures and in-toto provenance on artefacts you consume. Reads what `cdx --sign` writes and anything else in those formats. See the full [Attest Command Reference](attest/).

```bash
vulnetix attest verify sbom.cdx.json
vulnetix attest verify sbom.cdx.json --strict
vulnetix attest verify sbom.cdx.json --identity 'https://github.com/acme/repo/...' --issuer github
```

| Flag | Default | Description |
|------|---------|-------------|
| `--identity` | - | Require this exact signer (the command prints the one it found) |
| `--identity-regex` | - | Require the signer to match a pattern |
| `--issuer` | - | Require this OIDC issuer — a URL or `github`, `gitlab`, `google`, `microsoft`, `buildkite`, `codefresh` |
| `--strict` | `false` | Require the signer to be pinned; fails naming the exact flags to add |
| `--trusted-root` | resolved | Root of a private Sigstore deployment |
| `--require` | - | Fail when a named check did not run (repeatable) |
| `--verbose` | `false` | Show every check, including the ones that passed |

The Sigstore public-good root is **built in**, so the certificate chain is validated by default, as cosign does it. `--trusted-root` is an override for a private deployment, resolving through `SIGSTORE_ROOT_FILE` and `.vulnetix/trusted-root.pem` first — and the output names whichever anchor answered.

---

### vulnetix scan

Run every analysis in one pass. `scan` is an orchestrator: each pass is owned by its own subcommand (`sca`, `sast`, `secrets`, `containers`, `iac`, `license`, `malscan`, `aibom`, `cbom`) and `scan` composes them into one set of results, one SBOM and one quality-gate verdict. `--evaluate-*` selects a subset; `--no-*` switches a pass off. See the full [Scan Command Reference](scan/) for details.

```bash
vulnetix scan [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Directory to scan |
| `--depth` | `3` | Max recursion depth |
| `--exclude` | - | Exclude paths matching glob (repeatable) |
| `--include-ignored` | `false` | Include `.gitignore`-matched files (SAST/secrets/containers/IaC; sca and malscan always scan them) |
| `-o, --output` | - | Output target (repeatable): `json-cyclonedx`, `json-sarif` for stdout; `.cdx.json`, `.sarif` file paths to write to file |
| `--concurrency` | - | **Deprecated, no-op.** Set `VULNETIX_SCA_CONCURRENCY` (default `6`) instead |
| `--no-progress` | `false` | Suppress progress indicators |
| `--severity` | - | Exit `1` if any vuln or SAST finding meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--block-malware` | `false` | Exit `1` when any dependency is a known malicious package |
| `--block-eol` | `false` | Exit `1` when a runtime or package dependency is end-of-life |
| `--results-only` | `false` | Only output when findings exist; completely silent when the scan is clean |
| `--no-ci-package-analysis` | `false` | Skip dependency extraction from CI/CD pipeline files, including GitHub Actions workflows |
| `--no-shell-package-analysis` | `false` | Skip dependency extraction from shell scripts, Makefiles and task recipes |
| `--evaluate-sast` / `--no-sast` | - | Enable/disable SAST (general static analysis rules) |
| `--evaluate-sca` / `--no-sca` | - | Enable/disable SCA (package manifest vulnerability analysis) |
| `--evaluate-licenses` / `--no-licenses` | - | Enable/disable license analysis |
| `--evaluate-secrets` / `--no-secrets` | - | Enable/disable secret-detection rules |
| `--enable-containers` / `--no-containers` | - | Enable/disable container file analysis |
| `--evaluate-iac` / `--no-iac` | - | Enable/disable IaC file analysis |
| `--no-malscan` | `false` | Skip the in-process [malscan](malscan/) malware pass (runs by default) |
| `--vex-file` | - | Apply [VEX](vex/) statements before gates are evaluated (repeatable) |
| `--no-vex` | `false` | Ignore `--vex-file` |
| `--policy-file` / `--exceptions-file` | discovered | [Licence policy and exceptions](license/#licence-policy) |
| `--project` / `--cluster` / `--namespace` / `--environment` / `--tag` | inferred | [Deployment context](scan/#deployment-context) |
| `--disable-default-rules` | `false` | Skip built-in SAST rules (external `--rule` repos still loaded) |
| `-R, --rule` | - | External SAST rule repo in `org/repo` format (repeatable) — see [Custom Rule Repositories](../sast-rules/custom-rules/) |
| `--dry-run` | `false` | Detect files and parse packages only — zero API calls |
| `--from-memory` | `false` | Reconstruct from `.vulnetix/sbom.cdx.json` without API calls |

---

### vulnetix sca

Run only Software Composition Analysis — vulnerability analysis on package manifests plus CI/CD and shell install commands. All other features (SAST, licenses, secrets, containers, IaC) are disabled. See the [SCA Command Reference](sca/).

```bash
vulnetix sca [flags]
```

Equivalent to `vulnetix scan --evaluate-sca --no-sast --no-secrets --no-containers --no-iac --no-licenses`.

When `--block-malware` (or the org `blockMalware` policy) is in effect, `sca` also runs the in-process [malscan](malscan/) pass over the installed dependencies and gates on any locally-detected malware.

`--vex-file`, `--no-vex`, `--policy-file`, `--exceptions-file` and the [deployment-context](scan/#deployment-context) flags are registered on every member of the scan family — `scan`, `sca`, `sast`, `secrets`, `containers`, `iac` — and honoured by all of them.

---

### vulnetix fix

Resolve vulnerable dependencies to safe versions, apply the change with the project's own package manager, and rescan to confirm the finding is gone. This is the owner of remediation: `--sca-autofix` on the scan family triggers the same pipeline in-pass. `vulnetix autofix` is an alias. See the full [Fix Command Reference](fix/).

```bash
vulnetix fix [path] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--strategy` | `stable` | Fix target strategy: `stable`, `safest`, `latest` |
| `--manifest` | - | Restrict edits to one manifest file |
| `--max-major-bump` | `0` | Refuse targets crossing more than N major versions |
| `--yes` | `false` | Non-interactive: safe defaults, never prompt |
| `--dry-run` | `false` | Show the fix plan and change nothing |

---

### vulnetix report

Render the results of the last scan from `.vulnetix/sbom.cdx.json` — no discovery, no parsing, and by default no network calls at all. `scan --from-memory` is a deprecated alias for it. See the full [Report Command Reference](report/).

```bash
vulnetix report [path] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Project directory whose `.vulnetix/` results are rendered |
| `--fresh-exploits` | `false` | Re-fetch exploit intelligence for the stored findings |
| `--fresh-advisories` | `false` | Re-fetch remediation plans |
| `--fresh-vulns` | `false` | Re-check affected version ranges and scoring |

---

### vulnetix malscan

Scan the project's locally-installed dependencies for malware in-process — STIX IOC filesystem scan, manifest/install-script pattern detection, IOC extraction, and known-bad artifact hashing — and emit SARIF evidence. Complements `--block-malware` (a known-malicious-package policy lookup) by inspecting the installed bytes themselves. See the full [Malscan Command Reference](malscan/).

```bash
vulnetix malscan [path] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Directory to scan (positional `[path]` overrides; defaults to the git root) |
| `--include-home` | `false` | Also scan user-scoped/home caches (`~/.npm`, `~/go/pkg/mod`, `~/.cargo`, …) |
| `-o, --output` | `pretty` | Terminal output format: `pretty`, `json`, `sarif` |
| `--output-file` | - | SARIF output path (default `.vulnetix/malscan.sarif`) |
| `--no-ioc-feeds` | `false` | Skip the STIX network fetch; run `detect` + `badhash` only (offline) |
| `--no-binary-analysis` | `false` | Do not extract/match IOCs in binary files |
| `--no-upload` | `false` | Do not submit findings (submitted automatically when authenticated) |

Exit code `1` on any malware found. Also runs as a pass inside `scan` (default on) and `sca` (when `--block-malware`/org policy is in effect).

---

### vulnetix jail

Gate the pipeline on the organisation's policy over the repository's **accumulated** state — vulnerabilities past their remediation window, dependencies past end of life, strategic migrations that have not landed, hygiene categories that regressed. Distinct from the quality gate, which grades a single scan's findings. See the full [Jail Command Reference](jail/).

```bash
vulnetix jail [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` | Repository path to derive identity from |
| `--no-fail` | `false` | Report the verdict but always exit 0 |
| `--on-stale` | policy | Override the staleness posture (`fail`, `warn`, `pass`) — tightening only |
| `--staleness-days` | policy | Override the staleness window — tightening only |
| `--vex-out` | `.vulnetix/jail.vex.json` | Where to write the VEX document |
| `--vex-format` | `openvex` | `openvex` or `cyclonedx` |
| `--sarif-out` | `.vulnetix/jail.sarif` | Where to write the SARIF document |
| `--no-artefacts` | `false` | Do not write either document |
| `-o, --output` | `pretty` | Terminal output format: `pretty`, `json` |

Exit `0` clear, `1` jailed, `2` usage error, `3` indeterminate (the backend state a rule needs is stale or missing). Exit 3 is deliberately not exit 1: a breach is fixed by a developer, missing coverage by whoever owns the CI configuration. Subcommands `explain`, `list` and `exempt` inspect and waive without gating. Also available as a `--jail` flag on every scan-family command.

---

### vulnetix sast

Run only Static Application Security Testing. All other features are disabled. See the [SAST Command Reference](sast/).

```bash
vulnetix sast [flags]
```

Equivalent to `vulnetix scan --evaluate-sast --no-sca --no-secrets --no-containers --no-iac --no-licenses`.

---

### vulnetix secrets

Run only secret detection — identifies hardcoded credentials, API keys, and tokens. All other features are disabled. See the [Secrets Command Reference](secrets/).

```bash
vulnetix secrets [flags]
```

Equivalent to `vulnetix scan --evaluate-secrets --no-sast --no-sca --no-containers --no-iac --no-licenses`.

---

### vulnetix containers

Run only container file analysis — checks Dockerfiles and Containerfiles, and can inspect supplied rootfs/archive inputs for installed package DBs and ELF binaries. All other features are disabled. See the [Containers Command Reference](containers/).

```bash
vulnetix containers [flags]
```

Equivalent to `vulnetix scan --enable-containers --no-sast --no-sca --no-secrets --no-iac --no-licenses`.

---

### vulnetix iac

Run only Infrastructure as Code analysis — checks Terraform HCL and Nix files. All other features are disabled. See the [IaC Command Reference](iac/).

```bash
vulnetix iac [flags]
```

Equivalent to `vulnetix scan --evaluate-iac --no-sast --no-sca --no-secrets --no-containers --no-licenses`.

---

### vulnetix ignore

Manage suppression ("ignore") rules for scanner findings. Aliased `suppress`. See the full [Ignore / Suppress Command Reference](ignore/).

```bash
vulnetix ignore add [flags]     # create a rule
vulnetix ignore list [flags]    # list active rules
vulnetix ignore remove [flags]  # deactivate a rule
vulnetix ignore sync            # sync rules with the org backend
```

A rule is anchored by at least one of `--rule` (rego rule id), `--finding` (CVE / vuln id), or `--file`, and can be scoped by `--category` and typed with `--type` (`false_positive`, `wont_fix`, `risk_accepted`, `mitigated`, `deferred`, `rego_rule`, `nosec`). Use `--reason` to record why and `--expires-in` to auto-expire it. A finding is suppressed only when **every** anchor matches. Rules live in `.vulnetix/memory.yaml` and work offline; authenticated, they sync org-wide. Inline `nosec` comments in code are also honoured — see the [reference](ignore/).

---

### vulnetix triage

Fetch vulnerability alerts from external providers (e.g. GitHub Dependabot) and enrich them with remediation intelligence from the Vulnetix VDB.

```bash
vulnetix triage [flags]
vulnetix triage status [flags]
```

**Supported providers:** `github` (Dependabot alerts via the `gh` CLI)

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--provider` | string | `github` | Vulnerability data provider (`github`) |
| `--repo` | string | auto | Repository in `owner/repo` format (auto-detected from git context or `GITHUB_REPOSITORY`) |
| `--all` | bool | `false` | Include dismissed alerts (open only by default) |
| `--concurrency` | int | `5` | Number of concurrent VDB lookups |
| `--format` | string | `tui` | Output format: `tui`, `json`, `text` |
| `--include-guidance` | bool | `true` | Include CWE remediation guidance |

For each alert the triage command fetches:
- A context-aware **remediation plan** (upgrade path, verification steps)
- **Fix data** from registry, distribution, and upstream source in parallel

**Subcommands:**

#### triage status

Verify that provider CLI tools are installed, authenticated, and functional.

```bash
vulnetix triage status [--format text|json]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | `text` | Output format: `text`, `json` |

**Examples:**

```bash
# Interactive TUI (default)
vulnetix triage

# Triage a specific repository
vulnetix triage --repo owner/repo

# Include dismissed alerts, output as JSON
vulnetix triage --all --format json

# Check GitHub CLI auth and repo detection
vulnetix triage status

# Check status as JSON
vulnetix triage status --format json
```

> **Prerequisites:** The `github` provider requires the [`gh` CLI](https://cli.github.com/) to be installed and authenticated (`gh auth login`).

---

### vulnetix vdb

Interact with the Vulnetix Vulnerability Database (VDB) API. See the full [VDB Command Reference](vdb/) for all subcommands and detailed usage.

```bash
vulnetix vdb <subcommand> [flags]
```

| Subcommand | Description |
|------------|-------------|
| `vuln <vuln-id>` | Get information about a vulnerability (CVE, GHSA, PYSEC, and 75+ formats) |
| `ecosystems` | List available package ecosystems |
| `product <name> [version] [ecosystem]` | Get product version information |
| `vulns <package>` | Get vulnerabilities for a package |
| `spec` | Get the OpenAPI specification |
| `exploits <vuln-id>` | Get exploit intelligence for a vulnerability |
| `exploits search` | Search exploits across all vulnerabilities |
| `exploits sources` | List exploit intelligence sources |
| `exploits types` | List exploit type classifications |
| `fixes <vuln-id>` | Get fix data for a vulnerability |
| `fixes distributions` | List supported Linux distributions for fix advisories |
| `versions <package>` | Get all versions of a package across ecosystems |
| `gcve` | Get vulnerabilities by date range |
| `gcve issuances` | List GCVE issuance identifiers by calendar month |
| `purl <purl-string>` | Query VDB using a Package URL (PURL) |
| `ids <year> <month>` | List CVE identifiers published in a calendar month |
| `search <prefix>` | Search CVE identifiers by prefix |
| `sources` | List all vulnerability data sources |
| `metrics types` | List all vulnerability metric/scoring types |
| `status` | Check API health and display CLI/auth metadata |
| `packages search <query>` | Full-text search across packages |
| `ecosystem package <eco> <pkg>` | Get package info within an ecosystem |
| `ecosystem group <eco> <grp> <art>` | Get group/artifact info (Maven-style) |
| `eol product <product>` | Get end-of-life lifecycle data for a product (runtime, framework) |
| `eol package <eco> <pkg> <ver>` | Get end-of-life lifecycle data for a specific package version |

<div class="vdb-v2-only">

**V2-only subcommands** — the v2 API is now the **default**; `-V v1` is the legacy override:

| Subcommand | Description |
|------------|-------------|
| `workarounds <vuln-id>` | Get workaround information |
| `advisories <vuln-id>` | Get advisory data |
| `cwe guidance <vuln-id>` | Get CWE-based guidance |
| `kev <vuln-id>` | Get CISA KEV status |
| `timeline <vuln-id>` | Get vulnerability timeline |
| `affected <vuln-id>` | Get affected products/packages |
| `scorecard <vuln-id>` | Get vulnerability scorecard |
| `remediation plan <vuln-id>` | Get context-aware remediation plan |

</div>

### Tree-sitter reachability

`vulnetix vdb vuln` and the remediation flows automatically perform tree-sitter reachability analysis against your project, recording exactly which files (and line ranges) match the vulnerable pattern. Control with `--reachability=direct|transitive|both|off` (default `both`). See the [Reachability Analysis](reachability/) section for the full feature overview, [Languages](reachability/languages/) for the 17 bundled grammars, and [Internals](reachability/internals/) for how the CGo cross-compile is structured.

---

### vulnetix version

Print the version number of Vulnetix CLI.

```bash
vulnetix version [flags]
```

Also checks for available updates and prints a notice if a newer version exists.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--short` | bool | `false` | Print only the version number (no build info or update check) |

**Examples:**
```bash
# Full version info (with update check)
vulnetix version

# Just the version number, e.g. for scripting
vulnetix version --short
```

---

### vulnetix update

Update the Vulnetix CLI to the latest release from GitHub.

```bash
vulnetix update
```

Checks the GitHub Releases API for the latest version, then downloads and replaces the current binary in-place. Binaries built from source (via `go build` or `make dev`) are not updated — use your build toolchain instead.

**Behavior:**
- If already up to date: prints `Already up to date (vX.Y.Z).`
- If a newer version is available: prints the upgrade path and performs the in-place update
- If built from source: exits with an error indicating that `go build` should be used

**Examples:**
```bash
# Check for and apply the latest update
vulnetix update
```

---

### vulnetix triage

Triage vulnerability alerts from multiple providers (e.g. GitHub Dependabot) with integrated remediation intelligence from the Vulnetix Vulnerability Database.

```bash
vulnetix triage [flags]
vulnetix triage status      # Check provider CLI health
```

The `triage` command fetches vulnerability alerts from external providers, enriches each alert with VDB data (remediation plans, fix availability across registry/distribution/source), and presents them in an interactive TUI or text/JSON output.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--provider` | string | `github` | Vulnerability data provider |
| `--repo` | string | auto-detected | Repository in `owner/repo` format |
| `--all` | bool | `false` | Include dismissed alerts (open only by default) |
| `--concurrency` | int | `5` | Number of concurrent VDB lookups |
| `--format` | string | `tui` | Output format: `tui`, `json`, `text` |
| `--include-guidance` | bool | `true` | Include CWE remediation guidance |
| `--org-id` | string | community | Organization ID (uses stored credentials or community fallback) |

**Examples:**

```bash
# Interactive TUI with auto-detected repo
vulnetix triage

# Specify a repo and include dismissed alerts
vulnetix triage --repo owner/repo --all

# Non-interactive text output
vulnetix triage --format text

# JSON output for scripting
vulnetix triage --repo owner/repo --format json

# Check provider CLI health
vulnetix triage status
```

#### triage status

Verify that provider CLI tools (e.g. `gh`) are installed, authenticated, and can detect the current repository.

```bash
# Text output (default)
vulnetix triage status

# JSON output for scripting
vulnetix triage status --format json
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | `text` | Output format: `text`, `json` |

`--provider` is a flag on `vulnetix triage`, not on `triage status`; it defaults
to `vulnetix` and accepts `github`.

**Output (text):**

```
  GitHub CLI Status
──────────────────────────────────────────

  ✔ gh binary   : /usr/bin/gh
  ✔ authenticated: octocat
     Host         : github.com
     Token source : OAuth Token
     Token scopes : repo, workflow
  ✔ repo detected : owner/repo
```

---

### vulnetix completion

Generate shell autocompletion scripts.

```bash
vulnetix completion [bash|zsh|fish|powershell]
```

## Authentication

Full coverage lives in [Authentication](/docs/authentication/). Summary:

### Methods

| Method | Flag | Environment | `--org-id` |
|--------|------|-------------|------------|
| Bearer token | `--token` | `VULNETIX_API_TOKEN` | Not needed — org resolved server-side |
| ApiKey | `--api-key` | `VULNETIX_API_KEY` + `VULNETIX_ORG_ID` | Required |
| SigV4 | `--secret` | `VVD_ORG` + `VVD_SECRET` | Required |

SigV4 validates via a JWT token exchange with the VDB API, then derives the request credential as `HMAC-SHA256(secret, orgID)`.

### Credential Storage

| Store | Path | Use case |
|-------|------|----------|
| `keyring` (recommended) | OS keychain, metadata in `~/.vulnetix/credentials.json` | Secrets never touch disk in plaintext |
| `home` (default) | `~/.vulnetix/credentials.json` | User-wide credentials, mode `0600` |
| `project` | `.vulnetix/credentials.json` | Project-scoped credentials, mode `0600` |
| `.netrc` | `~/.netrc` or `%USERPROFILE%\_netrc` | Package Firewall credentials; also a fallback ApiKey source |

Override the home directory with `--store-dir DIR` or `VULNETIX_CREDENTIALS_DIR`. If no OS keychain backend is found, `--store keyring` warns and falls back to `home`.

### Credential Precedence

The CLI loads credentials in this order (first complete match wins):

1. `VULNETIX_API_TOKEN` (Bearer)
2. `VULNETIX_API_KEY` + `VULNETIX_ORG_ID` (ApiKey)
3. `VVD_ORG` + `VVD_SECRET` (SigV4)
4. Project dotfile: `.vulnetix/credentials.json`
5. Home directory: `~/.vulnetix/credentials.json`
6. `.netrc` / `_netrc` machine `packages.vulnetix.com`
7. Embedded community credential (VDB read-only, community rate limits)

Flags apply to the `auth login` command that *writes* a credential; they are not part of this load chain. Inspect the winner with `vulnetix auth status`.

## Global Flags

These flags are available on the root command and inherited by subcommands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--org-id` | string | stored | Organization ID (UUID); uses stored credentials if not set |
| `-v, --verbose` | bool | `false` | Show verbose diagnostic output (rate limits, retries, cache status, auth notes) |
| `--silent` | bool | `false` | Suppress all log output; print only the final result |
| `--no-progress` | bool | `false` | Suppress progress indicators |
| `--no-banner` | bool | `false` | Suppress the startup banner |
| `--no-analytics` | bool | `false` | Disable anonymous usage analytics |
| `--disable-memory` | bool | `false` | Disable `.vulnetix/memory.yaml` reads and writes |
| `--version` | - | - | Print the version and exit |
| `--help` | - | - | Help for any command |

{{< callout type="info" >}}
`--verbose` is **not** a log level — the CLI has no `--debug` flag and reads no `DEBUG` environment variable. It un-suppresses extra diagnostics on stderr. `--silent` suppresses info, status and warning output; errors and results are always printed.
{{< /callout >}}

`vulnetix --version` prints the bare version. `vulnetix version` prints the full report (commit, build date, and the versions of the bundled `malscan-engine`, `vdb-cyclonedx` and OPA modules).

## Environment Variables

| Variable | Description | Used By |
|----------|-------------|---------|
| `VULNETIX_API_KEY` | Direct API key (hex digest) | `auth`, `upload`, `vdb`, `triage` |
| `VULNETIX_ORG_ID` | Organization ID for Direct API Key auth | `auth`, `upload`, `vdb`, `triage` |
| `VVD_ORG` | Organization UUID for SigV4 auth | `vdb`, `auth` |
| `VVD_SECRET` | Secret key for SigV4 auth | `vdb`, `auth` |
| `GITHUB_TOKEN` | GitHub API token (also used for license resolution fallback) | `gha upload`, `license`, `scan` |
| `GH_TOKEN` | Alternative GitHub token variable (checked if `GITHUB_TOKEN` is not set) | `license`, `scan` |
| `GITHUB_REPOSITORY` | GitHub repository (owner/name) | `gha upload`, `triage` (auto-detect) |
| `GITHUB_RUN_ID` | GitHub Actions workflow run ID | `gha upload` |
| `GITHUB_API_URL` | GitHub API base URL (default: `https://api.github.com`) | `gha upload` |
| `GITHUB_ACTIONS` | Set to `true` in GitHub Actions | `gha upload` |

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | Authentication error |
| `4` | Network error |
| `5` | File not found |

## Common Usage Patterns

### Basic Usage
```bash
# Run authentication healthcheck
vulnetix
```

### Artifact Upload
```bash
# Upload an SBOM
vulnetix upload --file sbom.cdx.json

# Upload SARIF from a scanner
semgrep --sarif > results.sarif && vulnetix upload --file results.sarif

# Upload via the upload command with format override
vulnetix upload --file report.json --format sarif --json
```

### CI/CD Integration
```bash
# GitHub Actions
vulnetix gha upload --org-id "$VULNETIX_ORG_ID"

# GitLab CI
vulnetix upload --file results.sarif

# Jenkins
vulnetix upload --file results.sarif
```
