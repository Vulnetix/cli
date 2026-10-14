---
title: "Secrets Command Reference"
weight: 7
description: "Run only secret detection — identifies hardcoded credentials, API keys, tokens, and private keys in source code, binaries, and git history."
---

The `secrets` command runs a focused scan that evaluates only secret-detection Rego rules (rules with `kind: secrets`) against your source files, binary artifacts, and git history. It is equivalent to running:

```bash
vulnetix scan --evaluate-secrets --no-sast --no-sca --no-containers --no-iac --no-licenses
```

Package vulnerability analysis, general SAST rules, license analysis, container analysis, and IaC analysis are all disabled. Only rules that detect hardcoded credentials, API keys, tokens, and private keys run.

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

## What gets scanned

The secrets stage surfaces credentials wherever they hide:

- **Source files** — every text file in the scan path, up to 1 MiB each. Lockfiles, sumfiles, and minified JS/CSS are skipped to keep noise down.
- **Binary files** — by default the stage extracts printable strings (≥ 4 chars, the `strings(1)` default) and injects the result back into the scan input under the `__binary_strings__/<path>` synthetic key. EXIF/IPTC/XMP metadata of JPEG and TIFF files is extracted under `__exif__/<path>`. Use `--ignore-binaries` to opt out.
- **Git history** — by default the stage walks the git history of the scan root (newest first) and feeds the file contents of every changed path into the scan input under the `__git_history__/<short-sha>/<path>` synthetic key. This is bounded by `--git-history-max-commits` and `--git-history-max-files`. Use `--ignore-git` to opt out.
- **Helm / Kustomize** — Kubernetes Secret manifests with `data:` or `stringData:` fields are flagged by VNX-SEC-074.

The full catalog of 1090+ built-in secret rules — covering cloud, source control, AI/LLM providers, payment processors, communication platforms, SaaS APIs, databases, private keys, crypto/blockchain and webhooks — is documented in the [Secrets / Credentials rules](../sast-rules/secrets/) section. Each rule applies a keyword/prefix prefilter, regex token extraction, a placeholder allowlist, and a Shannon-entropy threshold to keep false positives low.

## Usage

```bash
vulnetix secrets [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `--ignore` | stringArray | - | Additional glob pattern to skip during the secrets stage (repeatable) |
| `--ignore-git` | bool | `false` | Skip the `.git` directory during the secrets stage. Default: scan `.git` so credentials in past commits are surfaced |
| `--ignore-binaries` | bool | `false` | Skip binary file inspection during the secrets stage. Default: extract printable strings and EXIF metadata from binaries |
| `--git-history` | bool | `true` | When the secrets stage runs, walk git history (newest first) and scan every changed file's contents |
| `--git-history-max-commits` | int | `500` | Cap the number of commits walked during the git-history stage (0 = no cap) |
| `--git-history-max-files` | int | `5000` | Cap the number of file versions extracted from git history (0 = no cap) |
| `-o, --output` | stringArray | - | Output target: `json-sarif` for stdout; `.sarif` file path for file output |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--severity` | string | - | Exit `1` if any finding meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--results-only` | bool | `false` | Only output when findings exist |
| `--dry-run` | bool | `false` | Report what this command would scan — rule kinds, external rule packs, discovered files — then replay stored results. Zero API calls. |
| `--list-default-rules` | bool | `false` | Print the built-in rule table and exit |
| `--snippet-context` | int | `-1` | Source lines captured around each SARIF finding (`-1` = dynamic, `0` disables) |
| `--secrets-include-ignored` | bool | `false` | Include files matched by `.gitignore` (default: gitignored paths are skipped) |
| `--rule` | stringArray | - | External Rego rule pack in `org/repo` format (repeatable). Combine with `Vulnetix/community-rules` and the OPA packs (regula, kics, cds-aws-tf, cigna-tf, trivy, snyk-labs-iac) for comprehensive coverage. |

## What Gets Detected

The 80 built-in secret-detection rules cover credentials across all major cloud providers and services:

| Category | Examples |
|----------|----------|
| Cloud providers | AWS access keys, Bedrock keys, Azure storage keys, GCP API keys, Alibaba, DigitalOcean, Heroku, HashiCorp Vault/Cloudflare, Tencent |
| Source control | GitHub PAT (classic, fine-grained, OAuth, App, refresh), GitLab PAT/runner/deploy/agent, Bitbucket, Atlassian |
| Communication | Slack tokens and webhooks, Twilio, Discord, Telegram, Teams webhooks, Mailgun, SendGrid |
| Payment | Stripe secret/restricted, Square, Shopify, PayPal, Braintree, Plaid |
| AI providers | OpenAI, Anthropic, Google Gemini/Vertex, Cohere, Hugging Face, Perplexity, Groq, Mistral, Replicate |
| Package registries | npm, PyPI, RubyGems, NuGet, Artifactory/JFrog, SonarQube, Snyk |
| SaaS APIs | Datadog, NewRelic, Sentry, Grafana, Notion, Linear, Airtable, Mapbox, Doppler |
| Private keys | RSA, DSA, EC, OpenSSH, PGP, age, WireGuard |
| Database connection strings | PostgreSQL, MySQL, MongoDB, Redis (with credentials) |
| Generic patterns | HTTP Basic/Bearer headers, curl with -u, generic high-entropy, Kubernetes Secret manifests |
| Crypto/blockchain | Ethereum private keys |
| Webhook URLs | Slack, Teams, Mattermost |

See the [Secrets / Credentials rules](../sast-rules/#secrets) section for the full list of 80 rules.

## Examples

```bash
# Basic secret scan of the current directory
vulnetix secrets

# Scan a specific directory
vulnetix secrets --path /path/to/project

# Skip the .git directory (use when you have a separate history scanner)
vulnetix secrets --ignore-git

# Skip binary inspection
vulnetix secrets --ignore-binaries

# Combine multiple external rule packs for exhaustive coverage
vulnetix secrets \
  --rule Vulnetix/community-rules \
  --rule Vulnetix/opa-fugue-regula \
  --rule Vulnetix/opa-checkmarx-kics \
  --rule Vulnetix/opa-cds-aws-tf \
  --rule Vulnetix/opa-cigna-tf \
  --rule Vulnetix/opa-aquasecurity-trivy \
  --rule vulnetix/opa-snyk-labs-iac \
  --output secrets.sarif

# Exclude test fixtures
vulnetix secrets --exclude "test/**" --ignore "fixtures/**"

# Break the build on any secret found
vulnetix secrets --severity high

# Emit SARIF JSON to stdout
vulnetix secrets --output json-sarif

# Write SARIF to a file
vulnetix secrets --output secrets.sarif

# Silent when no secrets found
vulnetix secrets --results-only
```

## Reading the output

The report is organised by **credential**, because a credential is what you rotate:
the same key written in three files is one row, and rotating it once fixes all three.
Two keys are the same when the line holds the same most-random-looking token; the token
is hashed in memory to decide that and is never printed or stored.

```text
 ✖ SECRETS 5 credentials in 7 places          2 to rotate · 1 not committed · 1 can wait · 1 in tests
   1090 rules ran · one value in several files counts once · values are never printed

 ROTATE NOW · 2 credentials · committed to production code
 ──────────────────────────────────────────────────────────────────────────────────────────────
 ● CRITICAL  AWS access key ID       VNX-SEC-001  .env.example:3
             committed in a1b2c3d, 41 days ago   also in deploy/prod.tfvars:14 +1 more

 NOT COMMITTED · 1 credential · remove it now and it never reaches the history
 ──────────────────────────────────────────────────────────────────────────────────────────────
 ● HIGH      Slack webhook URL       VNX-SEC-042  internal/notify/slack.go:31
```

| Group | What is in it |
|-------|---------------|
| **ROTATE NOW** | Critical and high credentials that are in git history, or whose history could not be read. |
| **NOT COMMITTED** | Critical and high credentials only in the working tree (an untracked file, or a line not committed yet). Removing them now means they never reach the history. |
| **CAN WAIT** | Medium and low confidence matches, such as generic high-entropy strings. |
| **IN TESTS** | Credentials in [test code](../sast/#test-suite-detection), listed and not ranked. `--show tests` ranks them. |
| **VENDORED** | Credentials under `third_party/`, `vendor/`, `node_modules/` and similar. |

How it got there comes from `git blame` on each line, run once after the scan and limited
to 200 findings. A copy found only in a past commit (the scan reads history) is reported
as *removed from the tree, still in history*: the file no longer holds it, but it is still
exposed. When the directory is not a git repository nothing is asked, and the credential
lands in ROTATE NOW without a history note, because an unknown history is not a clean one.

`--explain <rule-id>` (or a file path) gives the rotation steps in order — revoke at the
provider, check its access logs from the commit date, issue a replacement, remove the
copies — and then each place with its status (`committed a1b2c3d · 2026-09-03`,
`in git history`, or `not committed`). It never prints the value or the line it is on:
the match span is not recorded, and a wrong guess at it would print the secret.

These groups change only the terminal view. SARIF, JSON, uploads, annotations and gates
see every finding at its own severity.

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from secret detection |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, finding counts, git context) |

The SARIF output is the only output produced. No SBOM/BOM is emitted.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | A gate was breached (`--severity`), or a fatal error occurred |

## Known false negatives

Detection is deliberately conservative — a missed detection is preferred over a wrong one. Not detected, by design:

- Secrets encrypted at rest (SOPS, sealed-secrets, ansible-vault) — encrypted blobs are opaque.
- Double-encoded values (base64 inside base64); Kubernetes `Secret.data:` values are decoded one level and scanned.
- Values referenced but not present (`valueFrom.secretKeyRef`, `env_file:` entries) — references are never resolved, and reference *names* are never flagged as secrets.
- Credentials split across lines or assembled at runtime.

Absence of a finding is not verified absence of a secret.

## Related Commands

- [`vulnetix scan`](scan/) — Full scan with all features enabled
- [`vulnetix sca`](sca/) — SCA-only scan
- [`vulnetix sast`](sast/) — General SAST-only scan
- [`vulnetix containers`](containers/) — Container file analysis only
- [`vulnetix iac`](iac/) — IaC file analysis only
- [Secrets Rules Reference](../sast-rules/#secrets) — All 80 built-in secret-detection rules
