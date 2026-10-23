---
title: "Scan Command Reference"
weight: 4
description: "Discover manifest files locally, query the VDB for vulnerabilities, and write a CycloneDX SBOM — no file uploads."
---

The `scan` command walks your project directory, parses package manifests locally, extracts package-manager install commands from CI/CD and shell files, and queries the Vulnetix VDB API to identify vulnerable dependencies. **No file contents are ever uploaded to any server.** Results are saved to `.vulnetix/` and printed to your terminal.

> **Credentials are optional.** When no credentials are configured the [community fallback](https://www.vulnetix.com/features/community) is used automatically.

## Scan Is An Orchestrator

`scan` runs every analysis in one pass. It owns none of them: each is owned by its
own subcommand, and `scan` composes those owners so a single invocation produces one
coherent set of results, one SBOM and one quality-gate verdict.

| Pass | Owner | Enable only this | Turn off inside `scan` |
|------|-------|------------------|------------------------|
| Dependency vulnerabilities | [`sca`](../sca/) | `--evaluate-sca` | `--no-sca` |
| Static analysis | [`sast`](../sast/) | `--evaluate-sast` | `--no-sast` |
| Secret detection | [`secrets`](../secrets/) | `--evaluate-secrets` | `--no-secrets` |
| Container / OCI files | [`containers`](../containers/) | `--enable-containers` | `--no-containers` |
| Infrastructure as Code | [`iac`](../iac/) | `--evaluate-iac` | `--no-iac` |
| License policy | [`license`](../license/) | `--evaluate-licenses` | `--no-licenses` |
| Local malware | [`malscan`](../malscan/) | — (always on) | `--no-malscan` |
| AI inventory (AIBOM) | [`aibom`](../aibom/) | — (always on) | `--no-aibom` |
| Cryptography inventory (CBOM) | [`cbom`](../cbom/) | — (always on) | `--no-cbom` |
| Dependency fixes | [`fix`](../fix/) | — | `--sca-autofix` opts in |

Passing any `--evaluate-*` / `--enable-containers` flag switches `scan` to
opt-in mode: only the named passes run. `--no-*` always wins.

Every pass behaves exactly as its own subcommand does — the same code runs either
way, so `scan --evaluate-licenses --allow MIT` and `license --allow MIT` reach the
same verdict. Two things are deliberately different when you go through `scan`:

- **External rule packs are not kind-locked.** `--rule org/repo` on `scan` runs
  every rule kind the pack ships; on a specialized command only that command's kind
  runs.
- **`.gitignore` handling for manifests.** The specialized `containers` and `iac`
  commands prune gitignored manifests; `scan`, `sca`, `sast` and `secrets` do not,
  because dependency manifests routinely live in gitignored install directories.
  `--include-ignored` overrides the SAST-family behaviour.

Replaying results is not a scan: use [`report`](../report/) (`scan --from-memory`
is a deprecated alias for it).

## Reading the output

The default output answers one question first: *what do I do now?* It opens with
a verdict, groups packages by what to do about them, and ends with the next
command.

```text
 ✖ 12 advisories in 6 packages          2 need action · 3 can wait · 1 not affected
   142 packages · 2 manifests · sca sast · 4.2s

 NEEDS ACTION · 2 packages
 ────────────────────────────────────────────────────────────────────────────
 ● CRITICAL  log4j-core 2.14.1             → 2.17.1        maven  pom.xml
             CVE-2021-44228  ▲ KEV  ▲ weaponized  ▲ reachable
             + 3 more advisories, the same upgrade clears them
```

The unit is the **package**, not the advisory: nobody upgrades an advisory, they
upgrade a package once, to a version that clears every advisory on it. The arrow
is that version, taken from the advisory's own affected range when it has one.
`→ 2.31.0 (12 of 14)` means the upgrade clears twelve of fourteen advisories.

### Groups

Groups say what to do, which is not the same as how severe something is. A
critical advisory nothing reaches can wait; a medium one under active
exploitation cannot.

| Group | Meaning |
|-------|---------|
| `NEEDS ACTION` | Exploited, on a KEV list, reachable from your code, malicious, or SSVC `Act` |
| `CAN WAIT` | Affected, with none of those signals |
| `UNVERIFIED` | Matched by package name, but the advisory's range cannot be compared with your version (a git commit, for example). It **still counts**: unknown is not safe. It does not claim urgency, because nothing established the package is affected |
| `PROTECTED` | No fix, with an unexpired recorded control that blocks the request. Still affected, still counted |
| `MONITORED` | No fix, with a recorded detection or a block rule still in log-only mode. Stops nothing |
| `NOT AFFECTED` | Matched by name and ruled out by version |

The counts in the header always add up: every package with a counting advisory
is in exactly one of the first five groups.

### Version verdicts

Every finding carries a verdict: is the version installed here actually affected?
`sca --explain <id>` shows the working.

### Explaining one finding

`--explain` runs only what its query needs, and it changes nothing:

- **A package, `name@version` or purl:** only those packages are sent to the VDB. No rules run.
- **An advisory id:** the packages it affects are looked up, from the last scan's
  `.vulnetix/sbom.cdx.json` or else from the VDB, and only those packages are sent.
- **A rule id:** that rule runs alone, from whichever `--rule` pack supplied it. No dependency lookup is made.
- **A file path:** the rules run and the dependency lookup is skipped.

An explain run writes no memory, SBOM, SARIF or VEX, uploads nothing and opens no
snapshot, so it never overwrites the full scan's results with a fragment. It fails no
gate either. It exits `1` only when nothing matches the query.

Each command printed under NEXT can be pasted as it is:

- It names the scanner that owns the finding: `sca` for a dependency, `sast`, `secrets`,
  `iac` or `containers` for a rule, never `scan`, which would run every other kind as well.
- It loads the `--rule` pack that supplied the rule.
- It repeats the input flags the run was given, such as `--path`, `--exclude`,
  `--rule-registry` and `--vex-file`:

```text
 NEXT
   vulnetix iac --rule Vulnetix/opa-cigna-tf --exclude 'big/**' --explain CIGNA-TF-AWS-RDS-02
   vulnetix sca --exclude 'big/**' --explain golang.org/x/net
```

| Verdict | Basis | Counts toward `--fail-on` |
|---------|-------|---------------------------|
| `affected` | Inside a range the advisory supplied, or the source asserted it and nothing contradicts it | Yes |
| `unverified` | Matched by name and the version cannot be settled: the range is missing or is a git commit, or the range and the source disagree. After the scan reads the advisory's own record, most of these resolve to `affected` or `not affected` | Yes |
| `likely not affected` | No usable range, but you are not older than the recommended fix | No, unless `--strict` |
| `not affected` | Outside every range the advisory supplied, or the source said so | No, unless `--strict` |

Nothing is deleted: a finding the verdict rules out stays in `-o json-cyclonedx`,
SARIF and the SBOM, with its verdict attached. Only the terminal view and the
gates change.

#### How the version is checked

The scan response carries one affected range per finding, and for many advisories
that range is a git commit, or `*` (every release). Neither says whether *your*
version is affected. So after the response arrives, the scan reads the advisory's
own record for every finding it could not settle from a comparable range, and for
the aliases of that advisory when the record names no entry for your package. It
then compares your version against every comparable range in it.

- It **only resolves**. What it cannot settle stays `unverified` and counted; a
  lookup that fails is skipped, so a flaky network costs accuracy and never a scan.
- Evidence from an alias may only **clear** a finding when every alias that names
  the package agrees, because alias groups are not always clean.
- One vulnerability under several identifiers (`CVE-2018-16487` and `SNYK-JS-LODASH-73638`
  on the same lodash) is shown **once**, under the identifier that sorts first, with the
  others listed as "also known as" (and under `aliases` in JSON). Advisories fold only
  when one lists the other as an alias without naming a second id of the same family
  (a polluted group lists many), they are different kinds of identifier, and they
  reached the same verdict. The folded advisory keeps the strongest signals of its
  members. `--explain` finds a folded
  identifier. JSON, SARIF and the SBOM still hold every finding.
- An open-ended range (`< 1.11.23`, "introduced 0") is how a database writes "from
  the beginning, as far as I know". When the record also gives bounded ranges
  (`>= 1.11.0 < 1.11.23`) and your version falls in none of them, the finding is
  `unverified`, not `affected`. The same goes for versions the record merely
  enumerates, and for a bound that is a distribution rebuild (`5.2.1+echo.1`).
  A finding is also read against its record when it names no fix version, so the
  recommended upgrade reflects every advisory on the package.
- A wildcard (`*`) entry says nothing about where a fix landed and never outweighs
  a precise range, so a package well past its fix stops reporting vulnerable.
  There is one exception. An explicit "introduced 0, never fixed" range, in a record
  that has **no bounded range** for the package, settles the install as `affected`:
  the releases such a record lists beside it are that range spelled out, not the
  complete list. This is how whole-package malware is recorded, and judging your
  version against the listed releases alone reported every other version as safe.
  A bounded range still wins, and a bare `*` version or a git range is no evidence.
- Versions are compared the way their ecosystem writes them: PEP 440 (`1.0.0rc1`,
  `3.2.0.dev0`, `1.0.post1`) for Python, and a precompiled RubyGem's platform
  suffix (`1.19.1-x86_64-linux-gnu`) is ignored.
- A dependency with **no resolved version** (`latest`, `catalog:`, `workspace:*`,
  `${property}`, a bracketed Maven range) is not queried at all and stays in the
  SBOM: a versionless query asks for every advisory the package ever had.

Use `-v` to see how many findings were verified.

### Views

`--view` picks the presentation. `auto` (the default) chooses `plain` for a pipe,
a file or CI, and `packages` for a terminal.

| View | Shape |
|------|-------|
| `packages` | The default: groups, one block per package |
| `findings` | One line per advisory |
| `tree` | Packages under the manifest that declared them |
| `plain` | One line per package, stable columns, ASCII only. A documented output format scripts may rely on |
| `table` | The previous eighteen-column table, kept for one release |

The layout follows the terminal. At 100 columns and above a package line carries
its ecosystem and manifest; below that they drop out, and below 60 the fix moves
to its own line. A tier drops whole fields in a fixed order and never clips a
package name or a version. `--width`, `COLUMNS`, `--color`, `NO_COLOR` and
`--ascii` are honoured. Under GitHub Actions the plain view is followed by
workflow-command annotations on the manifest line, and a Markdown summary is
appended to `$GITHUB_STEP_SUMMARY`.

### Choosing what to show and when to fail

Showing and failing are different verbs, and they never imply each other. A
hidden finding cannot fail a build, and a failing one cannot be hidden.

```bash
vulnetix scan --filter reachable,fixable      # only what is reachable and has a fix
vulnetix scan --min-severity high             # hide below high (exit code unchanged)
vulnetix scan --hide defences,not-affected    # drop sections
vulnetix scan --show paths,scores             # add the transitive chain and CVSS
vulnetix scan -v                              # per-advisory version checks and scores
vulnetix scan -vv                             # plus match evidence and every severity source

vulnetix scan --fail-on high                  # exit 1 on high or critical
vulnetix scan --fail-on kev,malware,unprotected
vulnetix scan --fail-on high --strict         # also count findings ruled out by version
```

`--fail-on` takes `low | medium | high | critical`, `kev`,
`exploit=poc|active|weaponized`, `malware`, `eol[=severity]`, `unpinned`,
`unprotected`, `lag=<n>` and `cooldown=<n>d`, comma-separated or repeated. It is a
vocabulary over the gates that already existed, so org quality-gate policy still
overrides it, and where a legacy flag set the same gate the stricter value wins.

### Superseded flags

These still work and are hidden from `--help`. On a terminal the first use prints
one note naming the replacement; in CI it stays silent.

| Flag | Now |
|------|-----|
| `--severity <level>` | `--fail-on <level>` |
| `--block-malware` | `--fail-on malware` |
| `--block-eol`, `--block-eol-severity` | `--fail-on eol`, `--fail-on eol=<severity>` |
| `--block-unpinned` | `--fail-on unpinned` |
| `--exploits <tier>` | `--fail-on exploit=<tier>` (`kev` for active) |
| `--version-lag <n>`, `--cooldown <n>` | `--fail-on lag=<n>`, `--fail-on cooldown=<n>d` |
| `--no-exploits`, `--no-remediation` | `--hide exploits`, `--hide fixes` |
| `--show-introduced-paths`, `--paths` | `--show paths` |
| `--show-detected`, `--show-all-manifests` | `--show files`, `--show clean` |
| `--results-only` | `-q` |
| `--evaluate-X`, `--no-X` | `--only X`, `--skip X` |
| `--sca-autofix`, `--sca-autofix-strategy`, … | `--fix`, `--fix-strategy`, … (true aliases) |

## When there is no fix

A finding with no fix is never a dead end. Vulnetix builds protection from the
public exploits for a vulnerability, and `scan` says which of these holds for each
package that has no fix:

```text
 ● CRITICAL  legacy-xml 3.1.4              no fix          pypi   requirements.txt
             CVE-2025-11111  ▲ PoC exploit  ▲ referenced  app/parse.py:18
             ◆ block   ModSecurity · nginx     start in log only
             ◆ detect  Sigma
             → vulnetix defend CVE-2025-11111
```

- **block** is a *virtual patch*: a rule for your WAF, sensor or web server that
  stops the request.
- **detect** is a *countermeasure*: Sigma, YARA, STIX or OpenIOC that tells you
  it happened. Detection is not prevention.

They are never mixed on a line. The lines are specific about what could and could
not be established:

| Line | Meaning |
|------|---------|
| `◆ block …` / `◆ detect …` | Rules exist, with their formats |
| `◆ 2 block rules and 1 detection exist · Pro unlocks the rules` | They exist; rule bodies and downloads need Pro |
| `◆ nothing published for this yet` | Asked, and nothing has been built. Never "cannot be defended" |
| `◆ not indexed: … is not an advisory identifier the database can look up` | The identifier was not shaped like an advisory id, or the database refused it. Any advisory family is accepted and widened through its aliases |
| `◆ not checked (offline)` / `◆ lookup failed (…)` | We did not get an answer, which is not the same as none |

Use [`vulnetix defend`](../defend/) to read a rule's mode, false-positive risk and
coverage limits, save it in the file its tool loads, and record that a control is
in place. `--hide defences` skips the lookup.

The lookup asks the database once, in a single request for every no-fix finding, and waits at most 20 seconds. If it is slow or unavailable the scan carries on and the line says `lookup failed (timed out)` rather than claiming there is nothing.

## Usage

```bash
vulnetix scan [flags]
```

## Flags

The flags the [output section](#reading-the-output) lists as superseded (`--severity`, `--block-*`, `--exploits`, `--results-only`, `--evaluate-X`, `--no-X` and the rest) still work; they are hidden from `--help` and documented below for existing pipelines.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--only` | stringArray | - | Run just these passes: `sca`, `sast`, `secrets`, `licenses`, `containers`, `iac` (comma-separated, repeatable). Replaces the `--evaluate-X` flags |
| `--skip` | stringArray | - | Run everything except these passes. Replaces the `--no-X` flags |
| `--view` | string | `auto` | `auto`, `packages`, `findings`, `tree`, `plain` or `table`. See [Views](#views) |
| `--filter` | stringArray | - | Show only findings matching **all** of: `kev`, `exploited`, `reachable`, `fixable`, `nofix`, `defended`, `unprotected`, `direct`, `transitive` |
| `--min-severity` | string | - | Hide anything below `low`, `medium`, `high` or `critical`. Changes what is shown, never the exit code |
| `--sort` | string | `threat` | Order within a group: `threat`, `severity` or `package` |
| `--show` | stringArray | - | Add `paths`, `files`, `clean`, `scores`, `defences` or `tests` to the output (`tests` ranks high-severity code findings in test files with the rest instead of listing them under IN TESTS) |
| `--hide` | stringArray | - | Remove `fixes`, `exploits`, `defences` or `not-affected` from the output |
| `-v, --verbose` | count | `0` | `-v` adds per-advisory version checks and scores; `-vv` adds match evidence and every severity source |
| `-q, --quiet` | bool | `false` | Findings only: one line when there are findings, nothing when the scan is clean |
| `--explain` | string | - | Show why one finding applies, with the evidence: an advisory id, a rule id, a package, `name@version` or a file path. Runs only what that query needs, and writes and uploads nothing (see [Explaining one finding](#explaining-one-finding)) |
| `--fail-on` | stringArray | - | Exit `1` when any of these hold: `low`, `medium`, `high`, `critical`, `kev`, `exploit=poc\|active\|weaponized`, `malware`, `eol[=severity]`, `unpinned`, `unprotected`, `lag=<n>`, `cooldown=<n>d` (comma-separated, repeatable). Replaces `--severity`, `--block-*`, `--exploits`, `--version-lag` and `--cooldown` |
| `--strict` | bool | `false` | Also count findings the advisory rules out by version (`not affected`, `likely not affected`) toward the gates |
| `--accept-defended` | bool | `false` | Let an unexpired control recorded with [`defend --record`](../defend/) satisfy the gates for the finding it covers |
| `--color` | string | `auto` | `auto`, `always` or `never`. `NO_COLOR` is honoured |
| `--ascii` | bool | `false` | Draw with plain ASCII characters instead of unicode symbols |
| `--width` | int | terminal | Force the output width in columns. `COLUMNS` is honoured when stdout is not a terminal |
| `--fix` | bool | `false` | Alias of `--sca-autofix`; `--fix-strategy`, `--fix-manifest` and `--fix-max-major-bump` alias the other autofix flags |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `--include-ignored` | bool | `false` | Include files matched by `.gitignore`. By default the SAST, secrets, containers and IaC passes skip gitignored paths; **SCA and malscan always scan them** (dependency install dirs like `node_modules/` are commonly gitignored). |
| `-o, --output` | stringArray | - | Output target (repeatable): `json-cyclonedx` or `json-sarif` for stdout; file path (`.cdx.json`, `.cdx`, `.bom.json`, `.sbom.json`) for CycloneDX to file; file path (`.sarif`, `.sarif.json`) for SARIF to file. Multiple flags combine file outputs with pretty display. |
| `-f, --format` | string | - | **Deprecated** — maps to `--output json-cyclonedx`. Use `--output` instead. |
| `--concurrency` | int | - | **Deprecated, no-op.** It never had any effect; set `VULNETIX_SCA_CONCURRENCY` (default `6`) to change SCA fan-out |
| `--no-progress` | bool | `false` | Suppress progress indicators |
| `--paths` | bool | `false` | Show full transitive dependency paths (npm, Python, Rust, Ruby, PHP, Go). Edges are built from locally installed packages (`node_modules/`, venv, `vendor/`, `cargo metadata`). |
| `--no-exploits` | bool | `false` | Suppress the detailed exploit intelligence section |
| `--no-remediation` | bool | `false` | Suppress the detailed remediation section |
| `--no-licenses` | bool | `false` | Skip license analysis during scan (license analysis runs by default) |
| `--severity` | string | - | Exit with code `1` if any vulnerability meets or exceeds this level: `low`, `medium`, `high`, `critical`. Severity is coerced from all available scoring sources (CVSS, EPSS, Coalition ESS, SSVC). Also gates on SAST findings. |
| `--block-malware` | bool | `false` | Exit with code `1` when any dependency is a known malicious package. |
| `--block-eol` | bool | `false` | Exit with code `1` when a runtime or package dependency is end-of-life. Runtimes: Go, Node.js, Python, Ruby. Package-level checks activate when VDB has EOL data (404s are silently skipped). |
| `--block-unpinned` | bool | `false` | Exit with code `1` when any direct dependency uses a version range (`^`, `~`, `>=`) instead of an exact pin. |
| `--exploits` | string | - | Exit with code `1` when exploit maturity reaches the threshold: `poc` (any public exploit), `active` (CISA/EU KEV / actively exploited), `weaponized` (in-the-wild only). |
| `--results-only` | bool | `false` | Only output when findings exist; completely silent when the scan is clean. Also suppresses exploit and remediation detail sections. |
| `--no-ci-package-analysis` | bool | `false` | Skip dependency extraction from CI/CD pipeline files, including GitHub Actions workflows. |
| `--no-shell-package-analysis` | bool | `false` | Skip dependency extraction from shell scripts, Makefiles and task recipes. |
| `--version-lag` | int | `0` | Exit with code `1` when any dependency is within the N most recently published versions of that package (0 = disabled). |
| `--cooldown` | int | `0` | Exit with code `1` when any dependency version was published within the last N days (0 = disabled, best-effort). |
| `--sca-autofix` | bool | `false` | Apply validated SCA fixes with the project package manager, then rescan to confirm. See [SCA Autofix](sca-autofix/). |
| `--sca-autofix-strategy` | string | `stable` | Target strategy for `--sca-autofix`: `safest`, `stable`, `latest` or `rolling` ([definitions](/docs/cli-reference/sca-autofix/#strategies)). |
| `--sca-autofix-manifest` | string | - | Restrict autofix edits to one manifest file; implies non-interactive manifest selection. |
| `--sca-autofix-max-major-bump` | int | `0` | Refuse autofix targets crossing more than N major versions. |
| `--yes` | bool | `false` | Non-interactive autofix mode: auto-pick safe defaults and never prompt. |
| `--evaluate-sast` | bool | `false` | Enable SAST analysis (exclusive mode — disables all other features not explicitly enabled) |
| `--no-sast` | bool | `false` | Skip SAST (sast-kind) rules |
| `--evaluate-sca` | bool | `false` | Enable SCA — package manifest analysis (exclusive mode) |
| `--no-sca` | bool | `false` | Skip SCA — skip ordinary package manifests |
| `--evaluate-licenses` | bool | `false` | Enable license analysis (exclusive mode) |
| `--no-licenses` | bool | `false` | Skip license analysis |
| `--evaluate-secrets` | bool | `false` | Enable secret detection rules (exclusive mode) |
| `--no-secrets` | bool | `false` | Skip secret-detection SAST rules |
| `--enable-containers` | bool | `false` | Enable container file analysis (exclusive mode) |
| `--no-containers` | bool | `false` | Skip Dockerfile/OCI manifests and container SAST rules |
| `--evaluate-iac` | bool | `false` | Enable IaC analysis (exclusive mode) |
| `--no-iac` | bool | `false` | Skip HCL/Nix manifests and IaC SAST rules |
| `--allow` | string | - | Comma-separated SPDX licenses allowed by policy; passed to the [license](../license/) pass |
| `--allow-file` | string | - | YAML allow-list file for the license pass (overrides `--allow`) |
| `--license-mode` | string | `inclusive` | License conflict detection mode: `inclusive` (whole project) or `individual` (per manifest) |
| `--policy-file` | string | discovered | [Licence policy](../license/#licence-policy) document (default `.vulnetix/license-policy.yaml` when present) |
| `--exceptions-file` | string | discovered | [Approved licence exceptions](../license/#exceptions) (default `.vulnetix/license-exceptions.yaml` when present) |
| `--vex-file` | stringArray | - | Apply [VEX](../vex/) statements from this file or directory **before gates are evaluated** (repeatable) |
| `--no-vex` | bool | `false` | Ignore `--vex-file` and apply no third-party VEX |
| `--project` | string | inferred | What this artefact is / who owns it — see [Deployment context](#deployment-context) |
| `--cluster` | string | inferred | Where it is deployed |
| `--namespace` | string | inferred | Namespace within the cluster |
| `--environment` | string | inferred | Deployment stage, e.g. `production` |
| `--tag` | stringArray | - | Additional `key=value` deployment label (repeatable) |
| `--bom-manufacturer` | string | repo owner | Organization that created the BOM — see [BOM authoring identity](#bom-authoring-identity) |
| `--lifecycle` | string | derived | Lifecycle stage(s) the BOM data was captured at, comma-separated |
| `--snippet-context` | int | `-1` | Surrounding non-empty source lines captured around each SARIF finding (`-1` = dynamic, `0` disables). Also available on `sast`, `secrets`, `containers` and `iac` |
| `--no-malscan` | bool | `false` | Skip the in-process [malscan](../malscan/) pass over local dependency install dirs |
| `--no-aibom` | bool | `false` | Skip the [AIBOM](../aibom/) inventory pass |
| `--no-cbom` | bool | `false` | Skip the [CBOM](../cbom/) cryptography inventory pass |
| `--disable-default-rules` | bool | `false` | Skip built-in default SAST rules (external `--rule` repos still loaded) |
| `--list-default-rules` | bool | `false` | Print built-in SAST rules and exit. Also works on `sast`, `secrets`, `containers` and `iac` |
| `-R, --rule` | stringArray | - | External SAST rule repo in `org/repo` format (repeatable); fetched from GitHub or `--rule-registry` — see [Custom Rule Repositories](../sast-rules/custom-rules/) |
| `--rule-registry` | string | `https://github.com` | Override default registry URL for all `--rule` repos |
| `--dry-run` | bool | `false` | Detect files and parse packages locally, check memory, then exit — zero API calls. Honoured by every scan-family command, scoped to the passes that command runs. |
| `--from-memory` | bool | `false` | **Deprecated** — use [`vulnetix report`](../report/). Reconstructs the pretty output from `.vulnetix/sbom.cdx.json` without API calls |
| `--fresh-exploits` | bool | `false` | **Deprecated** — use `vulnetix report --fresh-exploits` |
| `--fresh-advisories` | bool | `false` | **Deprecated** — use `vulnetix report --fresh-advisories` |
| `--fresh-vulns` | bool | `false` | **Deprecated** — use `vulnetix report --fresh-vulns` |
| `--reachability` | string | `both` | Tree-sitter reachability mode: `direct`, `transitive`, `both`, or `off`. Per-finding source-level reachability analysis runs against every produced CVE. Disable globally with `off` for large monorepos. See the [Reachability Analysis](reachability/) section. |

## Third-party VEX

`--vex-file` and `--no-vex` are registered on **every** member of the scan
family — `scan`, `sca`, `sast`, `secrets`, `containers`, `iac`.

```bash
vulnetix sca --vex-file vendor.openvex.json --severity high
vulnetix scan --vex-file ./vex/
```

Statements are applied in **one place, immediately before the quality gates**,
so every gate honours VEX by construction. Filtering per gate would leave one
that could be forgotten, and the forgotten one fails a build over a finding the
vendor has already said does not apply.

The summary line names the suppressed count, because `0 vulnerabilities` on its
own reads as *"nothing was found"*:

```
1 packages | 0 vulnerabilities (12 suppressed by VEX)
```

Suppressed findings are annotated in the SBOM, never deleted. See the
[VEX Command Reference](../vex/) for the formats read, how statements are
matched, and what the provenance properties record.

## Deployment context

A repository scan answers *"what is in this code"*. It cannot answer *"which of
our clusters runs the vulnerable version"* — a repository has no idea where its
artefacts end up. These labels carry that from the pipeline that does know.

```bash
vulnetix scan --project payment-service --cluster prod-eu --namespace payments
```

| Dimension | Answers | Cardinality | Owned by |
|-----------|---------|-------------|----------|
| `cluster` / `namespace` / `environment` | Where is it deployed? | Low, stable | Platform team |
| `project` | What is it, who owns it? | High, volatile | Dev teams |

They are **separate, orthogonal** fields on purpose: a scan belongs to cluster
`prod-eu` **and** project `payment-service` at once, and collapsing them makes
either query impossible.

Unset values are inferred from `VULNETIX_CLUSTER`, `VULNETIX_PROJECT`,
`VULNETIX_NAMESPACE`, `VULNETIX_ENVIRONMENT`, `CI_ENVIRONMENT_NAME`,
`POD_NAMESPACE` and `CI_PROJECT_NAME`, so a pipeline can export them once for a
whole job.

**Nothing is inferred from a branch name.** "main means production" is a
convention this CLI has no business assuming, and a wrong environment label is
worse than an absent one — it attributes a finding to a cluster that never ran
the code.

The labels land in `metadata.properties` as `vulnetix:deployment/*`, in
`.vulnetix/memory.yaml`, and in the `cli.*` upload envelope, so the backend can
answer fleet-scale questions across repositories. Locally, the same labels are
queryable with [`bom ls`](../bom/#bom-ls) and [`bom where`](../bom/#bom-where).

## BOM authoring identity

Every CycloneDX document this CLI writes says who made it and what it was
looking at when it did. CycloneDX has no single field for that — it splits the
idea across five members of `metadata`, and their own descriptions decide which
is which:

| Field | The spec's own words | What we put there |
|-------|----------------------|-------------------|
| `metadata.manufacturer` | "The organization that **created the BOM**… common in BOMs created through **automated processes**" | The organization running the scan |
| `metadata.authors` | "The person(s) who created the BOM… common in BOMs created through **manual processes**" | Only where a person made the claims, as in a hand-curated VEX |
| `metadata.tools` | "The tool(s) used in the **creation, enrichment, and validation** of the BOM" | Every Vulnetix command that touched the document |
| `metadata.supplier` | "The organization that supplied **the component that the BOM describes**" | Subject-level; says nothing about who wrote the document |
| `metadata.lifecycles` | "The stage(s) in which **data in the BOM was captured**" | What this pass actually read |

### Who created it

`metadata.manufacturer` is the organization running the scan — **not Vulnetix**.
Vulnetix supplied the instrument, and the instrument is named in
`metadata.tools`; a document claiming Vulnetix created an inventory of your
repository would be saying something different, and something untrue.

It is resolved from the first of these that answers:

1. `--bom-manufacturer`
2. `VULNETIX_BOM_MANUFACTURER`
3. The repository owner your CI provider states — GitHub, GitLab, Azure DevOps, Bitbucket, Jenkins or the generic variables
4. The owner segment of the repository's git remote

If none of them answers, the field is **omitted**. An absent manufacturer costs
a reader one unknown; an invented one is a false claim they have no way to
detect.

When an organization id is available — `--org-id` or `VULNETIX_ORG_ID` — it
rides along as `manufacturer.bom-ref` (`urn:uuid:<org>`), tying the document to a
Vulnetix organization without asserting a display name the CLI cannot resolve.
An id on its own is not enough to name a manufacturer, though: `manufacturer.name`
is what a reader sees, so the field stays absent until one of the four sources
above supplies a name.

### What it was looking at

`metadata.lifecycles` is a statement about the observation, not about the
product, and it is an array because one pass reads several kinds of source:

| What the pass read | Phase |
|--------------------|-------|
| Manifests and lockfiles | `pre-build` |
| An installed dependency tree — `node_modules`, `site-packages`, `vendor/` | `build` |
| A container image, or packages recovered from compiled binaries | `post-build` |
| AI or cryptographic inventory, found by observation | `discovery` |
| Any of the above with deployment labels supplied | adds `operations` |

Reading a manifest tells you what a build is *intended* to resolve — the
artefacts do not exist yet — so that is `pre-build`. A consumer uses the
difference to decide how much the component list can be trusted.

For the scan family specifically that means `scan` and `sca` claim `pre-build`,
`containers` claims `post-build`, and any of them adds `operations` when
deployment labels are supplied. [`cdx`](../cdx/) reads more source kinds in one
pass and usually claims several phases at once.

`--lifecycle` replaces the derived answer outright, because a pipeline that
states its own stage is making a claim about its process that no amount of
filesystem inspection can contradict:

```bash
vulnetix scan --lifecycle post-build,operations
```

Valid phases are `design`, `pre-build`, `build`, `post-build`, `operations`,
`discovery` and `decommission`. An unrecognised value is rejected rather than
treated as a custom phase name — a typo silently becoming a custom lifecycle is
indistinguishable downstream from a deliberate one.

### Which tool

`metadata.tools.components[0]` is the command that authored the document, with
its real version, its purl and links back to the project:

```json
{
  "type": "application",
  "bom-ref": "urn:tool:vulnetix-sca",
  "group": "Vulnetix",
  "name": "vulnetix-sca",
  "version": "3.98.0",
  "purl": "pkg:golang/github.com/vulnetix/cli@v3.98.0",
  "externalReferences": [
    { "type": "website", "url": "https://www.vulnetix.com" },
    { "type": "vcs", "url": "https://github.com/vulnetix/cli" }
  ]
}
```

Each command names itself — `vulnetix-sca`, `vulnetix-containers`,
`vulnetix-cdx`, `vulnetix-aibom`, `vulnetix-cbom`, `vulnetix-vex`,
`vulnetix-license-analyzer` — because what produced a document is a real
question, and "an SBOM built from manifests" differs from "an inventory read out
of a container image" in ways the component list alone does not show.

### Re-scanning the same repository

A re-scan writes the **next revision of the same document**: the `serialNumber`
is kept and `version` increments, so two revisions can be ordered. Tool entries
from other producers are preserved; this CLI's own entry is replaced with the
version that just ran, rather than sitting beside the older one.

### Documents this CLI did not author

A command that transforms someone else's document — [`bom enrich`](../bom/#bom-enrich),
[`bom import`](../bom/#bom-import) — appends itself to `metadata.tools` and
leaves `manufacturer` and `authors` exactly as it found them. Enriching Syft's
SBOM does not make us its author. See
[Attribution when enriching](../bom/#attribution-when-enriching).

## Output Files

After every scan the following files are written under your project root:

| Path | Description |
|------|-------------|
| `.vulnetix/sbom.cdx.json` | CycloneDX 1.7 SBOM for all scanned packages |
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from SAST analysis (written when any SAST sub-category runs) |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, counts, git context) — also stores your [ignore rules](../ignore/) under a `suppressions:` block |

> **Suppressing findings.** To drop findings you have triaged (false positives, accepted risks, mitigated issues) use `nosec` comments in code or the [`vulnetix ignore`](../ignore/) command. Scans report how many findings each pass suppressed, so nothing disappears silently.

## Package Scope Support

Vulnerabilities and packages are organised by dependency scope where the package manager provides that information:

| Package Manager | Scopes |
|----------------|--------|
| npm | `production`, `development`, `peer`, `optional` |
| Python (Pipfile) | `production`, `development` |
| Python (requirements.txt) | `production` |
| Go | `production` (no scope distinction in go.mod / go.sum) |
| Rust | `production` (no scope distinction in Cargo.lock) |
| Ruby | `production` (group info requires Gemfile) |
| Maven / Gradle | `production`, `test`, `provided`, `runtime`, `system` |
| Composer | `production`, `development` |
| Yarn / pnpm | `production` (scope requires correlation with package.json) |
| NuGet | `production` |
| Swift | `production` |
| Pub (Dart) | `production`, `development` |
| Hex (Elixir) | `production` |
| sbt (Scala) | `production` |
| CocoaPods | `production` |
| Conan (C/C++) | `production` |
| vcpkg (C/C++) | `production` |

## Supported Manifest Files

The scanner recognizes these package manager manifest and lock files:

### JavaScript / TypeScript

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `package.json` | npm | No |
| `package-lock.json` | npm | Yes |
| `npm-shrinkwrap.json` | npm | Yes |
| `yarn.lock` | npm | Yes |
| `pnpm-lock.yaml` | npm | Yes |

When `package.json` is present without `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`, SCA resolves from the installed `node_modules/` tree. The scan fails before the VDB lookup if `node_modules/` is missing or if any direct dependency declared in `package.json` is not installed. When the install tree is present, Vulnetix reads each installed package's `package.json`, uses the actual installed versions in the `/v2/cli.sca` request, and adds installed undeclared packages as transitive dependencies where it can connect them through package manifest dependency fields.

### Python

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `pyproject.toml` | PyPI | No |
| `requirements.txt` | PyPI | No |
| `requirements.in` | PyPI | No |
| `setup.py` | PyPI | No |
| `setup.cfg` | PyPI | No |
| `Pipfile` | PyPI | No |
| `Pipfile.lock` | PyPI | Yes |
| `poetry.lock` | PyPI | Yes |
| `uv.lock` | PyPI | Yes |

### Conda

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `environment.yml` | Conda | No |
| `environment.yaml` | Conda | No |

Nested `pip:` dependencies inside a Conda `environment.yml` are attributed to PyPI.

### Go

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `go.mod` | Go | No |
| `go.sum` | Go | Yes |

### Rust

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Cargo.toml` | Cargo | No |
| `Cargo.lock` | Cargo | Yes |

### Deno

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `deno.json` | Deno | No |
| `deno.lock` | Deno | Yes |

### Ruby

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Gemfile` | RubyGems | No |
| `Gemfile.lock` | RubyGems | Yes |

### Java / Kotlin / Scala

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `pom.xml` | Maven | No |
| `build.gradle` | Maven | No |
| `build.gradle.kts` | Maven | No |
| `gradle.lockfile` | Maven | Yes |
| `build.sbt` | Maven | No |
| `build.lock` | Maven | Yes |
| `build.sc` | Maven | No |

### Clojure

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `project.clj` | Clojars | No |
| `deps.edn` | Clojars | No |
| `bb.edn` | Clojars | No |

Clojure coordinates resolve as Maven `group:artifact` PURLs.

### C# / .NET

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `*.csproj` | NuGet | No |
| `*.fsproj` | NuGet | No |
| `*.vbproj` | NuGet | No |
| `packages.config` | NuGet | No |
| `packages.lock.json` | NuGet | Yes |
| `paket.dependencies` | NuGet | No |
| `paket.lock` | NuGet | Yes |

### PHP

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `composer.json` | Composer | No |
| `composer.lock` | Composer | Yes |

### Swift / iOS

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Package.swift` | Swift | No |
| `Package.resolved` | Swift | Yes |
| `Podfile` | CocoaPods | No |
| `Podfile.lock` | CocoaPods | Yes |
| `Cartfile` | Carthage | No |
| `Cartfile.resolved` | Carthage | Yes |

### Dart

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `pubspec.yaml` | Pub | No |
| `pubspec.lock` | Pub | Yes |

### Elixir

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `mix.exs` | Hex | No |
| `mix.lock` | Hex | Yes |

### Erlang

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `rebar.config` | Hex | No |
| `rebar.lock` | Hex | Yes |

### C / C++

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `vcpkg.json` | vcpkg | No |
| `conanfile.txt` | Conan | No |
| `conanfile.py` | Conan | No |
| `conan.lock` | Conan | Yes |
| `CMakeLists.txt` | CPM | No |
| `CPM.cmake` | CPM | No |
| `meson.build` | Meson | No |

`CMakeLists.txt` is only recognized when the file contains `CPMAddPackage`.

### Haskell

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `*.cabal` | Cabal | No |
| `cabal.project.freeze` | Cabal | Yes |
| `stack.yaml` | Stack | No |
| `package.yaml` | hpack | No |

`package.yaml` is only recognized when the file is an hpack package description (it declares dependencies alongside an hpack section such as `library:` or `executables:`).

### OCaml

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `opam` | opam | No |
| `*.opam` | opam | No |

### Nix

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `flake.nix` | Nix | No |
| `flake.lock` | Nix | Yes |

### Julia

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Project.toml` | Julia | No |
| `Manifest.toml` | Julia | Yes |

### Crystal

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `shard.yml` | Crystal | No |
| `shard.lock` | Crystal | Yes |

### R

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `DESCRIPTION` | CRAN | No |
| `renv.lock` | CRAN | Yes |

### Zig

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `build.zig.zon` | Zig | No |

### Bazel / Buck

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `MODULE.bazel` | Bazel | No |
| `WORKSPACE` | Bazel | No |
| `WORKSPACE.bazel` | Bazel | No |
| `BUCK` | Buck | No |
| `BUCK2` | Buck | No |

### Containers

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Dockerfile` | Docker | No |
| `Containerfile` | Docker | No |
| `*.dockerfile` | Docker | No |
| `*.containerfile` | Docker | No |
| `compose.yaml` / `docker-compose.yml` | Docker | No |

Container images from `FROM` lines, Compose `image:` fields, Kubernetes manifests, and Helm charts are emitted as `pkg:oci/…` components. Each carries a `vulnetix:oci:registryType` (`dockerhub`/`gcr`/`ecr`/`acr`/`ghcr`/`gitlab`/`quay`/`local`/`private`) and `vulnetix:oci:private` property so private-registry usage is visible in the BOM.

### Kubernetes

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `*.yaml` / `*.yml` with `apiVersion` + `kind` | Kubernetes | No |

Container images are extracted from every pod-template shape — `Pod`, `Deployment`, `ReplicaSet`, `StatefulSet`, `DaemonSet`, `Job` and `CronJob` — including `initContainers` and `ephemeralContainers`.

### Helm

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Chart.yaml` | Helm | No |

Chart `dependencies` become `pkg:helm/…` components; container images declared in a sibling `values.yaml` (`image:` shorthand or `repository:`/`tag:` blocks) are emitted as `pkg:oci/…`.

### Registry config

| Filename | Ecosystem | Parsed for deps? |
|----------|-----------|------------------|
| `.npmrc` / `.yarnrc` / `.yarnrc.yml` | npm | No (registry endpoints only) |
| `settings.gradle` / `settings.gradle.kts` | Maven | No (registry endpoints only) |

These are not parsed for dependencies. The scanner extracts declared registry endpoints (never auth tokens) and prints an informational note when a private/custom registry is configured — a supply-chain visibility signal.

### Infrastructure as Code

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `*.tf` | Terraform | No |

### CI/CD

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `.github/workflows/*.yml` | GitHub Actions | No |
| `.github/workflows/*.yaml` | GitHub Actions | No |

### Existing SBOMs

The scanner also detects and ingests existing SBOM documents:

- **SPDX** JSON documents (identified by `spdxVersion` and `SPDXID` fields)
- **CycloneDX** JSON documents (identified by `bomFormat: "CycloneDX"` and `specVersion`)

## License Analysis

By default, `vulnetix scan` also runs license analysis on all discovered packages. License findings appear in the pretty output after the vulnerability summary and are stored in the CycloneDX BOM with source `vulnetix-license-analyzer`.

License resolution uses a multi-source pipeline (manifests, filesystem, container metadata, deps.dev, GitHub). See the [License Command Reference](license/) for full details on resolution sources, evaluation rules, and conflict detection.

To skip license analysis:

```bash
vulnetix scan --no-licenses
```

## Feature Control

By default, `vulnetix scan` runs all analysis categories: SCA, SAST (including secret detection, container rules, and IaC rules), and license analysis.

### Enabling individual features (exclusive mode)

When any `--evaluate-X` flag is set, only the explicitly enabled categories run — everything else is disabled. This makes it easy to scope a scan to a single concern:

```bash
# SCA only (vulnerability analysis on package manifests)
vulnetix scan --evaluate-sca

# SAST only (general static analysis rules)
vulnetix scan --evaluate-sast

# Secret detection only
vulnetix scan --evaluate-secrets

# Container analysis only (Dockerfile/OCI rules)
vulnetix scan --enable-containers

# IaC analysis only (Terraform, Nix)
vulnetix scan --evaluate-iac

# License analysis only
vulnetix scan --evaluate-licenses
```

### Disabling individual features

`--no-X` flags disable a specific category while leaving all others enabled:

```bash
# Run everything except license analysis
vulnetix scan --no-licenses

# Run everything except secret-detection rules
vulnetix scan --no-secrets

# Skip IaC files and rules
vulnetix scan --no-iac

# Skip containers
vulnetix scan --no-containers

# Skip all SAST-kind rules (but still run secrets/containers/IaC rules)
vulnetix scan --no-sast
```

### Specialized scan commands

For convenience, dedicated top-level commands wrap common single-category scans:

| Command | Equivalent |
|---------|------------|
| `vulnetix sca` | `vulnetix scan --evaluate-sca --no-sast --no-secrets --no-containers --no-iac --no-licenses` |
| `vulnetix sast` | `vulnetix scan --evaluate-sast --no-sca --no-secrets --no-containers --no-iac --no-licenses` |
| `vulnetix secrets` | `vulnetix scan --evaluate-secrets --no-sast --no-sca --no-containers --no-iac --no-licenses` |
| `vulnetix containers` | `vulnetix scan --enable-containers --no-sast --no-sca --no-secrets --no-iac --no-licenses` |
| `vulnetix iac` | `vulnetix scan --evaluate-iac --no-sast --no-sca --no-secrets --no-containers --no-licenses` |

## SAST (Static Application Security Testing)

By default, `vulnetix scan` also runs SAST analysis alongside SCA. SAST evaluates Rego-based rules against your source files to detect code-level security issues — weak cryptography, hardcoded credentials, missing lock files, insecure deserialization, and more.

SAST findings appear in the pretty output after the SCA summary and are written to `.vulnetix/sast.sarif` in SARIF 2.1.0 format. Each finding includes CWE, CAPEC, and MITRE ATT&CK technique mappings, plus stable fingerprints for tracking results across runs.

SAST rules are organized into four sub-categories that can be toggled independently:

| Sub-category | Flag to disable | Rule kind | Applies to |
|---|---|---|---|
| Static analysis | `--no-sast` | `sast` | General code security rules |
| Secret detection | `--no-secrets` | `secrets` | Hardcoded credentials, API keys, tokens |
| Container rules | `--no-containers` | `oci` | Dockerfile / Containerfile analysis |
| IaC rules | `--no-iac` | `iac` | Terraform HCL, Nix files |

### Disabling SAST

```bash
# Skip all SAST-kind rules (secrets/containers/IaC still run)
vulnetix scan --no-sast

# Skip secret-detection rules specifically
vulnetix scan --no-secrets

# Skip all SAST entirely (all four sub-categories)
vulnetix scan --no-sast --no-secrets --no-containers --no-iac

# Skip built-in rules only (external rule repos still loaded)
vulnetix scan --disable-default-rules --rule myorg/my-rules
```

### Listing Built-in Rules

Prints all all built-in rules with their IDs, names, severities, and language targets, then exit:

```bash
vulnetix scan --list-default-rules
```

### External Rule Repos

Load additional Rego rules from Git repositories. See the [Custom Rule Repositories](../sast-rules/custom-rules/) guide for a full walkthrough including repository setup, rule authoring, and all flag combinations. Rules are fetched from GitHub by default or from a custom registry.

```bash
# Load rules from a GitHub repo
vulnetix scan --rule myorg/custom-rules

# Load multiple external rule repos
vulnetix scan --rule myorg/rules-a --rule myorg/rules-b

# Use a custom registry (e.g. GitLab or self-hosted Gitea)
vulnetix scan --rule myorg/rules --rule-registry https://gitlab.example.com
```

### SAST Severity Gating

SAST findings participate in `--severity` gating alongside SCA vulnerabilities. When any SAST finding meets or exceeds the threshold, the scan exits with code `1`:

```bash
# Exit 1 on high or critical SAST findings (or SCA vulnerabilities)
vulnetix scan --severity high
```

### Built-in Rules

27 rules ship with the CLI. Run `vulnetix scan --list-default-rules` for full descriptions and CWE/CAPEC/ATT&CK mappings.

#### Cryptography

| Rule ID | Severity | Name | Languages |
|---------|----------|------|-----------|
| `VNX-CRYPTO-001` | medium | MD5 usage detected | Python, Node, Go, Java, Ruby, PHP |
| `VNX-CRYPTO-002` | medium | SHA-1 usage detected | Python, Node, Go, Java, Ruby, PHP |

#### Container Security

| Rule ID | Severity | Name | Applies to |
|---------|----------|------|------------|
| `VNX-DOCKER-001` | medium | Dockerfile missing USER directive | Dockerfile, Containerfile |
| `VNX-DOCKER-002` | medium | Dockerfile FROM :latest tag | Dockerfile, Containerfile |

#### Go

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-GO-001` | high | Missing go.sum |
| `VNX-GO-002` | high | Command injection via exec.Command |

#### Java

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-JAVA-001` | high | Command injection via Runtime.exec() |
| `VNX-JAVA-002` | medium | Spring actuator endpoints exposed |

#### Node.js

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-NODE-001` | high | Missing npm lock file |
| `VNX-NODE-002` | high | eval() or new Function() in JavaScript |
| `VNX-NODE-003` | high | Command injection via child_process |
| `VNX-NODE-004` | medium | Express app without helmet |
| `VNX-NODE-005` | medium | innerHTML or dangerouslySetInnerHTML usage |

#### PHP

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-PHP-001` | high | Missing composer.lock |
| `VNX-PHP-002` | high | Dangerous function in PHP |

#### Python

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-PY-001` | high | Missing Python lock file |
| `VNX-PY-002` | high | eval()/exec() usage in Python |
| `VNX-PY-003` | high | Insecure deserialization with pickle |
| `VNX-PY-004` | high | yaml.load() without SafeLoader |
| `VNX-PY-005` | medium | Weak PRNG for security operations |
| `VNX-PY-006` | medium | Django DEBUG=True |

#### Ruby

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-RUBY-001` | high | Missing Gemfile.lock |
| `VNX-RUBY-002` | high | eval() or system() in Ruby |

#### Rust

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-RUST-001` | high | Missing Cargo.lock |

#### Secrets & Credentials

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-SEC-001` | critical | AWS access key ID |
| `VNX-SEC-002` | critical | Private key committed |
| `VNX-SEC-004` | critical | GitHub or GitLab token |

### SARIF Output

SAST results are always written to `.vulnetix/sast.sarif`. To write a combined SARIF report (SCA + SAST) to a custom path, use `--output`:

```bash
# Write combined SARIF to a file; pretty summary still goes to stdout
vulnetix scan --output results.sarif

# Write both CycloneDX and SARIF files alongside pretty output
vulnetix scan --output sbom.cdx.json --output results.sarif
```

The auto-written `.vulnetix/sast.sarif` contains SAST-only findings. The `--output *.sarif` file contains all scan findings (SCA + SAST) in SARIF format.

## Auto-Discovery

The scanner walks the directory tree starting from `--path` up to `--depth` levels deep. It automatically skips common non-project directories:

- `node_modules`, `.git`, `.hg`
- `__pycache__`, `.tox`, `.venv`
- `vendor`, `.cargo`

Use `--exclude` to skip additional paths by glob pattern. Patterns follow root `.gitignore` rules:

| Pattern | Excludes |
|---------|----------|
| `testdata/` or `testdata` | every directory named `testdata`, at any depth, and everything beneath it |
| `./testdata/` or `/testdata/` | only the `testdata` directory at the scan root |
| `testdata/**` | everything under the root `testdata` directory |
| `**/fixtures/**` | everything under any `fixtures` directory |
| `*_test.go` | matching file names at any depth |
| `sub/*.json` | `.json` files directly inside the root `sub` directory |

### Dependency graph from installed packages

After parsing manifests, the scanner also reads locally installed package directories to build a complete transitive dependency graph. This improves SBOM `dependencies` section accuracy and powers `--paths` output — no extra flags required.

| Ecosystem | Install directory |
|-----------|-------------------|
| npm | `node_modules/` (follows symlinks for pnpm) |
| Python | venv `site-packages/*.dist-info/METADATA` |
| Rust | `cargo metadata` subprocess |
| Ruby | `vendor/bundle/` or `GEM_HOME` gemspec files |
| PHP | `vendor/*/composer.json` |
| Go | `go mod graph` subprocess |

If the install directory is not present, the scanner falls back to lock-file edge parsing where available.

For npm projects without a lock file, the installed `node_modules/` tree is not just an edge source: it is the authoritative source for resolved package versions. Orphaned installed packages are tolerated as best-effort transitives, but missing direct dependencies stop the scan early because the CLI cannot safely infer what version should be reported.

## Examples

### Auto-discover and scan the current directory

```bash
vulnetix scan
```

### Scan a specific project directory

```bash
vulnetix scan --path /path/to/project --depth 5
```

### Exclude test fixtures and vendor directories

```bash
vulnetix scan --exclude "test/**" --exclude "vendor/**"
```

### Emit CycloneDX JSON to stdout

```bash
vulnetix scan --output json-cyclonedx
```

### Emit SARIF JSON to stdout

```bash
vulnetix scan --output json-sarif
```

### Write CycloneDX to a file (pretty output still goes to stdout)

```bash
vulnetix scan --output /tmp/sbom.cdx.json
```

### Write SARIF to a file (pretty output still goes to stdout)

```bash
vulnetix scan --output /tmp/results.sarif
```

### Write both CycloneDX and SARIF files alongside pretty output

```bash
vulnetix scan --output /tmp/sbom.cdx.json --output /tmp/results.sarif
```

### Raw CycloneDX JSON for scripting

```bash
vulnetix scan -o json-cyclonedx | jq '.components'
```

### Suppress progress indicators (useful in CI without a TTY)

```bash
vulnetix scan --no-progress
```

### Break the build on high or critical vulnerabilities

```bash
# Exit 1 if any high or critical vulnerability is found
vulnetix scan --severity high

# Exit 1 on any scored severity and write a CycloneDX BOM
vulnetix scan --severity low -o dist/sbom.cdx.json
```

### Gate on EOL runtimes and packages

```bash
# Exit 1 when a runtime or package dependency is end-of-life
vulnetix scan --block-eol

# Combine with severity gating
vulnetix scan --block-eol --severity high
```

### Gate on version lag (supply chain freshness)

```bash
# Exit 1 if using the very latest published version of any dependency
vulnetix scan --version-lag 1

# Exit 1 if any dependency is within the 3 most recent releases
vulnetix scan --version-lag 3
```

### Gate on recently published dependencies (cooldown period)

```bash
# Exit 1 if any dependency was published in the last 3 days
vulnetix scan --cooldown 3

# Combine multiple supply chain gates
vulnetix scan --block-malware --block-unpinned --version-lag 1 --cooldown 3 --severity high
```

### Suppress output when clean (results-only mode)

```bash
# No output when scan is clean; table appears only when findings exist
vulnetix scan --results-only
```

### SAST — list, disable, and load custom rules

```bash
# List all built-in SAST rules and exit
vulnetix scan --list-default-rules

# Skip all SAST-kind rules (general static analysis)
vulnetix scan --no-sast

# Skip secret detection
vulnetix scan --no-secrets

# Skip all SAST entirely (all four sub-categories)
vulnetix scan --no-sast --no-secrets --no-containers --no-iac

# Skip built-in rules but load a custom rule repo from GitHub
vulnetix scan --disable-default-rules --rule myorg/custom-rules

# Load additional rules on top of the built-in set
vulnetix scan --rule myorg/extra-rules

# Use a self-hosted registry for custom rules
vulnetix scan --rule myorg/rules --rule-registry https://git.example.com
```

### Suppress extra sections

```bash
# Skip exploit intelligence and remediation details
vulnetix scan --no-exploits --no-remediation
```

### Skip license analysis

```bash
vulnetix scan --no-licenses
```

### Dry run (detect files, no API calls)

```bash
vulnetix scan --dry-run
```

### Reconstruct results from previous scan

```bash
# From memory — no API calls
vulnetix scan --from-memory

# Replaying stored results — prefer `vulnetix report`
vulnetix report --fresh-exploits
vulnetix report --fresh-advisories

# The deprecated equivalents (still accepted)
vulnetix scan --from-memory --fresh-exploits
vulnetix scan --from-memory --fresh-advisories
```

## Org Quality Gate Policy

When you run a scan while authenticated and your organization has configured a [Quality Gate](/docs/enterprise/quality-gates/), its settings are pulled in before the gate is evaluated and **override the matching scan flag defaults — org policy always wins**, even over a flag you pass explicitly. The override applies to `--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`, `--sca-autofix-strategy`, and `--sca-autofix-max-major-bump`. Settings the org left unset fall back to your flag or the builtin default.

Run with `--verbose` to see which settings were applied or superseded. Inspect the active policy with:

```bash
vulnetix config get quality-gate
```

Non-authenticated scans (no credentials, or the community fallback) have no organization to read from and use only the CLI flags you pass.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | A gate was breached (`--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`), or a fatal error occurred — including a file requested with `-o <path>` that could not be written |
| `2` | A local argument or configuration error, caught before any scanning started |
| `3` | With `--jail`: the policy ran but could not reach a verdict, because some rules have no current scan coverage. Not a pass and not a breach |

## When the advisory lookup is incomplete

If the lookup fails for some packages even after retries, the report says so instead
of presenting the rest as the whole answer. With no findings the headline reads
`INCOMPLETE` rather than `CLEAN`; with findings it adds "N not checked"; the default
view notes that the list may be incomplete; and `-o json` lists the packages under
`meta.unchecked`. Re-run the scan. Exit codes are unchanged.
