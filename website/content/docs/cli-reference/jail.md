---
title: "Jail Command Reference"
weight: 11
description: "Gate a pipeline on your organisation's policy over a repository's accumulated state — vulnerabilities past SLA, end-of-life dependencies, strategic migrations and hygiene — with VEX and SARIF evidence."
---

A repository is **jailed** when it breaches a policy-driven threshold. `vulnetix jail` asks the organisation's policy whether this repository is in breach, writes the evidence, and sets the pipeline's exit code.

> **This is not the quality gate.** `vulnetix scan --severity`, `--block-eol` and friends decide whether *this scan's findings* should break *this build*. Jail decides whether the repository — across every tool and category that has ever reported for it, over time — is in breach of policy. The two answer different questions and are configured separately.

## Usage

```bash
vulnetix jail [flags]
vulnetix jail explain [flags]
vulnetix jail list [flags]
vulnetix jail exempt --reason "..." [flags]
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clear — nothing breached |
| `1` | Jailed — at least one rule breached |
| `2` | Usage or configuration error |
| `3` | Indeterminate — the backend state a rule needs is stale or missing |

Exit 3 is deliberately distinct from exit 1. "You breached policy" is fixed by a developer; "your scan stage stopped running" is fixed by whoever owns the CI configuration. A gate that reported both the same way would send every failure to the wrong person.

When a run both breaches a rule *and* cannot evaluate another, the exit code is **1**. A definite violation on data we hold is a fact; an unknown elsewhere does not make it less true, and burying a real breach under "we could not tell" is the failure this ordering prevents.

## What a jail gates on

Every rule reduces to the same operation: **select a population, aggregate it, compare against a threshold.**

| Kind | Population | Notes |
|---|---|---|
| `VULN` | Open findings in the latest scan per tool | `COUNT_PAST_SLA` reads your [triage policy](/resolve/triage-policy) for the remediation window; the rule supplies only how many overdue is too many |
| `EOL` | Dependencies at or approaching end of life | Graded with the same bucket ladder `sca` uses — retired, within 30 days, this quarter, next quarter |
| `GOAL` | Anything matching a target pattern | A migration or refactor target, with a deadline and an optional ratchet |
| `HYGIENE` | Secrets, licence, IaC, container and malware findings | |

Rules are authored in the Vulnetix console under **Configuration → Jail**, where they can be reviewed and versioned. The CLI reads them.

### Latest state only

The policy is evaluated against the **newest scan of each tool, within each category**. A repository scanned nightly for a year contributes one result per tool, not 365 — otherwise every accumulated threshold would breach permanently.

"Latest" is resolved *per category*, not per repository. Categories run in separate CI jobs and drift apart, so anchoring them all to the repository's single newest commit would silently hide any category that did not run on it — and a hidden category reads as a clean one.

### Staleness

A rule whose evidence is older than its staleness window, or missing entirely, cannot be graded. What happens then is policy:

| `onStale` | Behaviour |
|---|---|
| `fail` (default) | The rule is **indeterminate** and the run exits 3 |
| `warn` | The rule is graded on whatever is there, and the verdict says so |
| `pass` | The rule is skipped |

The default is `fail` because a gate that silently passes on missing evidence is worse than no gate.

**Commit drift is reported, never gated.** A pull-request build scans the merge commit while the gate runs on the head commit, so treating inequality as a coverage failure would jail every PR. A scan taken outside a git checkout has no commit at all.

### Strategic goals

A `GOAL` rule states a target and a date — "usages of `pkg:npm/moment` must reach 0 by 2026-12-01".

- **Before the deadline** a breach warns rather than blocks. A goal that jails you the day it is written is a threshold wearing a deadline.
- **After the deadline** it blocks.
- With **ratchet** enabled it also breaches if the count *rose* against the same branch's last assessment, even before the deadline — so a migration cannot go backwards while its clock runs. A branch with no prior assessment records a baseline and passes.

### Exemptions

`vulnetix jail exempt --rule <uuid> --reason "tracked in JIRA-42"` waives a rule for this repository until a date (30 days by default, 365 maximum).

An exemption never rewrites the evidence. The verdict still reports the real observed value, the threshold, that the rule *would* have breached, and which exemption suppressed it — an exemption that silently zeroed a count is how policy erodes without anyone noticing.

Exemptions expire by design. A permanent waiver is a policy change and belongs in the policy, where somebody can see it.

## Artefacts

| File | Contents |
|---|---|
| `.vulnetix/jail.vex.json` | OpenVEX (or CycloneDX with `--vex-format cyclonedx`) for the vulnerability breaches |
| `.vulnetix/jail.sarif` | SARIF for the EOL, goal and hygiene breaches |

Both are written before the exit code is decided: a red gate is exactly when the evidence is needed.

VEX has no vocabulary for "this runtime is past end of life" or "this migration missed its deadline", which is why the non-vulnerability half is SARIF. The SARIF is written to disk and **not** uploaded — a gate that published its own findings would manufacture the very coverage the next run measures freshness against.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--path` | `.` | Repository path to derive identity from |
| `--repo`, `--branch` | | Assess another scope (`explain` and `list` only) |
| `--rule-uuid` | | Restrict evaluation to specific rules (repeatable) |
| `--no-fail` | `false` | Report the verdict but always exit 0 |
| `--on-stale` | policy | Override the staleness posture — **tightening only** |
| `--staleness-days` | policy | Override the staleness window — **tightening only** |
| `--vex-out` | `.vulnetix/jail.vex.json` | Where to write the VEX document |
| `--vex-format` | `openvex` | `openvex` or `cyclonedx` |
| `--sarif-out` | `.vulnetix/jail.sarif` | Where to write the SARIF document |
| `--no-artefacts` | `false` | Do not write either document |
| `--max-lookback-days` | server | How far back to consider scan coverage |
| `-o`, `--output` | `pretty` | `pretty` or `json` |
| `--timeout` | `60s` | Maximum time to wait for the gate |

`--on-stale` and `--staleness-days` may only make the gate **stricter**. A pipeline may demand fresher evidence than the organisation requires; it may not quietly accept staler evidence than the organisation allows, or the flag would be a way to opt out of the gate. A looser request is ignored and reported.

## Subcommands

### `vulnetix jail explain`

Reports every rule's verdict with the matched items behind it. No artefacts, no exit code, and it does not move a ratchet baseline — looking at a goal must not change its next verdict.

Every enabled rule is evaluated on every run. Rule order decides presentation and which rule supplies the headline reason, never which rules are checked.

### `vulnetix jail list`

Shows the resolved policy — the rules in effect, their thresholds and their current observed values — without gating. A per-repository policy overrides the organisation default outright when one exists; the reported source says which applied.

Also available as `vulnetix config get jail`.

### `vulnetix jail exempt`

Creates or retires a waiver.

```bash
vulnetix jail exempt --rule <uuid> --reason "tracked in JIRA-42" --expires 336h
vulnetix jail exempt --deactivate <uuid> --deactivate-reason "fixed in 2.4.0"
```

Also available as `vulnetix config set jail exempt`.

## In a pipeline

As its own step, after the scan stages have uploaded:

```yaml
- run: vulnetix scan
- run: vulnetix jail
```

Or folded into a scan, which uploads and then assesses in one invocation:

```yaml
- run: vulnetix sca --jail
```

`--jail` is available on `scan`, `sca`, `sast`, `secrets`, `containers` and `iac`. In that mode the invocation refreshes only the categories it actually ran, so the useful verdict is *"SCA current and clean, SAST forty days old — indeterminate"*. Jail breaches merge into the scan's own gate output, namespaced `jail:<rule>`.

## Adoption

Two things make this safe to turn on before any rule exists:

- An organisation with **no policy** reports `no policy` and exits 0. Adding the flag cannot break a pipeline that is already running.
- `--no-fail` reports everything and always exits 0, so a team can see what would fail before it does.

And one makes it safe to turn off without a release: setting **enforcement to warn only** in the console downgrades every rule at once, server-side.
