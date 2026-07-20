---
title: "Ignore / Suppress Command Reference"
weight: 11
description: "Suppress scanner findings you have triaged — from the CLI with vulnetix ignore, inline in code with nosec comments, offline in .vulnetix/memory.yaml, and org-wide once you authenticate."
---

Every scanner produces findings a team decides not to act on: a false positive, a risk you have consciously accepted, a vulnerability you have already mitigated another way. The `ignore` command (aliased `suppress`) is how you record that decision as an auditable **ignore rule** instead of a mute button.

A rule is **anchored** to what it applies to (a rego rule id, a finding id such as a CVE, and/or a file path), **typed** by why it exists, **justified** by a reason, and can **auto-expire** so a temporary exception cannot outlive its justification.

> **Credentials are optional.** With no credentials, rules live locally in `.vulnetix/memory.yaml` and work fully offline. When you are authenticated, rules also sync to the Vulnetix backend so the whole organisation shares one policy.

## Usage

```bash
vulnetix ignore add [flags]        # create a rule
vulnetix ignore list [flags]       # list active rules
vulnetix ignore remove [flags]     # deactivate a rule
vulnetix ignore sync               # pull org rules into local memory and push yours up
```

`suppress` is an alias, so `vulnetix suppress add ...` is identical.

## Flags (`ignore add`)

At least one **anchor** is required: `--rule`, `--finding`, or `--file`.

| Flag | Type | Description |
|------|------|-------------|
| `--rule` | string | Rego rule id to suppress (the rego file id), e.g. `vnx-sec-001`. |
| `--finding` | string | Finding id (a CVE or other vuln id) to suppress. |
| `--file` | string | File path to suppress findings in. Matching is suffix-tolerant. |
| `--category` | string | Scanner category: `sast`, `secrets`, `iac`, `container`, `sca`, `license`, or `malware`. |
| `--type` | string | Suppression type (see below). Defaults to `rego_rule` when `--rule` is set, otherwise `risk_accepted`. |
| `--reason` | string | Human-readable justification, stored on the rule. |
| `--line-range` | string | Line range within the file, e.g. `10-14`. |
| `--expires-in` | int | Auto-expire the rule after N days (`0` = never). |

## Suppression types

Five types record a human triage outcome. Two are machine sources that Vulnetix sets for you.

| Type | Meaning |
|------|---------|
| `false_positive` | The finding is not real in this context. |
| `wont_fix` | Acknowledged, but a fix is not planned. |
| `risk_accepted` | The risk is understood and accepted, with a reason on record. |
| `mitigated` | A compensating control is already in place. |
| `deferred` | Not now; revisit later (pair with `--expires-in`). |
| `rego_rule` | Machine source — the rule suppresses a rego rule id. |
| `nosec` | Machine source — the rule came from an inline `nosec` comment. |

## `nosec` in code

Some suppressions belong next to the line they describe. Vulnetix reads gosec-compatible `nosec` comments in `#`, `//`, `--`, and `;` comment styles (case-insensitive, anywhere on the line).

| Comment | Effect |
|---------|--------|
| `// nosec` on a finding's line | Drop **every** finding on that line. |
| `# nosec vnx-315,vnx-320` on a finding's line | Drop **only** those rule ids on that line. |
| `// nosec` on **line 1** of a file | Drop **every** finding in the whole file. |
| `# nosec vnx-315` on **line 1** of a file | Whole-file skip, but only the listed rule ids. |

The rule-id list after `nosec` is split on commas, spaces, or tabs; an empty list means "all rules on this line".

```go
password := os.Getenv("DB_PASSWORD") // nosec vnx-sec-014 — read from the environment, not hard-coded
```

Every scan reports how many findings each pass suppressed, so nothing disappears silently:

```
3 finding(s) suppressed by nosec comments
1 finding(s) suppressed by ignore rules
```

### nosec is synced automatically

You do not run `ignore add` for a `nosec` comment. A SAST-family scan
(`sast`/`secrets`/`iac`/`containers`) now does three things with the directives it finds:

1. **Writes them to `.vulnetix/memory.yaml`** as `origin: nosec` suppression records, so
   they persist across runs and work offline.
2. **Mints or updates an org rule** when you are authenticated: the reconciled set rides the
   scan's SARIF upload, and the backend upserts one `Suppression` row per directive (keyed by
   the rule + code snippet, so a re-scan updates the same row instead of duplicating).
3. **Tracks code drift.** Using git history (blame + rename following), the scanner relocates
   each suppression's file path and line number as the code moves. If the `nosec` comment (or the
   line a manual rule was pinned to) is deleted, the org row is **auto-deactivated** with reason
   `anchor removed` — reversible, and visible in the audit trail.

The identity a rule is tracked by is its **code snippet**, not its file/line, which is what lets
it follow a rename or a line shift without losing history or minting a duplicate.

## Local memory (`.vulnetix/memory.yaml`)

Rules created with `vulnetix ignore add` are written to `.vulnetix/memory.yaml` under a `suppressions:` block. This is the offline store — it works with no network and travels with the repo alongside your triage history.

```yaml
suppressions:
  - uuid: 6f1c9c3e-...
    rule_id: vnx-sec-001
    category: sast
    type: risk_accepted
    reason: "input is validated upstream by the gateway"
    finding_id: ""
    file_path: internal/handler/login.go
    line_range: "42-58"
    repository_full_name: acme/api
    branch: main
    created_at: 1721174400
    expires_at: 1729036800
    is_active: true
```

Only **active** and **unexpired** rules are applied on the next scan. `ignore remove` deactivates a rule (`is_active: false`) rather than deleting it, so the audit trail is preserved.

## Org-wide sync

```bash
# Authenticate first (see the Authentication section), then:
vulnetix ignore sync
```

`sync` pulls the organisation's rules into local memory and pushes your local rules up, so a suppression made on one machine holds across the whole team. In the Vulnetix console, the **Suppression Policies** page is the central registry: every rule grouped by repository and category, newest first, with extend / deactivate / delete actions. Per-finding "Ignore this finding" flows create rules straight from the finding pages.

## Matching: every anchor must match

Suppression is deliberately conservative. A rule silences a finding **only when every anchor it specifies matches**:

- `--rule` is compared against the finding's rule id, case-insensitively.
- `--finding` is compared against the finding id (CVE / vuln id).
- `--category` is compared against the scanner category.
- `--file` uses suffix-tolerant matching, so `src/app.go` covers `repo/src/app.go`.

An **anchorless** rule matches nothing — an "ignore everything" mistake is not expressible. This is what makes a `ruleId`-specific rule safe: `--rule vnx-sec-001` suppresses that one weakness class and leaves everything else reporting.

Matching applies across every scanner pipeline — SAST, secrets, IaC and container (by rego rule id), SCA (by CVE and manifest file), license (by rule / SPDX id / file), and malscan (by rule / file).

## Worked examples

**Accept a specific CVE for 90 days:**

```bash
vulnetix ignore add \
  --finding CVE-2024-0001 \
  --category sca \
  --type risk_accepted \
  --reason "vulnerable path is not reachable; upstream fix tracked in JIRA-123" \
  --expires-in 90
```

**Silence one SAST rule in one file:**

```bash
vulnetix ignore add \
  --rule vnx-sec-001 \
  --file internal/handler/login.go \
  --line-range 42-58 \
  --reason "input validated by the gateway"
```

**Mark a known false positive from a secrets scan:**

```bash
vulnetix ignore add \
  --file config/example.env \
  --category secrets \
  --type false_positive \
  --reason "sample values only"
```

**List and remove:**

```bash
vulnetix ignore list
vulnetix ignore remove --rule vnx-sec-001
```

**Share the decision with the org:**

```bash
vulnetix ignore sync
```

## See also

- [Scan Command Reference](../scan/) — where findings are produced and suppressions are applied.
- [SAST Command Reference](../sast/) — the rego rule ids you suppress with `--rule` and `nosec`.
