---
title: "Policy as code"
weight: 6
description: "The .vulnetix/ai-firewall.yaml schema, and how apply reconciles the org's live policy to it — with drift reporting, prune, and a CI gate."
---

`vulnetix ai-firewall apply` makes the organisation's live policy match a file you can review, diff, and commit.

```bash
vulnetix ai-firewall export                    # capture what is live today
vulnetix ai-firewall apply --dry-run           # what would change
vulnetix ai-firewall apply                     # change it
```

## The file

`.vulnetix/ai-firewall.yaml`:

```yaml
apiVersion: vulnetix.com/v1
kind: AiFirewallPolicy

metadata:
  # Optional, and worth setting. apply refuses to run if this does not match the
  # authenticated org — the commonest way to do real damage with a policy file is
  # to run staging's against production.
  org: 6f2a1c3e-0000-0000-0000-000000000001

spec:
  # Whether apply deletes server objects this file does not mention. Default false.
  prune: false

  settings:
    logsEnabled: false

  baseline:
    enabled: true          # pull in the server's recommended guardrails
    ref: recommended
    exclude:               # baseline guardrail ids to skip
      - pii-phone

  providers:
    - slug: openai
      action: allow        # allow | deny | default
      key:
        fromEnv: OPENAI_PROVIDER_KEY   # never the key itself
    - slug: openrouter
      action: deny

  models:
    - slug: gpt-4o
      provider: openai     # exactly one of provider: or anyProvider: true
      action: allow        # allow | deny
    - slug: claude-sonnet-4-5
      anyProvider: true
      action: allow

  guardrails:
    - name: block-aws-keys
      ruleType: blocked_pattern    # blocked_pattern | max_messages | pii_redact
      action: block                # block | redact | flag
      pattern: '(?i)AKIA[0-9A-Z]{16}'
      priority: 10
      enabled: true
    - name: cap-conversation
      ruleType: max_messages
      action: block
      pattern: "50"                # the integer, as a string
      priority: 50
```

### Fields

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `apiVersion` | string | yes | — | Must be `vulnetix.com/v1` |
| `kind` | string | yes | — | Must be `AiFirewallPolicy` |
| `metadata.org` | uuid | no | — | Guard. `apply` refuses on a mismatch unless `--force` |
| `spec.prune` | bool | no | `false` | Delete server objects absent from this file |
| `spec.settings.logsEnabled` | bool | no | unset | Inference logging (metadata only). Paid plans |
| `spec.baseline.enabled` | bool | no | `false` | Compose the server's recommended guardrails in |
| `spec.baseline.ref` | string | no | `recommended` | Named baseline set |
| `spec.baseline.exclude` | \[string] | no | — | Baseline guardrail **ids** to skip |
| `spec.providers[].slug` | string | yes | — | e.g. `openai` |
| `spec.providers[].action` | enum | yes | — | `allow` \| `deny` \| `default` |
| `spec.providers[].key.fromEnv` | string | no | — | Environment variable holding the provider key |
| `spec.providers[].key.fromFile` | path | no | — | File holding the provider key (`~` expanded) |
| `spec.models[].slug` | string | yes | — | Model id |
| `spec.models[].provider` | string | — | — | Exactly one of this or `anyProvider` |
| `spec.models[].anyProvider` | bool | — | `false` | Expand across every provider listing the slug |
| `spec.models[].action` | enum | yes | — | `allow` \| `deny` |
| `spec.guardrails[].name` | string | yes | — | **The reconcile key. Must be unique** |
| `spec.guardrails[].ruleType` | enum | yes | — | `blocked_pattern` \| `max_messages` \| `pii_redact` |
| `spec.guardrails[].action` | enum | yes | — | `block` \| `redact` \| `flag` |
| `spec.guardrails[].pattern` | string | — | — | RE2 regex, or an integer for `max_messages` |
| `spec.guardrails[].priority` | int | no | `0` | Ascending, lowest first |
| `spec.guardrails[].enabled` | bool | no | `true` | |
| `spec.guardrails[].baselineId` | string | no | — | Written by `export` when the rule came from a baseline |

The file is validated before anything is sent: enums, `provider` xor `anyProvider`, integer `max_messages`, and **every pattern is compiled**. A file with a lookbehind in it fails here rather than uploading a rule that would be silently skipped at request time.

### Keys are never in the file

`key.fromEnv` and `key.fromFile` name *where the key comes from*; the key itself is resolved at apply time. A credential in a file that lives in a repository is a credential that gets committed. `export` never writes a key source at all — the server does not return keys, so there is nothing to write.

## Reconcile keys

| Object | Keyed by |
| --- | --- |
| provider | `slug` |
| model | `(provider, slug)` |
| guardrail | **`name`** |

Guardrails are keyed on the server by UUID, but a UUID is meaningless in a file you are writing by hand. So `apply` resolves name → UUID from the live policy. That has a consequence:

{{< callout type="warning" >}}
**Guardrail names must be unique within the organisation.** `apply` hard-errors if the file contains a duplicate name, or if the server does. Rename one, or address it by `--uuid` with `policy guardrail` instead.
{{< /callout >}}

## Execution order

Changes are applied in this order, and it is not arbitrary:

```text
guardrails → models → providers → keys → settings
```

Guardrails go in **first**. If providers were enabled before the guardrails that constrain them, there would be a window — small, but real — in which the organisation's traffic was flowing through a firewall that had not yet been told what to block. Tightening a policy must never pass through a state looser than either the old one or the new one.

If a change fails midway, `apply` stops and tells you exactly how far it got:

```text
Error: applied 3 of 7 change(s), then failed: create guardrail block-aws-keys: 403 Forbidden
```

A half-applied policy is bad. A half-applied policy you do not know about is worse.

## Drift, and `--prune`

Objects that exist on the server but are not in your file are **reported, not destroyed**:

```text
Drift (left alone)
  guardrail "Ad-hoc PII rule": on the server, not in this file (pass --prune to delete)
```

Someone authored that in the dashboard, possibly during an incident, possibly an hour ago. Deleting it because it was absent from a file written last quarter would be the wrong default. Pass `--prune` (or set `spec.prune: true`) when you genuinely want the file to be the whole truth — and run `--dry-run` first, which lists exactly what would be deleted.

## `--dry-run`

Prints the plan and changes nothing:

```text
AI Firewall policy plan (dry run — nothing was changed)

  Policy file    .vulnetix/ai-firewall.yaml
  Baseline       baseline recommended (2026-07-01) composed in

Changes
  Op      Kind       Target             Detail
  create  guardrail  block-aws-keys     blocked_pattern / block, priority 10
  update  guardrail  PII redaction      action flag -> redact, priority 100 -> 20
  create  model      openai/gpt-4o      allow
  update  provider   openrouter         deny

Drift (left alone)
  guardrail "Ad-hoc PII rule": on the server, not in this file (pass --prune to delete)
```

## export

```bash
vulnetix ai-firewall export                  # writes .vulnetix/ai-firewall.yaml
vulnetix ai-firewall export --stdout         # to stdout
vulnetix ai-firewall export -f prod.yaml --force
```

Serialises the live policy. It refuses to overwrite an existing file without `--force`.

`export` → `apply` is a fixpoint: applying what you just exported produces no changes. That is worth knowing, because it means you can safely adopt this workflow on an organisation that has been managed by hand — export, commit, and you have a starting point that is exactly what is already live.

With one exception, and it is a useful one. If the organisation already holds a guardrail whose pattern does not compile, `export` writes it out faithfully and `apply` then **refuses the file**:

```text
Error: .vulnetix/ai-firewall.yaml: guardrails[Broken rule]: pattern does not compile:
  error parsing regexp: invalid named capture: `(?<=orgUuid=)\S+`
  Go uses RE2, which has no lookahead or lookbehind. Drop it — `orgUuid=\S+` blocks
  the same requests as `(?<=orgUuid=)\S+`.
```

That rule was never being enforced — the gateway skips a pattern it cannot compile. Adopting policy-as-code surfaces it and makes you fix it, which is the correct outcome even though it means the first `apply` after an `export` can fail.

## In CI

Check that the live policy matches the committed file on every pull request, and apply it on merge:

```yaml
- name: Check AI Firewall policy
  run: vulnetix ai-firewall apply --dry-run --baseline-required
  env:
    VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}

- name: Apply AI Firewall policy
  if: github.ref == 'refs/heads/main'
  run: vulnetix ai-firewall apply --baseline-required
  env:
    VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
    OPENAI_PROVIDER_KEY: ${{ secrets.OPENAI_PROVIDER_KEY }}
```

`--baseline-required` matters here. Outside CI, an unavailable baseline is a soft failure — you should not be blocked from applying your own policy because a recommendation service is down. In CI that leniency is wrong: it would apply a policy missing every baseline guardrail and report success. See [baseline](/docs/ai-firewall/baseline/).

## Flags

| Flag | Meaning |
| --- | --- |
| `-f, --file` | Policy file (default `.vulnetix/ai-firewall.yaml`) |
| `--dry-run` | Print the plan; change nothing |
| `--prune` | Delete server objects the file does not mention |
| `--no-baseline` | Do not compose in the recommended guardrails |
| `--baseline-required` | Fail if the baseline cannot be fetched (use in CI) |
| `--catalog` | Use a local baseline file instead of the server's |
| `--force` | Apply even when `metadata.org` does not match |
| `-o json` | Machine-readable plan |
