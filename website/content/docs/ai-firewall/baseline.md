---
title: "Recommended guardrails"
weight: 7
description: "The server-maintained baseline — PII masking, prompt injection — how it composes with your own rules, and why an unavailable baseline is a soft failure everywhere except CI."
---

The baseline is a set of guardrails the server recommends: PII redaction, prompt-injection detection, and so on. It is maintained centrally, so the rules improve without you upgrading the CLI or editing anything.

```bash
vulnetix ai-firewall baseline
```

```text
Recommended guardrails

  Ref      recommended
  Version  2026-07-01

  ID                        Name                        Rule             Action  Priority
  pii-email-redact          PII email redaction         pii_redact       redact        20
  pii-card-redact           PII card redaction          pii_redact       redact        21
  prompt-injection-ignore   Prompt injection: override  blocked_pattern  flag          30
```

It contains **guardrails only**. There are no provider or model allow/deny lists in it, and there never will be: which models an organisation may call is a decision about that organisation's business, not something to be pushed as a default.

## Using it

Set `spec.baseline.enabled` in your [policy file](/docs/ai-firewall/policy-file/) and apply:

```yaml
spec:
  baseline:
    enabled: true
    ref: recommended
    exclude:
      - pii-phone       # by id, not by name
```

```bash
vulnetix ai-firewall apply --dry-run
```

The baseline guardrails are composed into your own and applied together.

## Composition rules

**A local guardrail with the same name always wins.** The file is what your organisation decided; the baseline is a recommendation. So if the baseline ships `PII email redaction` as `redact`, and your file has a rule of that name set to `flag`, you get `flag` — you downgraded it deliberately, and an "improvement" that silently overrode that would be a bug.

**`exclude` drops entries by `id`**, not by name. The `id` is stable and never reused, which is precisely why it, and not the human-facing name, is the key: a baseline rule can be renamed for clarity without breaking every exclusion in the field.

Composed baseline rules record their origin, so `export` round-trips them:

```yaml
guardrails:
  - name: PII email redaction
    baselineId: pii-email-redact
    ruleType: pii_redact
    action: redact
    priority: 20
```

## Validation

Every pattern in the baseline is compiled before any of it is applied. If one fails, **the whole baseline is rejected** — not the bad rule alone.

That is deliberate. Applying nine of ten security rules and reporting success would leave you believing you had the full set when you had a hole in it. Better to apply none and say so loudly.

## When the baseline is unavailable

Outside CI, an unreachable or invalid baseline is a **soft failure**: an informational message, and the command carries on with your local policy.

```text
Baseline unavailable: the server does not serve a guardrail baseline (404). Continuing with local policy only.
```

Exit code 0. Your own policy is yours and should not become unappliable because a recommendation service is having a bad day. In `-o json` this surfaces as `"baseline": {"available": false}`.

{{< callout type="warning" >}}
In CI that leniency is exactly wrong: a pipeline that silently applies a policy with none of the baseline guardrails, and goes green, is worse than a pipeline that fails. Pass **`--baseline-required`**, which turns any baseline failure into a hard error.
{{< /callout >}}

## Overriding it

`--catalog <file>` replaces the server's baseline entirely with a local JSON or YAML file. Nothing is fetched.

```bash
vulnetix ai-firewall apply --catalog ./our-baseline.yaml
vulnetix ai-firewall baseline --catalog ./our-baseline.yaml
```

The file uses the same schema the server serves:

```yaml
version: "2026-07-01"
ref: our-baseline
guardrails:
  - id: pii-email-redact
    name: PII email redaction
    description: Redacts email addresses from prompts and completions.
    ruleType: pii_redact
    action: redact
    pattern: ""
    priority: 20
    enabled: true
    tags: [pii]
    severity: medium

  - id: prompt-injection-ignore-instructions
    name: "Prompt injection: instruction override"
    description: Flags attempts to override the system prompt.
    ruleType: blocked_pattern
    action: flag
    pattern: '(?i)ignore (all|any|previous) (prior |above )?instructions'
    priority: 30
    enabled: true
    tags: [prompt-injection]
    severity: high
```

Fields are the same enums as an ordinary guardrail, because a baseline entry is applied through the ordinary guardrail path — there is no separate mechanism, and nothing a baseline can express that you could not write yourself.

`--no-baseline` disables both the server fetch and any catalog.

## Flags

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--ref` | `baseline`, `apply` | Named baseline set (default `recommended`) |
| `--catalog` | `baseline`, `apply` | Local baseline file, replacing the server's |
| `--no-baseline` | `apply` | Do not compose any baseline in |
| `--baseline-required` | `apply` | Fail if the baseline cannot be fetched |
