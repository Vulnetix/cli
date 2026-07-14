---
title: "Guardrails"
weight: 4
description: "Content rules the gateway enforces inline — blocked patterns, PII redaction, and message caps — with RE2 pattern rules and a cookbook."
---

A guardrail inspects the content of a request and blocks, redacts, or flags it. Guardrails run after provider and model policy, in ascending `priority` (lowest first), on every proxied request.

```bash
vulnetix ai-firewall policy guardrail "No connection strings" \
  --rule-type blocked_pattern \
  --action block \
  --pattern '(?i)postgres://\S+' \
  --priority 10
```

## Rule types and actions

Three rule types, three actions. Every combination is valid, and they mean different things:

| Rule type | `pattern` holds | What it matches |
| --- | --- | --- |
| `blocked_pattern` | an RE2 regex | anything in the request content |
| `pii_redact` | an RE2 regex, **or empty** | empty selects the built-in detectors: email, credit card, SSN, phone |
| `max_messages` | a positive integer | conversations longer than that many messages |

| Action | What the gateway does |
| --- | --- |
| `block` | 403 `request_blocked`, naming the rule in `blocked_by`. The request never reaches the provider. |
| `redact` | Rewrites each match to the literal `[REDACTED]` and **forwards** the request. |
| `flag` | Forwards the request and records **that** a rule matched — never what it matched. |

`flag` is the one to reach for first. It tells you how often a rule would have fired without breaking anyone's workflow, which is how you find out that your "obviously safe" pattern matches half the legitimate prompts in the company.

## Patterns are Go RE2

{{< callout type="error" >}}
**RE2 has no lookahead and no lookbehind.** `(?=...)`, `(?!...)`, `(?<=...)`, and `(?<!...)` do not compile.

And a guardrail whose pattern does not compile is **skipped by the gateway**. It sits in the dashboard looking enforced, and enforces nothing — a silent hole in your policy, which is far worse than an error.

`vulnetix ai-firewall status` compiles every pattern and warns about any that fail. Run it in CI.
{{< /callout >}}

The fix is nearly always to drop the assertion. You are matching content in order to block it, not extracting a capture group — so the surrounding context can stay in the match:

```text
(?<=orgUuid=)\S+      ✗ does not compile
orgUuid=\S+           ✓ blocks exactly the same requests
```

RE2 is linear-time by construction, which is why it is used: a catastrophically backtracking regex in an inline proxy would be a denial-of-service vector against your own AI traffic.

Everything else you would expect works: `(?i)` for case-insensitivity, character classes, alternation, anchors, bounded repetition.

## Priority

Ascending, **lowest first**. The default is `100`.

```bash
--priority 10    # runs first
--priority 100   # default
--priority 900   # runs last
```

Order matters when actions differ. A `redact` rule at priority 10 rewrites the text before a `block` rule at priority 20 ever sees it — so the block rule may no longer match. If you want a hard block, give it a *lower* priority number than any redaction that might mask it.

## PII redaction

```bash
vulnetix ai-firewall policy guardrail "PII redaction" \
  --rule-type pii_redact --action redact --pattern '' --priority 20
```

An empty pattern selects the built-in detectors: **email addresses, credit card numbers, social security numbers, and phone numbers**. Supply a pattern instead to redact something specific to your organisation — an internal employee ID format, say.

With `--action redact` the matched text becomes `[REDACTED]` and the request continues, so the model still gets a usable prompt. With `--action block` a prompt containing PII is refused outright.

## Message caps

```bash
vulnetix ai-firewall policy guardrail "Agent loop cap" \
  --rule-type max_messages --action block --pattern '40' --priority 50
```

This is the practical brake on a runaway agent. An agent stuck in a tool-call loop will happily burn an afternoon's budget; a cap at 40 messages ends it. `pattern` is the integer, as a string.

## Cookbook

Every pattern below is RE2 and compiles.

**AWS access key**

```bash
--rule-type blocked_pattern --action block --priority 10 \
--pattern '(?i)AKIA[0-9A-Z]{16}'
```

**Private key material**

```bash
--rule-type blocked_pattern --action block --priority 10 \
--pattern '-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'
```

**Database connection strings**

```bash
--rule-type blocked_pattern --action block --priority 10 \
--pattern '(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s"'"'"']+'
```

**Internal hostnames** — tune the suffix to your estate

```bash
--rule-type blocked_pattern --action flag --priority 30 \
--pattern '(?i)[a-z0-9.-]+\.(internal|corp|local|svc\.cluster\.local)\b'
```

**Prompt injection: instruction override** — start on `flag`; this one has false positives

```bash
--rule-type blocked_pattern --action flag --priority 30 \
--pattern '(?i)ignore (all |any )?(the )?(previous|prior|above) instructions'
```

**Generic high-entropy secret assignment**

```bash
--rule-type blocked_pattern --action block --priority 15 \
--pattern '(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'"'"']?[A-Za-z0-9/+_-]{20,}'
```

Rather than curating these yourself, pull in the [server-maintained baseline](/docs/ai-firewall/baseline/) — PII masking, prompt injection, and more — which improves without you doing anything.

## Managing rules

Guardrails are keyed by UUID on the server, but the CLI addresses them by **name** when reconciling from a [policy file](/docs/ai-firewall/policy-file/), so names must be unique within an organisation.

```bash
# Create or update by name
vulnetix ai-firewall policy guardrail "No connection strings" \
  --rule-type blocked_pattern --action block --pattern '(?i)postgres://\S+'

# Update or delete an existing rule by uuid
vulnetix ai-firewall policy guardrail "No connection strings" --uuid <uuid> --disable
vulnetix ai-firewall policy guardrail "No connection strings" --uuid <uuid> --delete
```

| Flag | Meaning |
| --- | --- |
| `--uuid` | Existing guardrail (required for `--delete`) |
| `--rule-type` | `blocked_pattern`, `max_messages`, `pii_redact` — required when creating |
| `--action` | `block`, `redact`, `flag` |
| `--pattern` | Regex, or the integer for `max_messages` |
| `--priority` | Evaluation order, lowest first (default `100`) |
| `--enable` / `--disable` | Toggle without deleting |
| `--delete` | Remove it (needs `--uuid`) |

## What is recorded

With inference logging on, the gateway records that a request was blocked, redacted, or flagged, and which guardrails matched. It does **not** record the prompt, the completion, or the matched text — a log of everything your PII rule caught would itself be the largest PII spill in the building. See `vulnetix ai-firewall settings --logs`.
