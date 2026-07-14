---
title: "Block responses & exit codes"
weight: 30
description: "The 403 the gateway returns when it refuses a request, every code it can carry, and the CLI exit codes."
---

When the gateway refuses a request it returns **HTTP 403** with an OpenAI-shaped error body. That shape is the point: an OpenAI SDK raises it as an ordinary permission error, so a policy refusal lands in error handling you already have rather than in a code path nobody wrote.

```json
{
  "error": {
    "message": "request blocked by AI firewall policy: guardrail 'No connection strings' matched",
    "type": "policy_violation",
    "code": "request_blocked",
    "blocked_by": ["No connection strings"]
  }
}
```

`type` is always `policy_violation`. `code` says which stage refused it. `blocked_by` is present for guardrail blocks and names every rule that matched.

## Codes

| Status | `code` | Meaning | What to do |
| --- | --- | --- | --- |
| 403 | `provider_denied` | The org denies this provider outright. | `vulnetix ai-firewall policy provider <slug> --allow`, or point the client somewhere else. |
| 403 | `provider_key_missing` | No provider key is stored for this org, so the gateway has nothing to call upstream with. | `vulnetix ai-firewall key set <slug>` — see [BYOK](/docs/ai-firewall/byok/). |
| 403 | `model_denied` | This model is on the org's deny list. | Use another model, or remove the deny entry. |
| 403 | `model_not_allowed` | The provider is in **allowlist mode** and this model is not on the list — note that nobody denied it. | Add it: `policy model <slug> --provider <p> --allow`. See [the allowlist flip](/docs/ai-firewall/policy/). |
| 403 | `request_blocked` | A guardrail with `--action block` matched. `blocked_by` names it. | Change the prompt, or the rule. |
| 401 | — | The Vulnetix API key is missing, wrong, or the client is sending the *provider's* key instead. | See below. |

## 401 versus 403

A **403** means you authenticated fine and policy said no. A **401** means the gateway does not know who you are — and the usual cause is the two-key confusion:

- The client is sending its **provider** key. The gateway wants your **Vulnetix** key; the provider key is the one it holds server-side.
- For Anthropic, the client set `ANTHROPIC_API_KEY` (sent as `x-api-key`) rather than `ANTHROPIC_AUTH_TOKEN` (sent as `Authorization: Bearer`). The gateway only reads the Bearer header, so it sees no credential at all.

`vulnetix ai-firewall status` checks for both.

## Redaction and flagging do not fail

Only `--action block` produces a 403. The other two actions let the request through:

- **`redact`** rewrites each match to the literal `[REDACTED]` and forwards the request. The model sees the redacted prompt. Your code sees a normal 200.
- **`flag`** forwards the request untouched and records that a rule matched. Your code sees a normal 200; the match shows up in the inference log.

So a `flag` rule that is firing constantly is invisible from the client's side. Check the logs, not the responses.

## Streaming

A request refused by policy is refused **before** the stream opens, so you get a plain 403 with the JSON body above — not a stream that opens and then dies, and not a partial completion. Streaming error handling does not need a special case.

## CLI exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. `status` also exits 0 when it reports findings, so it is safe in a shell prompt. |
| `1` | The command failed: authentication, a network error, an invalid flag, an invalid policy file — or `status --strict` with an error-level check. |

Commands that gate in CI:

```bash
vulnetix ai-firewall status --strict                    # non-zero on any error-level check
vulnetix ai-firewall apply --dry-run --baseline-required   # non-zero if the baseline is unavailable
```
