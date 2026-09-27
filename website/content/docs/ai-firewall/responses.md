---
title: "Block responses & exit codes"
weight: 30
description: "The 403 the gateway returns when it refuses a request, every code it can carry, the X-Vulnetix-Firewall-* response headers, and the CLI exit codes."
---

When the gateway refuses a request it returns **HTTP 403** with an OpenAI-shaped error body. That shape is the point: an OpenAI SDK raises it as an ordinary permission error, so a policy refusal lands in error handling you already have rather than in a code path nobody wrote.

```json
{
  "error": {
    "message": "request blocked by AI firewall policy: guardrail 'No connection strings' matched",
    "type": "policy_violation",
    "code": "request_blocked",
    "blocked_by": "No connection strings",
    "violations": [
      {"policy_uuid": "…", "policy_name": "No connection strings", "rule_type": "blocked_pattern", "action": "block", "detail": "content matched pattern for policy \"No connection strings\""}
    ]
  }
}
```

`type` is always `policy_violation`. `code` says which stage refused it. `blocked_by` names the rule that refused the request, and `violations` lists every rule that matched, including redact and flag rules that fired before it. It never includes the matched text. An Anthropic-dialect route returns the same fields inside Anthropic's `{"type":"error","error":{"type":"permission_error",…}}` envelope.

## Codes

| Status | `code` | Meaning | What to do |
| --- | --- | --- | --- |
| 403 | `provider_denied` | The org denies this provider outright. | `vulnetix ai-firewall policy provider <slug> --allow`, or point the client somewhere else. |
| 403 | `provider_key_missing` | No provider key is stored for this org, so the gateway has nothing to call upstream with. | `vulnetix ai-firewall key set <slug>` — see [BYOK](/docs/ai-firewall/byok/). |
| 403 | `model_denied` | This model is on the org's deny list. | Use another model, or remove the deny entry. |
| 403 | `model_not_allowed` | The provider is in **allowlist mode** and this model is not on the list — note that nobody denied it. | Add it: `policy model <slug> --provider <p> --allow`. See [the allowlist flip](/docs/ai-firewall/policy/). |
| 403 | `request_blocked` | A guardrail with `--action block` matched. `blocked_by` names it. | Change the prompt, or the rule. |
| 403 | `tool_denied`, `mcp_denied`, `skill_denied`, `client_denied` | A capability rule refused a tool, MCP server, skill or client the request carried. | See the agent context rules. |
| 403 | `delimiter_tampered` | A `delimiter_integrity` guardrail refused a request carrying a sealed harness block that failed its integrity check. | See [nonces](/docs/ai-firewall/nonces/). |
| 401 | — | The Vulnetix API key is missing, wrong, or the client is sending the *provider's* key instead. | See below. |

## 401 versus 403

A **403** means you authenticated fine and policy said no. A **401** means the gateway does not know who you are — and the usual cause is the two-key confusion:

- The client is sending its **provider** key. The gateway wants your **Vulnetix** key; the provider key is the one it holds server-side.
- The key is sent in neither header the gateway reads. It accepts `Authorization: Bearer` first, then `x-api-key`, so `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` both work, as long as the value is the **Vulnetix** key.

`vulnetix ai-firewall status` checks for both.

## Redaction and flagging do not fail

Only `--action block` produces a 403. The other two actions let the request through:

- **`redact`** rewrites each match to the literal `[REDACTED]` and forwards the request. The model sees the redacted prompt. Your code sees a normal 200 carrying `X-Vulnetix-Firewall-Decision: redact`.
- **`flag`** forwards the request untouched and records that a rule matched. Your code sees a normal 200 carrying `X-Vulnetix-Firewall-Decision: flag`, and the match shows up in the inference log.

The body never says a rule fired; the response headers do. A client that reads them, as Belai does, can show the user that a redaction or flag happened without the gateway revealing what it matched.

## Response headers

Every response the gateway answers reports what it did. The values are facts: a decision, rule **names**, counts and an id. They never include the text a rule matched, and a provider cannot set them, because the gateway drops any `X-Vulnetix-*` header from the upstream response.

| Header | Value |
| --- | --- |
| `X-Vulnetix-Firewall-Request-Id` | A UUID for this request, on every response, refusals included. |
| `X-Vulnetix-Firewall-Decision` | `allow`, `redact`, `flag` or `block`. Set once the guardrails have run. |
| `X-Vulnetix-Firewall-Rules` | The names of the matched rules, percent-encoded and comma-separated. At most 8 names or 512 bytes. |
| `X-Vulnetix-Firewall-Redactions` | How many redacting rules matched. |
| `X-Vulnetix-Firewall-Stripped` | How many tools or MCP servers a `strip` rule removed. |
| `X-Vulnetix-Firewall-Nonce` | Only when the request carried sealed blocks: `mode=enforce\|observe;verified=N;unknown=N;tampered=N;stripped=N`. See [nonces](/docs/ai-firewall/nonces/). |

```http
HTTP/1.1 200 OK
X-Vulnetix-Firewall-Request-Id: 6f1c2d0e-8a4b-4c1e-9f3a-2b7d5e6a9c10
X-Vulnetix-Firewall-Decision: redact
X-Vulnetix-Firewall-Rules: PII%20emails
X-Vulnetix-Firewall-Redactions: 1
```

On a stream the headers arrive before the first token.

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
