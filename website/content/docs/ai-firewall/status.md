---
title: "Status & checks"
weight: 8
description: "Every alignment check the CLI runs — the 403s you would otherwise meet at runtime, and the client whose traffic is bypassing the firewall without ever erroring."
---

```bash
vulnetix ai-firewall status
```

Reports the organisation's policy, which local clients are wired to the gateway, and every way the two disagree.

```text
Vulnetix AI Firewall

  Gateway              https://guardrails.vulnetix.com
  Organization         6f2a1c3e-0000-0000-0000-000000000001
  Credential source    keyring
  Inference logging    off

Providers
  Slug       Org policy       Key      Wiring
  openai     default (allow)  stored   OPENAI_BASE_URL, OPENAI_API_BASE
  anthropic  deny             stored   ANTHROPIC_BASE_URL
  mistral    default (allow)  missing  snippet only (no SDK base-URL env var)

Guardrails
  Priority  Name                  Rule             Action  Enabled
        10  No connection strings blocked_pattern  block   true
        20  PII redaction         pii_redact       redact  true

Local clients
  Client         Scope    State            Path
  Shell          user     wired            /home/you/.zshrc
  Codex          user     wired            /home/you/.codex/config.toml
  Claude Code    project  points elsewhere /home/you/repo/.claude/settings.json
  Cursor         user     manual

Checks
  [warning] base URL is https://api.anthropic.com, not the gateway — requests from Claude Code are not screened by the AI Firewall
```

## Client states

| State | Meaning |
| --- | --- |
| `wired` | The client's base URL points at this organisation's gateway. |
| **`points elsewhere`** | The client has a base URL, and it is not ours. Its traffic goes straight to the provider. |
| `not wired` | No base URL configured. The client is present but unconfigured. |
| `manual` | The client keeps its base URL in application state — there is no file to read. Cursor and Windsurf. |
| `not installed` | Not on this machine. Not reported. |

`points elsewhere` is why this command exists. Every other misconfiguration surfaces eventually as an error someone has to debug. A client quietly calling `api.openai.com` never errors at all — it simply is not protected, and nothing tells you.

## The checks

| Check | Severity | What happens at runtime | Fix |
| --- | --- | --- | --- |
| `bypasses_firewall` | warning | Nothing — and that is the problem. The request is unscreened. | `vulnetix ai-firewall install <client>` |
| `provider_denied` | error | Every request returns 403 | Allow the provider, or unwire the client |
| `provider_key_missing` | error | Every request returns 403 | `vulnetix ai-firewall key set <provider>` |
| `model_denied` | error | Every request returns 403 | Change the pinned model, or the policy |
| `model_not_allowed` | error | Every request returns 403 | The provider is in [allowlist mode](/docs/ai-firewall/policy/) and this model is not on the list |
| `key_env_unset` | warning | Requests fail to authenticate | `export VULNETIX_API_KEY=...` |
| `guardrail_pattern_invalid` | warning | **The rule is silently skipped** — it is not enforced | Fix the pattern; RE2 has no lookaround |
| `wire_unsupported` | warning | The client cannot talk to the gateway at all | See [wire formats](/docs/ai-firewall/) |

The error-level checks are all the same shape: a 403 you would otherwise meet at request time with no idea which of five policy stages produced it. The CLI already knows the policy and already knows what each client has pinned, so it can tell you before you ship.

### Where pinned models are read from

| Client | Source |
| --- | --- |
| Claude Code | `ANTHROPIC_MODEL` in `.claude/settings.json` |
| Codex | `model` in `~/.codex/config.toml` |
| aider | `model:` in `.aider.conf.yml` |
| Continue | `models[].model` in `~/.continue/config.yaml` |

### On environment variables

The shell client is checked against the **process environment**, not against what is written in your rc file. The rc file is what the CLI wrote; the environment is what an SDK will actually see — and that is the thing that decides whether traffic is proxied. A block written into `.zshrc` that was never sourced correctly shows as `not wired`.

Only variable *names*, and whether they are set, are read or printed. Values never are.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command ran. Findings may still have been reported. |
| `1` | The command failed — or `--strict` was passed and an error-level check fired. |

Exit 0 with findings is deliberate: it makes `status` safe to call from a shell prompt or a status line. Use `--strict` in CI, where a silent misalignment is the thing you are trying to catch:

```bash
vulnetix ai-firewall status --strict
```

## JSON

```bash
vulnetix ai-firewall status -o json
```

```json
{
  "gateway": { "baseUrl": "https://guardrails.vulnetix.com", "org": "6f2a...", "logsEnabled": false },
  "providers": [ { "slug": "openai", "orgAction": "", "hasKey": true } ],
  "guardrails": [ { "name": "PII redaction", "ruleType": "pii_redact" } ],
  "clients": [
    { "id": "codex", "name": "Codex", "scope": "user", "state": "wired",
      "path": "/home/you/.codex/config.toml", "baseUrl": "https://guardrails.vulnetix.com/openai/6f2a.../v1", "model": "gpt-5" }
  ],
  "checks": [
    { "id": "model_not_allowed", "severity": "error", "client": "codex",
      "message": "Codex has \"gpt-5\" pinned, but openai is in allowlist mode and this model is not on the list — every request returns 403 model_not_allowed" }
  ],
  "summary": { "errors": 1, "warnings": 0 }
}
```
