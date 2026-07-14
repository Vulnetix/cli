---
title: "Providers & models"
weight: 3
description: "Allow and deny providers and models — and the allowlist flip, where allowing one model silently refuses every other."
---

Provider and model policy decides *what* an organisation may call. It is evaluated before any guardrail runs, and a refusal here never reaches the provider at all.

## Providers

A provider is in one of three states:

| State | How | Effect |
| --- | --- | --- |
| default | no association (the initial state) | usable, if a key is stored |
| `allow` | `--allow` | usable — an explicit pin, useful as documentation |
| `deny` | `--deny` | every request returns 403 `provider_denied` |

```bash
vulnetix ai-firewall policy provider openrouter --deny
vulnetix ai-firewall policy provider openai --allow
vulnetix ai-firewall policy provider openai --clear    # back to default
```

Default and `allow` behave identically today. The difference is intent: an explicit `allow` records that someone decided, which matters when you are reading a policy six months later, and it survives a future change to what "default" means.

A provider with **no stored key** is not usable whatever its policy says — the gateway has nothing to authenticate upstream with, and returns `provider_key_missing`. See [BYOK](/docs/ai-firewall/byok/).

## Models

```bash
vulnetix ai-firewall policy model gpt-4o --provider openai --allow
vulnetix ai-firewall policy model gpt-3.5-turbo --provider openai --deny
vulnetix ai-firewall policy model claude-sonnet-4-5 --any-provider --allow
vulnetix ai-firewall policy model gpt-4o --provider openai --remove
```

Exactly one of `--provider <slug>` or `--any-provider` is required.

`--any-provider` expands, **at the moment you run it**, to every provider whose catalog currently lists that model slug. It is not a standing rule: a provider added to the catalog next month, or one that starts offering the model later, is *not* covered retroactively. Re-run the command if you want them included.

## The allowlist flip

{{< callout type="error" >}}
**The first `--allow` entry for a provider turns that provider allowlist-only.** From then on, any model that is not on the allow list is refused with `model_not_allowed` — even though nobody denied it.
{{< /callout >}}

Worked through:

```bash
# Nothing configured. Every model OpenAI offers is usable.
curl .../chat/completions -d '{"model":"gpt-4o", ...}'          # 200
curl .../chat/completions -d '{"model":"gpt-4o-mini", ...}'     # 200

# Deny one model. Only that model is blocked.
vulnetix ai-firewall policy model gpt-3.5-turbo --provider openai --deny
curl .../chat/completions -d '{"model":"gpt-4o", ...}'          # 200
curl .../chat/completions -d '{"model":"gpt-3.5-turbo", ...}'   # 403 model_denied

# Allow one model. OpenAI is now allowlist-only.
vulnetix ai-firewall policy model gpt-4o --provider openai --allow
curl .../chat/completions -d '{"model":"gpt-4o", ...}'          # 200
curl .../chat/completions -d '{"model":"gpt-4o-mini", ...}'     # 403 model_not_allowed  ← never denied
```

That last line is the one that catches people. `gpt-4o-mini` was working, nobody touched it, and it stopped — because someone allowed a *different* model.

This is a deliberate design: an allowlist that only takes effect once you have also denied everything else would not be an allowlist. But it is surprising, so:

- `vulnetix ai-firewall status` flags any wired client whose pinned model would be refused this way, and says explicitly that the provider is in allowlist mode.
- `vulnetix ai-firewall install --model <slug>` refuses to pin a model the policy would reject, rather than writing it and letting you discover the 403 later.

To leave allowlist mode, remove every allow entry for that provider:

```bash
vulnetix ai-firewall policy model gpt-4o --provider openai --remove
```

## Model discovery

`GET /v1/models` through the gateway is filtered by policy. A client that autodiscovers models — and most agent frameworks do — only ever sees models it is permitted to call, so it will not offer your users a model that would 403 on first use.

## Reading the current policy

```bash
vulnetix ai-firewall get
vulnetix ai-firewall get -o json
```

Or serialise it to a file you can review and commit — see [policy as code](/docs/ai-firewall/policy-file/):

```bash
vulnetix ai-firewall export
```

## Flags

`policy provider <slug>`

| Flag | Meaning |
| --- | --- |
| `--allow` | Explicitly allow the provider |
| `--deny` | Deny it org-wide |
| `--clear` | Remove the association (back to default) |

`policy model <slug>`

| Flag | Meaning |
| --- | --- |
| `--allow` | Add to the allow list (**puts the provider into allowlist mode**) |
| `--deny` | Add to the deny list |
| `--remove` | Remove the entry |
| `--provider <slug>` | Scope to one provider |
| `--any-provider` | Expand across every provider currently listing this model |

Both also accept `--base-url` and `-o {pretty,json}`.

{{< callout type="info" >}}
These commands are also spelled `vulnetix config set ai-firewall provider` and `... model`. Both spellings run the same code; the `config` form is kept because scripts use it.
{{< /callout >}}
