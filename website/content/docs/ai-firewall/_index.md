---
title: "AI Firewall"
weight: 9
description: "Route AI clients through a policy-enforcing gateway — provider and model allow/deny, content guardrails, PII redaction, and BYOK provider keys."
---

The **AI Firewall** is a hosted, OpenAI-compatible gateway. Your code points its `base_url` at it instead of at the provider, and every request is screened against the organisation's policy — which providers may be called, which models, and what may appear in a prompt — before it is forwarded upstream.

The CLI wires the AI clients on a machine to that gateway, proves they are wired, and manages the policy the gateway enforces.

```bash
vulnetix ai-firewall key set openai --from-env OPENAI_API_KEY
vulnetix ai-firewall install
vulnetix ai-firewall status
```

## The gateway URL

```text
https://guardrails.vulnetix.com/{providerSlug}/{orgUuid}/v1
                                └─ openai      └─ your org
```

The organisation is a **path component**, not a header. That is a deliberate constraint: most SDKs let you override the base URL and nothing else. If the org travelled in an `X-Organisation-UUID` header, every client would need custom header support and most would be unable to use the firewall at all. As a path segment it works anywhere a `base_url` can be set — which is everywhere.

(The Package Firewall makes the opposite trade, carrying the org as the HTTP Basic username, because package managers all speak netrc and none of them let you rewrite a URL path.)

## Two keys, and only one of them is yours to carry

This is the part that trips everyone up. There are two credentials, and they are not interchangeable:

| Credential | Who holds it | What it does |
| --- | --- | --- |
| **Vulnetix API key** | your machine, your CI | authenticates you to the *gateway* |
| **Provider key** (OpenAI, Anthropic, …) | the server, encrypted | authenticates the *gateway* to the provider |

A wired client sends `Authorization: Bearer $VULNETIX_API_KEY`. The gateway resolves your org from the URL, checks the request against policy, decrypts your provider key, swaps it into the outbound `Authorization` header, and forwards the call. The request that reaches OpenAI is authenticated with *your* OpenAI key — so billing stays direct with the provider, and there is no token markup.

The provider key never travels to a developer machine. It is stored write-only: no API returns it, and the CLI can only tell you whether one exists ([BYOK](/docs/ai-firewall/byok/)).

{{< callout type="error" >}}
It follows that a client is only wired when **both** halves are right: the base URL points at the gateway *and* the API key variable holds the Vulnetix key. Setting only the base URL sends your provider key to the gateway, which rejects it. Setting only the key sends the Vulnetix key straight to OpenAI, which rejects it. `vulnetix ai-firewall status` checks for exactly this.
{{< /callout >}}

## What the gateway enforces, and in what order

Each stage below returns HTTP 403 with an OpenAI-shaped error body, so an SDK surfaces it as an ordinary permission error. The `code` tells you which stage stopped the request.

1. **Provider policy** — a denied provider fails immediately: `provider_denied`.
2. **BYOK key** — no stored key for that provider, nothing to forward with: `provider_key_missing`.
3. **Model policy** — a denied model fails with `model_denied`. A model that is merely *unlisted* fails with `model_not_allowed`, but only in allowlist mode — see below.
4. **Guardrails** — evaluated in ascending `priority`, lowest first. A `block` match returns `request_blocked` naming the rule; a `redact` match rewrites the matched text and forwards; a `flag` match forwards and records that a rule matched.

Full reference: [block responses and exit codes](/docs/ai-firewall/responses/).

### The allowlist flip

> **The first allow entry for a provider turns that provider allowlist-only.**

With no model entries, every model the provider offers is usable. Deny a model and it alone is blocked. But **allow** a model — even one — and the provider switches to allowlist mode: from that moment, any model *not* on the allow list is refused with `model_not_allowed`, without ever having been denied.

This is the single most surprising behaviour in the product, and the usual cause of "it worked yesterday". `vulnetix ai-firewall status` flags a client whose pinned model would be refused this way. [More in the policy reference](/docs/ai-firewall/policy/).

## Wire formats

The gateway proxies an OpenAI-compatible surface. That matters because not every client speaks it:

- **`/v1/chat/completions`** — the OpenAI SDKs, LangChain, LlamaIndex, aider, Continue, Cursor, Windsurf.
- **`/v1/messages`** — the Anthropic wire. Claude Code speaks *only* this.
- **`/v1/responses`** — the OpenAI Responses API. Codex speaks *only* this: its `wire_api` setting no longer accepts anything else.

The CLI does not guess. It asks the server what the gateway proxies for each provider, and if a client needs a wire the gateway does not serve, `install` **skips that client and says why** rather than writing a configuration that would 404 at request time.

`/v1/models` is filtered by policy, so a client that autodiscovers models only ever sees ones it is permitted to call.

## What the CLI adds

The dashboard can do policy. The CLI can do policy *and* the machine:

- [`install`](/docs/ai-firewall/install/) writes the base URL and key into every AI client on the box — shell, project env, Claude Code, Codex, Continue, aider — and tells you what to paste into the ones that have no config file.
- [`status`](/docs/ai-firewall/status/) is the honest answer to "is this actually on?" It finds clients whose traffic is bypassing the firewall entirely, and guardrails that look enforced but are not.
- [`apply`](/docs/ai-firewall/policy-file/) reconciles the whole policy from a file you can review and commit.
- [`snippet`](/docs/ai-firewall/snippets/) is the only route for the clients that environment variables cannot reach.

{{< cards >}}
  {{< card link="quickstart" title="Quickstart" subtitle="Store a key, wire the machine, prove it works, watch a guardrail fire." >}}
  {{< card link="install" title="Wiring clients" subtitle="Every client, the exact file written, and the ones that cannot be written at all." >}}
  {{< card link="policy" title="Providers & models" subtitle="Allow, deny, and the allowlist flip that catches people out." >}}
  {{< card link="guardrails" title="Guardrails" subtitle="Rule types, RE2 patterns, PII redaction, and a cookbook." >}}
  {{< card link="byok" title="Provider keys (BYOK)" subtitle="How your OpenAI key is stored, used, and rotated." >}}
  {{< card link="policy-file" title="Policy as code" subtitle=".vulnetix/ai-firewall.yaml, apply, prune, and drift." >}}
  {{< card link="baseline" title="Recommended guardrails" subtitle="The server-supplied baseline, and how to override it." >}}
  {{< card link="status" title="Status & checks" subtitle="Every check, what it means, and how to fix it." >}}
  {{< card link="snippets" title="Code snippets" subtitle="For the SDKs and providers env vars cannot reach." >}}
  {{< card link="responses" title="Block responses" subtitle="Every 403 code, and what to do about it." >}}
  {{< card link="uninstall" title="Uninstall" subtitle="Removing the wiring without damaging your configs." >}}
  {{< card link="troubleshooting" title="Troubleshooting" subtitle="Blocked when you did not expect it, and worse — not blocked when you did." >}}
{{< /cards >}}
