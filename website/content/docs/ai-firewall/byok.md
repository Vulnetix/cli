---
title: "Provider keys (BYOK)"
weight: 5
description: "How your OpenAI or Anthropic key is stored, used by the gateway, rotated, and why no API will ever give it back to you."
---

The gateway calls the provider with **your** key. Bring your own key (BYOK): billing stays direct with the provider, there is no token markup, and Vulnetix never resells you inference.

```bash
vulnetix ai-firewall key set openai --from-env OPENAI_API_KEY
vulnetix ai-firewall key remove openai
```

## Where the key lives

The key is encrypted with AWS KMS under an **encryption context bound to your organisation and that provider**. The context is part of the ciphertext's integrity check: the same key material encrypted for org A cannot be decrypted in the context of org B, even by a caller who obtains the ciphertext. The binding is not a policy decision that could be misconfigured away — it is cryptographic.

It is stored **write-only**. No endpoint returns it: not the API, not this CLI, not the dashboard. The only things any of them can tell you are whether a key exists and when it was last updated:

```bash
vulnetix ai-firewall status
```

```text
Providers
  Slug       Org policy       Key      Wiring
  openai     default (allow)  stored   OPENAI_BASE_URL, OPENAI_API_BASE
  anthropic  default (allow)  missing  ANTHROPIC_BASE_URL
```

A key you cannot read back is a key that cannot leak through a misconfigured read endpoint, a debug log, or a support screenshot. The cost is that there is no "show me the key" — if you lose it, you rotate it at the provider and store the new one.

## How it is used

On each request the gateway resolves your org from the URL path, authenticates you by your Vulnetix API key, applies policy, and only then decrypts the provider key and swaps it into the outbound `Authorization` header. The provider key exists in plaintext for the duration of one proxied request, in the gateway's memory, and nowhere else.

Your machine never holds it. That is the point: a laptop that is compromised gives up a Vulnetix API key — which you can revoke centrally, and which only works through a policy-enforcing proxy — rather than an OpenAI key with your whole organisation's billing behind it.

## Setting a key

Three sources, exactly one at a time:

| Flag | Use when |
| --- | --- |
| `--from-env VAR` | Normal use. The key is already in your environment or your secret manager. |
| `--stdin` | Piping from a password manager: `op read op://vault/openai/key \| vulnetix ai-firewall key set openai --stdin` |
| `--key <literal>` | Automation with no better option. **Warns**, because it puts the key in your shell history and in the process list where any local user can read it. |

The CLI validates before sending: the key must be non-empty, at most 4096 bytes, and free of control characters. That last check is not pedantry — a newline in the key would be smuggled into the upstream `Authorization` header, and header injection into a request that carries your organisation's credentials is exactly the sort of thing worth refusing loudly.

## Rotating

There is no atomic swap. Store the new key over the old one:

```bash
vulnetix ai-firewall key set openai --from-env NEW_OPENAI_KEY
```

The write is a replace, so the window in which requests could fail is the duration of that one call. Revoke the old key at the provider afterwards, not before — revoking first means every request between the revocation and the update fails upstream with a provider 401, which is harder to diagnose than a clean `provider_key_missing`.

## When there is no key

Every request through that provider returns:

```json
{
  "error": {
    "message": "no provider key configured for this organisation",
    "type": "policy_violation",
    "code": "provider_key_missing"
  }
}
```

This is also why `vulnetix ai-firewall install` **will not wire a provider that has no key**. Writing a base URL that points at a gateway which cannot fulfil the request would produce a 403 at some later, more confusing moment. The install output names the providers it skipped:

```text
Skipped providers
  anthropic: no key stored for this org — run 'vulnetix ai-firewall key set anthropic'
```

## Keys in a policy file

A [policy file](/docs/ai-firewall/policy-file/) can name where a key comes from — never the key itself:

```yaml
providers:
  - slug: openai
    action: allow
    key:
      fromEnv: OPENAI_PROVIDER_KEY     # resolved at apply time
```

A provider entry with no `key:` block leaves the stored key untouched, so a policy file can be applied repeatedly by someone who has no access to the key at all.
