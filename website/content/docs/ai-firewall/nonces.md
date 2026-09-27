---
title: "Nonces & sealed blocks"
weight: 29
description: "How the gateway issues nonces for a harness's sealed blocks, verifies them on every request, and strips forged blocks for a client that asks it to."
---

A coding harness such as [Belai](https://github.com/Vulnetix/belai) writes blocks of its own into a conversation: its system prompt, attachments, directives. It seals each one with a nonce and a SHA-256 of the content:

```
<attachment nonce="…" integrity="9f86d0…">file contents</attachment>
```

Text the model reads can contain things that *look* like those blocks: a file, a web page, a tool's output. The seal is what tells them apart. A forged block cannot carry a nonce the real harness reserved. When the harness takes its nonces from the gateway, the gateway can check the seals too, so a forged block is removed before it reaches the provider.

## Getting nonces

```bash
curl -H "Authorization: Bearer $VULNETIX_API_KEY" \
  "https://guardrails.vulnetix.com/openai/$ORG/v1/nonces?count=16"
```

```json
{"nonces": ["…"], "count": 16, "expires_at": "2026-09-28T10:00:00Z"}
```

The endpoint is authenticated like any inference route and gated by the provider allow/deny list. It never calls upstream. `count` is 1–64 (default 16).

A nonce is **signed, not stored**. It is random bytes plus an expiry (24 hours), authenticated with an HMAC keyed by your principal's own secret. Any gateway replica can verify it, nothing about it is written anywhere, and a nonce issued to one member or service account never verifies for another.

## What the gateway checks

On every inference, each sealed block of a harness kind (`system`, `agent`, `plan`, `goal`, `tools`, `skills`, `hooks`, `attachment`, `exploration`, `directive`, `diagnostics`) is one of:

| Result | Meaning |
| --- | --- |
| verified | The nonce was issued to you and is unexpired, and the hash matches the content. |
| unknown | The nonce was never issued to you, or has expired. |
| tampered | The hash does not match the content, or an `attachment`, `directive` or `diagnostics` block has none. |

Other tags (`<div>`, `<b>`, anything not on that list) are ordinary text and are never touched.

## Observe or enforce

- **Observe** is the default. Blocks are counted and nothing is removed, so a client that mints its own nonces is never broken.
- **Enforce**: a client sends `X-Vulnetix-Nonce-Mode: enforce` when every nonce it used came from this gateway. Unknown and tampered blocks are then **stripped** before the guardrails run and before the request is forwarded. Belai sends the header only while its whole nonce pool came from the gateway.

To refuse such requests instead of cleaning them, add a guardrail:

```bash
vulnetix ai-firewall policy guardrail "Sealed blocks intact" \
  --rule-type delimiter_integrity --action block
```

A request carrying a tampered block is then refused with 403 `delimiter_tampered`. With `--action flag` it is recorded and allowed.

## What the client sees

Every response reports the result:

```http
X-Vulnetix-Firewall-Nonce: mode=enforce;verified=12;unknown=0;tampered=1;stripped=1
```

Belai turns a non-zero `stripped` or `tampered` into a card in its thread. The header is absent when a request carried no sealed block. See [response headers](/docs/ai-firewall/responses/#response-headers) for the rest.
