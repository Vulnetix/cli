---
title: "Code snippets"
weight: 10
description: "Ready-to-run boilerplate wired to the gateway — and the SDKs and providers for which setting base_url in code is the only route through the firewall."
---

```bash
vulnetix ai-firewall snippet --lang python --sdk openai
vulnetix ai-firewall snippet --lang ts --sdk vercel-ai --output-file src/ai.ts
vulnetix ai-firewall snippet --lang sh --sdk curl | sh
```

Prints code that calls the gateway, with the base URL and key already wired for your organisation. It writes to stdout by default, so it pipes.

## This is not a convenience

For two categories of client, a snippet is the **only** way through the firewall — environment variables cannot do it:

**The Vercel AI SDK does not read `OPENAI_BASE_URL`** ([vercel/ai#8564](https://github.com/vercel/ai/issues/8564)). Whatever you export, it calls the provider directly. It needs `createOpenAI({ baseURL })`.

**Most providers have no base-URL environment variable at all.** There is no `MISTRAL_BASE_URL`, `XAI_BASE_URL`, `OPENROUTER_BASE_URL`, `TOGETHER_BASE_URL`, `DEEPSEEK_BASE_URL`, or `FIREWORKS_BASE_URL` — no SDK reads them, and the CLI will not write a variable that nothing reads. For those providers, `base_url` in code is the mechanism.

`install` says so in its output rather than leaving you to find out:

```text
Not reachable by environment variable
  No SDK reads a base-URL variable for: mistral, openrouter
  Set base_url in code instead:
    vulnetix ai-firewall snippet --provider mistral --lang python --sdk openai
```

## Available pairs

| `--lang` | `--sdk` | Notes |
| --- | --- | --- |
| `python` | `openai` | Any OpenAI-compatible provider |
| `python` | `anthropic` | Uses `auth_token`, not `api_key` |
| `python` | `langchain` | Also covered by env vars — this makes it explicit |
| `python` | `llamaindex` | Also covered by env vars |
| `ts` | `openai` | |
| `ts` | `anthropic` | Uses `authToken`, not `apiKey` |
| `ts` | `vercel-ai` | **Env vars do not work.** Required |
| `go` | `openai` | |
| `sh` | `curl` | Doubles as the smoke test |

## Python, OpenAI

```python
import os

from openai import OpenAI

client = OpenAI(
    base_url="https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1",
    api_key=os.environ["VULNETIX_API_KEY"],
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
print(response.choices[0].message.content)
```

A policy refusal arrives as an ordinary `openai.PermissionDeniedError` — a 403 in the shape the SDK already understands, so it does not need error handling you have never written. See [block responses](/docs/ai-firewall/responses/).

## TypeScript, Vercel AI SDK

```ts
import { createOpenAI } from '@ai-sdk/openai'
import { generateText } from 'ai'

// The Vercel AI SDK does NOT read OPENAI_BASE_URL — the environment variables
// written by `vulnetix ai-firewall install` have no effect here. Without this
// createOpenAI({ baseURL }) the SDK calls the provider directly and the firewall
// never sees the request.
const vulnetix = createOpenAI({
  baseURL: 'https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1',
  apiKey: process.env.VULNETIX_API_KEY!,
})

const { text } = await generateText({
  model: vulnetix('gpt-4o'),
  prompt: 'Hello',
})
console.log(text)
```

## Python, Anthropic

```python
import os

from anthropic import Anthropic

# auth_token, not api_key: api_key is sent as the `x-api-key` header, and the
# gateway authenticates with `Authorization: Bearer`.
client = Anthropic(
    base_url="https://guardrails.vulnetix.com/anthropic/YOUR_ORG_UUID",
    auth_token=os.environ["VULNETIX_API_KEY"],
)

message = client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
print(message.content[0].text)
```

Passing the key as `api_key` here produces a 401 that looks exactly like a bad credential, because the SDK sends it as `x-api-key` and the gateway is looking for a Bearer token. Every Anthropic snippet uses the auth-token form for that reason.

## curl

```bash
curl -s https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1/chat/completions \
  -H "Authorization: Bearer $VULNETIX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
```

Piping this to `sh` is the fastest end-to-end check that authentication, policy, the stored provider key, and the upstream call all work:

```bash
vulnetix ai-firewall snippet --lang sh --sdk curl | sh
```

## Flags

| Flag | Meaning |
| --- | --- |
| `--lang` | `python`, `ts`, `go`, `sh` |
| `--sdk` | `openai`, `anthropic`, `vercel-ai`, `langchain`, `llamaindex`, `curl` |
| `--provider` | Provider slug. Default: the first with a stored key |
| `--model` | Model to call. Default: one the org allows |
| `--output-file` | Write to a file instead of stdout. Refuses to overwrite without `--force` |
| `-o json` | `{"content": "..."}` |

A `--model` the organisation's policy would refuse is rejected up front, rather than emitted into a file you would run once and then have to debug.
