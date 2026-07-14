---
title: "Quickstart"
weight: 1
description: "Store a provider key, wire this machine to the gateway, prove it works, and watch a guardrail block a request."
---

Five commands, from nothing to a request being blocked by policy. You need to be authenticated (`vulnetix auth login`) and to have your provider's own API key to hand.

## 1. Store the provider key

The gateway calls OpenAI with *your* OpenAI key, so it has to hold one. Give it the key from an environment variable rather than typing it — a key on the command line lands in your shell history and in the process list.

```bash
vulnetix ai-firewall key set openai --from-env OPENAI_API_KEY
```

The key is encrypted server-side under a context bound to your organisation and that provider. Nothing — not this CLI, not the dashboard — can read it back out. See [BYOK](/docs/ai-firewall/byok/).

## 2. Preview the wiring

```bash
vulnetix ai-firewall install --dry-run
```

```text
Vulnetix AI Firewall install dry run

  Credential source     keyring
  Organization          6f2a1c3e-...
  Gateway               https://guardrails.vulnetix.com
  Providers             openai
  API key               vlx_...4f2a

Actions
  /home/you/.zshrc: would update shell config
  /home/you/.codex/config.toml: would update config (backing up the existing file)
  /home/you/repo/.aider.conf.yml: would update config

Configure by hand
  Cursor — Settings > Models > Override OpenAI Base URL:
      Base URL: https://guardrails.vulnetix.com/openai/6f2a1c3e-.../v1
      API key:  your $VULNETIX_API_KEY
```

Nothing has been written. Read the action list: it names every file that would change.

## 3. Wire it

```bash
vulnetix ai-firewall install
```

Then start a new shell (or `source` your rc file) so the environment variables take effect.

Any config file that gets rewritten wholesale is backed up to `<file>.vulnetix.bak` first, and [`uninstall`](/docs/ai-firewall/uninstall/) puts it back.

## 4. Prove it

```bash
vulnetix ai-firewall status
```

```text
Local clients
  Client         Scope    State   Path
  Shell          user     wired   /home/you/.zshrc
  Codex          user     wired   /home/you/.codex/config.toml
  aider          project  wired   /home/you/repo/.aider.conf.yml
  Cursor         user     manual

Checks
  No problems found.
```

`wired` means that client's base URL points at your organisation's gateway. Anything reported as **`points elsewhere`** is talking to the provider directly and is *not* being screened — that is the finding this command exists for.

Now send a real request:

```bash
vulnetix ai-firewall snippet --lang sh --sdk curl | sh
```

A 200 with a completion means the whole path works: your client authenticated to the gateway, the gateway applied policy, decrypted your OpenAI key, and forwarded the call.

## 5. Watch a guardrail fire

Add a rule that blocks anything looking like a Postgres connection string:

```bash
vulnetix ai-firewall policy guardrail "No connection strings" \
  --rule-type blocked_pattern \
  --action block \
  --pattern '(?i)postgres://\S+' \
  --priority 10
```

Then send a prompt that matches it:

```bash
curl -s https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1/chat/completions \
  -H "Authorization: Bearer $VULNETIX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"debug postgres://user:pw@db.internal/prod"}]}'
```

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

HTTP 403, in the shape an OpenAI SDK already understands — so it raises as an ordinary permission error rather than something your error handling has never seen. The prompt never reached OpenAI.

{{< callout type="warning" >}}
Patterns are **Go RE2**: linear-time, and with no lookahead or lookbehind. `(?<=postgres://)\S+` will not compile, and a guardrail whose pattern does not compile is *skipped by the gateway* — it sits in the dashboard looking enforced while enforcing nothing. `vulnetix ai-firewall status` compiles every pattern and warns you. See [guardrails](/docs/ai-firewall/guardrails/).
{{< /callout >}}

## Next

- Not every client can be wired with environment variables — the Vercel AI SDK and most non-OpenAI providers need [a code snippet](/docs/ai-firewall/snippets/).
- Put the policy in a file and apply it in CI: [policy as code](/docs/ai-firewall/policy-file/).
- Pull in the [recommended guardrails](/docs/ai-firewall/baseline/) — PII redaction, prompt injection — rather than writing them yourself.
