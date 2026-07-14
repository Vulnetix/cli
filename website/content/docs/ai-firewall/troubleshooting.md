---
title: "Troubleshooting"
weight: 32
description: "Blocked when you did not expect it — and, worse, not blocked when you did."
---

## Check what is configured

Start here. It answers most of the questions below without guessing:

```bash
vulnetix ai-firewall status
```

It reports which clients are wired, which are pointing somewhere else, which providers have keys, and every conflict between your local config and the organisation's policy. Each finding names the 403 it would produce at runtime.

## Authentication

- **`401 Unauthorized`** — the gateway does not know who you are. Almost always the two-key confusion: the client is sending the **provider's** key, when the gateway wants your **Vulnetix** key. The provider key lives server-side; your machine should never hold it.
  - Check `$VULNETIX_API_KEY` is exported and is what the client's key variable resolves to.
  - For Anthropic: `ANTHROPIC_API_KEY` is sent as `x-api-key` and the gateway never reads it. You need **`ANTHROPIC_AUTH_TOKEN`**, which produces `Authorization: Bearer`. This failure looks exactly like a bad key, and checking the key will not fix it.

- **`403` with a `code`** — you authenticated fine; policy refused the request. The code says which stage. See [block responses](/docs/ai-firewall/responses/).

## Requests are not going through the gateway

The quiet failure, and the one worth hunting: nothing errors, and nothing is screened.

- **`status` says `points elsewhere`.** That client has a base URL, and it is not ours. Re-run `vulnetix ai-firewall install <client>`.
- **The shell block was written but never sourced.** `status` checks the *process environment*, not the rc file — because that is what the SDK sees. Start a new shell, or `source ~/.zshrc`.
- **The SDK does not read the variable you set.** Only `OPENAI_BASE_URL`, `OPENAI_API_BASE`, and `ANTHROPIC_BASE_URL` are honoured by real SDKs. `MISTRAL_BASE_URL` and friends **do not exist** — no SDK reads them, and the CLI does not write them. For those providers you must set `base_url` in code: [snippets](/docs/ai-firewall/snippets/).
- **You are using the Vercel AI SDK.** It ignores `OPENAI_BASE_URL` entirely. It needs `createOpenAI({ baseURL })` — `vulnetix ai-firewall snippet --lang ts --sdk vercel-ai`.
- **The `.env` is not being expanded.** `${VULNETIX_API_KEY}` expands under python-dotenv and direnv, but plain Node `dotenv` does not expand it without `dotenv-expand`. Export the variable in the shell instead.

## Blocked when you did not expect it

- **`model_not_allowed` on a model nobody denied.** Someone allowed a *different* model for that provider, which put the provider into [allowlist mode](/docs/ai-firewall/policy/). Every unlisted model is now refused. Add yours to the list, or remove the allow entries.
- **`request_blocked` naming a rule you did not write.** You have `spec.baseline.enabled: true` and a [baseline guardrail](/docs/ai-firewall/baseline/) matched. `vulnetix ai-firewall baseline` lists them; exclude it by `id` if it is wrong for you.
- **A redaction is mangling legitimate prompts.** Switch the rule to `--action flag` for a while and read the logs. A pattern that looks obviously safe usually is not.

## Not blocked when you did expect it

Worse than the above, because nothing tells you.

- **The pattern does not compile, so the gateway skips the rule.** It sits in the dashboard looking enforced and enforces nothing. `vulnetix ai-firewall status` compiles every pattern and warns. The usual cause is lookaround: RE2 has none. Rewrite `(?<=orgUuid=)\S+` as `orgUuid=\S+`, which blocks the same requests.
- **The guardrail is disabled.** `enabled: false`, or `--disable`.
- **A redaction ran first.** Guardrails evaluate in ascending priority. A `redact` rule at priority 10 rewrites the text before a `block` rule at priority 20 sees it, so the block may no longer match. Give the block the lower number.
- **The client was never wired.** See the section above — an unwired client's traffic never reaches a guardrail at all.

## Agents

- **Codex.** Its `wire_api` only accepts `responses`, so it cannot use a chat-completions-only gateway. If the gateway does not serve the Responses API for the provider, `install` skips Codex and says so — it will not write a config that 404s on first use.
- **Claude Code.** It speaks the Anthropic Messages API (`/v1/messages`), not chat completions. Same gate. Also: its token is not written into `.claude/settings.json` (that file gets committed), so it must come from your shell — or from `settings.local.json` with `--embed-key`.
- **Continue.** It is an IDE extension and **cannot read your shell environment**. It resolves `${{ secrets.VULNETIX_API_KEY }}` from `~/.continue/.env`, which is why that file is the one place the CLI writes a literal key.
- **Cursor / Windsurf.** No config file to write; the base URL lives in application state and you must paste it into their settings. Their integrated terminals *do* inherit the shell block, so `aider` and `codex` run inside them are already wired.

## Policy files

- **"declares metadata.org X, but you are authenticated as Y"** — you are about to apply one organisation's policy to another. That guard exists because it is the easiest way to do real damage. Check before reaching for `--force`.
- **"duplicate name"** — guardrails are reconciled by name, so names must be unique. Rename one, or manage it by `--uuid` with `policy guardrail`.
- **`apply` deleted nothing you expected it to.** Deletion is opt-in: unmanaged objects are reported as drift. Pass `--prune`, after a `--dry-run`.
- **CI applied a policy with no baseline guardrails and went green.** Add `--baseline-required`. Outside CI an unavailable baseline is a soft failure by design; in CI that is exactly the wrong behaviour.

## Start over

```bash
vulnetix ai-firewall uninstall --all --dry-run   # check first
vulnetix ai-firewall uninstall --all
vulnetix ai-firewall install
```

Uninstall touches local files only — your policy, guardrails, and stored provider keys are untouched, and it needs no authentication.
