---
title: "Wiring clients"
weight: 2
description: "Every AI client the CLI can point at the gateway, the exact file it writes, and the clients that cannot be wired with environment variables at all."
---

`vulnetix ai-firewall install` points the AI clients on this machine at the gateway. With no arguments it wires every client it detects; name one or more to wire exactly those.

```bash
vulnetix ai-firewall install                 # everything detected
vulnetix ai-firewall install shell codex     # just these
vulnetix ai-firewall install --dry-run       # show the plan, write nothing
```

Only providers your organisation has stored a key for are wired. Without a key the gateway refuses every request with `provider_key_missing`, so writing a config that points at it would only produce a confusing failure later; the command tells you which providers it skipped and why.

## The clients

| Client | Scope | File written | How | Key handling |
| --- | --- | --- | --- | --- |
| `shell` | user | `~/.zshrc`, `~/.bashrc`, `~/.config/fish/config.fish`, … | managed block | references `$VULNETIX_API_KEY` |
| `env` | project | `.env`, `.envrc`, `Makefile` at the git root | managed block | references `${VULNETIX_API_KEY}` |
| `claude-code` | project (or user) | `.claude/settings.json` | JSON merge into `env` | not written — comes from the shell |
| `codex` | user | `~/.codex/config.toml` | managed block + root keys | `env_key = "VULNETIX_API_KEY"` |
| `continue` | user | `~/.continue/config.yaml` | YAML merge into `models[]` | **literal**, in `~/.continue/.env` |
| `aider` | project | `.aider.conf.yml` at the git root | YAML merge | not written — read from the environment |
| `cursor` | — | *none* | detect and instruct | you paste it |
| `windsurf` | — | *none* | detect and instruct | you paste it |

LangChain and LlamaIndex need no file of their own: both read `OPENAI_API_BASE`, which the shell and project-env writers set. `status` reports them as covered by the environment.

{{< callout type="warning" >}}
**Only three base-URL environment variables are real.** `OPENAI_BASE_URL`, `OPENAI_API_BASE` (the older spelling, and the one LangChain and LlamaIndex read), and `ANTHROPIC_BASE_URL`. `GROQ_BASE_URL` appears to work but is unverified.

There is **no** `MISTRAL_BASE_URL`, `XAI_BASE_URL`, `OPENROUTER_BASE_URL`, `TOGETHER_BASE_URL`, `DEEPSEEK_BASE_URL`, or `FIREWORKS_BASE_URL`. No SDK reads them. The CLI will not write them, because a variable that looks like an SDK setting and is read by nothing is worse than no variable at all: you would believe you were protected while your traffic went straight to the provider.

For those providers the only route through the firewall is to set `base_url` in code — see [snippets](/docs/ai-firewall/snippets/). `install` records the gateway URL in an informational `VULNETIX_AIFW_<PROVIDER>_BASE_URL` so the value is to hand, and says so in its output.
{{< /callout >}}

## shell

The managed block goes in the rc file for your login shell, in that shell's own syntax.

`~/.zshrc` (also bash, and `.profile` as the fallback):

```sh
# Vulnetix AI Firewall
export OPENAI_BASE_URL="https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1"
export OPENAI_API_BASE="https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1"
export OPENAI_API_KEY="$VULNETIX_API_KEY"
export ANTHROPIC_BASE_URL="https://guardrails.vulnetix.com/anthropic/YOUR_ORG_UUID"
export ANTHROPIC_AUTH_TOKEN="$VULNETIX_API_KEY"
# End Vulnetix AI Firewall
```

`~/.config/fish/config.fish`:

```fish
# Vulnetix AI Firewall
set -gx OPENAI_BASE_URL https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1
set -gx OPENAI_API_KEY $VULNETIX_API_KEY
# End Vulnetix AI Firewall
```

`~/.tcshrc` and `~/.cshrc` get `setenv`. On Windows the variables are persisted with `setx` into the user environment instead.

The key is **referenced, never expanded**: `$VULNETIX_API_KEY` is what lands in the file, so the rc file itself holds no secret. Export that variable however you normally handle credentials.

### The Anthropic base URL has no `/v1`

Look closely at the two base URLs above: the OpenAI one ends in `/v1` and the Anthropic one does not. That is not a typo.

The two SDK families disagree about who owns the version segment:

- **OpenAI**'s `base_url` *includes* it (`https://api.openai.com/v1`); the SDK appends only `/chat/completions` or `/responses`.
- **Anthropic**'s `base_url` is the bare *root* (`https://api.anthropic.com`); the SDK appends `/v1/messages` itself.

So an `ANTHROPIC_BASE_URL` ending in `/v1` makes Claude Code POST to `.../v1/v1/messages`, which 404s — and reads like the gateway is broken rather than like a config error. The CLI writes each form correctly; this is only worth knowing if you are setting the variables by hand.

### `ANTHROPIC_AUTH_TOKEN`, not `ANTHROPIC_API_KEY`

`ANTHROPIC_API_KEY` is sent by the SDK as the `x-api-key` header. The gateway authenticates with `Authorization: Bearer`. Setting the key variable you would expect therefore produces a 401 that looks exactly like a bad key, and no amount of checking the key will fix it. `ANTHROPIC_AUTH_TOKEN` is the variable that produces a Bearer header, so it is the one the CLI writes.

(The gateway also accepts the key in `x-api-key`, so a Claude Code that sends `ANTHROPIC_API_KEY` still authenticates — but it must be the *Vulnetix* key, not your Anthropic one.)

## env

The project writers touch `.env`, `.envrc`, and `Makefile` at the git root — but **only if they already exist**. A `.env` this tool invented would not be loaded by anything your project already runs, so creating one silently would be theatre. If none exists the command says so; pass `--create-env` if you want one.

`.env`:

```bash
# Vulnetix AI Firewall
OPENAI_BASE_URL=https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1
OPENAI_API_BASE=https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1
OPENAI_API_KEY=${VULNETIX_API_KEY}
# End Vulnetix AI Firewall
```

`${VULNETIX_API_KEY}` is expanded by python-dotenv and by direnv. Node's `dotenv` does **not** expand it without `dotenv-expand`; if you use plain `dotenv`, export `VULNETIX_API_KEY` in the shell instead, or pass `--embed-key` (see below).

## claude-code

Merged into the `env` object of `.claude/settings.json`, leaving `permissions`, `hooks`, and every other key untouched:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://guardrails.vulnetix.com/anthropic/YOUR_ORG_UUID",
    "ANTHROPIC_MODEL": "claude-sonnet-4-5"
  }
}
```

The auth token is deliberately **not** written here. `settings.json` is routinely committed, and a credential in it would be published with the repository. It comes from the shell block instead — or, with `--embed-key`, from `.claude/settings.local.json`, which is git-ignored by convention.

Use `--scope user` to write `~/.claude/settings.json` instead of the project file.

Claude Code speaks the Anthropic Messages API, so this wiring depends on the gateway proxying `/v1/messages` for the `anthropic` slug. If it does not, `install` skips the client and says so.

## codex

A managed block plus two root keys in `~/.codex/config.toml`:

```toml
# Vulnetix AI Firewall
[model_providers.vulnetix-openai]
name = "Vulnetix AI Firewall (openai)"
base_url = "https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1"
env_key = "VULNETIX_API_KEY"
wire_api = "responses"
# End Vulnetix AI Firewall

model_provider = "vulnetix-openai"
model = "gpt-5"
```

The file is edited as **text**, never round-tripped through a TOML encoder — an encoder drops comments and reorders tables, so a hand-ordered config would come back silently rearranged. The result is parsed before it is written, so the CLI never leaves you with a `config.toml` Codex cannot load.

Codex requires `wire_api = "responses"`; its config no longer accepts any other value. If the gateway does not serve the Responses API for the provider, Codex cannot use it at all, and `install` skips it rather than writing a config that fails on first use.

## continue

An entry in `models[]` in `~/.continue/config.yaml`, merged through the YAML node API so your comments and key order survive:

```yaml
models:
  - name: Vulnetix AI Firewall (openai)
    provider: openai
    model: gpt-4o
    apiBase: https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1
    apiKey: ${{ secrets.VULNETIX_API_KEY }}
    roles: [chat, edit, apply]
```

Continue is an IDE extension: **it cannot read your shell environment**. It resolves `${{ secrets.X }}` from `~/.continue/.env`, not from the shell. So the writer also puts the key there:

```bash
VULNETIX_API_KEY=vlx_live_...
```

This is the one place a literal credential is unavoidable. The file is written `0600` and the action list says so explicitly. If that is not acceptable, do not install the `continue` client and configure it by hand.

## aider

```yaml
openai-api-base: https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1
model: openai/gpt-4o
```

No key: aider reads `OPENAI_API_KEY` from the environment or from `.env`, both of which the shell and project-env writers already set.

## cursor and windsurf

These are **detected, never written**. Neither keeps its API base URL in a user-editable config file — the setting lives in application state. `.cursor/` and `~/.codeium/windsurf/` hold rules and MCP config, nothing that would change where requests go. Writing a file there would produce something the application ignores and a status check that lies about it.

So the CLI prints what to paste:

```text
Cursor — Settings > Models > Override OpenAI Base URL:
    Base URL: https://guardrails.vulnetix.com/openai/YOUR_ORG_UUID/v1
    API key:  your $VULNETIX_API_KEY
```

Note that their **integrated terminals inherit the shell block**, so `aider`, `codex`, and any script you run inside Cursor or Windsurf are already wired regardless.

## Why there is no `install vercel-ai`

The Vercel AI SDK does not read `OPENAI_BASE_URL` ([vercel/ai#8564](https://github.com/vercel/ai/issues/8564)). No environment variable will route it through the gateway. It needs `createOpenAI({ baseURL })` in code, which is what `vulnetix ai-firewall snippet --lang ts --sdk vercel-ai` emits.

## How files are edited

Every write is **surgical**. The CLI owns a marked region of your file and nothing else:

- **Managed blocks** are fenced by `# Vulnetix AI Firewall` … `# End Vulnetix AI Firewall`. Re-running `install` replaces the block in place rather than appending a second one.
- **Merges** (JSON, TOML, YAML) touch only the keys the firewall owns. Your unrelated settings, and your comments, survive byte-for-byte — there are tests that assert exactly that.
- Any file rewritten wholesale is copied to `<file>.vulnetix.bak` first, and [`uninstall`](/docs/ai-firewall/uninstall/) restores it.

The markers differ from the Package Firewall's on purpose. Both write to the same `~/.zshrc`, and `package-firewall uninstall` must not strip the AI Firewall's block out from under it.

## Flags

| Flag | Meaning |
| --- | --- |
| `--provider <slug>` | Wire only these providers (repeatable). Default: every provider with a stored key. |
| `--model <slug>` | Pin a default model in the agent configs that take one. Refused up front if the org's policy would reject it. |
| `--scope user\|project` | Where to write, for the clients that support both. |
| `--embed-key` | Write the literal API key instead of referencing `$VULNETIX_API_KEY`. |
| `--create-env` | Create a project `.env` if none exists. |
| `--gateway-url` | Default `https://guardrails.vulnetix.com`. |
| `--dry-run` | Print the action list; write nothing. |
| `-o json` | Machine-readable plan and results. |

### `--embed-key`

Opt-in, and it refuses on a file that git would happily commit — the check is `git check-ignore`, and a file that is not ignored is rejected with an explanation rather than written. Files that do receive a literal key are chmod'ed `0600`.

Prefer exporting `VULNETIX_API_KEY` and letting the configs reference it. The exception is Continue, which has no way to read an environment variable at all.
