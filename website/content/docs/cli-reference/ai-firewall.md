---
title: "ai-firewall"
weight: 10
description: "Command reference for vulnetix ai-firewall — install, status, policy, key, apply, export, baseline, inventory, snippet, uninstall."
---

Wire local AI clients to the Vulnetix AI Firewall gateway, and manage the policy it enforces.

```text
vulnetix ai-firewall
├── install     [client...]   wire the AI clients on this machine
├── uninstall   [client...]   remove the wiring
├── status                    what is wired, and where it conflicts with policy
├── policy      provider | model | guardrail
├── key         set | remove
├── settings                  org-wide toggles
├── get                       show the current policy
├── apply                     reconcile policy from a file
├── export                    write the live policy to a file
├── baseline                  the server's recommended guardrails
├── inventory                 tools, MCP servers and skills seen on the wire
└── snippet                   ready-to-run code wired to the gateway
```

Full documentation: [AI Firewall](/docs/ai-firewall/).

## Common flags

Available on every subcommand that talks to the API:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--base-url` | the VDB API | Vulnetix API base URL |
| `--gateway-url` | `https://guardrails.vulnetix.com` | AI Firewall gateway |
| `-o, --output` | `pretty` | `pretty` or `json` |

## install

```bash
vulnetix ai-firewall install [client...]
```

Clients: `shell`, `env`, `claude-code`, `codex`, `continue`, `aider`, `cursor`, `windsurf`. With no arguments, every client detected on this machine is wired. Only providers with a stored key are wired.

| Flag | Meaning |
| --- | --- |
| `--provider <slug>` | Wire only these providers (repeatable) |
| `--model <slug>` | Pin a default model in agent configs |
| `--scope user\|project` | Where to write |
| `--embed-key` | Write the literal key rather than `$VULNETIX_API_KEY` |
| `--create-env` | Create a project `.env` if none exists |
| `--dry-run` | Print the plan; write nothing |

## uninstall

```bash
vulnetix ai-firewall uninstall [client...] [--all] [--except a,b]
```

Local files only; no authentication needed. Exactly one selector is required.

| Flag | Meaning |
| --- | --- |
| `--all` | Every client |
| `--except a,b` | Every client except these |
| `--dry-run` | Print the plan; write nothing |

## status

```bash
vulnetix ai-firewall status [--strict]
```

`--strict` exits non-zero on any error-level check. Exits 0 with findings otherwise, so it is safe in a shell prompt.

## policy

```bash
vulnetix ai-firewall policy provider <slug>  --allow | --deny | --clear
vulnetix ai-firewall policy model <slug>     --allow | --deny | --remove
                                             (--provider <slug> | --any-provider)
vulnetix ai-firewall policy guardrail <name> --rule-type --action --pattern
                                             [--priority] [--enable|--disable]
                                             [--uuid] [--delete]
```

`--rule-type`: `blocked_pattern`, `max_messages`, `pii_redact`. `--action`: `block`, `redact`, `flag`. Patterns are Go RE2 — no lookahead or lookbehind.

Also spelled `vulnetix config set ai-firewall <sub>`; both run the same code.

## key

```bash
vulnetix ai-firewall key set <provider> --from-env VAR | --stdin | --key <literal>
vulnetix ai-firewall key remove <provider>
```

The key is write-only: no command returns it. `--key` warns, because it lands in your shell history.

## settings

```bash
vulnetix ai-firewall settings --logs | --no-logs
```

Inference logging records metadata only — model, decision, matched guardrails, tokens, latency. Never prompts or completions. Paid plans.

## get / export

```bash
vulnetix ai-firewall get [-o json]
vulnetix ai-firewall export [-f FILE] [--stdout] [--force]
```

## apply

```bash
vulnetix ai-firewall apply [-f .vulnetix/ai-firewall.yaml] [--dry-run]
```

| Flag | Meaning |
| --- | --- |
| `-f, --file` | Policy file (default `.vulnetix/ai-firewall.yaml`) |
| `--dry-run` | Print the plan; change nothing |
| `--prune` | Delete server objects the file does not mention |
| `--no-baseline` | Do not compose in the recommended guardrails |
| `--baseline-required` | Fail if the baseline cannot be fetched (CI) |
| `--catalog` | Local baseline file instead of the server's |
| `--force` | Apply despite a `metadata.org` mismatch |

## baseline

```bash
vulnetix ai-firewall baseline [--ref recommended] [--catalog FILE]
```

## inventory

```bash
vulnetix ai-firewall inventory [--kind KIND] [--client NAME] [--search TEXT] [--limit N] [--clear]
```

Every tool, MCP server and skill the gateway has seen this org's agents carry,
each graded `declared`, `invoked` or `inferred`. Metadata only — never a prompt,
completion, tool argument or tool result. Requires an authenticated org.

| Flag | Values |
| --- | --- |
| `--kind` | `tool`, `mcp_server`, `skill` |
| `--client` | Exact client name, e.g. `claude-code` |
| `--search` | Substring match on the identity |
| `--limit` | 1-1000 (default `200`) |
| `--clear` | Delete the inventory instead of reading it |

Full documentation: [Capability inventory](/docs/ai-firewall/inventory/).

## snippet

```bash
vulnetix ai-firewall snippet --lang python --sdk openai
```

| Flag | Values |
| --- | --- |
| `--lang` | `python`, `ts`, `go`, `sh` |
| `--sdk` | `openai`, `anthropic`, `vercel-ai`, `langchain`, `llamaindex`, `curl` |
| `--provider` | Provider slug (default: the first with a stored key) |
| `--model` | Model (default: one the org allows) |
| `--output-file` | Write to a file instead of stdout |
| `--force` | Overwrite the output file |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Failure — auth, network, invalid flags or policy file, `status --strict` with an error-level check |
