---
title: "Capability inventory"
weight: 9
description: "Every tool, MCP server and skill the gateway has seen your agents carry, graded by how it was learnt."
---

A repository scan finds the AI that is written down. The inventory finds what ran.

These APIs are stateless, so a client re-sends its whole tool array on every
turn. An MCP server somebody wired into a local config on Tuesday — holding a
token for the issue tracker — appears in no manifest, but it appears in every
request that agent makes.

```bash
vulnetix ai-firewall inventory
```

```text
KIND        NAME                        CLIENT       EVIDENCE
tool        Bash                        claude-code  invoked
tool        Read                        claude-code  declared
tool        mcp__github__create_pr      claude-code  declared
tool        mcp__prod_db__query         claude-code  invoked
mcp_server  jira                        codex-cli    declared
            https://mcp.atlassian.com/v1/sse
skill       deploy                      claude-code  inferred
tool        local_shell                 codex-cli    declared
tool        apply_patch                 unknown      declared

# 3 clients · 2 MCP servers · 24 tools
```

## Evidence grades

| Grade | Means |
|---|---|
| `declared` | Read verbatim from a request's tool array |
| `invoked` | Seen being called, not merely offered |
| `inferred` | Derived from a naming convention, e.g. an `mcp__<server>__<tool>` prefix |

The grade is shown rather than smoothed over. A naming convention is a strong
hint about which MCP server a tool came from, and it is still a convention — it
must never read as a protocol fact.

## What is recorded

Metadata only: a tool name, an MCP server host, a client's user-agent. No
prompt, completion, tool argument or tool result is involved. That is why the
gateway records the inventory for **every** organisation, not only the ones that
turned on [inference logging](/docs/ai-firewall/guardrails/).

`observations` in the JSON output counts distinct observation windows, **not**
requests: the gateway collapses an unchanged agent configuration to one write
per window, so it tells you how often a configuration has turned up, not how
much traffic it carried.

## Filters

| Flag | Purpose |
|---|---|
| `--kind` | `tool`, `mcp_server` or `skill` |
| `--client` | Exact client name, e.g. `claude-code` |
| `--search` | Substring match on the capability's identity |
| `--limit` | 1–1000, default `200`. The output says when a limit truncated it |
| `--clear` | Delete the whole inventory instead of reading it |
| `-o json` | The full records, including `firstSeenAt`, `lastSeenAt` and `observations` |

```bash
vulnetix ai-firewall inventory --kind mcp_server
vulnetix ai-firewall inventory --client claude-code --search github
vulnetix ai-firewall inventory -o json
```

## Pairs with AI-BOM

[`vulnetix aibom`](/docs/cli-reference/aibom/) scans repositories for declared
AI. The inventory watches the wire for what ran. Static discovery plus runtime
observation is a complete AI asset inventory — the shape ISO 42001, the NIST AI
RMF and EU AI Act record-keeping all ask for. Either alone is not.

## Requires an authenticated org

The inventory is per-organisation, not per-member: a per-member view would show
the organisation a fraction of what its people had wired in, without saying
which fraction. Community credentials are refused.
