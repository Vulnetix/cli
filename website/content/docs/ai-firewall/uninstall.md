---
title: "Uninstall"
weight: 31
description: "Removing the AI Firewall wiring from local clients without damaging the configs it was folded into."
---

```bash
vulnetix ai-firewall uninstall --all
vulnetix ai-firewall uninstall codex aider
vulnetix ai-firewall uninstall --except shell
vulnetix ai-firewall uninstall --all --dry-run
```

Undoes `vulnetix ai-firewall install`. It touches **local files only** — server-side policy, guardrails, and stored provider keys are left exactly as they are, and the command needs no authentication at all.

Exactly one selector is required: named clients, `--all`, or `--except`.

## What it does to each file

| How it was written | How it is reverted |
| --- | --- |
| managed block (shell rc, `.env`, `.envrc`, `Makefile`) | the block between the markers is removed; the rest of the file is untouched |
| merge (`settings.json`, `config.toml`, `config.yaml`, `.aider.conf.yml`) | the `.vulnetix.bak` written at install time is restored; failing that, only the keys we injected are stripped |

{{< callout type="info" >}}
**A file you wrote is never deleted.** A shell rc is not removed even if the managed block was the only thing in it, and a config we merged into is restored rather than replaced. The only files that can be deleted are ones the firewall created and that still point at the gateway.
{{< /callout >}}

Install → uninstall is byte-for-byte reversible. That is asserted by tests, on a `config.toml` with comments and a hand-ordered provider table, a `settings.json` with unrelated `permissions` and `hooks`, a Continue config with another model in it, and an `.aider.conf.yml` with unrelated keys.

## Coexisting with the Package Firewall

Both firewalls write to the same `~/.zshrc`. They use different markers —

```sh
# Vulnetix Package Firewall     …     # End Vulnetix Package Firewall
# Vulnetix AI Firewall          …     # End Vulnetix AI Firewall
```

— so `vulnetix package-firewall uninstall --all` strips only its own block, and this command strips only its own. Neither can damage the other. There is a test for precisely that, because getting it wrong would silently unwire a user's AI clients when they uninstalled something unrelated.

## Cursor and Windsurf

Nothing was written for them (there is no file to write — the base URL lives in application state), so there is nothing to remove:

```text
Cursor: nothing written — clear the base URL override in the application's settings
```

You have to clear it there yourself.

## What is left behind

- `$VULNETIX_API_KEY` in your environment, if you exported it. Unset it yourself.
- Server-side policy, guardrails, and provider keys. Remove those with `vulnetix ai-firewall policy ...` and `vulnetix ai-firewall key remove <provider>`.
- Backup files are consumed on restore, so a successful uninstall leaves no `.vulnetix.bak` behind.

## Flags

| Flag | Meaning |
| --- | --- |
| `--all` | Every client |
| `--except a,b` | Every client except these |
| `--dry-run` | Show what would change; write nothing |
| `--gateway-url` | The gateway host to detect and strip (default `https://guardrails.vulnetix.com`) |
| `-o json` | Machine-readable action list |
