---
title: "Uninstall"
weight: 29
description: "Remove Package Firewall configuration for one, some, or every ecosystem — and optionally the shared credential."
---

`vulnetix package-firewall uninstall` reverses what `vulnetix package-firewall <ecosystem>` wrote. It removes the managed registry config for each targeted ecosystem and, on request, the shared `~/.netrc` credential. It needs **no authentication** — it operates on local files only.

## Getting started

Name the ecosystems to unconfigure:

```bash
vulnetix package-firewall uninstall npm pypi
```

Or select in bulk — one selector at a time:

```bash
vulnetix package-firewall uninstall --all              # every supported ecosystem
vulnetix package-firewall uninstall --except aur       # all except the ones you name
```

The shared `~/.netrc` entry (`machine packages.vulnetix.com`) authenticates **every** ecosystem, so it is left in place by default. Remove it explicitly:

```bash
vulnetix package-firewall uninstall npm --remove-credentials   # this eco + shared credential
vulnetix package-firewall uninstall --purge                    # every ecosystem + the credential
```

Preview first with `--dry-run` — it reports exactly what would be removed and writes nothing.

**Flags:** `--all` (every ecosystem), `--except <csv>` (all but these), `--remove-credentials` (also drop the shared netrc entry), `--purge` (= `--all` + `--remove-credentials`), `--proxy-url` (host to detect and strip, default `https://packages.vulnetix.com`), `--dry-run` to preview without writing. Exactly one of positional ecosystems / `--all` / `--except` is required.

{{< callout type="warning" >}}
The netrc credential is shared. Removing it while another ecosystem is still configured will make that ecosystem fail authentication — the command prints a warning listing any such ecosystems. Prefer `--purge`, or pass `--remove-credentials` only once every ecosystem is being removed.
{{< /callout >}}

## What it removes

Removal mirrors how each ecosystem was configured:

| How it was written | What uninstall does |
| --- | --- |
| Managed block (`.npmrc`, `pip.conf`/`uv.toml`, cargo `config.toml`, `.gemrc`, `.Rprofile`, `hex.env`, `pub.env`, `homebrew.env`, …) | strips the `# Vulnetix Package Firewall … # End …` block; deletes the file if nothing else remains |
| Whole-file config (`settings.xml`, `NuGet.Config`, composer/conan JSON, `pub-tokens.json`, helm `repositories.yaml`, staged `arch-mirrorlist`/`pacman.conf`) | deletes the file if it still points at the firewall; leaves it untouched otherwise |
| Merged config (paru `paru.conf`, yay `config.json`) | restores the `.vulnetix.bak` backup written at setup, or strips the injected keys if no backup exists |
| Go shell/env (`GOPROXY`/`GOAUTH` in your shell rc and git-root `.env`/`.envrc`/`Makefile`) | removes the managed block and the `GOPROXY`/`GOAUTH` lines |
| Shared `~/.netrc` credential | removed only with `--remove-credentials` or `--purge` |

## Verify

```bash
vulnetix auth status
```

The **Package Firewall ecosystems** section should no longer list the ecosystems you removed. After `--purge` it lists none, and the `machine packages.vulnetix.com` netrc entry is gone.
