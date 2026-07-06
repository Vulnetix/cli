---
title: "Arch Linux"
weight: 24
description: "Configure Arch Linux (AUR helpers + pacman official repos) to use the Vulnetix Package Firewall."
---

Arch Linux is firewalled in two places: the AUR helpers `paru`/`yay` are pointed at the `/aur` prefix (RPC + git base), and the official `pacman` repositories (`core`/`extra`/`multilib`) are served through the `/arch` prefix. This is the free, community-tier ecosystem.

- **Proxy URL:** `https://packages.vulnetix.com/aur` (AUR) and `https://packages.vulnetix.com/arch` (pacman)
- **Plan:** Community — free
- **Enforcement:** Gate — pacman databases are signed and served unchanged; a blocked package download returns a policy status.

## Getting started

```bash
vulnetix package-firewall aur
```

This resolves your organization credentials, writes them to `~/.netrc`, and folds the firewall settings **non-destructively** into your existing `~/.config/paru/paru.conf` and `~/.config/yay/config.json` (the original is backed up to `<file>.vulnetix.bak` first). Re-run any time; it updates in place.

pacman's config lives in root-owned `/etc`, so the command **stages** the official-repo files under `~/.config/vulnetix/package-firewall/` rather than editing `/etc` — install them with `sudo` (below).

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

### AUR helpers (automatic)

`~/.config/paru/paru.conf`:

```ini
[options]
AurUrl = https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/aur
AurRpcUrl = https://YOUR_ORG_UUID:YOUR_API_KEY@packages.vulnetix.com/aur/rpc
```

`~/.config/yay/config.json` gets the equivalent `aururl` / `aurrpcurl` keys.

### pacman official repos (manual, needs root)

The command writes two staged files you install with `sudo`:

- `~/.config/vulnetix/package-firewall/arch-mirrorlist` — a `Server = …/arch/$repo/os/$arch` line.
- `~/.config/vulnetix/package-firewall/pacman.conf` — a complete, self-contained pacman config for a no-root scoped test.

Install the mirrorlist and point the official repos at it:

```bash
sudo cp ~/.config/vulnetix/package-firewall/arch-mirrorlist /etc/pacman.d/vulnetix-mirrorlist
# Then add, above the other Server/Include lines in [core], [extra] (and [multilib]) in /etc/pacman.conf:
#   Include = /etc/pacman.d/vulnetix-mirrorlist
```

Or test without root using the staged config directly:

```bash
pacman --config ~/.config/vulnetix/package-firewall/pacman.conf --dbpath /tmp/vx-db --cachedir /tmp/vx-cache -Syp bash
```

## Use it

```bash
paru -S some-aur-package     # AUR
sudo pacman -Syu             # official repos, once the mirrorlist is installed
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked package download returns the policy status while the signed database is served unchanged. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall aur` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- The pacman step needs root and is not automated — the command only stages the files; install the mirrorlist with `sudo`.
- To back the AUR helper config out, [`vulnetix package-firewall uninstall aur`](/docs/enterprise/package-firewall/uninstall/) restores the `.vulnetix.bak` backups.
- Remember to remove the `/etc/pacman.d/vulnetix-mirrorlist` include manually if you installed it — the CLI does not modify root-owned files.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
