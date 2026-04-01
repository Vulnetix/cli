---
title: "Shell Completions"
weight: 5
description: "Set up tab completion for Vulnetix CLI commands, flags, and values in your shell."
---

Vulnetix CLI supports tab completion for commands, subcommands, flags, and flag values across all major shells. Completions are generated dynamically from the CLI binary, so they stay in sync with the version you have installed.

## What Gets Completed

| Category | Example |
|----------|---------|
| Commands | `vulnetix v<TAB>` &rarr; `vdb`, `version` |
| Subcommands | `vulnetix vdb e<TAB>` &rarr; `ecosystems`, `exploits` |
| Flag names | `vulnetix scan --f<TAB>` &rarr; `--file`, `--format` |
| Flag values | `vulnetix upload --format <TAB>` &rarr; `cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex` |
| File paths | `vulnetix upload --file <TAB>` &rarr; _(file browser)_ |
| Directories | `vulnetix scan --path <TAB>` &rarr; _(directory browser)_ |

---

## Bash

Requires **bash 4.1+** and the `bash-completion` v2 package.

### Current Session

```bash
source <(vulnetix completion bash)
```

### Permanent Installation

Choose one of the following:

```bash
# Option 1: bash-completion directory (recommended)
vulnetix completion bash > ~/.local/share/bash-completion/completions/vulnetix

# Option 2: System-wide (requires root)
vulnetix completion bash | sudo tee /etc/bash_completion.d/vulnetix > /dev/null

# Option 3: macOS with Homebrew
vulnetix completion bash > $(brew --prefix)/etc/bash_completion.d/vulnetix

# Option 4: Source from .bashrc
echo 'source <(vulnetix completion bash)' >> ~/.bashrc
```

Restart your shell or run `source ~/.bashrc` to activate.

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install bash-completion

# macOS (Homebrew) — bash-completion v2 for bash 4.1+
brew install bash-completion@2
```

---

## Zsh

### Current Session

```bash
source <(vulnetix completion zsh)
```

### Permanent Installation

```bash
# Standard zsh (writes to first directory in fpath)
vulnetix completion zsh > "${fpath[1]}/_vulnetix"

# Oh My Zsh
mkdir -p ~/.oh-my-zsh/completions
vulnetix completion zsh > ~/.oh-my-zsh/completions/_vulnetix

# macOS with Homebrew
vulnetix completion zsh > $(brew --prefix)/share/zsh/site-functions/_vulnetix
```

After installing, restart your shell or run:

```bash
compinit
```

### Troubleshooting

If completions don't load, ensure `compinit` is called in your `.zshrc`:

```bash
autoload -Uz compinit && compinit
```

If you see a warning about insecure directories, either fix the directory permissions or add this before `compinit`:

```bash
ZSH_DISABLE_COMPFIX=true
```

---

## Fish

### Current Session

```fish
vulnetix completion fish | source
```

### Permanent Installation

```fish
vulnetix completion fish > ~/.config/fish/completions/vulnetix.fish
```

Fish automatically loads completions from `~/.config/fish/completions/`, so no additional configuration is needed. Completions are available immediately in new shells.

---

## PowerShell

### Current Session

```powershell
vulnetix completion powershell | Out-String | Invoke-Expression
```

### Permanent Installation

```powershell
# Add to your PowerShell profile
vulnetix completion powershell >> $PROFILE
```

If your profile doesn't exist yet:

```powershell
New-Item -Path $PROFILE -ItemType File -Force
vulnetix completion powershell >> $PROFILE
```

You may need to adjust the execution policy:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Profile Locations

| Shell | Path |
|-------|------|
| PowerShell Core | `~/.config/powershell/Microsoft.PowerShell_profile.ps1` |
| Windows PowerShell | `~\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` |

---

## Flags with Value Completion

The following flags provide tab-completable values:

| Command | Flag | Values |
|---------|------|--------|
| `auth login` | `--method` | `apikey`, `sigv4` |
| `auth login` | `--store` | `home`, `project`, `keyring` |
| `scan` | `--type` | `manifest`, `spdx`, `cyclonedx` |
| `scan` | `--output` | `json`, `pretty` |
| `scan` | `--format` | `cdx17`, `cdx16`, `json` |
| `upload` | `--format` | `cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex` |
| `vdb` | `--method` | `apikey`, `sigv4` |
| `vdb` | `--output` | `json`, `yaml`, `pretty` |
| `vdb` | `-V, --api-version` | `v1`, `v2` |
| `vdb` | `--highlight` | `dark`, `light`, `none` |
| `vdb exploits search` | `--source` | `exploitdb`, `metasploit`, `nuclei`, `vulncheck-xdb`, `crowdsec`, `github`, `poc` |
| `vdb exploits search` | `--severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `vdb exploits search` | `--sort` | `recent`, `epss`, `severity`, `maturity` |
| `vdb timeline` | `--dates` | `published`, `modified`, `reserved` |

File path flags (`upload --file`, `scan --file`) use your shell's native file browser. The `scan --path` flag completes directory names only.

---

## Package Manager Notes

- **Homebrew**: Completions are installed automatically by the formula for bash, zsh, and fish. No manual setup is needed.
- **Scoop**: Does not install completions automatically. Use the PowerShell instructions above.
- **Nix**: The flake does not install completions. Use the instructions for your shell above.
- **go install / curl**: Completions are not installed automatically. Use the instructions for your shell above.

---

## Updating Completions

After upgrading Vulnetix CLI, regenerate your completions to pick up new commands and flags:

```bash
# Re-run the same command you used to install
vulnetix completion bash > ~/.local/share/bash-completion/completions/vulnetix
```

If you installed via Homebrew, completions are updated automatically with `brew upgrade vulnetix`.
