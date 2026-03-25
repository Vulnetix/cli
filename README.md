# Vulnetix CLI & GitHub Action

This GitHub Action provides the Vulnetix CLI for your workflows, enabling automated vulnerability management directly in your CI/CD pipeline.

Please also check out our [GitHub App](https://github.com/marketplace/vulnetix) for additional integrations.

## Claude Code Plugin

Integrate Vulnetix vulnerability intelligence directly into your Claude Code workflow with our official plugin. Get real-time security insights as you code, with automated pre-commit scanning and interactive vulnerability analysis.

### Installation

In Claude Code, add the marketplace:

```
/plugin marketplace add Vulnetix/claude-code-plugin
```

Then install the plugin:

```
/plugin install vulnetix@vulnetix-plugins
```

Or clone locally:

```bash
git clone https://github.com/Vulnetix/claude-code-plugin.git ~/claude-code-plugin
/plugin add ~/claude-code-plugin/vulnetix
```

### Upgrading

```
/plugin update vulnetix
```

For local installs: `cd ~/claude-code-plugin && git pull`, then `/plugin remove vulnetix` and `/plugin add ~/claude-code-plugin/vulnetix`.

**Prerequisites:**
- Vulnetix CLI installed (see [Platform Support](#platform-support) below)
- Authenticated with `vulnetix auth login`

### Features

#### 🪝 Automatic Pre-Commit Scanning

The plugin automatically scans staged dependency files before each commit:

```bash
git add package.json package-lock.json
git commit -m "Update dependencies"
```

**What happens:**
- Detects changes to 15+ manifest types (npm, Python, Go, Rust, Maven, etc.)
- Scans for vulnerabilities using Vulnetix VDB
- Reports findings by severity: `2 critical, 5 high, 8 medium`
- **Never blocks commits** — informational only, helping you make informed decisions

**Developer benefit:** Catch vulnerable dependencies at commit time, not in production. Zero configuration required.

#### 🔍 Interactive Skills

Six interactive skills for proactive security:

| Skill | Purpose |
|-------|---------|
| `/vulnetix:package-search <name>` | Search packages and assess risk before adding dependencies |
| `/vulnetix:exploits <vuln-id>` | Analyze exploit intelligence (PoCs, EPSS, CISA KEV, threat model) |
| `/vulnetix:fix <vuln-id>` | Get fix intelligence and apply concrete remediation |
| `/vulnetix:vuln <vuln-id or package>` | Look up vulnerability details or list all vulns for a package |
| `/vulnetix:exploits-search [query]` | Search for exploits across all vulns with ecosystem/severity filters |
| `/vulnetix:remediation <vuln-id>` | Get a context-aware remediation plan with verification steps |

Plus four slash commands for direct VDB CLI access: `/vulnetix:vdb-vuln`, `/vulnetix:vdb-vulns`, `/vulnetix:vdb-exploits-search`, `/vulnetix:vdb-remediation`.

**Developer benefit:** Full vulnerability lifecycle — discover, analyze, prioritize, remediate, and track decisions — all without leaving Claude Code.

#### 🪝 Multi-Hook Architecture

Beyond pre-commit scanning, the plugin provides five additional hooks:

| Hook | Trigger | Purpose |
|------|---------|---------|
| Pre-commit scan | `git commit` | Scan staged manifests for vulnerabilities |
| Manifest edit gate | Edit/Write on manifests | Check packages for vulns before adding to manifests |
| Post-install scan | `npm install`, `pip install`, etc. | Auto-scan after dependency changes |
| Session dashboard | Session start | Show vulnerability status summary |
| Stop reminder | Session end | Remind about unresolved P1/P2 vulnerabilities |
| Vuln context inject | User message | Auto-detect CVE/GHSA IDs and inject prior context |

### When to Use Each Skill

| Scenario | Command | Benefit |
|----------|---------|---------|
| Adding a new dependency | `/vulnetix:package-search lodash` | Choose the safest option upfront |
| Commit hook found vulnerabilities | `/vulnetix:exploits CVE-2024-1234` | Understand severity and urgency |
| Need to patch a CVE | `/vulnetix:fix CVE-2024-1234` | Get concrete fix steps |
| Looking up a CVE or package | `/vulnetix:vuln CVE-2024-1234` | Quick vulnerability details |
| Scanning exploit landscape | `/vulnetix:exploits-search --in-kev` | Find actively exploited vulns in your ecosystem |
| Need a full remediation plan | `/vulnetix:remediation CVE-2024-1234` | Context-aware fix with verification steps |
| Evaluating alternatives | `/vulnetix:package-search axios` | Compare security postures |

### Configuration

The plugin works out of the box with zero configuration. Optional customization:

- **Disable hook temporarily:** `/plugin disable vulnetix`
- **Re-enable:** `/plugin enable vulnetix`
- **Check status:** `/plugins`

### Privacy & Security

- **No code sent to Vulnetix** — only dependency names/versions
- Local scanning via Vulnetix CLI
- PoC exploits analyzed statically, never executed
- All API calls authenticated via HTTPS

[📖 **Full plugin documentation →**](https://github.com/Vulnetix/claude-code-plugin)

## Platform Support

Vulnetix supports all major platforms and installation methods:

| Method | Linux | macOS | Windows | CI/CD | Enterprise | Installation |
|--------|-------|-------|---------|-------|------------|-------------|
| [**Homebrew**](./docs/homebrew.md) | ✅ | ✅ | - | - | ✅ | `brew install vulnetix/tap/vulnetix` |
| [**Scoop**](./docs/scoop.md) | - | - | ✅ | - | ✅ | `scoop install vulnetix` |
| [**Nix**](./docs/nix.md) | ✅ | ✅ | - | ✅ | ✅ | `nix profile install github:Vulnetix/cli` |
| [**Go Install**](./docs/go-install.md) | ✅ | ✅ | ✅ | ✅ | ✅ | `go install github.com/vulnetix/cli@latest` |
| [**Binary Download**](./docs/curl.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Direct download with curl |
| [**From Source**](./docs/from-source.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Full customization |
| [**GitHub Actions**](./docs/github-actions.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Native GitHub integration |
| [**GitLab CI**](./docs/gitlab-ci.md) | ✅ | ✅ | ✅ | ✅ | ✅ | GitLab pipeline integration |
| [**Azure DevOps**](./docs/azure-devops.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Azure pipeline integration |
| [**Bitbucket**](./docs/bitbucket.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Bitbucket pipeline integration |

**Architecture Support:** AMD64, ARM64, ARM, 386 across all platforms

### Quick Start Examples

#### Homebrew (Recommended)

```bash
brew tap vulnetix/tap
brew install vulnetix
vulnetix
```

#### Scoop (Windows)

```powershell
scoop bucket add vulnetix https://github.com/Vulnetix/scoop-bucket
scoop install vulnetix
vulnetix
```

#### Nix

```bash
nix profile install github:Vulnetix/cli
vulnetix
```

#### Go Install

```bash
go install github.com/vulnetix/cli@latest
vulnetix
```

#### Local Binary

Download and run the binary directly:

```bash
# Linux AMD64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Intel)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Apple Silicon)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-arm64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.exe" -OutFile "vulnetix.exe"
.\vulnetix.exe --org-id "your-org-id-here"
```

[📖 **View detailed usage examples →**](./USAGE.md)

## Available Tasks

Vulnetix supports multiple task types to cover different aspects of vulnerability management:

| Task | Description | Use Case | Required Flags |
|------|-------------|----------|----------------|
| `info` | Auth healthcheck (default) | Verify credential setup | - |

## Documentation

- **[Installation](docs/README.md)** - Installation guides for all platforms
- **[CLI Reference](docs/CLI-REFERENCE.md)** - Complete command-line documentation
- **[Usage Examples](USAGE.md)** - Comprehensive usage guide
- **[GitHub Actions Artifact Upload](docs/GHA_COMMAND.md)** - Upload workflow artifacts to Vulnetix
- **[Distribution](docs/PUBLISHING.md)** - How we distribute across platforms

## Distribution

Vulnetix CLI is published on each release:

- **Homebrew Tap** -- `brew install vulnetix/tap/vulnetix`
- **Scoop Bucket** -- `scoop install vulnetix` (Windows)
- **Nix Flake** -- `nix profile install github:Vulnetix/cli`
- **GitHub Releases** -- Go Install, Binary Downloads
- **GitHub Marketplace** -- GitHub Actions integration
