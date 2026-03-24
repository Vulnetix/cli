# Vulnetix CLI & GitHub Action

This GitHub Action provides the Vulnetix CLI for your workflows, enabling automated vulnerability management directly in your CI/CD pipeline.

Please also check out our [GitHub App](https://github.com/marketplace/vulnetix) for additional integrations.

## Claude Code Plugin

Integrate Vulnetix vulnerability intelligence directly into your Claude Code workflow with our official plugin. Get real-time security insights as you code, with automated pre-commit scanning and interactive vulnerability analysis.

### Installation

Clone the repository and add it locally:

```bash
git clone https://github.com/Vulnetix/claude-code-plugin.git
/plugin add /path/to/claude-code-plugin
```

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

Three powerful skills for proactive security:

##### 1. `/vulnetix:package-search <name>`

**What it does:** Search packages before adding them as dependencies

```
/vulnetix:package-search express
```

**Workflow:**
1. Detects your project's ecosystems (npm, PyPI, Maven, etc.)
2. Searches Vulnetix package database for matching packages
3. Shows vulnerability counts, max severity, and Safe Harbour scores
4. Proposes exact manifest edits with the safest version
5. Asks for confirmation before applying changes

**Developer benefit:** Make informed dependency choices. Compare alternatives, understand security posture, and add packages with confidence.

##### 2. `/vulnetix:exploits <vuln-id>`

**What it does:** Analyze exploit intelligence for a vulnerability

```
/vulnetix:exploits CVE-2021-44228
```

**Workflow:**
1. Fetches public exploits (PoCs, Metasploit modules, security advisories)
2. Retrieves CVSS scores, EPSS probability, and CISA KEV status
3. Checks if your dependencies are affected
4. Analyzes exploit reachability via static analysis
5. Provides exploitability rating: CRITICAL/HIGH/MEDIUM/LOW/N/A
6. Recommends next steps

**Developer benefit:** Understand real-world impact. Is this CVE actively exploited? Do we use the vulnerable code path? Should we drop everything and patch?

##### 3. `/vulnetix:fix <vuln-id>`

**What it does:** Get fix intelligence and concrete remediation steps

```
/vulnetix:fix GHSA-xxxx-yyyy-zzzz
```

**Workflow:**
1. Fetches fix data: version bumps, patches, workarounds
2. Identifies affected dependencies in your manifests
3. Shows exact edits with version upgrades
4. Assesses breaking change risk (patch/minor/major)
5. Proposes changes and asks for confirmation
6. Suggests test commands and re-scanning to verify

**Developer benefit:** Fix vulnerabilities fast. No manual version hunting, no guessing about breaking changes. Just clear, actionable remediation.

### When to Use Each Skill

| Scenario | Command | Benefit |
|----------|---------|---------|
| Adding a new dependency | `/vulnetix:package-search lodash` | Choose the safest option upfront |
| Commit hook found vulnerabilities | `/vulnetix:exploits CVE-2024-1234` | Understand severity and urgency |
| Need to patch a CVE | `/vulnetix:fix CVE-2024-1234` | Get concrete fix steps |
| Evaluating alternatives | `/vulnetix:package-search axios` | Compare security postures |
| Triaging security alerts | `/vulnetix:exploits <vuln-id>` | Assess real-world exploitability |

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

[📖 **Full plugin documentation →**](https://github.com/Vulnetix/Vulnetix/tree/main/claude-code-plugin)

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
