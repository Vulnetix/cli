---
title: "Custom SAST Rule Repositories"
weight: 1
description: "Author your own Rego-based SAST rules, publish them to a Git repository, and load them with the --rule flag — alongside or instead of the built-in rules."
---

Vulnetix SAST is powered by [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) and evaluates rules written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/). You can author rules that encode your team's specific security policies and load them at scan time from any Git repository with `--rule`.

## How It Works

When you pass `--rule org/repo`, Vulnetix:

1. Builds the clone URL: `<registry>/<org>/<repo>` (default registry is `https://github.com`)
2. Shallow-clones the repository into a local cache directory
3. Walks the `rules/` directory inside the repo and loads every `.rego` file it finds
4. Compiles all loaded modules (built-in + external) together before evaluation
5. On subsequent runs, pulls updates to the cached clone automatically

The local cache lives at:

| OS | Path |
|----|------|
| Linux | `~/.cache/vulnetix/rules/<org>/<repo>/` |
| macOS | `~/Library/Caches/vulnetix/rules/<org>/<repo>/` |
| Windows | `%LOCALAPPDATA%\vulnetix\rules\<org>\<repo>\` |

## Required Repository Structure

Your repository must contain a `rules/` directory at the root. Vulnetix only looks inside this directory; everything else (README, tests, CI config) is ignored.

```
my-sast-rules/
├── rules/
│   ├── my-sql-injection.rego
│   ├── my-hardcoded-password.rego
│   └── subdir/
│       └── my-framework-rule.rego   ← subdirectories are walked recursively
└── README.md
```

Any `.rego` file found anywhere under `rules/` is loaded. Subdirectories are fine.

## Rego Rule Format

Each rule file must export two values:

- `metadata` — a JSON object describing the rule
- `findings` — a set of finding objects, evaluated against `input.file_contents`

### Annotated example

```rego
package vulnetix.rules.my_sql_injection

import rego.v1

# metadata is used for display, SARIF output, and severity gating.
metadata := {
    "id":          "MY-SQL-001",
    "name":        "Raw SQL concatenation in Python",
    "description": "String concatenation used to build a SQL query; use parameterised queries instead.",
    "help_uri":    "https://wiki.example.com/security/sql-injection",
    "languages":   ["python"],
    "severity":    "high",
    "level":       "error",
    "kind":        "sast",
    "cwe":         [89],
    "capec":       ["CAPEC-66"],
    "attack_technique": ["T1190"],
    "cvssv4":      "",
    "cwss":        "",
    "tags":        ["sql-injection", "python"],
}

# Helper — limit to Python files.
_is_python(path) if endswith(path, ".py")

# findings is the core detection logic.
# input.file_contents maps file path → full file content as a string.
findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_python(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for cursor.execute with string concatenation
    contains(line, "cursor.execute")
    contains(line, " + ")
    finding := {
        "rule_id":      metadata.id,
        "message":      "Raw SQL concatenation detected; use parameterised queries (cursor.execute(sql, params))",
        "artifact_uri": path,
        "severity":     metadata.severity,
        "level":        metadata.level,
        "start_line":   i + 1,
        "snippet":      line,
    }
}
```

### Metadata fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique rule identifier (e.g. `MY-SQL-001`). Avoid clashes with built-in `VNX-*` IDs. |
| `name` | Yes | Short human-readable name shown in scan output |
| `description` | Yes | Full description of what the rule detects |
| `help_uri` | No | URL to remediation docs (shown in SARIF `helpUri`) |
| `languages` | Yes | Array of language strings the rule targets (used for display only; filtering is done by your Rego logic) |
| `severity` | Yes | `low`, `medium`, `high`, or `critical` — used for `--severity` gating |
| `level` | No | SARIF level: `note`, `warning`, or `error`. Defaults to a severity-derived value if omitted. |
| `kind` | No | Rule sub-category for `--no-*` filtering: `sast` (default), `secrets`, `oci`, or `iac` |
| `cwe` | No | Array of integer CWE numbers |
| `capec` | No | Array of CAPEC strings (e.g. `"CAPEC-66"`) |
| `attack_technique` | No | Array of MITRE ATT&CK technique IDs |
| `cvssv4` | No | CVSSv4 vector string |
| `cwss` | No | CWSS score string |
| `tags` | No | Array of free-form tags for display |

### The `findings` set

Each element of `findings` must be a JSON object with these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `rule_id` | Yes | Must match `metadata.id` |
| `message` | Yes | Specific message for this finding instance |
| `artifact_uri` | Yes | File path (from `input.file_contents` key) |
| `severity` | Yes | Severity for this specific finding |
| `level` | Yes | SARIF level for this finding |
| `start_line` | Yes | 1-based line number |
| `snippet` | No | The matching source line (shown in output) |

### What `input` contains

Your Rego code receives a single `input` object:

```json
{
  "file_contents": {
    "src/app.py":       "import os\n...",
    "src/db/query.py":  "...\n",
    "templates/index.html": "..."
  }
}
```

`input.file_contents` maps every file path (relative to the scan root) to its full text content. Your rule iterates over these to find matches.

---

## Step-by-Step: Create a Rule Repo with the GitHub CLI

### 1. Install and authenticate the GitHub CLI

```bash
# Install (macOS)
brew install gh

# Install (Linux — see https://cli.github.com for other methods)
sudo apt install gh

# Authenticate
gh auth login
```

### 2. Create the repository

```bash
# Create a public repo (recommended — no auth needed at scan time)
gh repo create myorg/sast-rules \
  --public \
  --description "Custom SAST rules for Vulnetix" \
  --clone

# OR create a private repo (requires SSH or HTTPS auth at scan time)
gh repo create myorg/sast-rules \
  --private \
  --description "Custom SAST rules for Vulnetix" \
  --clone
```

### 3. Set up the directory structure

```bash
cd sast-rules
mkdir -p rules
```

### 4. Write your first rule

```bash
cat > rules/my-sql-001.rego << 'EOF'
package vulnetix.rules.my_sql_001

import rego.v1

metadata := {
    "id":          "MY-SQL-001",
    "name":        "Raw SQL concatenation in Python",
    "description": "String concatenation used to build a SQL query; use parameterised queries instead.",
    "help_uri":    "",
    "languages":   ["python"],
    "severity":    "high",
    "level":       "error",
    "kind":        "sast",
    "cwe":         [89],
    "capec":       ["CAPEC-66"],
    "attack_technique": ["T1190"],
    "cvssv4":      "",
    "cwss":        "",
    "tags":        ["sql-injection", "python"],
}

_is_python(path) if endswith(path, ".py")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_python(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    contains(line, "cursor.execute")
    contains(line, " + ")
    finding := {
        "rule_id":      metadata.id,
        "message":      "Raw SQL concatenation; use cursor.execute(sql, params) instead",
        "artifact_uri": path,
        "severity":     metadata.severity,
        "level":        metadata.level,
        "start_line":   i + 1,
        "snippet":      line,
    }
}
EOF
```

### 5. Commit and push

```bash
git add rules/
git commit -m "feat: add SQL injection detection rule"
git push origin main
```

### 6. Run a scan with your new rules

```bash
# Use your custom rules alongside the built-in set
vulnetix scan --rule myorg/sast-rules

# Use only your custom rules (disable built-ins)
vulnetix scan --rule myorg/sast-rules --disable-default-rules
```

---

## Flag Reference

### `--rule org/repo`

Load rules from the repository at `https://github.com/<org>/<repo>`. The repo must be publicly accessible (or the running user must have SSH/HTTPS access for private repos).

```bash
vulnetix scan --rule myorg/sast-rules
```

### Multiple `--rule` flags

Pass `--rule` multiple times to load from several repositories. All rules are compiled together.

```bash
vulnetix scan \
  --rule myorg/sast-rules \
  --rule myorg/secrets-rules \
  --rule thirdparty/opa-policies
```

### `--disable-default-rules`

Skip the 253 built-in rules shipped with the CLI. Only the rules from `--rule` repos are evaluated. Useful when you want full control over what runs.

```bash
# Only your rules, no built-ins
vulnetix scan \
  --disable-default-rules \
  --rule myorg/sast-rules
```

### `--rule-registry`

Override the default registry (`https://github.com`) for all `--rule` references. The flag value must be the bare base URL of your Git host — `<registry>/<org>/<repo>` is the full clone URL.

```bash
# Load from GitLab.com
vulnetix scan \
  --rule myorg/sast-rules \
  --rule-registry https://gitlab.com

# Load from a self-hosted Gitea or Forgejo instance
vulnetix scan \
  --rule myorg/sast-rules \
  --rule-registry https://git.corp.example.com

# Load from GitHub Enterprise Server
vulnetix scan \
  --rule myorg/sast-rules \
  --rule-registry https://github.example.com
```

> `--rule-registry` applies to **all** `--rule` flags in the same invocation. If you need rules from multiple registries, run separate scans or merge the rule repos.

### Combining flags

```bash
# Disable built-ins, load from two custom repos, severity gate
vulnetix scan \
  --disable-default-rules \
  --rule myorg/sast-rules \
  --rule myorg/secrets-rules \
  --severity high

# Custom rules on a private GitLab instance, SARIF output
vulnetix scan \
  --rule internal/security-policies \
  --rule-registry https://gitlab.corp.example.com \
  --output results.sarif

# sast command with custom rules
vulnetix sast \
  --rule myorg/sast-rules \
  --disable-default-rules
```

---

## Public vs Private Repositories

### Public repositories (recommended for most teams)

The CLI clones over HTTPS without authentication. No extra setup is needed.

```bash
# Works out of the box
vulnetix scan --rule myorg/sast-rules
```

### Private repositories

The CLI uses `go-git` to clone, which honours your system's Git credential helpers and SSH agent.

**SSH access (recommended for private repos):**

```bash
# Ensure your SSH key is added to the agent
ssh-add ~/.ssh/id_ed25519

# The clone URL becomes git@github.com:myorg/sast-rules.git when SSH is used
# Override the registry to use the SSH URL scheme
vulnetix scan \
  --rule myorg/sast-rules \
  --rule-registry git@github.com:
```

> Note: when using SSH, `--rule-registry` must be the SSH URL prefix — e.g. `git@github.com:` (including the trailing colon).

**HTTPS with a token (CI/CD environments):**

```bash
# Set a credential helper or embed credentials in the registry URL
vulnetix scan \
  --rule myorg/sast-rules \
  --rule-registry "https://oauth2:${GITLAB_TOKEN}@gitlab.com"
```

**GitHub Actions — private repo in the same org:**

```yaml
- name: Scan with private custom rules
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
    vulnetix scan --rule myorg/sast-rules
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Vulnetix
        run: |
          curl -sSfL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh

      - name: Scan with custom rules
        run: |
          vulnetix scan \
            --rule myorg/sast-rules \
            --severity high \
            --output results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

**Using only your rules (no built-ins) in CI:**

```yaml
      - name: Scan with custom rules only
        run: |
          vulnetix scan \
            --disable-default-rules \
            --rule myorg/sast-rules \
            --rule myorg/secrets-rules \
            --output results.sarif
```

### GitLab CI

```yaml
sast-scan:
  image: ubuntu:24.04
  script:
    - curl -sSfL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh
    - vulnetix scan
        --rule myorg/sast-rules
        --rule-registry https://gitlab.com
        --severity high
        --output gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

---

## Testing Your Rules Locally

### List loaded rules before running

```bash
# See exactly which rules will run (built-in + your repo)
vulnetix scan --list-default-rules --rule myorg/sast-rules
```

### Dry-run to verify rule loading

```bash
# Detect files and confirm rule loading messages, but make no API calls
vulnetix scan --dry-run --rule myorg/sast-rules
```

Watch for the line:

```
Imported N rules from myorg/sast-rules
```

If it shows `0`, check that your `.rego` files are inside a `rules/` directory at the repo root.

### Run against a test fixture

Create a minimal test file that should trigger your rule, then scan it:

```bash
# Create a fixture
mkdir -p /tmp/test-proj
cat > /tmp/test-proj/app.py << 'EOF'
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
EOF

# Run with only your rule, no built-ins
vulnetix scan \
  --path /tmp/test-proj \
  --disable-default-rules \
  --rule myorg/sast-rules \
  --no-sca --no-licenses
```

You should see your finding appear in the output.

### Check the rule cache

Vulnetix caches cloned rule repos locally. To force a fresh clone, delete the cache:

```bash
# Linux
rm -rf ~/.cache/vulnetix/rules/myorg/sast-rules

# macOS
rm -rf ~/Library/Caches/vulnetix/rules/myorg/sast-rules

# Windows (PowerShell)
Remove-Item -Recurse "$env:LOCALAPPDATA\vulnetix\rules\myorg\sast-rules"
```

On the next scan run, the repo is re-cloned from scratch.

---

## Troubleshooting

### `Warning: rules registry not found: myorg/sast-rules`

The clone URL could not be reached. Check:

- The repo exists and is publicly accessible (or you have auth set up)
- `--rule-registry` is set correctly if not using GitHub
- Network connectivity / proxy settings (see [Corporate Proxy](../enterprise/corporate-proxy/))

### `Imported 0 rules from myorg/sast-rules`

The repo cloned successfully but no `.rego` files were found. Check:

- Your `.rego` files are inside a `rules/` directory **at the repo root** (not a nested subdirectory like `src/rules/`)
- Files end with `.rego` (not `.rego.txt` etc.)

### `parse <file>: <error>`

A `.rego` file failed to parse. Common causes:

- Syntax error in your Rego code
- Missing `import rego.v1` statement
- Using Rego v0 syntax without `import rego.v1` — add the import at the top of each rule file

### `Warning: walking rules in myorg/sast-rules: <error>`

Permission error reading the cache directory. Try deleting the cache (see above) and re-running.

### Finding is produced but `--severity high` does not gate

Ensure the finding's `severity` field in `findings` matches or exceeds the threshold. The `metadata.severity` alone is not enough — each finding object must also set `"severity": metadata.severity` (or a higher value) explicitly.

---

## Related

- [SAST Rules Reference](../) — All 253 built-in rule pages
- [Scan Command Reference](../../cli-reference/scan/) — Full `vulnetix scan` flag reference
- [SAST Command Reference](../../cli-reference/sast/) — `vulnetix sast` for SAST-only scans
- [Corporate Proxy](../../enterprise/corporate-proxy/) — Proxy configuration for rule fetching in restricted environments
