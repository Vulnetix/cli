// Command aibomgen renders the AIBOM detection documentation from the single
// source of truth: the embedded catalog (internal/aibom/catalog/*.json).
//
// It validates the catalog (every regex/glob compiles) and then writes:
//   - website/content/docs/aibom/_index.md
//   - website/content/docs/aibom/supported-tools.md
//   - website/content/docs/aibom/libraries.md
//   - website/content/docs/aibom/catalog-format.md
//   - website/content/docs/cli-reference/aibom.md
//
// Docs therefore can never drift from the detection rules. Run via:
//
//	just gen-aibom        # go run ./internal/aibom/aibomgen
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/aibom"
)

func main() {
	root, err := repoRoot()
	if err != nil {
		fail(err)
	}
	cat, err := aibom.LoadCatalog("", false)
	if err != nil {
		fail(err)
	}
	if _, err := cat.Compile(); err != nil {
		fail(fmt.Errorf("catalog failed validation: %w", err))
	}

	docs := filepath.Join(root, "website", "content", "docs")
	writes := map[string]string{
		filepath.Join(docs, "aibom", "_index.md"):          indexMD(cat),
		filepath.Join(docs, "aibom", "supported-tools.md"): toolsMD(cat),
		filepath.Join(docs, "aibom", "libraries.md"):       librariesMD(cat),
		filepath.Join(docs, "aibom", "catalog-format.md"):  formatMD(),
		filepath.Join(docs, "cli-reference", "aibom.md"):   commandMD(),
	}
	for path, body := range writes {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fail(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			fail(err)
		}
	}

	tools, services, conventions := 0, 0, 0
	for _, t := range cat.Tools {
		switch t.Type {
		case "service":
			services++
		case "convention":
			conventions++
		default:
			tools++
		}
	}
	fmt.Printf("aibomgen: catalog %s — %d agents, %d services, %d conventions, %d libraries, %d model families\n",
		cat.Version, tools, services, conventions, len(cat.Libraries), len(cat.Families))
	fmt.Printf("aibomgen: wrote %d docs under %s\n", len(writes), docs)
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "aibomgen:", err)
	os.Exit(1)
}

// ---- markdown builders ---------------------------------------------------

func indexMD(cat *aibom.Catalog) string {
	agents, services, conventions := 0, 0, 0
	for _, t := range cat.Tools {
		switch t.Type {
		case "service":
			services++
		case "convention":
			conventions++
		default:
			agents++
		}
	}
	var b strings.Builder
	b.WriteString(`---
title: "AIBOM"
weight: 7
description: "Discover AI coding agents and AI usage, and emit a CycloneDX AI Bill of Materials."
---

`)
	b.WriteString("The `vulnetix aibom` command discovers evidence of AI coding agents/assistants and AI usage in a project and produces an **AI Bill of Materials (AIBOM)** in CycloneDX 1.7 format.\n\n")
	b.WriteString("> **This page is generated** from the detection catalog (`internal/aibom/catalog/*.json`). Run `just gen-aibom` after editing the catalog.\n\n")
	b.WriteString("## What it detects\n\n")
	b.WriteString("Three passes, all driven by a maintainable catalog:\n\n")
	b.WriteString("- **Environment** — known AI tool / provider environment-variable *names*. Values are never read or emitted, so secrets never leak into the AIBOM.\n")
	b.WriteString("- **Filesystem** — tool config directories, instruction files, ignore files, skills, hooks, plugins, steering, memory, prompts, agents, commands and marketplace manifests.\n")
	b.WriteString("- **Source code** — AI SDK/framework usage per language, and the model-name literals passed to them. Model names are extracted by anchoring on the SDK parameter (`model=`, `modelId=`, `deployment_name=`), so **future / unknown model names are still captured**.\n")
	b.WriteString("- **Commit history** — commits authored by an AI agent, identified by `Co-Authored-By` trailers, session markers (e.g. `Claude-Session:`), agent bot authors, or \"Generated with <tool>\" lines. Catches agent use that left no file/env/source trace.\n\n")
	fmt.Fprintf(&b, "The builtin catalog (version `%s`) covers **%d AI coding agents**, **%d AI provider services**, **%d conventions**, and **%d AI SDKs** across many languages.\n\n",
		cat.Version, agents, services, conventions, len(cat.Libraries))
	b.WriteString("{{< cards >}}\n")
	b.WriteString("  {{< card link=\"supported-tools\" title=\"Supported Agents\" subtitle=\"Every AI coding tool & provider the catalog detects.\" icon=\"chip\" >}}\n")
	b.WriteString("  {{< card link=\"libraries\" title=\"AI SDKs\" subtitle=\"SDKs detected and the model parameters extracted.\" icon=\"code\" >}}\n")
	b.WriteString("  {{< card link=\"catalog-format\" title=\"Catalog Format\" subtitle=\"Extend or override detection with --catalog.\" icon=\"document-text\" >}}\n")
	b.WriteString("  {{< card link=\"../cli-reference/aibom\" title=\"Command Reference\" subtitle=\"vulnetix aibom flags and examples.\" icon=\"terminal\" >}}\n")
	b.WriteString("{{< /cards >}}\n")
	return b.String()
}

func toolsMD(cat *aibom.Catalog) string {
	tools := append([]aibom.ToolDef(nil), cat.Tools...)
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Type != tools[j].Type {
			return tools[i].Type < tools[j].Type
		}
		return tools[i].Name < tools[j].Name
	})

	var b strings.Builder
	b.WriteString(`---
title: "Supported Agents & Providers"
weight: 1
description: "Every AI coding agent, provider service and convention the AIBOM detector recognises."
---

`)
	b.WriteString("Each entry below is detected by the environment and filesystem passes. The **Detection signals** column lists the catalog rules — environment-variable names and repo-relative path globs.\n\n")
	b.WriteString("> Generated from the catalog. To add or refine a tool, edit `internal/aibom/catalog/tools.json` and run `just gen-aibom`.\n\n")
	b.WriteString("| Tool | Vendor | Type | Detection signals |\n")
	b.WriteString("|------|--------|------|-------------------|\n")
	for _, t := range tools {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s |\n", t.Name, t.Vendor, t.Type, toolSignals(t))
	}
	return b.String()
}

func toolSignals(t aibom.ToolDef) string {
	var parts []string
	if len(t.Env) > 0 {
		parts = append(parts, "env: "+code(t.Env))
	}
	cats := make([]string, 0, len(t.Paths))
	for c := range t.Paths {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		if len(t.Paths[c]) == 0 {
			continue
		}
		parts = append(parts, c+": "+code(t.Paths[c]))
	}
	if len(t.CommitPatterns) > 0 {
		parts = append(parts, "commit: "+code(t.CommitPatterns))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "<br>")
}

func librariesMD(cat *aibom.Catalog) string {
	libs := append([]aibom.LibraryDef(nil), cat.Libraries...)
	sort.Slice(libs, func(i, j int) bool {
		if libs[i].Provider != libs[j].Provider {
			return libs[i].Provider < libs[j].Provider
		}
		return libs[i].Name < libs[j].Name
	})

	var b strings.Builder
	b.WriteString(`---
title: "AI SDKs & Frameworks"
weight: 2
description: "AI SDKs detected by the source-code pass and the model-name parameters extracted from each."
---

`)
	b.WriteString("The source-code pass scans files in the matching language for these SDKs. When an SDK is in use, the catalog extracts the model-name literal bound to the listed parameters — so unknown / future model names are captured without a hardcoded model list.\n\n")
	b.WriteString("> Generated from the catalog. To add an SDK, edit `internal/aibom/catalog/libraries.json` and run `just gen-aibom`.\n\n")
	b.WriteString("| Library | Provider | Languages | Model parameters |\n")
	b.WriteString("|---------|----------|-----------|------------------|\n")
	for _, l := range libs {
		params := map[string]bool{}
		var ps []string
		for _, m := range l.ModelExtractors {
			if m.Param != "" && !params[m.Param] {
				params[m.Param] = true
				ps = append(ps, m.Param)
			}
		}
		sort.Strings(ps)
		pcell := "—"
		if len(ps) > 0 {
			pcell = code(ps)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", l.Name, l.Provider, strings.Join(l.Languages, ", "), pcell)
	}
	return b.String()
}

func formatMD() string {
	return `---
title: "Catalog Format"
weight: 3
description: "The detection catalog schema, and how to extend or override it with --catalog."
---

All AIBOM detection is driven by a declarative catalog so it can be maintained over time without code changes. The builtin catalog is embedded in the binary (` + "`internal/aibom/catalog/*.json`" + `). You can extend or replace it at runtime:

` + "```bash" + `
vulnetix aibom --catalog ./my-rules.json          # merge over the builtin (override by id)
vulnetix aibom --catalog ./only.json --no-builtin-catalog   # replace entirely
` + "```" + `

A catalog file is JSON with any of three top-level arrays: ` + "`tools`, `libraries`, `model_families`" + `.

## Tool entry

` + "```jsonc" + `
{
  "id": "cursor",                       // unique id (override key)
  "name": "Cursor",
  "vendor": "Anysphere",
  "type": "cli-agent | ide | ide-extension | service | convention",
  "homepage": "https://cursor.com",
  "env": ["CURSOR_*"],                  // env var NAMES (exact, or globs with *). Values are never read.
  "paths": {                            // category -> repo-relative path globs (* , ** , ? supported)
    "config":       [".cursor/**"],
    "instructions": [".cursorrules"],
    "ignore":       [".cursorignore"],
    "skills":       [".cursor/skills/**"]
    // also: agents, commands, hooks, plugins, steering, memory, prompts, marketplace
  },
  "model_config_extractors": [          // optional: pull model names from this tool's config files
    {"file_glob": ".cursor/config.json", "json_key": "model"}
    // or: {"file_glob": "...", "pattern": "regex-with-one-capture-group"}
  ],
  "commit_patterns": [                   // optional: identify commits authored by this agent
    "(?i)co-authored-by:\\s*cursor\\b"   // matched against author/committer identity + message
  ]
}
` + "```" + `

A tool needs at least one **primary** (tool-specific) path, env/home, or commit hit to be reported. Cross-tool convention files (` + "`AGENTS.md`, `.mcp.json`" + `) are surfaced only through dedicated ` + "`type: \"convention\"`" + ` entries, so a single shared file does not light up every tool.

## Library entry

` + "```jsonc" + `
{
  "id": "openai-python",
  "name": "openai",
  "provider": "OpenAI",
  "languages": ["python"],             // canonical ecosystem keys (javascript covers ts/js)
  "purl_names": {"pypi": "openai"},    // ecosystem -> package name (for the component purl)
  "import_patterns": ["(?m)^\\s*(?:from|import)\\s+openai\\b"],   // confirm the SDK is used
  "model_extractors": [
    {"param": "model", "pattern": "\\bmodel\\s*=\\s*[\"']([^\"']+)[\"']", "task": "chat"}
  ]
}
` + "```" + `

Every ` + "`model_extractors[].pattern`" + ` must have **exactly one capture group** — the model-name literal. Anchoring on the parameter (not the value) is what makes unknown / future model names detectable.

## Model family

Family hints map a model-name prefix to a provider/family. They only enrich confidence — an unknown literal is still emitted.

` + "```jsonc" + `
{"prefix_regex": "^claude-", "provider": "Anthropic", "family": "Claude"}
` + "```" + `

All patterns are Go RE2 (no backreferences/lookaround). The catalog is validated (every pattern compiles, every extractor has a capture group) at load time and by ` + "`just gen-aibom`" + `.
`
}

func commandMD() string {
	return `---
title: "AIBOM Command Reference"
weight: 8
description: "Discover AI coding agents and AI usage, and emit a CycloneDX AI Bill of Materials."
---

The ` + "`aibom`" + ` command discovers evidence of AI coding agents/assistants and AI usage in a project and produces an **AI Bill of Materials (AIBOM)** in CycloneDX 1.7 format. See [AIBOM](../aibom/) for what is detected and the catalog format.

## Usage

` + "```bash" + `
vulnetix aibom [path] [flags]
` + "```" + `

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| ` + "`--path`" + ` | string | ` + "`.`" + ` | Directory to scan (a positional ` + "`[path]`" + ` argument overrides this) |
| ` + "`--depth`" + ` | int | ` + "`25`" + ` | Maximum recursion depth for file discovery |
| ` + "`--ignore`" + ` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| ` + "`-o, --output`" + ` | string | ` + "`cyclonedx-json`" + ` | Output format: ` + "`cyclonedx-json`, `json`, `table`" + ` |
| ` + "`--output-file`" + ` | string | - | Write output to this file instead of stdout |
| ` + "`--spec-version`" + ` | string | ` + "`1.7`" + ` | CycloneDX spec version: ` + "`1.6`" + ` or ` + "`1.7`" + ` |
| ` + "`--catalog`" + ` | string | - | Catalog file to merge over (or replace) the builtin catalog |
| ` + "`--no-builtin-catalog`" + ` | bool | ` + "`false`" + ` | Do not load the embedded catalog (use only ` + "`--catalog`" + `) |
| ` + "`--no-env`" + ` | bool | ` + "`false`" + ` | Skip the environment-variable detection pass |
| ` + "`--include-home`" + ` | bool | ` + "`false`" + ` | Also probe the user's home directory for tool config dirs |
| ` + "`--no-source`" + ` | bool | ` + "`false`" + ` | Skip the source-code SDK / model detection pass |
| ` + "`--no-commits`" + ` | bool | ` + "`false`" + ` | Skip the git commit-history detection pass |
| ` + "`--commit-scan-max`" + ` | int | ` + "`2000`" + ` | Max commits (from HEAD) the commit-history pass inspects |
| ` + "`--aibom-include-ignored`" + ` | bool | ` + "`false`" + ` | Include files matched by ` + "`.gitignore`" + ` (default: gitignored paths are skipped) |

## Output

- ` + "`cyclonedx-json`" + ` (default) — a CycloneDX AIBOM. AI coding tools map to ` + "`application`" + ` components, AI SDKs to ` + "`library`" + ` components, and model names to ` + "`machine-learning-model`" + ` components (each with a ` + "`modelCard`" + `). Evidence rides on component ` + "`properties`" + ` under the ` + "`vulnetix:ai/*`" + ` namespace. The document is schema-validated before it is written.
- ` + "`table`" + ` — a human-readable summary.
- ` + "`json`" + ` — the raw detection result.

## Examples

` + "```bash" + `
vulnetix aibom                                  # scan ., emit CycloneDX AIBOM to stdout
vulnetix aibom ./myproject -o table             # human-readable summary
vulnetix aibom --output-file aibom.cdx.json     # write the AIBOM to a file
vulnetix aibom --no-env --no-source             # filesystem evidence only
vulnetix aibom --catalog ./extra-rules.json     # extend the builtin catalog
` + "```" + `

## Privacy

The environment pass records only variable **names** and their presence — never their values. No source content is uploaded.
`
}

// code renders a list of strings as comma-separated inline code spans.
func code(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = "`" + x + "`"
	}
	return strings.Join(parts, ", ")
}
