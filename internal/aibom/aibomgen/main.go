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
		filepath.Join(docs, "aibom", "infrastructure.md"):  infrastructureMD(cat),
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
	infraRuntimes, infraCRDs := 0, 0
	if cat.Infrastructure != nil {
		infraRuntimes = len(cat.Infrastructure.Runtimes)
		infraCRDs = len(cat.Infrastructure.CRDs)
	}
	fmt.Printf("aibomgen: catalog %s — %d agents, %d services, %d conventions, %d libraries, %d model families, %d infra runtimes, %d CRDs\n",
		cat.Version, tools, services, conventions, len(cat.Libraries), len(cat.Families), infraRuntimes, infraCRDs)
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
	b.WriteString("- **Commit history** — commits authored by an AI agent, identified by `Co-Authored-By` trailers, session markers (e.g. `Claude-Session:`), agent bot authors, or \"Generated with <tool>\" lines. Catches agent use that left no file/env/source trace.\n")
	b.WriteString("- **IaC** — Kubernetes manifests (incl. KServe / Kubeflow / KubeRay CRDs), docker-compose files and Dockerfiles: AI serving runtimes, agent platforms, vector databases, training/eval frameworks, declared model identities, model-artifact volumes and GPU requests. Anything that cannot be verified from the file carries an explicit confidence gap.\n\n")
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

func infrastructureMD(cat *aibom.Catalog) string {
	var b strings.Builder
	b.WriteString(`---
title: "AI Infrastructure (IaC)"
weight: 3
description: "AI serving runtimes, agent platforms, vector databases and training frameworks detected from Kubernetes manifests, compose files and Dockerfiles."
---

`)
	b.WriteString("The IaC pass analyzes **repository files** — Kubernetes manifests (including CRDs), docker-compose files and Dockerfiles — for the AI infrastructure they would produce. Every detection is validated; a value that cannot be verified from the file is either dropped (likely false positive) or reported with `vulnetix:ai/confidence-gap` = `true` and a `vulnetix:ai/gap-reason` stating exactly what could not be verified and why. **Nothing is ever guessed.**\n\n")
	b.WriteString("> Generated from the catalog. To add or refine a rule, edit `internal/aibom/catalog/infrastructure.json` and run `just gen-aibom`.\n\n")

	in := cat.Infrastructure
	if in == nil {
		b.WriteString("_The catalog carries no infrastructure section._\n")
		return b.String()
	}

	b.WriteString("## Runtimes detected by container image\n\n")
	b.WriteString("Image patterns are matched against the image **name** (registry + repository, tag/digest split off). The version is reported only when the tag is semver-shaped; otherwise the raw tag is preserved and the component carries a confidence gap.\n\n")
	b.WriteString("| Runtime | Category | Image patterns |\n")
	b.WriteString("|---------|----------|----------------|\n")
	runtimes := append([]aibom.InfraRuntimeDef(nil), in.Runtimes...)
	sort.Slice(runtimes, func(i, j int) bool {
		if runtimes[i].Category != runtimes[j].Category {
			return runtimes[i].Category < runtimes[j].Category
		}
		return runtimes[i].Name < runtimes[j].Name
	})
	for _, r := range runtimes {
		fmt.Fprintf(&b, "| %s | `%s` | %s |\n", r.Name, r.Category, code(r.ImagePatterns))
	}

	b.WriteString("\n## Custom resources (CRDs)\n\n")
	b.WriteString("| Kind | API group prefix | Category | Declared fields extracted |\n")
	b.WriteString("|------|------------------|----------|---------------------------|\n")
	for _, c := range in.CRDs {
		var fields []string
		for _, f := range c.Fields {
			fields = append(fields, f.Path)
		}
		cell := "pod templates (embedded)"
		if len(fields) > 0 {
			cell = code(fields)
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n", c.Kind, c.APIVersionPrefix, c.Category, cell)
	}

	b.WriteString("\n## Model identity signals\n\n")
	fmt.Fprintf(&b, "- **Environment values**: %s (a `valueFrom` secret/configMap reference is never resolved — it produces a confidence gap instead)\n", code(in.ModelEnvVars))
	fmt.Fprintf(&b, "- **Container args/command flags**: %s (both `--flag value` and `--flag=value`)\n", code(in.ModelArgFlags))
	fmt.Fprintf(&b, "- **Declared annotations**: prefixes %s\n", code(in.AnnotationPrefixes))
	fmt.Fprintf(&b, "- **Volume mounts** (model artifacts): path-boundary prefixes %s — `/models` matches `/models/x` but never `/models-shared`\n", code(in.ModelMountPrefixes))
	fmt.Fprintf(&b, "- **Dataset volumes** (training workloads only): names %s, mount prefixes %s\n", code(in.DatasetVolumeNames), code(in.DatasetMountPrefixes))

	b.WriteString("\n## Workload environment-name signals\n\n")
	b.WriteString("Only the variable **name** is matched — values are never read.\n\n")
	b.WriteString("| Env var | Framework | Category |\n")
	b.WriteString("|---------|-----------|----------|\n")
	sigs := append([]aibom.WorkloadEnvSignal(nil), in.WorkloadEnvSignals...)
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].Env < sigs[j].Env })
	for _, s := range sigs {
		fmt.Fprintf(&b, "| `%s` | %s | `%s` |\n", s.Env, s.Name, s.Category)
	}
	fmt.Fprintf(&b, "\nRemote AI API dependencies (e.g. `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) declared on workload containers are surfaced through the same provider-service catalog as the local environment pass.\n")

	fmt.Fprintf(&b, "\n## GPU / accelerator signals\n\nResource keys: %s, plus node selectors mentioning `accelerator`.\n", code(in.GPUResourceKeys))

	if len(in.TerraformSignals) > 0 {
		b.WriteString("\n## Terraform / OpenTofu signals\n\n")
		b.WriteString("Matched by resource type (regex over `.tf`/`.tofu` content — resource names and variables are never interpreted). An **attribute gate** additionally requires a pattern inside the resource block, so e.g. a `ComputerVision` cognitive account never matches the Azure OpenAI signal.\n\n")
		b.WriteString("| Signal | Provider | Category | Resource pattern | Attribute gate |\n")
		b.WriteString("|--------|----------|----------|------------------|----------------|\n")
		for _, ts := range in.TerraformSignals {
			gate := "—"
			if ts.AttrPattern != "" {
				gate = "`" + ts.AttrPattern + "`"
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | `%s` | %s |\n", ts.Name, ts.Provider, ts.Category, ts.ResourcePattern, gate)
		}
	}

	if len(in.ModelFileExtensions) > 0 {
		fmt.Fprintf(&b, "\n## Model files on disk\n\nWeight files present in the repository (%s) are reported as verified `data` components — the artifact literally exists. `.pt` is deliberately excluded (too many non-model uses).\n", code(in.ModelFileExtensions))
	}

	b.WriteString(`
## Known false negatives

Detection is deliberately allowlist-driven — a missed detection is preferred over a wrong one. The following are **not** detected, by design:

- Images mirrored to private or organisation-local registries (the official-registry patterns will not match a mirror).
- Helm values that are still templated (` + "`{{ .Values.image }}`" + `) — structural parsing skips them; the narrow regex fallback reports what it finds with an explicit confidence gap.
- Models fetched at runtime (entrypoint scripts, init downloads) that leave no declared trace in the manifest.
- Model identities passed through ConfigMaps or Secrets — references are never resolved.
- Bare ` + "`/data`" + ` mounts on workloads with no training signal (not assumed to be datasets).

Absence of a finding is therefore **not** verified absence of AI infrastructure.
`)
	return b.String()
}

func formatMD() string {
	return `---
title: "Catalog Format"
weight: 4
description: "The detection catalog schema, and how to extend or override it with --catalog."
---

All AIBOM detection is driven by a declarative catalog so it can be maintained over time without code changes. The builtin catalog is embedded in the binary (` + "`internal/aibom/catalog/*.json`" + `). You can extend or replace it at runtime:

` + "```bash" + `
vulnetix aibom --catalog ./my-rules.json          # merge over the builtin (override by id)
vulnetix aibom --catalog ./only.json --no-builtin-catalog   # replace entirely
` + "```" + `

A catalog file is JSON with any of the top-level sections: ` + "`tools`, `libraries`, `model_families`, `infrastructure`" + `. The ` + "`infrastructure`" + ` section drives the IaC pass — see [AI Infrastructure (IaC)](../infrastructure/) for its rule tables; its ` + "`runtimes`/`crds`/`terraform_signals`" + ` entries override by ` + "`id`" + `, ` + "`workload_env_signals`" + ` by ` + "`env`" + `, and a non-empty scalar list (e.g. ` + "`model_env_vars`" + `) **replaces** the builtin list.

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
