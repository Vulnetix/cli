package main

// The granular catalogue: the actions a repository picks by what it is made of
// (sast/python, sca/yarn) and the single-purpose actions beside the scanners.
// spec.go holds the actions every repository can use as they are.

// sastLanguages are the languages with a dedicated action. The bar is 15 or more
// rules and an evaluation fixture; below it a language is reachable through
// `sast` with `language:`.
var sastLanguages = []struct{ Key, Title string }{
	{"python", "Python"}, {"java", "Java"}, {"javascript", "JavaScript"}, {"typescript", "TypeScript"},
	{"c-cpp", "C and C++"}, {"go", "Go"}, {"php", "PHP"}, {"ruby", "Ruby"}, {"kotlin", "Kotlin"},
	{"csharp", "C#"}, {"shell", "Shell"}, {"rust", "Rust"},
}

// scaManagers are the package managers with a dedicated action. The bar is real
// manifest parsing and a fixture.
var scaManagers = []struct{ Key, Title string }{
	{"bun", "Bun"}, {"bundler", "Bundler"}, {"cargo", "Cargo"}, {"cocoapods", "CocoaPods"}, {"composer", "Composer"},
	{"go", "Go modules"}, {"gradle", "Gradle"}, {"hex", "Hex"}, {"maven", "Maven"}, {"npm", "npm"}, {"nuget", "NuGet"},
	{"pip", "pip"}, {"pipenv", "Pipenv"}, {"pnpm", "pnpm"}, {"poetry", "Poetry"}, {"pub", "pub"}, {"swift", "Swift Package Manager"},
	{"uv", "uv"}, {"yarn", "Yarn"},
}

// fileOutput is a generated-file output path, as the command's own flag.
func fileOutput(flag, def, desc string) input {
	return input{Name: "output-file", Desc: desc, Default: def, Flag: flag}
}

// postureInputs are the inputs of the gha analysis tasks.
func postureInputs(positionalPath bool) []input {
	in := []input{
		{Name: "gha-fail-on", Desc: "Exit 1 when a finding is at or above this severity: critical, high, medium or low (passed as --fail-on)", Flag: "--fail-on"},
		{Name: "min-severity", Desc: "Drop findings below this severity", Flag: "--min-severity"},
		{Name: "offline", Desc: "Do not call the GitHub API: analyse local files only. Rules that need the API report not evaluated: true or false", Default: "false", Flag: "bool:--offline"},
		{Name: "upload", Desc: "Publish the SARIF to Vulnetix as a snapshot (needs Vulnetix credentials): true or false", Default: "false", Flag: "bool:--upload"},
		{Name: "repo", Desc: "Repository as owner/name (default: this repository)", Flag: "--repo"},
		{Name: "rule", Desc: "Only run these rule ids, one per line (passed as --rule)", Flag: "lines:--rule"},
	}
	if positionalPath {
		in = append([]input{{Name: "target", Desc: "Directory holding the workflows", Default: ".", Flag: "lines"}}, in...)
	}
	return in
}

func posture(name, title, desc string, positionalPath bool, extra ...input) action {
	task := name[len("gha-"):]
	return action{Name: name, Title: title, Desc: desc,
		Command: []string{"gha", task, "--format", "sarif"}, CodeScanning: true,
		Inputs: append(append(postureInputs(positionalPath), fileOutput("--output", ".vulnetix/"+name+".sarif", "SARIF report path")), extra...)}
}

func init() {
	for _, l := range sastLanguages {
		actions = append(actions, action{Name: "sast-" + l.Key, Dir: "sast/" + l.Key, Title: "SAST " + l.Title,
			Desc:    "Scan the " + l.Title + " files of a repository with the SAST rules (vulnetix sast --language " + l.Key + ")." + aliasNote(l.Key),
			Command: []string{"sast", "--language", l.Key}, Path: true, Scan: true, CodeScanning: true,
			Inputs: append(append([]input{}, vexInputs...), scanGateInputs...)})
	}
	for _, m := range scaManagers {
		actions = append(actions, action{Name: "sca-" + m.Key, Dir: "sca/" + m.Key, Title: "SCA " + m.Title,
			Desc:    "Scan the " + m.Title + " dependencies of a repository for known vulnerabilities (vulnetix sca --package-manager " + m.Key + ").",
			Command: []string{"sca", "--package-manager", m.Key}, Path: true, Scan: true, CodeScanning: true,
			Inputs: append(append([]input{}, vexInputs...), scanGatePlainInputs...)})
	}
	actions = append(actions,
		action{Name: "scan", Title: "Scan", Desc: "Run every scanner in one job (vulnetix scan). For a monorepo with three or more languages; otherwise use the granular actions.",
			Command: []string{"scan"}, Path: true, Scan: true, CodeScanning: true, DependencyGraph: true,
			Inputs: append(append([]input{}, vexInputs...), scanGateInputs...)},
		action{Name: "image", Title: "Image", Desc: "Inventory a container image for container curation (vulnetix image).",
			Command: []string{"image"},
			Inputs: []input{
				{Name: "reference", Desc: "Image reference or archive, for example ghcr.io/acme/app:1.2.3", Flag: "lines"},
				{Name: "platform", Desc: "Platform to read from a multi-platform image, for example linux/arm64", Flag: "--platform"},
				{Name: "source", Desc: "Where to read the image: auto, registry, docker, podman or archive", Flag: "--source"},
				{Name: "no-upload", Desc: "Inventory locally only and record nothing: true or false", Default: "false", Flag: "bool:--no-upload"},
				fileOutput("--output", ".vulnetix/image.cdx.json", "Write the image's CycloneDX SBOM to this file"),
			}},
		action{Name: "report", Title: "Report", Desc: "Render the stored scan results of an earlier step without rescanning (vulnetix report).",
			Command: []string{"report"}, Path: true,
			Inputs: []input{
				{Name: "view", Desc: "How to present results: auto, packages, findings, tree, table or plain", Flag: "--view"},
				{Name: "filter", Desc: "Show only findings that match all of these, one per line (passed as --filter)", Flag: "lines:--filter"},
				{Name: "min-severity", Desc: "Hide anything below this severity", Flag: "--min-severity"},
			}},
		action{Name: "fix", Title: "Fix", Desc: "Resolve vulnerable dependencies to safe versions and write the change as a patch artifact; it never commits (vulnetix fix --yes).",
			Command: []string{"fix", "--yes"}, Path: true, Script: "fix",
			Inputs: []input{
				{Name: "strategy", Desc: "Target strategy: stable, safest, latest or rolling", Default: "stable", Flag: "--strategy"},
				{Name: "manifest", Desc: "Restrict edits to one manifest", Flag: "--manifest"},
				{Name: "patch-file", Desc: "Where to write the patch of the applied fixes", Default: ".vulnetix/fix.patch"},
			}},
		action{Name: "triage", Title: "Triage", Desc: "Triage this repository's GitHub or Vulnetix alerts into a report (vulnetix triage --format json).",
			Command: []string{"triage", "--format", "json"},
			Inputs: []input{
				{Name: "provider", Desc: "Alert source: github or vulnetix", Default: "github", Flag: "--provider"},
				{Name: "tool", Desc: "Comma-separated sub-tools, for github: dependabot, codeql, secrets", Flag: "--tool"},
				{Name: "severity", Desc: "Only alerts at or above this severity", Flag: "--severity"},
				{Name: "repo", Desc: "Repository as owner/name (default: this repository)", Flag: "--repo"},
			}},
		action{Name: "ignore-sync", Title: "Ignore sync", Desc: "Pull the organisation's suppression rules into .vulnetix/memory.yaml before a scan (vulnetix ignore sync).",
			Command: []string{"ignore", "sync"}, Path: true},

		posture("gha-workflows", "GHA workflows", "Find injection, privilege and trust flaws in this repository's GitHub Actions workflows (vulnetix gha workflows).", true),
		posture("gha-actions", "GHA actions", "Check the actions and images this repository's workflows run (vulnetix gha actions).", true),
		posture("gha-settings", "GHA settings", "Check the repository settings that protect the code and CI (vulnetix gha settings).", false),
		posture("gha-org", "GHA org", "Check organisation settings (vulnetix gha org). Needs a token that can read them.", false,
			input{Name: "org", Desc: "Organisation to check (default: the repository owner)", Flag: "--org"}),
		posture("gha-audit", "GHA audit", "Run every GitHub posture check: workflows, actions, settings and organisation (vulnetix gha audit).", true),
		action{Name: "gha-status", Title: "GHA status", Desc: "Report what this workflow run published to Vulnetix (vulnetix gha status).",
			Command: []string{"gha", "status"},
			Inputs: []input{
				{Name: "run-id", Desc: "Workflow run id to report on (default: this run)", Flag: "--run-id"},
				{Name: "uuid", Desc: "Report on one ingestion snapshot instead of a whole run", Flag: "--uuid"},
			}},
		action{Name: "github-advisories", Title: "GitHub advisories", Desc: "Draft GitHub repository security advisories for this repository's SAST findings (vulnetix gha publish advisories).",
			Command: []string{"gha", "publish", "advisories"}, Path: true,
			Inputs: []input{
				{Name: "sarif", Desc: "SARIF files to read, one per line (default: .vulnetix/sast.sarif)", Flag: "lines:--sarif"},
				{Name: "min-severity", Desc: "Lowest severity that gets an advisory", Flag: "--min-severity"},
				{Name: "max", Desc: "Most advisories to draft or update in one run", Flag: "--max"},
				{Name: "dry-run", Desc: "Print what would be drafted and call nothing: true or false", Default: "false", Flag: "bool:--dry-run"},
			}},

		action{Name: "bom-diff", Title: "BOM diff", Desc: "Compare two SBOM documents and fail on the changes you name (vulnetix bom diff).",
			Command: []string{"bom", "diff"},
			Inputs: []input{
				{Name: "before", Desc: "The earlier SBOM", Flag: "lines"},
				{Name: "after", Desc: "The later SBOM", Flag: "lines"},
				{Name: "diff-fail-on", Desc: "Exit non-zero on these changes: none, any, added, removed, downgraded, vulnerable (passed as --fail-on)", Flag: "--fail-on"},
			}},
		action{Name: "bom-validate", Title: "BOM validate", Desc: "Check an SBOM's structure and field completeness (vulnetix bom validate).",
			Command: []string{"bom", "validate"},
			Inputs: []input{
				{Name: "file", Desc: "The SBOM to check", Flag: "lines"},
				{Name: "min-score", Desc: "Exit non-zero when the completeness score is below this value", Flag: "--min-score"},
			}},
		action{Name: "bom-merge", Title: "BOM merge", Desc: "Combine SBOM documents into one, such as the fragments of scoped sca jobs (vulnetix bom merge).",
			Command: []string{"bom", "merge"},
			Inputs: []input{
				{Name: "files", Desc: "SBOMs to merge, one per line", Flag: "lines"},
				fileOutput("--out", ".vulnetix/merged.cdx.json", "Where to write the merged document"),
			}},
		action{Name: "bom-enrich", Title: "BOM enrich", Desc: "Resolve licences and attach vulnerabilities and VEX to a supplied SBOM (vulnetix bom enrich).",
			Command: []string{"bom", "enrich"},
			Inputs: []input{
				{Name: "file", Desc: "The SBOM to enrich", Flag: "lines"},
				fileOutput("--out", ".vulnetix/enriched.cdx.json", "Where to write the enriched document"),
				{Name: "no-licenses", Desc: "Skip licence resolution: true or false", Default: "false", Flag: "bool:--no-licenses"},
				{Name: "no-vulns", Desc: "Skip the vulnerability lookup: true or false", Default: "false", Flag: "bool:--no-vulns"},
				{Name: "no-vex", Desc: "Skip VEX application: true or false", Default: "false", Flag: "bool:--no-vex"},
				signInput,
			}},

		action{Name: "api-discover", Title: "API discover", Desc: "Find OpenAPI and Swagger descriptions in the working tree and upload them (vulnetix api discover).",
			Command: []string{"api", "discover"},
			Inputs: []input{
				{Name: "target", Desc: "Directory to search", Default: ".", Flag: "lines"},
				{Name: "no-upload", Desc: "Find and print the specs without uploading them: true or false", Default: "false", Flag: "bool:--no-upload"},
			}},
		action{Name: "api-upload", Title: "API upload", Desc: "Upload one OpenAPI or Swagger file (vulnetix api upload).",
			Command: []string{"api", "upload"},
			Inputs:  []input{{Name: "file", Desc: "The OpenAPI or Swagger file", Flag: "lines"}}},
		action{Name: "config-export", Title: "Config export", Desc: "Write the organisation's configuration as code, for a drift job or a backup (vulnetix config export).",
			Command: []string{"config", "export"},
			Inputs: []input{
				{Name: "format", Desc: "yaml, hcl or sh", Flag: "--format"},
				{Name: "kind", Desc: "Only this kind", Flag: "--kind"},
				{Name: "manager", Desc: "Only objects owned by this manager", Flag: "--manager"},
				fileOutput("--output", ".vulnetix/config-export.yaml", "Where to write the documents"),
			}},
		action{Name: "jail-explain", Title: "Jail explain", Desc: "Show why the repository is or is not jailed, rule by rule (vulnetix jail explain).",
			Command: []string{"jail", "explain"}, Path: true,
			Inputs: []input{{Name: "branch", Desc: "Branch to assess", Flag: "--branch"}}},
		action{Name: "license-policy-validate", Title: "License policy validate", Desc: "Check a licence policy document for problems (vulnetix license policy validate).",
			Command: []string{"license", "policy", "validate"}, Path: true,
			Inputs: []input{{Name: "file", Desc: "Explicit document path", Flag: "--file"}}},
		action{Name: "license-exceptions-check", Title: "License exceptions check", Desc: "Report licence exceptions expiring soon (vulnetix license exceptions check).",
			Command: []string{"license", "exceptions", "check"}, Path: true,
			Inputs: []input{
				{Name: "expiring-within", Desc: "Window to report, for example 30d", Flag: "--expiring-within"},
				{Name: "file", Desc: "Explicit document path", Flag: "--file"},
			}},
		action{Name: "ai-firewall-apply", Title: "AI Firewall apply", Desc: "Reconcile the organisation's AI Firewall policy from a file (vulnetix ai-firewall apply).",
			Command: []string{"ai-firewall", "apply"},
			Inputs: []input{
				{Name: "file", Desc: "Policy file (default: .vulnetix/ai-firewall.yaml)", Flag: "--file"},
				{Name: "dry-run", Desc: "Print the plan without changing anything: true or false", Default: "false", Flag: "bool:--dry-run"},
				{Name: "prune", Desc: "Delete server objects the file does not mention: true or false", Default: "false", Flag: "bool:--prune"},
				{Name: "baseline-required", Desc: "Fail if the baseline cannot be fetched: true or false", Default: "true", Flag: "bool:--baseline-required"},
			}},
		action{Name: "surface-liveness", Title: "Surface liveness", Desc: "Check that registered routes and hosts still answer, from inside your network (vulnetix surface liveness).",
			Command: []string{"surface", "liveness"},
			Inputs: []input{
				{Name: "repo", Desc: "Limit the check to one repository (owner/name)", Flag: "--repo"},
				{Name: "scheme", Desc: "Scheme to reach hosts with", Flag: "--scheme"},
			}},
		action{Name: "package-firewall", Title: "Package Firewall", Desc: "Point a package manager on this runner at the Vulnetix Package Firewall, so later install steps go through it (vulnetix package-firewall <ecosystem>).",
			Command: []string{"package-firewall"}, FlagHost: []string{"package-firewall", "npm"},
			Inputs: []input{
				{Name: "ecosystem", Desc: "Ecosystem to configure: npm, pypi, go, cargo, maven, gem, composer, nuget and others", Flag: "lines"},
				{Name: "proxy-url", Desc: "Package Firewall proxy URL", Flag: "--proxy-url"},
				{Name: "dry-run", Desc: "Show planned changes without writing files: true or false", Default: "false", Flag: "bool:--dry-run"},
			}},
	)
}

// aliasNote says when two actions are one scan, so a repository does not run both.
func aliasNote(key string) string {
	if key == "typescript" {
		return " TypeScript is JavaScript to the CLI: this is the same scan, with the same files, category and tool name as sast/javascript, so use one of them."
	}
	return ""
}
