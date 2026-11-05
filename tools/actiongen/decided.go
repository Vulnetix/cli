package main

// declined says why a command has no action of its own. Each key matches a
// command and everything under it. A new subcommand fails
// TestEverySubcommandDecided until it is given an action or a line here, which
// is the point: nothing ships without someone deciding how CI should use it.
var declined = map[string]string{
	// Editor, shell and workstation tooling: nothing for a runner to do.
	"lsp":                   "an editor's language server",
	"completion":            "shell completion for a person's terminal",
	"env":                   "prints the local environment; use setup and run:",
	"update":                "a workflow pins its version; the setup action installs",
	"version":               "use setup and run:",
	"agent":                 "wires coding agents on a workstation",
	"pix":                   "installs an editor plugin on a workstation",
	"skills":                "installs agent skills on a workstation",
	"ai-firewall install":   "wires AI clients on a workstation",
	"ai-firewall uninstall": "wires AI clients on a workstation",
	"ai-firewall kiro":      "an interactive sign-in",
	"ai-firewall key":       "stores a credential by hand; it must not live in a workflow",
	"__manifest":            "internal, validates documentation",

	// Credentials: CI passes them as inputs. Verifying them is a setup step.
	"auth": "credentials are action inputs; run `vulnetix auth verify` after setup to check them",

	// Read-only lookups a person or a script runs: setup then run:.
	"vdb":                   "read-only queries; use setup and run:",
	"bom import":            "read-only; use setup and run:",
	"bom ls":                "read-only; use setup and run:",
	"bom search":            "read-only; use setup and run:",
	"bom skew":              "read-only; use setup and run:",
	"bom tree":              "read-only; use setup and run:",
	"bom where":             "read-only; use setup and run:",
	"tea collection":        "read-only; use setup and run:",
	"tea components":        "read-only; use setup and run:",
	"tea discover":          "read-only; use setup and run:",
	"tea product":           "read-only; use setup and run:",
	"tea products":          "read-only; use setup and run:",
	"tea resolve":           "read-only; use setup and run:",
	"tea distribution list": "read-only; use setup and run:",
	"tea publish list":      "read-only; use setup and run:",
	"config kinds":          "read-only; use setup and run:",
	"config schema":         "read-only; use setup and run:",
	"config get":            "read-only; use setup and run:",
	"ai-firewall baseline":  "read-only; use setup and run:",
	"ai-firewall export":    "config-export covers the drift job",
	"ai-firewall get":       "read-only; use setup and run:",
	"ai-firewall inventory": "read-only; use setup and run:",
	"ai-firewall snippet":   "prints sample code for a person",
	"ai-firewall status":    "reports on this machine's clients",
	"ignore list":           "read-only; use setup and run:",
	"jail list":             "read-only; use setup and run:",
	"license policy show":   "read-only; use setup and run:",
	"license exceptions ls": "read-only; use setup and run:",
	"triage status":         "reports this machine's provider CLIs",
	"gha setup":             "writes a workflow; a person runs it once",

	// Human decisions: an automated job must not make them.
	"defend":                  "chooses a compensating control for a finding",
	"jail exempt":             "a time-boxed exemption is a person's decision",
	"ignore add":              "a suppression is a person's decision",
	"ignore remove":           "a suppression is a person's decision",
	"license exceptions add":  "an exception is a person's decision",
	"license policy init":     "writes a starting policy once",
	"config set":              "changes live organisation policy by hand; config-apply is the reviewed path",
	"ai-firewall policy":      "changes live policy by hand; ai-firewall-apply is the reviewed path",
	"ai-firewall settings":    "changes live settings by hand; ai-firewall-apply is the reviewed path",
	"tea publish":             "low-level steps of tea-release",
	"tea distribution add":    "tea-release declares channels with tea-channels",
	"tea distribution remove": "withdrawing a link is a person's decision",
	"tea share":               "changing who may read a release is a person's decision",

	// Covered by a publish action rather than one per target.
	"gha publish campaigns":        "github-publish with campaigns: true",
	"gha publish code-scanning":    "github-publish",
	"gha publish dependency-graph": "github-publish",
	"gha publish release-assets":   "the release-tag input of every action",
}
