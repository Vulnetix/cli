package main

// The spec table: one entry per subdirectory action. Everything about an
// action that differs from the others is here; the shape every action shares
// is in main.go's templates.

// input is an action input beyond the common set. Flag says how run.sh turns
// it into argv (gen writes the mapping into action-lib/commands.sh):
//
//	"--name"      a flag with the value, when the value is not empty
//	"bool:--name" the flag alone, when the value is "true"
//	"lines"       one positional argument per non-empty line
//	"lines:--name" the flag repeated, once per non-empty line, each with that line
//	""            not passed to the CLI (read by a script)
type input struct {
	Name, Desc, Default, Flag string
}

type action struct {
	// Name is the action's key: its case in commands.sh and its docs page.
	Name string
	// Dir is where it lives, used as Vulnetix/cli/<Dir>@v4. Empty means Name.
	Dir   string
	Title string
	Desc  string
	// FlagHost is the command a test checks flags against when Command takes its
	// subcommand from an input.
	FlagHost []string
	// Command is the argv after `vulnetix`; empty for setup.
	Command []string
	// Path adds --path <path input>.
	Path bool
	// Scan marks a scan-family command, which publishes to GitHub itself
	// through --github-publish (and so needs no publish step).
	Scan bool
	// CodeScanning and DependencyGraph are the GitHub publish targets the
	// action offers.
	CodeScanning, DependencyGraph bool
	// SBOM attests with actions/attest and sbom-path rather than build
	// provenance.
	SBOM   bool
	Inputs []input
	// Script replaces run.sh's generic command (config, publish).
	Script string
	// Setup installs only.
	Setup bool
	Extra string // extra prose for the docs page
}

// vexInputs is the vex input of the scan actions: VEX documents, paths or https
// URLs, one per line, each passed to the scan as --vex.
var vexInputs = []input{{Name: "vex", Desc: "VEX documents to apply before the gates, one path, directory or https URL per line (passed as --vex). VexSource documents under .vulnetix/config apply too", Flag: "lines:--vex"}}

// scanGatePlainInputs are the gate and path inputs of every scan command. They
// are comma-separated or one per line, so a value with a space stays one value,
// which args cannot do.
var scanGatePlainInputs = []input{
	{Name: "fail-on", Desc: "Exit 1 when any of these hold, one per line or comma-separated: low, medium, high, critical, kev, malware, unpinned, exploit=poc and the rest of --fail-on", Flag: "lines:--fail-on"},
	{Name: "exclude", Desc: "Paths to skip, one glob per line (passed as --exclude)", Flag: "lines:--exclude"},
}

// scanGateInputs adds the external rule packs of the commands that run rules.
var scanGateInputs = append(append([]input{}, scanGatePlainInputs...),
	input{Name: "rules", Desc: "External rule repositories in org/repo form, one per line (passed as --rule)", Flag: "lines:--rule"})

// ruleScanInputs are the inputs of the rule-driven scanners.
var ruleScanInputs = append(append([]input{}, vexInputs...), scanGateInputs...)

// bomAuthoringInputs are the identity and customisation inputs of the three
// generators. They exist as inputs rather than `args` because an author is
// written as `Name <email>` and a licence as an expression, both with spaces,
// and `args` is split on whitespace. Everything else (--bom-serial,
// --component-*) goes through `args` or the VULNETIX_BOM_* environment.
var bomAuthoringInputs = []input{
	{Name: "bom-manufacturer", Desc: "Organisation that created the BOM (metadata.manufacturer); defaults to the repository owner", Flag: "--bom-manufacturer"},
	{Name: "bom-author", Desc: "Author of the document as Name <email>, one per line (metadata.authors; passed as --bom-author)", Flag: "lines:--bom-author"},
	{Name: "bom-supplier", Desc: "Supplier of the component the BOM describes (metadata.supplier)", Flag: "--bom-supplier"},
	{Name: "bom-license", Desc: "Licence of the document itself, an SPDX id or expression (metadata.licenses)", Flag: "--bom-license"},
	{Name: "bom-property", Desc: "Document property as name=value, one per line (metadata.properties; passed as --bom-property)", Flag: "lines:--bom-property"},
	{Name: "bom-overlay", Desc: "CycloneDX JSON fragments merged into the document before validation, one path per line (passed as --bom-overlay)", Flag: "lines:--bom-overlay"},
}

// signInput is the --sign toggle of the three generators.
var signInput = input{Name: "sign", Desc: "Sign the document with the runner's OIDC identity (needs id-token: write): true or false", Default: "false", Flag: "bool:--sign"}

var actions = []action{
	{Name: "setup", Title: "Setup", Desc: "Install the Vulnetix CLI and put it on PATH for later steps.", Setup: true},
	{Name: "sca", Title: "SCA", Desc: "Scan dependencies for known vulnerabilities (vulnetix sca).",
		Command: []string{"sca"}, Path: true, Scan: true, CodeScanning: true, DependencyGraph: true,
		Inputs: append(append(append([]input{}, vexInputs...), scanGatePlainInputs...),
			input{Name: "package-manager", Desc: "Scan only these package managers, comma-separated. Prefer the sca/<manager> action", Flag: "--package-manager"},
			input{Name: "not-package-manager", Desc: "Scan everything except these package managers, comma-separated: the rest step beside sca/<manager> jobs", Flag: "--not-package-manager"})},
	{Name: "sast", Title: "SAST", Desc: "Scan source code with the SAST rules (vulnetix sast).",
		Command: []string{"sast"}, Path: true, Scan: true, CodeScanning: true,
		Inputs: append(append([]input{}, ruleScanInputs...),
			input{Name: "language", Desc: "Scan only these languages, comma-separated. Prefer the sast/<language> action", Flag: "--language"},
			input{Name: "not-language", Desc: "Scan everything except these languages, comma-separated: the rest step beside sast/<language> jobs", Flag: "--not-language"})},
	{Name: "secrets", Title: "Secrets", Desc: "Scan for committed secrets (vulnetix secrets).",
		Command: []string{"secrets"}, Path: true, Scan: true, CodeScanning: true, Inputs: ruleScanInputs},
	{Name: "iac", Title: "IaC", Desc: "Scan infrastructure as code (vulnetix iac).",
		Command: []string{"iac"}, Path: true, Scan: true, CodeScanning: true, Inputs: ruleScanInputs},
	{Name: "containers", Title: "Containers", Desc: "Scan container files and images (vulnetix containers).",
		Command: []string{"containers"}, Path: true, Scan: true, CodeScanning: true, Inputs: ruleScanInputs},
	{Name: "license", Title: "License", Desc: "Evaluate dependency licences against the licence policy (vulnetix license).",
		Command: []string{"license"}, Path: true, CodeScanning: true},
	{Name: "malscan", Title: "Malscan", Desc: "Scan installed dependencies for malicious code (vulnetix malscan).",
		Command: []string{"malscan"}, Path: true},
	{Name: "analyze", Title: "Analyze", Desc: "Report the repository's tech stack, ownership and risk (vulnetix analyze).",
		Command: []string{"analyze"}, Path: true},
	{Name: "cbom", Title: "CBOM", Desc: "Write a cryptography bill of materials (vulnetix cbom).",
		Command: []string{"cbom"}, Path: true, Inputs: append([]input{signInput}, bomAuthoringInputs...)},
	{Name: "aibom", Title: "AIBOM", Desc: "Write an AI bill of materials (vulnetix aibom).",
		Command: []string{"aibom"}, Path: true, Inputs: append([]input{signInput}, bomAuthoringInputs...)},
	{Name: "sbom", Title: "SBOM", Desc: "Write a CycloneDX SBOM (vulnetix cdx).",
		Command: []string{"cdx"}, Path: true, DependencyGraph: true, SBOM: true,
		Inputs: append([]input{signInput}, bomAuthoringInputs...)},
	{Name: "upload", Title: "Upload", Desc: "Upload one artifact file to Vulnetix (vulnetix upload).",
		Command: []string{"upload", "--json"},
		Inputs: []input{
			{Name: "upload-file", Desc: "Path to the artifact file to upload", Flag: "--file"},
			{Name: "upload-format", Desc: "Override the detected format (cyclonedx, spdx, sarif, openvex, csaf_vex)", Flag: "--format"},
		}},
	{Name: "gha-upload", Title: "GHA upload", Desc: "Upload every artifact of this workflow run to Vulnetix (vulnetix gha upload).",
		Command: []string{"gha", "upload", "--json"}},
	{Name: "tea-release", Title: "TEA release", Desc: "Publish a product release and its artifacts to the Transparency Exchange API (vulnetix tea release).",
		Command: []string{"tea", "release"},
		Inputs: []input{
			{Name: "tea-files", Desc: "Files to publish, one path or glob per line", Flag: "lines"},
			{Name: "tea-product", Desc: "TEA product name; defaults to the GitHub repository", Flag: "--product"},
			{Name: "tea-purl", Desc: "Package URL identifying the TEA product", Flag: "--purl"},
			{Name: "tea-version", Desc: "TEA release version; defaults to the tag on a tag run", Flag: "--version"},
			{Name: "tea-date", Desc: "TEA release date (RFC3339)", Flag: "--date"},
			{Name: "tea-pre-release", Desc: "Mark the release as a pre-release: true or false", Default: "false", Flag: "bool:--pre-release"},
			{Name: "tea-visibility", Desc: "Visibility once published: private, shared or public. Public cannot be undone", Flag: "--visibility"},
			{Name: "tea-dry-run", Desc: "Print what would be published and exit: true or false", Default: "false", Flag: "bool:--dry-run"},
			{Name: "tea-channels", Desc: "Install channels with no single file to fetch, as name=...,url=...,purl=..., one per line (passed as --channel)", Flag: "lines:--channel"},
			{Name: "tea-auto-version", Desc: "Outside a tag run, derive the version: git describe", Flag: "--auto-version"},
			{Name: "tea-checksums-from-release", Desc: "On a tag run, take the checksums from the GitHub release: true or false", Default: "false", Flag: "bool:--checksums-from-release"},
		}},
	{Name: "config-plan", Title: "Config plan", Desc: "Plan Platform IaC documents against the config engine and comment the plan on the pull request (vulnetix config plan). Authenticate with org-id and the api-key of an owner, an admin or an admin service account, or with api-token.",
		Script: "config", Inputs: configInputs(true)},
	{Name: "config-apply", Title: "Config apply", Desc: "Apply Platform IaC documents through the config engine (vulnetix config apply). Authenticate with org-id and the api-key of an owner, an admin or an admin service account, or with api-token.",
		Script: "config", Inputs: configInputs(false)},
	{Name: "attest", Title: "Attest verify", Desc: "Verify an artefact's signature, identity and provenance (vulnetix attest verify).",
		Command: []string{"attest", "verify"},
		Inputs:  []input{{Name: "subject", Desc: "The artefact to verify", Flag: "lines"}}},
	{Name: "jail", Title: "Jail", Desc: "Assess the repository against the organisation's jail policy (vulnetix jail).",
		Command: []string{"jail"}, Path: true},
	{Name: "vex", Title: "VEX", Desc: "Work with VEX documents: validate, list, merge or apply (vulnetix vex <vex-command>).",
		Command: []string{"vex"},
		Inputs:  []input{{Name: "vex-command", Desc: "The vex subcommand: validate, ls, merge or apply", Default: "validate", Flag: "lines"}}},
	{Name: "github-publish", Title: "GitHub publish", Desc: "Publish existing results into GitHub: code scanning, the dependency graph, release assets and security campaigns (vulnetix gha publish).",
		Script: "publish", CodeScanning: true, DependencyGraph: true,
		Inputs: []input{
			{Name: "sarif", Desc: "SARIF files to upload to code scanning, one per line (default: every .vulnetix/*.sarif under path)"},
			{Name: "sbom", Desc: "CycloneDX SBOM to submit to the dependency graph (default: .vulnetix/sbom.cdx.json under path)"},
			{Name: "campaigns", Desc: "Mirror Vulnetix remediation campaigns (Pro) as GitHub security campaigns (vulnetix gha publish campaigns). Run it as an organization-level scheduled job after code scanning has published: true or false", Default: "false"},
			{Name: "campaigns-org", Desc: "GitHub organization that owns the campaigns; defaults to the repository owner"},
			{Name: "campaigns-github-token", Desc: "GitHub token of an organization owner or security manager (a PAT or GitHub App token); the workflow token cannot manage campaigns. Defaults to github-token"},
			{Name: "campaigns-recreate", Desc: "Close and recreate a GitHub campaign whose Vulnetix cohort changed, because GitHub cannot change a campaign's alerts: true or false", Default: "false"},
			{Name: "campaigns-dry-run", Desc: "Print what would change and write nothing: true or false", Default: "false"},
		}},
}

func configInputs(plan bool) []input {
	in := []input{
		{Name: "config-path", Desc: "Config documents, one file or directory per line (default: .vulnetix/config)"},
		{Name: "config-manager", Desc: "Manager the documents are declared by (default: gitops:<owner/repo> of this repository)"},
		{Name: "config-prune", Desc: "Delete objects this manager owns that the documents no longer declare: true or false", Default: "false"},
	}
	if plan {
		in = append(in, input{Name: "validate-only", Desc: "Validate the documents offline (vulnetix config validate) instead of planning: true or false", Default: "false"})
	}
	return in
}

// Third-party actions, pinned by commit SHA. Bump deliberately.
const (
	uploadArtifact = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2"
	attestBuild    = "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2"
	attestSBOM     = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2"
	cosignInstall  = "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2"
)
