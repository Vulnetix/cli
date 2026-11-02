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
//	""            not passed to the CLI (read by a script)
type input struct {
	Name, Desc, Default, Flag string
}

type action struct {
	Name  string
	Title string
	Desc  string
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

var actions = []action{
	{Name: "setup", Title: "Setup", Desc: "Install the Vulnetix CLI and put it on PATH for later steps.", Setup: true},
	{Name: "sca", Title: "SCA", Desc: "Scan dependencies for known vulnerabilities (vulnetix sca).",
		Command: []string{"sca"}, Path: true, Scan: true, CodeScanning: true, DependencyGraph: true},
	{Name: "sast", Title: "SAST", Desc: "Scan source code with the SAST rules (vulnetix sast).",
		Command: []string{"sast"}, Path: true, Scan: true, CodeScanning: true},
	{Name: "secrets", Title: "Secrets", Desc: "Scan for committed secrets (vulnetix secrets).",
		Command: []string{"secrets"}, Path: true, Scan: true, CodeScanning: true},
	{Name: "iac", Title: "IaC", Desc: "Scan infrastructure as code (vulnetix iac).",
		Command: []string{"iac"}, Path: true, Scan: true, CodeScanning: true},
	{Name: "containers", Title: "Containers", Desc: "Scan container files and images (vulnetix containers).",
		Command: []string{"containers"}, Path: true, Scan: true, CodeScanning: true},
	{Name: "license", Title: "License", Desc: "Evaluate dependency licences against the licence policy (vulnetix license).",
		Command: []string{"license"}, Path: true, CodeScanning: true},
	{Name: "malscan", Title: "Malscan", Desc: "Scan installed dependencies for malicious code (vulnetix malscan).",
		Command: []string{"malscan"}, Path: true},
	{Name: "analyze", Title: "Analyze", Desc: "Report the repository's tech stack, ownership and risk (vulnetix analyze).",
		Command: []string{"analyze"}, Path: true},
	{Name: "cbom", Title: "CBOM", Desc: "Write a cryptography bill of materials (vulnetix cbom).",
		Command: []string{"cbom"}, Path: true},
	{Name: "aibom", Title: "AIBOM", Desc: "Write an AI bill of materials (vulnetix aibom).",
		Command: []string{"aibom"}, Path: true},
	{Name: "sbom", Title: "SBOM", Desc: "Write a CycloneDX SBOM (vulnetix cdx).",
		Command: []string{"cdx"}, Path: true, DependencyGraph: true, SBOM: true,
		Inputs: []input{{Name: "sign", Desc: "Sign the SBOM with the runner's OIDC identity (needs id-token: write): true or false", Default: "false", Flag: "bool:--sign"}}},
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
		}},
	{Name: "config-plan", Title: "Config plan", Desc: "Plan Platform IaC documents against the config engine and comment the plan on the pull request (vulnetix config plan).",
		Script: "config", Inputs: configInputs(true)},
	{Name: "config-apply", Title: "Config apply", Desc: "Apply Platform IaC documents through the config engine (vulnetix config apply).",
		Script: "config", Inputs: configInputs(false)},
	{Name: "attest", Title: "Attest verify", Desc: "Verify an artefact's signature, identity and provenance (vulnetix attest verify).",
		Command: []string{"attest", "verify"},
		Inputs:  []input{{Name: "subject", Desc: "The artefact to verify", Flag: "lines"}}},
	{Name: "jail", Title: "Jail", Desc: "Assess the repository against the organisation's jail policy (vulnetix jail).",
		Command: []string{"jail"}, Path: true},
	{Name: "vex", Title: "VEX", Desc: "Work with VEX documents: validate, list, merge or apply (vulnetix vex <vex-command>).",
		Command: []string{"vex"},
		Inputs:  []input{{Name: "vex-command", Desc: "The vex subcommand: validate, ls, merge or apply", Default: "validate", Flag: "lines"}}},
	{Name: "github-publish", Title: "GitHub publish", Desc: "Publish existing results into GitHub: code scanning, the dependency graph and release assets (vulnetix gha publish).",
		Script: "publish", CodeScanning: true, DependencyGraph: true,
		Inputs: []input{
			{Name: "sarif", Desc: "SARIF files to upload to code scanning, one per line (default: every .vulnetix/*.sarif under path)"},
			{Name: "sbom", Desc: "CycloneDX SBOM to submit to the dependency graph (default: .vulnetix/sbom.cdx.json under path)"},
		}},
}

func configInputs(plan bool) []input {
	in := []input{
		{Name: "config-token", Desc: "Config management token (vmt_...). Passed to the CLI as VULNETIX_CONFIG_TOKEN, never on the command line"},
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
)
