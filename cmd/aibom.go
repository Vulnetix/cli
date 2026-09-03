package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/aibom"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var aibomCmd = &cobra.Command{
	Use:   "aibom [path]",
	Short: "Discover AI coding agents and AI usage, and emit a CycloneDX AIBOM",
	Long: `Discover evidence of AI coding agents/assistants and AI usage in a project
and produce an AI Bill of Materials (AIBOM) in CycloneDX format.

Detection passes, all driven by a maintainable catalog:
  • environment — known AI tool / provider env-var NAMES (values are never read)
  • filesystem  — tool config dirs, instructions, ignore files, skills, hooks,
                  plugins, steering, memory, prompts, agents, commands and
                  marketplace manifests
  • source code — AI SDK usage per language (OpenAI, Anthropic, Bedrock, Azure,
                  Vertex, LiteLLM, LangChain, …) and the model-name literals
                  passed to them. Model names are extracted by anchoring on the
                  SDK parameter (model=, modelId=, deployment_name=), so future
                  / unknown model names are still captured.
  • IaC         — Kubernetes manifests (incl. KServe / Kubeflow / KubeRay CRDs),
                  docker-compose files and Dockerfiles: AI serving runtimes
                  (vLLM, TGI, Triton, Ollama, …), agent platforms, vector
                  databases, training/eval frameworks, declared model
                  identities, model-artifact volumes and GPU requests. Values
                  that cannot be verified from the file (templated Helm values,
                  secret-referenced envs, non-semver image tags) are either
                  dropped or reported with an explicit confidence gap — never
                  guessed.

The catalog is embedded and can be extended or replaced at runtime with
--catalog. No source content is ever uploaded.

The CycloneDX AIBOM is always written to .vulnetix/ai-bom.cdx.json (override the
path with --output-file). The terminal output format is set by -o.

Detected components are tracked in .vulnetix/memory.yaml. A component that
disappears from a later scan is marked resolved and attested in
.vulnetix/vex-aibom.openvex.json. Pass --disable-memory to turn this off.

Examples:
  vulnetix aibom                                  # pretty summary; writes .vulnetix/ai-bom.cdx.json
  vulnetix aibom ./myproject -o json              # print detections as JSON
  vulnetix aibom -o cyclonedx-json                # print CycloneDX to stdout (still saved to file)
  vulnetix aibom --output-file build/aibom.json   # write the AIBOM to a custom path
  vulnetix aibom --no-env --no-source             # filesystem evidence only
  vulnetix aibom --catalog ./extra-rules.json     # extend the builtin catalog`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAIBOM,
}

func init() {
	aibomCmd.Flags().String("path", ".", "Directory to scan")
	aibomCmd.Flags().Int("depth", 25, "Maximum recursion depth for file discovery")
	aibomCmd.Flags().StringArray("ignore", nil, "Exclude paths matching glob pattern (repeatable)")
	aibomCmd.Flags().StringP("output", "o", "pretty", "Terminal output format: pretty (alias: table), json, cyclonedx-json")
	aibomCmd.Flags().String("output-file", "", "Path to write the CycloneDX AIBOM (default: <path>/.vulnetix/ai-bom.cdx.json)")
	aibomCmd.Flags().String("spec-version", "1.7", "CycloneDX spec version: 1.6 or 1.7")
	aibomCmd.Flags().String("catalog", "", "Path to a catalog file to merge over (or replace) the builtin catalog")
	aibomCmd.Flags().Bool("no-builtin-catalog", false, "Do not load the embedded catalog (use only --catalog)")
	aibomCmd.Flags().Bool("no-env", false, "Skip the environment-variable detection pass")
	aibomCmd.Flags().Bool("include-home", false, "Also probe the user's home directory for tool config dirs")
	aibomCmd.Flags().Bool("no-source", false, "Skip the source-code SDK / model detection pass")
	aibomCmd.Flags().Bool("no-commits", false, "Skip the git commit-history detection pass")
	aibomCmd.Flags().Bool("no-iac", false, "Skip the IaC (Kubernetes/compose/Dockerfile) infrastructure detection pass")
	aibomCmd.Flags().Int("commit-scan-max", 2000, "Maximum number of commits (from HEAD) the commit-history pass inspects")
	aibomCmd.Flags().Bool("no-upload", false, "Do not submit the AIBOM to Vulnetix (it is submitted automatically when authenticated)")
	aibomCmd.Flags().Bool("aibom-include-ignored", false, "Include files matched by .gitignore (default: gitignored paths are skipped)")
	rootCmd.AddCommand(aibomCmd)
}

func runAIBOM(cmd *cobra.Command, args []string) error {
	rootPath, _ := cmd.Flags().GetString("path")
	if len(args) == 1 && args[0] != "" {
		rootPath = args[0]
	}
	depth, _ := cmd.Flags().GetInt("depth")
	ignore, _ := cmd.Flags().GetStringArray("ignore")
	outputFmt, _ := cmd.Flags().GetString("output")
	outputFile, _ := cmd.Flags().GetString("output-file")
	specVersion, _ := cmd.Flags().GetString("spec-version")
	catalogPath, _ := cmd.Flags().GetString("catalog")
	noBuiltin, _ := cmd.Flags().GetBool("no-builtin-catalog")
	noEnv, _ := cmd.Flags().GetBool("no-env")
	includeHome, _ := cmd.Flags().GetBool("include-home")
	noSource, _ := cmd.Flags().GetBool("no-source")
	noCommits, _ := cmd.Flags().GetBool("no-commits")
	noIaC, _ := cmd.Flags().GetBool("no-iac")
	commitMax, _ := cmd.Flags().GetInt("commit-scan-max")
	noUpload, _ := cmd.Flags().GetBool("no-upload")
	includeIgnored, _ := cmd.Flags().GetBool("aibom-include-ignored")

	switch outputFmt {
	case "pretty", "table", "json", "cyclonedx-json":
	default:
		return fmt.Errorf("--output must be one of: pretty (alias: table), json, cyclonedx-json")
	}
	switch specVersion {
	case "1.6", "1.7":
	default:
		return fmt.Errorf("--spec-version must be one of: 1.6, 1.7")
	}

	// Detection, memory reconcile, CycloneDX build and the (authenticated,
	// best-effort) submission all live in runAIBOMPass — the same entry point
	// `scan` uses, so the two never drift.
	pass, err := runAIBOMPass(AIBOMPassOptions{
		RootPath:         rootPath,
		Depth:            depth,
		Ignore:           ignore,
		CatalogPath:      catalogPath,
		NoBuiltinCatalog: noBuiltin,
		Passes:           aibomPasses{Env: !noEnv, Source: !noSource, Commits: !noCommits, Iac: !noIaC},
		IncludeHome:      includeHome,
		CommitMax:        commitMax,
		RespectGitignore: !includeIgnored,
		SpecVersion:      specVersion,
		Upload:           !noUpload,
	})
	if err != nil {
		return err
	}
	det, bomData := pass.Detections, pass.BOM

	// Always persist the CycloneDX AIBOM to a file. Default location is
	// <path>/.vulnetix/ai-bom.cdx.json; --output-file overrides the path.
	warnOutputExtension(outputFile, ".cdx.json")
	outFile := outputFile
	if outFile == "" {
		outFile = filepath.Join(rootPath, ".vulnetix", "ai-bom.cdx.json")
	}
	if err := writeAIBOMFile(outFile, bomData); err != nil {
		return err
	}

	// Terminal rendering (the file above is written regardless of format).
	switch outputFmt {
	case "json":
		data, err := json.MarshalIndent(det, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(data))
		return nil
	case "cyclonedx-json":
		fmt.Fprintln(os.Stdout, string(bomData))
		return nil
	default: // pretty / table
		if err := renderAIBOMTable(cmd, det); err != nil {
			return err
		}
		// Say what was withheld. A quietly smaller inventory is indistinguishable
		// from a scan that found less.
		if pass.Suppressed > 0 {
			fmt.Fprintf(os.Stdout, "\n%d AI component(s) skipped by ignore rules (vulnetix ignore list).\n", pass.Suppressed)
		}
		return nil
	}
}

// aibomFindingRecords converts an AIBOM detection result into memory records.
//
// An AI bill of materials is pure inventory — nothing here is a defect — so
// every record carries memory.StatusInventory. That keeps them out of the
// open-findings queries that drive `vulnetix triage` and the dashboard, while
// still letting a component that leaves the codebase be auto-resolved and
// attested with VEX.
func aibomFindingRecords(det cyclonedx.AIDetections) map[string]memory.FindingRecord {
	out := make(map[string]memory.FindingRecord,
		len(det.Tools)+len(det.Libraries)+len(det.Models))

	firstEvidenceLocation := func(ev []cyclonedx.AIEvidence) []memory.Location {
		for _, e := range ev {
			if e.Locator != "" {
				return []memory.Location{{File: e.Locator, Snippet: e.Snippet}}
			}
		}
		return nil
	}

	// No Aliases anywhere below: the synthetic key is what reaches the OpenVEX
	// statement, and it is the only unambiguous name (two SDKs can expose the
	// same model). The human-readable name still rides in Package.
	for _, t := range det.Tools {
		id := t.ID
		if id == "" {
			id = t.Name
		}
		out["AIBOM:tool:"+id] = memory.FindingRecord{
			Package:   t.Name,
			Severity:  "info",
			Status:    memory.StatusInventory,
			Source:    "vulnetix-aibom",
			Locations: firstEvidenceLocation(t.Evidence),
		}
	}

	for _, l := range det.Libraries {
		id := l.ID
		if id == "" {
			id = l.Name
		}
		out["AIBOM:library:"+id] = memory.FindingRecord{
			Package:   l.Name,
			Severity:  "info",
			Status:    memory.StatusInventory,
			Source:    "vulnetix-aibom",
			Locations: firstEvidenceLocation(l.Evidence),
		}
	}

	for _, m := range det.Models {
		out[fmt.Sprintf("AIBOM:model:%s:%s", m.Name, m.ViaSDK)] = memory.FindingRecord{
			Package:   m.Name,
			Severity:  "info",
			Status:    memory.StatusInventory,
			Source:    "vulnetix-aibom",
			Locations: firstEvidenceLocation(m.Evidence),
		}
	}

	for _, inf := range det.Infrastructure {
		out["AIBOM:infra:"+inf.ID] = memory.FindingRecord{
			Package:   inf.Name,
			Severity:  "info",
			Status:    memory.StatusInventory,
			Source:    "vulnetix-aibom",
			Locations: firstEvidenceLocation(inf.Evidence),
		}
	}

	for _, d := range det.Data {
		out[fmt.Sprintf("AIBOM:data:%s:%s", d.Kind, d.Name)] = memory.FindingRecord{
			Package:   d.Name,
			Severity:  "info",
			Status:    memory.StatusInventory,
			Source:    "vulnetix-aibom",
			Locations: firstEvidenceLocation(d.Evidence),
		}
	}

	return out
}

// aibomPasses records which AIBOM detection passes ran. The filesystem pass
// always runs; env, source and commit-history are individually disableable.
type aibomPasses struct {
	Env     bool
	Source  bool
	Commits bool
	Iac     bool
}

// aibomReconcileScope maps the passes that ran onto the finding-ID prefixes that
// may participate in reconciliation. Tools are surfaced by the env, filesystem
// and commit-history passes together — disabling either optional one could hide
// a tool that is still very much in use — so both must have run before a tool
// record may be resolved. Libraries and models come solely from the source pass.
func aibomReconcileScope(p aibomPasses) []string {
	var prefixes []string
	if p.Env && p.Commits {
		prefixes = append(prefixes, "AIBOM:tool:")
	}
	if p.Source {
		prefixes = append(prefixes, "AIBOM:library:")
	}
	// Models are produced by both the source and IaC passes, so resolving a
	// model record requires both to have run.
	if p.Source && p.Iac {
		prefixes = append(prefixes, "AIBOM:model:")
	}
	if p.Iac {
		prefixes = append(prefixes, "AIBOM:infra:", "AIBOM:data:")
	}
	// An empty prefix list means "reconcile everything"; when no pass qualifies
	// we must reconcile nothing, so return a prefix that matches no record.
	if len(prefixes) == 0 {
		return []string{"\x00none"}
	}
	return prefixes
}

// reconcileAIBOMMemory records the detected AI inventory and resolves anything
// that has left the codebase since the last run, attesting resolutions in
// .vulnetix/vex-aibom.openvex.json.
//
// It must run even when the current detection is empty — that is precisely the
// case where every prior component should be resolved.
func reconcileAIBOMMemory(rootPath string, gitCtx *gitctx.GitContext, det cyclonedx.AIDetections, passes aibomPasses) {
	if disableMemory {
		return
	}
	changes := reconcileStandalone(rootPath, gitCtx, memory.ToolAIBOM,
		aibomFindingRecords(det), reconcileOptions{
			Mode:             memory.ResolveOnAbsence,
			RegressionStatus: memory.StatusInventory,
			IDPrefixes:       aibomReconcileScope(passes),
		})
	if vexPath, err := writeToolOpenVEX(rootPath, memory.ToolAIBOM, changes); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not write AIBOM OpenVEX: %v\n", err)
	} else if vexPath != "" && !silent {
		fmt.Fprintf(os.Stderr, "  VEX: %s\n", vexPath)
	}
}

// AIBOMPassOptions is the AIBOM owner's entry contract. The `aibom` command
// builds it from its flags; `scan` builds it with the pass defaults. Both go
// through runAIBOMPass, so there is one definition of "detect AI usage".
type AIBOMPassOptions struct {
	RootPath         string
	Depth            int
	Ignore           []string
	CatalogPath      string
	NoBuiltinCatalog bool
	// Passes selects which detection passes run; the zero value runs none, so
	// callers must be explicit.
	Passes           aibomPasses
	IncludeHome      bool
	CommitMax        int
	RespectGitignore bool
	// SpecVersion defaults to 1.7.
	SpecVersion string
	// Upload submits the AIBOM to the backend when authenticated.
	Upload bool
	GitCtx *gitctx.GitContext
}

// AIBOMPassResult carries what the caller renders or writes.
type AIBOMPassResult struct {
	Detections  cyclonedx.AIDetections
	BOM         []byte
	SpecVersion string
	// Suppressed counts AI components dropped by an active ignore rule. They are
	// skipped outright rather than labelled: an ignored AI component is also
	// never shown in the console.
	Suppressed int
}

// runAIBOMPass detects AI usage, reconciles it against local memory, builds the
// CycloneDX AIBOM and (optionally) submits it. It writes no file and prints
// nothing: the caller decides those.
//
// Memory reconciliation runs even when nothing is detected — an empty detection
// is exactly when previously-recorded components must be resolved — but an empty
// AIBOM is never uploaded.
func runAIBOMPass(opts AIBOMPassOptions) (*AIBOMPassResult, error) {
	rootPath := opts.RootPath
	if rootPath == "" {
		rootPath = "."
	}
	specVersion := opts.SpecVersion
	if specVersion == "" {
		specVersion = "1.7"
	}
	cat, err := aibom.LoadCatalog(opts.CatalogPath, opts.NoBuiltinCatalog)
	if err != nil {
		return nil, err
	}
	compiled, err := cat.Compile()
	if err != nil {
		return nil, fmt.Errorf("invalid AIBOM catalog: %w", err)
	}
	det, err := aibom.Detect(aibom.Options{
		Root:             rootPath,
		MaxDepth:         opts.Depth,
		Ignore:           opts.Ignore,
		ScanEnv:          opts.Passes.Env,
		IncludeHome:      opts.IncludeHome,
		ScanSource:       opts.Passes.Source,
		ScanCommits:      opts.Passes.Commits,
		ScanIaC:          opts.Passes.Iac,
		CommitMax:        opts.CommitMax,
		Catalog:          compiled,
		RespectGitignore: opts.RespectGitignore,
	})
	if err != nil {
		return nil, err
	}

	gitCtx := opts.GitCtx
	if gitCtx == nil {
		gitCtx = gitctx.Collect(rootPath)
	}
	// Drop ignored AI components before anything else consumes the detection, so
	// they reach neither memory.yaml, the emitted CycloneDX nor the backend.
	suppressed := filterSuppressedAIDetections(&det, scanSuppressionSetLoad(rootPath, gitCtx))

	// Memory always lives under the resolved scan root, never the process CWD.
	reconcileAIBOMMemory(rootPath, gitCtx, det, opts.Passes)

	// An AI inventory is found by observing source, config and commit history
	// rather than by resolving a declared dependency set, which is what the
	// spec's discovery phase describes; design applies too, because it is read
	// out of source rather than out of a built artefact.
	authorship := cdx.Authoring(cyclonedx.ToolAIBOM,
		cdx.ResolveManufacturer(cdx.ManufacturerSources{Git: gitCtx, OrgID: orgID}),
		cdx.PhaseDesign, cdx.PhaseDiscovery)

	bomData, err := cyclonedx.BuildAIBOM(det, cyclonedx.AIBOMOptions{
		SpecVersion: specVersion,
		Authorship:  &authorship,
		Project:     aibomProject(gitCtx, gitctx.CollectSystemInfo()),
	})
	if err != nil {
		return nil, err
	}

	if opts.Upload && aibomDetectionCount(det) > 0 {
		uploadAIBOM(specVersion, det, bomData, gitCtx)
	}
	return &AIBOMPassResult{Detections: det, BOM: bomData, SpecVersion: specVersion, Suppressed: suppressed}, nil
}

// aibomDetectionCount is the "did we find anything" test used to avoid uploading
// empty snapshots.
func aibomDetectionCount(det cyclonedx.AIDetections) int {
	return len(det.Tools) + len(det.Libraries) + len(det.Models) +
		len(det.Infrastructure) + len(det.Data)
}

// detectAndUploadAIBOM captures the AI inventory alongside a scan: every pass,
// upload when authenticated, no file written and no output. Best-effort — any
// error is swallowed so it can never affect the scan's exit code.
func detectAndUploadAIBOM(rootPath string, gitCtx *gitctx.GitContext) {
	_, _ = runAIBOMPass(AIBOMPassOptions{
		RootPath: rootPath,
		Passes:   aibomPasses{Env: true, Source: true, Commits: true, Iac: true},
		Upload:   true,
		GitCtx:   gitCtx,
	})
}

// aibomProject maps the CLI's git/system context to the shared AIBOMProject the
// vdb-cyclonedx builder consumes for metadata.component and git/env properties.
func aibomProject(g *gitctx.GitContext, sys *gitctx.SystemInfo) *cyclonedx.AIBOMProject {
	p := &cyclonedx.AIBOMProject{}
	if g != nil {
		p.Name = cdx.GitProjectName(g)
		p.Version = cdx.GitProjectVersion(g)
		p.Branch = g.CurrentBranch
		p.Commit = g.CurrentCommit
		p.CommitTimestamp = g.HeadCommitTimestamp
		p.CommitMessage = g.HeadCommitMessage
		p.CommitAuthor = g.HeadCommitAuthor
		p.CommitEmail = g.HeadCommitEmail
		p.Tags = g.HeadTags
		p.IsDirty = g.IsDirty
		p.IsWorktree = g.IsWorktree
		p.RepoRoot = g.RepoRootPath
		p.RemoteURLs = g.RemoteURLs
		for _, c := range g.RecentCommitters {
			p.RecentCommitters = append(p.RecentCommitters, cyclonedx.AIBOMContact{Name: c.Name, Email: c.Email})
		}
	}
	if sys != nil {
		p.System = &cyclonedx.AIBOMSystem{
			Hostname: sys.Hostname, Shell: sys.Shell, OS: sys.OS, Arch: sys.Arch, Username: sys.Username,
		}
	}
	return p
}

// uploadAIBOM submits the AIBOM to POST /v2/cli.ai-bom. It is best-effort:
// community/unauthenticated callers are skipped (the server does not persist
// their data — see the community no-persist gate) and any error is non-fatal.
func uploadAIBOM(specVersion string, det cyclonedx.AIDetections, bomData []byte, git *gitctx.GitContext) {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		return
	}
	// Build the client directly from the resolved credentials. We must NOT use
	// newCliClient() here: it reads the package global vdbCreds, which the aibom
	// command never populates, so it would silently fall back to community creds
	// and the server would refuse to persist (community no-persist gate).
	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	if client.HTTPClient != nil {
		client.HTTPClient.Timeout = 180 * time.Second
	}
	detJSON, err := json.Marshal(det)
	if err != nil {
		return
	}
	env := envForCliWithGit(git)
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "vulnetix-aibom",
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}
	resp, err := client.CliAIBOM(env, vdb.CliAIBOMRequest{
		SpecVersion:    specVersion,
		CatalogVersion: det.CatalogVersion,
		BomJSON:        string(bomData),
		Detections:     detJSON,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "aibom: upload failed: %v\n", err)
		}
		return
	}
	if resp != nil && resp.Data.Aibom != nil && resp.Data.Aibom.URL != "" && !silent {
		fmt.Fprintf(os.Stderr, "AI Inventory: %s\n", resp.Data.Aibom.URL)
	}
}

// writeAIBOMFile writes the CycloneDX AIBOM to path, creating the parent
// directory (e.g. .vulnetix/) when needed.
func writeAIBOMFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "Wrote AIBOM to %s\n", path)
	}
	return nil
}

func renderAIBOMTable(cmd *cobra.Command, det cyclonedx.AIDetections) error {
	dctx := display.FromCommand(cmd)
	if dctx.IsJSON() {
		data, err := json.MarshalIndent(det, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	t := display.NewTerminal()
	var b strings.Builder
	b.WriteString(display.Header(t, "AI Bill of Materials"))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  Catalog %s — %d tool(s), %d SDK(s), %d model(s), %d infrastructure, %d data\n\n",
		det.CatalogVersion, len(det.Tools), len(det.Libraries), len(det.Models),
		len(det.Infrastructure), len(det.Data))

	if len(det.Tools) > 0 {
		b.WriteString(display.Header(t, "AI Coding Agents & Services"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Tools))
		for _, x := range det.Tools {
			rows = append(rows, []string{x.Name, x.Vendor, x.Type, x.Confidence, strconv.Itoa(len(x.Evidence))})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Tool"}, {Header: "Vendor"}, {Header: "Type"},
			{Header: "Confidence"}, {Header: "Evidence", Align: display.AlignRight},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(det.Libraries) > 0 {
		b.WriteString(display.Header(t, "AI SDKs / Frameworks"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Libraries))
		for _, x := range det.Libraries {
			rows = append(rows, []string{x.Name, x.Provider, strings.Join(x.Languages, ", "), x.Confidence})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Library"}, {Header: "Provider"}, {Header: "Languages"}, {Header: "Confidence"},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(det.Models) > 0 {
		b.WriteString(display.Header(t, "Models"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Models))
		for _, x := range det.Models {
			rows = append(rows, []string{x.Name, x.Provider, x.Family, x.ViaSDK, strconv.Itoa(x.Occurrences), x.Confidence})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Model"}, {Header: "Provider"}, {Header: "Family"}, {Header: "Via SDK"},
			{Header: "Uses", Align: display.AlignRight}, {Header: "Confidence"},
		}, rows))
		b.WriteString("\n")
	}

	if len(det.Infrastructure) > 0 {
		b.WriteString(display.Header(t, "AI Infrastructure"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Infrastructure))
		for _, x := range det.Infrastructure {
			verified := "verified"
			if x.ConfidenceGap {
				verified = "⚠ " + x.GapReason
			}
			version := x.Version
			if version == "" && x.RawTag != "" {
				version = "(" + x.RawTag + ")"
			}
			rows = append(rows, []string{x.Name, x.Category, version, verified})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Component"}, {Header: "Category"}, {Header: "Version"}, {Header: "Verification"},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(det.Data) > 0 {
		b.WriteString(display.Header(t, "AI Data / Model Artifacts"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Data))
		for _, x := range det.Data {
			verified := "verified"
			if x.ConfidenceGap {
				verified = "⚠ " + x.GapReason
			}
			rows = append(rows, []string{x.Name, x.Kind, x.Source, x.MountPath, verified})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Artifact"}, {Header: "Kind"}, {Header: "Source"}, {Header: "Mount"}, {Header: "Verification"},
		}, rows))
		b.WriteString("\n")
	}

	if len(det.Tools) == 0 && len(det.Libraries) == 0 && len(det.Models) == 0 &&
		len(det.Infrastructure) == 0 && len(det.Data) == 0 {
		b.WriteString("  No AI coding agents or AI usage detected.\n")
	}

	fmt.Print(b.String())
	return nil
}
