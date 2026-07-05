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
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var aibomCmd = &cobra.Command{
	Use:   "aibom [path]",
	Short: "Discover AI coding agents and AI usage, and emit a CycloneDX AIBOM",
	Long: `Discover evidence of AI coding agents/assistants and AI usage in a project
and produce an AI Bill of Materials (AIBOM) in CycloneDX format.

Three detection passes, all driven by a maintainable catalog:
  • environment — known AI tool / provider env-var NAMES (values are never read)
  • filesystem  — tool config dirs, instructions, ignore files, skills, hooks,
                  plugins, steering, memory, prompts, agents, commands and
                  marketplace manifests
  • source code — AI SDK usage per language (OpenAI, Anthropic, Bedrock, Azure,
                  Vertex, LiteLLM, LangChain, …) and the model-name literals
                  passed to them. Model names are extracted by anchoring on the
                  SDK parameter (model=, modelId=, deployment_name=), so future
                  / unknown model names are still captured.

The catalog is embedded and can be extended or replaced at runtime with
--catalog. No source content is ever uploaded.

The CycloneDX AIBOM is always written to .vulnetix/ai-bom.cdx.json (override the
path with --output-file). The terminal output format is set by -o.

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
	aibomCmd.Flags().StringP("output", "o", "pretty", "Terminal output format: pretty, json, cyclonedx-json")
	aibomCmd.Flags().String("output-file", "", "Path to write the CycloneDX AIBOM (default: <path>/.vulnetix/ai-bom.cdx.json)")
	aibomCmd.Flags().String("spec-version", "1.7", "CycloneDX spec version: 1.6 or 1.7")
	aibomCmd.Flags().String("catalog", "", "Path to a catalog file to merge over (or replace) the builtin catalog")
	aibomCmd.Flags().Bool("no-builtin-catalog", false, "Do not load the embedded catalog (use only --catalog)")
	aibomCmd.Flags().Bool("no-env", false, "Skip the environment-variable detection pass")
	aibomCmd.Flags().Bool("include-home", false, "Also probe the user's home directory for tool config dirs")
	aibomCmd.Flags().Bool("no-source", false, "Skip the source-code SDK / model detection pass")
	aibomCmd.Flags().Bool("no-commits", false, "Skip the git commit-history detection pass")
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
	commitMax, _ := cmd.Flags().GetInt("commit-scan-max")
	noUpload, _ := cmd.Flags().GetBool("no-upload")
	includeIgnored, _ := cmd.Flags().GetBool("aibom-include-ignored")

	switch outputFmt {
	case "pretty", "table", "json", "cyclonedx-json":
	default:
		return fmt.Errorf("--output must be one of: pretty, json, cyclonedx-json")
	}
	switch specVersion {
	case "1.6", "1.7":
	default:
		return fmt.Errorf("--spec-version must be one of: 1.6, 1.7")
	}

	cat, err := aibom.LoadCatalog(catalogPath, noBuiltin)
	if err != nil {
		return err
	}
	compiled, err := cat.Compile()
	if err != nil {
		return fmt.Errorf("invalid AIBOM catalog: %w", err)
	}

	det, err := aibom.Detect(aibom.Options{
		Root:             rootPath,
		MaxDepth:         depth,
		Ignore:           ignore,
		ScanEnv:          !noEnv,
		IncludeHome:      includeHome,
		ScanSource:       !noSource,
		ScanCommits:      !noCommits,
		CommitMax:        commitMax,
		Catalog:          compiled,
		RespectGitignore: !includeIgnored,
	})
	if err != nil {
		return err
	}

	// Build the CycloneDX AIBOM once — used both for cyclonedx-json output and
	// for the backend submission below. The format (build + validate) lives in
	// the shared vdb-cyclonedx module so producers and consumers agree.
	gitCtx := gitctx.Collect(rootPath)
	bomData, err := cyclonedx.BuildAIBOM(det, cyclonedx.AIBOMOptions{
		SpecVersion: specVersion,
		ToolName:    "vulnetix-aibom",
		ToolVersion: version,
		Project:     aibomProject(gitCtx, gitctx.CollectSystemInfo()),
	})
	if err != nil {
		return err
	}

	// Auto-submit to the Vulnetix backend when authenticated. Best-effort: never
	// fails the command, and community/unauthenticated callers are skipped (the
	// server would not persist their data anyway).
	if !noUpload {
		uploadAIBOM(specVersion, det, bomData, gitCtx)
	}

	// Always persist the CycloneDX AIBOM to a file. Default location is
	// <path>/.vulnetix/ai-bom.cdx.json; --output-file overrides the path.
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
		return renderAIBOMTable(cmd, det)
	}
}

// detectAndUploadAIBOM runs the AIBOM detection passes against rootPath and
// submits the result to the backend. Best-effort: silent on any error and never
// affects the caller's exit code. Used by `scan` to capture AI coding-agent /
// SDK / model inventory alongside the rest of the scan. Skips the submission
// entirely when nothing AI-related is detected (no empty snapshots).
func detectAndUploadAIBOM(rootPath string, gitCtx *gitctx.GitContext) {
	if rootPath == "" {
		rootPath = "."
	}
	cat, err := aibom.LoadCatalog("", false)
	if err != nil {
		return
	}
	compiled, err := cat.Compile()
	if err != nil {
		return
	}
	det, err := aibom.Detect(aibom.Options{
		Root:        rootPath,
		ScanEnv:     true,
		ScanSource:  true,
		ScanCommits: true,
		Catalog:     compiled,
	})
	if err != nil || len(det.Tools)+len(det.Libraries)+len(det.Models) == 0 {
		return
	}
	data, err := cyclonedx.BuildAIBOM(det, cyclonedx.AIBOMOptions{
		SpecVersion: "1.7",
		ToolName:    "vulnetix-aibom",
		ToolVersion: version,
		Project:     aibomProject(gitCtx, gitctx.CollectSystemInfo()),
	})
	if err != nil {
		return
	}
	uploadAIBOM("1.7", det, data, gitCtx)
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
	fmt.Fprintf(&b, "  Catalog %s — %d tool(s), %d SDK(s), %d model(s)\n\n",
		det.CatalogVersion, len(det.Tools), len(det.Libraries), len(det.Models))

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

	if len(det.Tools) == 0 && len(det.Libraries) == 0 && len(det.Models) == 0 {
		b.WriteString("  No AI coding agents or AI usage detected.\n")
	}

	fmt.Print(b.String())
	return nil
}
