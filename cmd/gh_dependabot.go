package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/triage"
	"github.com/vulnetix/cli/v3/internal/tui"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var (
	triageProvider        string
	triageTool            string
	triageRepo            string
	triageAll             bool
	triageConcurrency     int
	triageFormat          string
	triageIncludeGuidance bool
	triageSeverity        string

	// Vulnetix provider specific flags
	triageVEXFormat        string
	triageVEXOutput        string
	triageMemoryDir        string
	triageDisableMemory    bool
	triagePkg              string
	triageVersion          string
	triageEcosystem        string
	triageVEXStatus        string
	triageVEXJustification string
)

// vulnetixToolKinds is the canonical set of vulnetix sub-tools that can be
// triaged from the on-disk .vulnetix/memory.yaml.
var vulnetixToolKinds = []string{
	memory.ToolSCA,
	memory.ToolSAST,
	memory.ToolIaC,
	memory.ToolSecrets,
	memory.ToolContainer,
	memory.ToolQuality,
	memory.ToolLicense,
}

// triageCmd represents the triage command, which can operate in two modes:
// 1. GitHub provider mode (github, dependabot, codeql, secrets): fetches alerts from GitHub
// 2. Vulnetix provider mode (vulnetix): triages vulnerability IDs and generates VEX
var triageCmd = &cobra.Command{
	Use:   "triage [vuln-id...]",
	Short: "Triage vulnerabilities using GitHub alerts or Vulnetix VDB",
	Long: `Triage vulnerabilities using either GitHub security alerts or the Vulnetix VDB.

Providers (-p / --provider) are: github or vulnetix (default: vulnetix).
Sub-tools (--tool, comma-separated, or "all") select what to triage:

  github   : dependabot, codeql, secrets
  vulnetix : sca, sast, iac, secrets, container, quality, license

When --provider=github, alerts are fetched from the GitHub API and enriched
with VDB data. When --provider=vulnetix, vulnerability IDs are read from
arguments / STDIN / .vulnetix memory (filtered by --tool) and triaged
against the Vulnetix VDB with VEX output.

Examples:
  # GitHub Dependabot alerts only
  vulnetix triage -p github --tool dependabot

  # Every GitHub security signal at once
  vulnetix triage -p github --tool all

  # Triage specific CVEs against VDB
  vulnetix triage -p vulnetix CVE-2021-44228 CVE-2022-22965

  # Triage only SAST findings from memory
  vulnetix triage -p vulnetix --tool sast

  # Triage all open findings from memory (default)
  vulnetix triage
`,
	Args: cobra.ArbitraryArgs,
}

func init() {
	// Register the triage command with the root command
	rootCmd.AddCommand(triageCmd)

	// Configure flags
	triageCmd.Flags().StringVarP(&triageProvider, "provider", "p", "vulnetix", "Alert source: github or vulnetix")
	triageCmd.Flags().StringVar(&triageTool, "tool", "all", "Comma-separated sub-tools to triage. github: dependabot,codeql,secrets. vulnetix: sca,sast,iac,secrets,container,quality,license. Use 'all' for every tool of the chosen provider.")
	triageCmd.Flags().StringVar(&triageRepo, "repo", "", "Repository in owner/repo format (auto-detected if not set)")
	triageCmd.Flags().StringVar(&triageSeverity, "severity", "", "Filter alerts to only show those meeting this severity (low, medium, high, critical)")
	triageCmd.Flags().BoolVar(&triageAll, "all", false, "Include dismissed alerts (open only by default)")
	triageCmd.Flags().IntVar(&triageConcurrency, "concurrency", 5, "Number of concurrent VDB lookups")
	triageCmd.Flags().StringVar(&triageFormat, "format", "tui", "Output format: tui, json, text (for GitHub providers)")
	triageCmd.Flags().BoolVar(&triageIncludeGuidance, "include-guidance", true, "Include CWE remediation guidance")

	// Flags for vulnetix provider
	triageCmd.Flags().StringVar(&triageVEXFormat, "vex-format", "cdx", "VEX output format when provider=vulnetix: openvex, cdx, json")
	triageCmd.Flags().StringVar(&triageVEXOutput, "vex-output", ".vulnetix/sbom.cdx.json", "VEX output file")
	triageCmd.Flags().StringVar(&triageMemoryDir, "memory-dir", ".vulnetix", "Path to .vulnetix directory")
	triageCmd.Flags().BoolVar(&triageDisableMemory, "disable-memory", false, "Disable memory updates for vulnetix provider")
	triageCmd.Flags().StringVar(&triagePkg, "pkg", "", "Package name for vulnetix triage (used when vuln not in memory)")
	triageCmd.Flags().StringVar(&triageVersion, "version", "", "Installed version for vulnetix triage")
	triageCmd.Flags().StringVar(&triageEcosystem, "ecosystem", "", "Package ecosystem for vulnetix triage")
	triageCmd.Flags().StringVar(&triageVEXStatus, "vex-status", "", "VEX status for non-interactive mode: not_affected, affected, fixed, under_investigation")
	triageCmd.Flags().StringVar(&triageVEXJustification, "vex-justification", "", "VEX justification (for not_affected): component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist")

	// Set the main run function
	triageCmd.RunE = runTriageCmd
	triageCmd.AddCommand(triageStatusCmd)
}

// parseToolList parses --tool into a deduped lowercased list of tool tags,
// validating each against `valid`. The literal "all" expands to a copy of
// `valid`. An empty string is treated as "all".
func parseToolList(raw string, valid []string, provider string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "all" {
		out := make([]string, len(valid))
		copy(out, valid)
		return out, nil
	}
	validSet := make(map[string]bool, len(valid))
	for _, v := range valid {
		validSet[v] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" {
			continue
		}
		if tok == "all" {
			out = make([]string, len(valid))
			copy(out, valid)
			return out, nil
		}
		if !validSet[tok] {
			return nil, fmt.Errorf("--tool %q is not valid for provider %s (valid: %s, all)", tok, provider, strings.Join(valid, ", "))
		}
		if !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--tool produced no values (provider=%s)", provider)
	}
	return out, nil
}

func runTriageCmd(cmd *cobra.Command, args []string) error {
	switch triageProvider {
	case "github":
		return runGitHubTriage(cmd, args)
	case "vulnetix":
		return runVulnetixTriage(cmd, args)
	default:
		return fmt.Errorf("unknown --provider %q (supported: github, vulnetix)", triageProvider)
	}
}

func runGitHubTriage(cmd *cobra.Command, args []string) error {
	_ = args

	// Validate format
	switch triageFormat {
	case "tui", "json", "text":
	default:
		return fmt.Errorf("unknown format %q (use tui, json, or text)", triageFormat)
	}

	// Resolve --tool to a kind list for the GitHub multi-provider.
	kinds, err := parseToolList(triageTool, triage.GitHubToolKinds, "github")
	if err != nil {
		return err
	}

	// Create GitHub API client (resolves token from env or gh CLI)
	ghClient, err := triage.NewGitHubClient()
	if err != nil {
		return err
	}

	// Verify authentication
	login, err := ghClient.CheckAuth(cmd.Context())
	if err != nil {
		return fmt.Errorf("GitHub authentication failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Authenticated as %s (token: %s)\n", login, ghClient.TokenSource())

	provider := triage.GetGitHubProvider(ghClient, kinds)

	// Determine repository
	repo := triageRepo
	if repo == "" {
		repo = triage.DetectRepo()
	}
	if repo == "" {
		return fmt.Errorf("no repository detected — set GITHUB_REPOSITORY env var, or use --repo owner/repo")
	}

	// Fetch alerts from provider
	fmt.Fprintf(os.Stderr, "Fetching alerts from github [%s] (%s)...\n", strings.Join(kinds, ","), repo)
	alerts, err := provider.FetchAlerts(context.Background(), triage.FetchOptions{
		IncludeDismissed: triageAll,
		Repo:             repo,
	})
	if err != nil {
		return err
	}

	if len(alerts) == 0 {
		fmt.Println("No vulnerability alerts found.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d alert(s). Enriching with VDB data...\n", len(alerts))

	// Create VDB client (with community fallback)
	vdbClient := getOrCreateVDBClient()

	// Concurrently enrich alerts with VDB data
	enriched := enrichAlerts(alerts, vdbClient, triageConcurrency)

	// Sort by severity (most severe first)
	sortAlertsBySeverity(enriched)

	// Persist + reconcile against memory unless explicitly disabled, so a
	// later scan (or the next triage run) knows which alerts have since been
	// fixed/dismissed upstream.
	memDir := triageMemoryDir
	if memDir == "" {
		memDir = ".vulnetix"
	}
	if !triageDisableMemory {
		mem, merr := memory.Load(memDir)
		if merr != nil || mem == nil {
			mem = &memory.Memory{Version: "1"}
		}
		// Branch tag from the current working dir's git context (best-effort).
		repoBranch := ""
		if gc := gitctx.Collect("."); gc != nil {
			repoBranch = gc.CurrentBranch
		}
		mem.SetScanContext(&memory.ScanContext{Branch: repoBranch})

		currentIDs := make(map[string]bool, len(enriched))
		seed := make(map[string]memory.FindingRecord, len(enriched))
		for _, ea := range enriched {
			id := ea.Alert.CVE
			if id == "" {
				id = ea.Alert.RuleID
			}
			if id == "" {
				id = "#" + ea.Alert.Number
			}
			currentIDs[id] = true
			rec := memory.FindingRecord{
				Aliases:   []string{ea.Alert.CVE, ea.Alert.RuleID},
				Package:   ea.Alert.Package,
				Ecosystem: ea.Alert.Ecosystem,
				Severity:  ea.Alert.Severity,
				Tool:      memory.ToolSCA,
				Source:    "github-dependabot",
			}
			if ea.Alert.Manifest != "" {
				rec.Locations = []memory.Location{{File: ea.Alert.Manifest}}
			}
			seed[id] = rec
		}
		mem.RecordCategorizedFindings(memory.ToolSCA, seed)
		changes := mem.ReconcileTool(memory.ReconcileContext{
			Tool:       memory.ToolSCA,
			CurrentIDs: currentIDs,
			Branch:     repoBranch,
		})
		if len(changes) > 0 {
			fmt.Fprintf(os.Stderr, "Reconciled %d Dependabot finding(s) against current GitHub state.\n", len(changes))
		}
		if err := memory.Save(memDir, mem); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save memory: %v\n", err)
		}
	}

	// Output based on format
	switch triageFormat {
	case "json":
		return outputJSON(enriched)
	case "text":
		return outputText(enriched)
	default:
		// Validate severity
		if triageSeverity != "" {
			valid := false
			for _, v := range scan.ValidSeverityThresholds {
				if triageSeverity == v {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid --severity %q: must be one of: %s",
					triageSeverity, strings.Join(scan.ValidSeverityThresholds, ", "))
			}
		}
		return tui.RunTriage(enriched, tui.TriageOptions{
			GHClient:        ghClient,
			Repo:            repo,
			VulnetixDir:     triageMemoryDir,
			VexFormat:       triageVEXFormat,
			InitialSeverity: triageSeverity,
		})
	}
}

// runVulnetixTriage executes triage using the Vulnetix VDB provider.
// It triages vulnerability IDs (provided as args or from stdin), generates VEX
// attestations, and updates the memory file. When running interactively (TTY),
// it launches the TUI for interactive resolution; otherwise it uses --vex-status
// and --vex-justification for batch processing.
func runVulnetixTriage(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Resolve --tool list for vulnetix-provider filtering. This filters which
	// memory-resident open findings count as a triage source when no IDs are
	// supplied; explicit args / stdin override the filter.
	toolList, err := parseToolList(triageTool, vulnetixToolKinds, "vulnetix")
	if err != nil {
		return err
	}

	// Validate VEX format
	switch triageVEXFormat {
	case "openvex", "cdx", "cyclonedx", "json":
	default:
		return fmt.Errorf("unknown vex-format %q (supported: openvex, cdx, json)", triageVEXFormat)
	}

	// Validate VEX status if provided
	if triageVEXStatus != "" {
		switch triageVEXStatus {
		case "not_affected", "affected", "fixed", "under_investigation":
		default:
			return fmt.Errorf("unknown vex-status %q (supported: not_affected, affected, fixed, under_investigation)", triageVEXStatus)
		}
	}

	// Validate VEX justification if provided
	if triageVEXJustification != "" {
		switch triageVEXJustification {
		case "component_not_present", "vulnerable_code_not_present",
			"vulnerable_code_not_in_execute_path",
			"vulnerable_code_cannot_be_controlled_by_adversary",
			"inline_mitigations_already_exist":
		default:
			return fmt.Errorf("unknown vex-justification %q", triageVEXJustification)
		}
		if triageVEXStatus != "" && triageVEXStatus != "not_affected" {
			return fmt.Errorf("--vex-justification is only valid with --vex-status=not_affected")
		}
	}

	// Create VDB client (with community fallback)
	vdbClient := getOrCreateVDBClient()

	// Create Vulnetix provider using the VDB client for both v1 and v2 endpoints
	triageProv := triage.NewVulnetixProvider(vdbClient, vdbClient)

	// Resolve memory directory
	memDir := triageMemoryDir
	if memDir == "" {
		memDir = ".vulnetix"
	}

	// Load or create memory
	mem, err := memory.Load(memDir)
	if err != nil {
		mem = &memory.Memory{Version: "1"}
	}

	// Build per-CVE context from existing findings so triage picks up
	// package/version/ecosystem info that was stored on prior runs.
	findContext := func(vulnID string, fromMem bool) (pkg, ver, eco string) {
		if fromMem {
			if f := mem.GetFinding(vulnID); f != nil {
				pkg = f.Package
				if f.Versions != nil {
					ver = f.Versions.Current
				}
				eco = f.Ecosystem
			}
		}
		pkg = coalesceStr(pkg, triagePkg)
		ver = coalesceStr(ver, triageVersion)
		eco = coalesceStr(eco, triageEcosystem)
		return
	}

	// Resolve vulnerability IDs: explicit args > stdin > open findings in memory.
	var vulnContexts []struct {
		id, pkg, ver, eco string
	}

	// Detect whether stdin is a TTY (interactive terminal).
	stdinStat, _ := os.Stdin.Stat()
	isInteractive := (stdinStat.Mode() & os.ModeCharDevice) != 0

	if len(args) > 0 {
		for _, id := range args {
			pkg, ver, eco := findContext(id, true)
			vulnContexts = append(vulnContexts, struct{ id, pkg, ver, eco string }{id, pkg, ver, eco})
		}
	} else if !isInteractive {
		// Read from stdin when data is piped
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		lines := strings.Split(string(b), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				pkg, ver, eco := findContext(line, true)
				vulnContexts = append(vulnContexts, struct{ id, pkg, ver, eco string }{line, pkg, ver, eco})
			}
		}
	} else {
		// No ids provided — fall back to open findings from memory, filtered by --tool.
		open := mem.GetOpenFindingsByTools(toolList)
		if len(open) == 0 {
			return fmt.Errorf("no vulnerability IDs provided and no open findings in memory for tool(s) %s", strings.Join(toolList, ","))
		}
		fmt.Fprintf(os.Stderr, "Loading %d open finding(s) from memory as triage source (tools: %s)\n", len(open), strings.Join(toolList, ","))
		for id, f := range open {
			pkg := coalesceStr(f.Package, triagePkg)
			ver := triageVersion
			if f.Versions != nil {
				ver = coalesceStr(f.Versions.Current, triageVersion)
			}
			eco := coalesceStr(f.Ecosystem, triageEcosystem)
			vulnContexts = append(vulnContexts, struct{ id, pkg, ver, eco string }{id, pkg, ver, eco})
		}
	}

	if len(vulnContexts) == 0 {
		return fmt.Errorf("no vulnerability IDs to triage")
	}

	// Process each vulnerability
	findings := make([]*triage.TriageFinding, 0, len(vulnContexts))
	for _, vc := range vulnContexts {
		vulnID := vc.id
		fmt.Fprintf(os.Stderr, "Triage: %s...\n", vulnID)

		existing := mem.GetFinding(vulnID)
		pkgName := vc.pkg
		pkgVersion := vc.ver
		ecosystem := vc.eco

		// Perform triage via VDB
		finding, err := triageProv.TriageCVE(cmd.Context(), vulnID, pkgName, pkgVersion, ecosystem, existing)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: triage failed for %s: %v\n", vulnID, err)
			continue
		}

		// Apply explicit VEX status/justification if provided (non-interactive mode).
		if triageVEXStatus != "" {
			finding.Status = triageVEXStatus
			finding.Justification = triageVEXJustification
		}

		findings = append(findings, finding)

		// Update memory (unless disabled)
		if !triageDisableMemory {
			updateMemoryFromFinding(mem, vulnID, finding)
		}
	}

	// Save memory
	if !triageDisableMemory {
		if err := memory.Save(memDir, mem); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save memory: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Memory updated in %s\n", memDir)
		}
	}

	// If running interactively and no explicit --vex-status was given, launch the TUI.
	if isInteractive && triageVEXStatus == "" && triageFormat != "json" && triageFormat != "text" {
		enriched := findingsToEnrichedAlerts(findings)
		sortAlertsBySeverity(enriched)
		return tui.RunTriage(enriched, tui.TriageOptions{
			VulnetixDir: memDir,
			VexFormat:   triageVEXFormat,
		})
	}

	// Non-interactive: generate VEX output
	var outputBytes []byte
	switch triageVEXFormat {
	case "openvex":
		outputBytes, err = triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{
			Author:  "Vulnetix",
			Tooling: "vulnetix-cli",
		})
	case "cdx", "cyclonedx":
		outputBytes, err = triage.GenerateCDXVEX(findings, "1.5")
	case "json":
		// JSON summary
		type jsonFinding struct {
			CVEID         string  `json:"cve_id"`
			Package       string  `json:"package"`
			Ecosystem     string  `json:"ecosystem"`
			InstalledVer  string  `json:"installed_version"`
			FixedVer      string  `json:"fixed_version"`
			Status        string  `json:"status"`
			Justification string  `json:"justification"`
			Action        string  `json:"action_response"`
			Severity      string  `json:"severity"`
			CWSS          float64 `json:"cwss_score,omitempty"`
			ExploitCount  int     `json:"exploit_count"`
			InKEV         bool    `json:"in_kev"`
		}
		jsonOut := make([]jsonFinding, 0, len(findings))
		for _, f := range findings {
			jf := jsonFinding{
				CVEID:         f.CVEID,
				Package:       f.Package,
				Ecosystem:     f.Ecosystem,
				InstalledVer:  f.InstalledVer,
				FixedVer:      f.FixedVer,
				Status:        f.Status,
				Justification: f.Justification,
				Action:        f.ActionResponse,
				Severity:      f.Severity,
				ExploitCount:  f.ExploitCount,
				InKEV:         f.InKEV,
			}
			if f.CWSS != nil {
				jf.CWSS = f.CWSS.Score
			}
			jsonOut = append(jsonOut, jf)
		}
		outputBytes, err = json.MarshalIndent(jsonOut, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("generate VEX output: %w", err)
	}

	// Write output
	if triageVEXOutput != "" {
		if err := os.WriteFile(triageVEXOutput, outputBytes, 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "VEX output written to %s\n", triageVEXOutput)
	} else {
		fmt.Fprint(out, string(outputBytes))
	}

	return nil
}

// updateMemoryFromFinding persists a TriageFinding into the memory store.
func updateMemoryFromFinding(mem *memory.Memory, vulnID string, finding *triage.TriageFinding) {
	var threatModel *memory.ThreatModel
	if finding.ThreatModel != nil {
		threatModel = &memory.ThreatModel{
			Techniques:         finding.ThreatModel.Techniques,
			Tactics:            finding.ThreatModel.Tactics,
			AttackVector:       finding.ThreatModel.AttackVector,
			AttackComplexity:   finding.ThreatModel.AttackComplexity,
			PrivilegesRequired: finding.ThreatModel.PrivilegesRequired,
			UserInteraction:    finding.ThreatModel.UserInteraction,
			Reachability:       finding.ThreatModel.Reachability,
			Exposure:           finding.ThreatModel.Exposure,
		}
	}
	var cwss *memory.CWSSData
	if finding.CWSS != nil {
		cwss = &memory.CWSSData{
			Score:    finding.CWSS.Score,
			Priority: finding.CWSS.Priority,
			Factors:  finding.CWSS.Factors,
		}
	}

	mem.SetFinding(vulnID, memory.FindingRecord{
		Aliases:    []string{finding.CVEID},
		Package:    finding.Package,
		Ecosystem:  finding.Ecosystem,
		Tool:       memory.ToolSCA,
		LastSeenAt: time.Now().UTC().Format(time.RFC3339),
		Discovery:  &memory.DiscoveryInfo{Source: "vulnetix-triage", Date: time.Now().UTC().Format(time.RFC3339)},
		Versions: &memory.VersionInfo{
			Current:   finding.InstalledVer,
			FixedIn:   finding.FixedVer,
			FixSource: "vdb",
		},
		Severity:       finding.Severity,
		SafeHarbour:    finding.SafeHarbour,
		Status:         finding.Status,
		Justification:  finding.Justification,
		ActionResponse: finding.ActionResponse,
		ThreatModel:    threatModel,
		CWSS:           cwss,
		Decision:       finding.Decision,
		History:        finding.History,
		Source:         finding.Source,
	})
}

// findingsToEnrichedAlerts converts TriageFindings to EnrichedAlerts for the TUI.
func findingsToEnrichedAlerts(findings []*triage.TriageFinding) []triage.EnrichedAlert {
	enriched := make([]triage.EnrichedAlert, 0, len(findings))
	for _, f := range findings {
		alert := triage.Alert{
			Number:    f.CVEID,
			State:     f.Status,
			CVE:       f.CVEID,
			Severity:  f.Severity,
			Package:   f.Package,
			Version:   f.InstalledVer,
			Ecosystem: f.Ecosystem,
		}
		ea := triage.EnrichedAlert{Alert: alert}
		enriched = append(enriched, ea)
	}
	return enriched
}

func getOrCreateVDBClient() *vdb.Client {
	// Try org-id flag first, then direct API key, then community fallback
	if orgID != "" {
		directKey := os.Getenv("VULNETIX_API_KEY")
		if directKey != "" {
			return vdb.NewClientFromCredentials(&auth.Credentials{
				OrgID:  orgID,
				APIKey: directKey,
				Method: auth.DirectAPIKey,
			})
		}
		sigv4 := os.Getenv("VVD_SECRET")
		if sigv4 != "" {
			return vdb.NewClient(orgID, sigv4)
		}
	}
	// Community fallback
	return vdb.NewClientFromCredentials(auth.CommunityCredentials())
}

func enrichAlerts(alerts []triage.Alert, client *vdb.Client, concurrency int) []triage.EnrichedAlert {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	results := make([]triage.EnrichedAlert, len(alerts))

	for i, alert := range alerts {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, a triage.Alert) {
			defer wg.Done()
			defer func() { <-sem }()

			results[idx] = enrichSingleAlert(a, client)
		}(i, alert)
	}

	wg.Wait()
	return results
}

// enrichSingleAlert enriches one alert with VDB data based on its type.
// - Dependabot alerts (have CVE + ecosystem + package): full enrichment
// - CodeQL alerts (have CWE, rule ID as CVE): CWE guidance + scorecard if CVE-like
// - Secret Scanning alerts: no VDB enrichment (leaked secrets, not vulns)
func enrichSingleAlert(a triage.Alert, client *vdb.Client) triage.EnrichedAlert {
	result := triage.EnrichedAlert{Alert: a}

	switch a.Ecosystem {
	case "secrets":
		// Secret scanning alerts are leaked credentials, not software vulnerabilities.
		// No VDB enrichment applies.
		return result

	case "codeql":
		// CodeQL alerts are code-level findings identified by rule ID.
		// Fetch CWE guidance if a CWE is available.
		if a.CWE != "" {
			guidance, err := client.V2CweGuidance(a.CWE)
			if err == nil {
				result.Remediation = &guidance
			}
		}
		// If the identifier looks like a CVE, fetch scorecard/KEV data
		if strings.HasPrefix(a.CVE, "CVE-") {
			plan, err := client.V2RemediationPlan(a.CVE, vdb.V2RemediationParams{
				IncludeGuidance: triageIncludeGuidance,
			})
			if err == nil {
				result.Remediation = &plan
			}
		}
		return result

	default:
		// Dependabot and other package-ecosystem alerts: full enrichment
		return enrichPackageAlert(a, client)
	}
}

// enrichPackageAlert does full VDB enrichment for package-based alerts.
func enrichPackageAlert(a triage.Alert, client *vdb.Client) triage.EnrichedAlert {
	result := triage.EnrichedAlert{Alert: a}

	vdbEco := mapEcosystem(a.Ecosystem)
	if vdbEco == "" {
		result.Error = fmt.Sprintf("unsupported ecosystem %q", a.Ecosystem)
		return result
	}

	// Fetch remediation plan
	params := vdb.V2RemediationParams{
		V2QueryParams: vdb.V2QueryParams{
			Ecosystem:   vdbEco,
			PackageName: a.Package,
		},
		CurrentVersion:           a.Version,
		PackageManager:           mapPackageManager(a.Ecosystem),
		IncludeGuidance:          triageIncludeGuidance,
		IncludeVerificationSteps: true,
	}

	plan, err := client.V2RemediationPlan(a.CVE, params)
	if err == nil {
		result.Remediation = &plan
	}

	// Fetch fixes in parallel
	fixes, fErr := fetchFixesMerged(a.CVE, vdbEco, a.Package, client)
	if fErr == nil {
		result.Fixes = fixes
	}

	if err != nil {
		result.Error = err.Error()
	}

	return result
}

func fetchFixesMerged(cveID, ecosystem, packageName string, client *vdb.Client) (*triage.FixesMerged, error) {
	type fetchResult struct {
		key  string
		data map[string]any
		err  error
	}

	ch := make(chan fetchResult, 3)
	var wg sync.WaitGroup
	p := vdb.V2QueryParams{
		Ecosystem:   ecosystem,
		PackageName: packageName,
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		data, err := client.V2RegistryFixes(cveID, p)
		ch <- fetchResult{"registry", data, err}
	}()
	go func() {
		defer wg.Done()
		data, err := client.V2DistributionPatches(cveID, p)
		ch <- fetchResult{"distributions", data, err}
	}()
	go func() {
		defer wg.Done()
		data, err := client.V2SourceFixes(cveID, p)
		ch <- fetchResult{"source", data, err}
	}()
	go func() {
		wg.Wait()
		close(ch)
	}()

	merged := &triage.FixesMerged{}
	var allFailed = true

	for r := range ch {
		if r.err != nil {
			continue
		}
		allFailed = false
		switch r.key {
		case "registry":
			merged.Registry = r.data
		case "distributions":
			merged.Distributions = r.data
		case "source":
			merged.Source = r.data
		}
	}

	if allFailed {
		return nil, fmt.Errorf("all fix sources failed")
	}

	return merged, nil
}

var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
}

func sortAlertsBySeverity(alerts []triage.EnrichedAlert) {
	for i := 0; i < len(alerts); i++ {
		for j := i + 1; j < len(alerts); j++ {
			a, b := severityRank(alerts[i].Alert.Severity), severityRank(alerts[j].Alert.Severity)
			if b < a {
				alerts[i], alerts[j] = alerts[j], alerts[i]
			}
		}
	}
}

func severityRank(sev string) int {
	if r, ok := severityOrder[sev]; ok {
		return r
	}
	return 99
}

func outputJSON(alerts []triage.EnrichedAlert) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(alerts)
}

func outputText(alerts []triage.EnrichedAlert) error {
	fmt.Printf("\nFound %d alert(s):\n\n", len(alerts))
	for i, a := range alerts {
		fixStatus := "N/A"
		if a.Fixes != nil && a.Fixes.HasFix() {
			fixStatus = "FIX AVAILABLE"
		}
		if a.Error != "" {
			fixStatus = "VDB ERROR"
		}

		id := a.Alert.Identifier()
		var subject string
		switch a.Alert.Ecosystem {
		case "codeql":
			subject = a.Alert.Manifest
			if subject == "" {
				subject = a.Alert.Description
			}
		case "secrets":
			subject = a.Alert.Description
		default:
			subject = fmt.Sprintf("%s@%s", a.Alert.Package, a.Alert.Version)
		}

		fmt.Printf("  %2d. %-25s %-10s  %-24s  (%s) %s\n",
			i+1, id, strings.ToUpper(a.Alert.Severity),
			subject, a.Alert.Ecosystem, fixStatus)
	}
	fmt.Println()
	return nil
}

var triageStatusFormat string

var triageStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check provider CLI health",
	Long:  "Verify that provider CLI tools (e.g. gh) are installed, authenticated, and functional.",
	RunE:  runTriageStatus,
}

func init() {
	triageStatusCmd.Flags().StringVar(&triageStatusFormat, "format", "text", "Output format: text, json")
}

func runTriageStatus(cmd *cobra.Command, args []string) error {
	_ = cmd
	_ = args
	switch triageProvider {
	case "github":
		return statusGitHub(triageStatusFormat)
	case "vulnetix":
		return statusVulnetix(triageStatusFormat)
	default:
		return fmt.Errorf("unknown provider %q (supported: github, vulnetix)", triageProvider)
	}
}

// statusVulnetix is a placeholder so `triage status -p vulnetix` doesn't error;
// the vulnetix provider has no separate CLI prerequisite, but the surface
// should still respond predictably.
func statusVulnetix(format string) error {
	if format == "json" {
		fmt.Println(`{"provider":"vulnetix","ok":true}`)
		return nil
	}
	fmt.Println("vulnetix provider: VDB credentials resolved at request time; no separate CLI prerequisite.")
	return nil
}

func statusGitHub(format string) error {
	client, clientErr := triage.NewGitHubClient()

	var status triage.GHStatus
	if clientErr != nil {
		status.AuthError = clientErr.Error()
	} else {
		status = triage.CheckGHAuth(client)
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(status)
	}

	ok := "\u2714"   // ✔
	fail := "\u2718" // ✘

	var b strings.Builder
	b.WriteString("\n  GitHub API Status\n")
	b.WriteString(strings.Repeat("─", 42) + "\n\n")

	// Auth check
	if status.Authenticated {
		b.WriteString(fmt.Sprintf("  %s authenticated: %s\n", ok, status.User))
		b.WriteString(fmt.Sprintf("     Host         : %s\n", status.Host))
		if status.TokenSource != "" {
			b.WriteString(fmt.Sprintf("     Token source : %s\n", status.TokenSource))
		}
	} else {
		b.WriteString(fmt.Sprintf("  %s authenticated: not authenticated\n", fail))
		if status.AuthError != "" {
			b.WriteString(fmt.Sprintf("     Error        : %s\n", status.AuthError))
		}
		b.WriteString("\n  Set GITHUB_TOKEN env var or run 'gh auth login'\n")
	}

	// gh binary (optional info)
	if status.BinaryFound {
		b.WriteString(fmt.Sprintf("  %s gh binary    : %s\n", ok, status.BinaryPath))
	}

	// Repo detection
	repo := triage.DetectRepo()
	if repo != "" {
		b.WriteString(fmt.Sprintf("  %s repo detected : %s\n", ok, repo))
	} else {
		b.WriteString(fmt.Sprintf("  %s repo detected : none\n", fail))
		b.WriteString("     Set --repo flag or GITHUB_REPOSITORY env var\n")
	}

	b.WriteString("\n")
	fmt.Print(b.String())
	return nil
}

// mapEcosystem maps provider ecosystem names to VDB ecosystem names.
func mapEcosystem(providerEco string) string {
	switch strings.ToLower(providerEco) {
	case "npm":
		return "npm"
	case "pip", "python":
		return "pypi"
	case "maven":
		return "maven"
	case "ruby", "rubygems":
		return "rubygems"
	case "golang", "go":
		return "golang"
	case "cargo", "rust":
		return "cargo"
	case "nuget", ".net", "dotnet":
		return "nuget"
	case "composer", "php":
		return "composer"
	case "hex", "elixir":
		return "hex"
	case "swift", "swiftPM":
		return "swift"
	case "pub", "dart":
		return "pub"
	case "deb", "debian", "ubuntu":
		return "linux"
	case "docker":
		return "linux"
	default:
		return ""
	}
}

// mapPackageManager maps provider ecosystem names to VDB package manager names.
func mapPackageManager(providerEco string) string {
	switch strings.ToLower(providerEco) {
	case "golang", "go":
		return "go"
	case "ruby", "rubygems":
		return "gem"
	case ".net", "dotnet":
		return "nuget"
	case "elixir":
		return "hex"
	}
	return mapEcosystem(providerEco)
}

// coalesceStr returns the first non-empty string, like a 2-arg coalesce.
func coalesceStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
