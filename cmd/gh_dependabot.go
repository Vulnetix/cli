package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/triage"
	"github.com/vulnetix/cli/internal/tui"
	"github.com/vulnetix/cli/internal/vdb"
)

var (
	triageProvider        string
	triageRepo            string
	triageAll             bool
	triageConcurrency     int
	triageFormat          string
	triageIncludeGuidance bool
)

func init() {
	triageCmd.Flags().StringVar(&triageProvider, "provider", "github", "Vulnerability data provider (github)")
	triageCmd.Flags().StringVar(&triageRepo, "repo", "", "Repository in owner/repo format (auto-detected if not set)")
	triageCmd.Flags().BoolVar(&triageAll, "all", false, "Include dismissed alerts (open only by default)")
	triageCmd.Flags().IntVar(&triageConcurrency, "concurrency", 5, "Number of concurrent VDB lookups")
	triageCmd.Flags().StringVar(&triageFormat, "format", "tui", "Output format: tui, json, text")
	triageCmd.Flags().BoolVar(&triageIncludeGuidance, "include-guidance", true, "Include CWE remediation guidance")
	triageCmd.RunE = runTriageCmd
	triageCmd.AddCommand(triageStatusCmd)
}

func runTriageCmd(cmd *cobra.Command, args []string) error {
	// Validate flags
	switch triageFormat {
	case "tui", "json", "text":
	default:
		return fmt.Errorf("unknown format %q (use tui, json, or text)", triageFormat)
	}

	// Get provider
	provider, err := triage.GetProvider(triageProvider)
	if err != nil {
		return err
	}

	// For GitHub provider, verify gh CLI and auth
	if triageProvider == "github" {
		if err := triage.RequireGHAuth(); err != nil {
			return err
		}
	}

	// Determine repository
	repo := triageRepo
	if repo == "" {
		repo = triage.DetectRepo()
	}
	if repo == "" {
		return fmt.Errorf("no repository detected — set GITHUB_REPOSITORY env var, or use --repo owner/repo")
	}

	// Fetch alerts from provider
	fmt.Fprintf(os.Stderr, "Fetching alerts from %s (%s)...\n", triageProvider, repo)
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

	// Output based on format
	switch triageFormat {
	case "json":
		return outputJSON(enriched)
	case "text":
		return outputText(enriched)
	default:
		return tui.RunTriage(enriched)
	}
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

			result := triage.EnrichedAlert{Alert: a}

			vdbEco := mapEcosystem(a.Ecosystem)
			if vdbEco == "" {
				result.Error = fmt.Sprintf("unsupported ecosystem %q", a.Ecosystem)
				results[idx] = result
				return
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

			results[idx] = result
		}(i, alert)
	}

	wg.Wait()
	return results
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
		fmt.Printf("  %2d. %-25s %-10s  %-24s  (%s) %s\n",
			i+1, a.Alert.CVE, strings.ToUpper(a.Alert.Severity),
			fmt.Sprintf("%s@%s", a.Alert.Package, a.Alert.Version),
			a.Alert.Ecosystem, fixStatus)
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
	switch triageProvider {
	case "github":
		return statusGitHub(triageStatusFormat)
	default:
		return fmt.Errorf("unknown provider %q", triageProvider)
	}
}

func statusGitHub(format string) error {
	status := triage.CheckGHAuth()

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(status)
	}

	ok := "\u2714" // ✔
	fail := "\u2718" // ✘

	var b strings.Builder
	b.WriteString("\n  GitHub CLI Status\n")
	b.WriteString(strings.Repeat("─", 42) + "\n\n")

	// Binary check
	if status.BinaryFound {
		b.WriteString(fmt.Sprintf("  %s gh binary   : %s\n", ok, status.BinaryPath))
	} else {
		b.WriteString(fmt.Sprintf("  %s gh binary   : not found\n", fail))
		b.WriteString(fmt.Sprintf("     Error        : %s\n", status.BinaryError))
		b.WriteString("\n  Install gh CLI from https://cli.github.com/\n")
		fmt.Println(b.String())
		return nil
	}

	// Auth check
	if status.Authenticated {
		b.WriteString(fmt.Sprintf("  %s authenticated: %s\n", ok, status.User))
		b.WriteString(fmt.Sprintf("     Host         : %s\n", status.Host))
		if status.TokenSource != "" {
			b.WriteString(fmt.Sprintf("     Token source : %s\n", status.TokenSource))
		}
		if status.TokenScopes != "" {
			b.WriteString(fmt.Sprintf("     Token scopes : %s\n", status.TokenScopes))
		}
	} else {
		b.WriteString(fmt.Sprintf("  %s authenticated: not authenticated\n", fail))
		if status.AuthError != "" {
			b.WriteString(fmt.Sprintf("     Error        : %s\n", status.AuthError))
		}
		b.WriteString("\n  Run 'gh auth login' to authenticate\n")
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
