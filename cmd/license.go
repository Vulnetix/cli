package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/internal/license"
	"github.com/vulnetix/cli/internal/memory"
	"github.com/vulnetix/cli/internal/scan"
)

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Analyze package licenses for conflicts and policy compliance",
	Long: `Analyze licenses in your project's dependencies locally.

Manifests are discovered by walking the directory tree, parsed locally,
and each package's license is resolved from manifest fields or an embedded
SPDX license database. No data is uploaded to any server.

License findings are stored in the CycloneDX SBOM at .vulnetix/sbom.cdx.json
alongside vulnerability findings (neither overwrites the other).

Examples:
  vulnetix license                                # scan current directory
  vulnetix license --path ./myproject             # scan a specific directory
  vulnetix license --allow MIT,Apache-2.0         # only allow these licenses
  vulnetix license --allow-file .vulnetix/license-allow.yaml
  vulnetix license --severity high                # exit 1 if any high+ findings
  vulnetix license -o json                        # output as CycloneDX JSON
  vulnetix license -o json-spdx                   # output as SPDX 2.3 JSON
  vulnetix license --mode individual              # per-manifest conflict detection
  vulnetix license --from-memory                  # reconstruct from saved state
  vulnetix license --dry-run                      # detect files only, no evaluation`,
	RunE: runLicense,
}

func runLicense(cmd *cobra.Command, args []string) error {
	rootPath, _ := cmd.Flags().GetString("path")
	maxDepth, _ := cmd.Flags().GetInt("depth")
	excludes, _ := cmd.Flags().GetStringArray("exclude")
	mode, _ := cmd.Flags().GetString("mode")
	allowCSV, _ := cmd.Flags().GetString("allow")
	allowFile, _ := cmd.Flags().GetString("allow-file")
	severityThreshold, _ := cmd.Flags().GetString("severity")
	outputFmt, _ := cmd.Flags().GetString("output")
	noProgress, _ := cmd.Flags().GetBool("no-progress")
	fromMemory, _ := cmd.Flags().GetBool("from-memory")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	resultsOnly, _ := cmd.Flags().GetBool("results-only")

	_ = noProgress // reserved for future progress bar

	vulnetixDir := filepath.Join(rootPath, ".vulnetix")

	// ── --from-memory path ──────────────────────────────────────────────
	if fromMemory {
		return loadLicenseFromMemory(vulnetixDir, outputFmt)
	}

	// ── Walk and detect manifests ───────────────────────────────────────
	files, err := scan.WalkForScanFiles(scan.WalkOptions{
		RootPath: rootPath,
		MaxDepth: maxDepth,
		Excludes: excludes,
	})
	if err != nil {
		return fmt.Errorf("walk failed: %w", err)
	}

	// Filter to manifests only.
	var manifests []scan.DetectedFile
	for _, f := range files {
		if f.FileType == scan.FileTypeManifest && f.ManifestInfo != nil {
			manifests = append(manifests, f)
		}
	}

	if len(manifests) == 0 {
		fmt.Fprintln(os.Stderr, "No manifest files found.")
		return nil
	}

	// ── Parse packages ──────────────────────────────────────────────────
	var allPackages []scan.ScopedPackage
	for _, m := range manifests {
		pkgs, err := scan.ParseManifestWithScope(m.Path, m.ManifestInfo.Type)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to parse %s: %v\n", m.RelPath, err)
			continue
		}
		for i := range pkgs {
			if pkgs[i].SourceFile == "" {
				pkgs[i].SourceFile = m.RelPath
			}
			if pkgs[i].Ecosystem == "" {
				pkgs[i].Ecosystem = m.ManifestInfo.Ecosystem
			}
		}
		allPackages = append(allPackages, pkgs...)
	}

	if len(allPackages) == 0 {
		fmt.Fprintln(os.Stderr, "No packages found in manifests.")
		return nil
	}

	// ── Dry run ─────────────────────────────────────────────────────────
	if dryRun {
		t := display.NewTerminal()
		fmt.Fprintf(os.Stderr, "%s Found %d manifests, %d packages\n",
			display.CheckMark(t), len(manifests), len(allPackages))
		for _, m := range manifests {
			fmt.Fprintf(os.Stderr, "  • %s (%s)\n", m.RelPath, m.ManifestInfo.Ecosystem)
		}
		return nil
	}

	// ── Detect licenses ─────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "Resolving licenses for %d packages...\n", len(allPackages))
	// Build ManifestGroups for dependency path tracking.
	filePackages := map[string][]scan.ScopedPackage{}
	fileEcosystems := map[string]string{}
	for _, m := range manifests {
		fileEcosystems[m.RelPath] = m.ManifestInfo.Ecosystem
	}
	// Group allPackages by SourceFile (which the parsers set to RelPath or absolute path).
	for _, pkg := range allPackages {
		sf := pkg.SourceFile
		filePackages[sf] = append(filePackages[sf], pkg)
		// Also register the ecosystem for this source file.
		if _, ok := fileEcosystems[sf]; !ok {
			fileEcosystems[sf] = pkg.Ecosystem
		}
	}
	manifestGroups := scan.BuildManifestGroups(filePackages, fileEcosystems)
	for i := range manifestGroups {
		mg := &manifestGroups[i]
		if mg.Graph != nil && mg.Ecosystem == "golang" {
			graphDir := mg.Dir
			if !filepath.IsAbs(graphDir) {
				graphDir = filepath.Join(rootPath, graphDir)
			}
			if err := mg.Graph.PopulateGoModGraph(graphDir); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: go mod graph failed in %s: %v\n", mg.Dir, err)
			}
		}
	}

	licensedPackages := license.DetectLicenses(allPackages, manifestGroups)

	// Count resolved.
	resolved := 0
	for _, pkg := range licensedPackages {
		if pkg.LicenseSpdxID != "UNKNOWN" {
			resolved++
		}
	}
	fmt.Fprintf(os.Stderr, "  %d/%d licenses resolved\n", resolved, len(licensedPackages))

	// ── Build allow list ────────────────────────────────────────────────
	var allowedLicenses []string
	if allowFile != "" {
		al, err := license.LoadAllowListFromFile(allowFile)
		if err != nil {
			return fmt.Errorf("failed to load allow list: %w", err)
		}
		allowedLicenses = al.Licenses
	} else if allowCSV != "" {
		al := license.ParseAllowListCSV(allowCSV)
		allowedLicenses = al.Licenses
	}

	// ── Evaluate ────────────────────────────────────────────────────────
	result := license.Evaluate(licensedPackages, license.EvalConfig{
		Mode:              mode,
		AllowedLicenses:   allowedLicenses,
		SeverityThreshold: severityThreshold,
	})

	// ── Write to CDX BOM (merge, don't overwrite) ───────────────────────
	sbomPath := filepath.Join(vulnetixDir, "sbom.cdx.json")
	cdxVulns := license.FindingsToCDXVulnerabilities(result.Findings, result.Packages)
	if err := license.MergeBOM(sbomPath, cdxVulns, license.CDXSourceName); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not merge license findings into BOM: %v\n", err)
	}

	// Populate license data on BOM components and dependency tree.
	license.PopulateBOMLicenses(sbomPath, result.Packages, manifestGroups)

	// ── Write to memory ─────────────────────────────────────────────────
	if !disableMemory {
		writeLicenseMemory(vulnetixDir, result)
	}

	// ── Output ──────────────────────────────────────────────────────────
	switch outputFmt {
	case "json":
		// Output the merged BOM to stdout.
		data, err := os.ReadFile(sbomPath)
		if err != nil {
			return fmt.Errorf("failed to read BOM after merge: %w", err)
		}
		fmt.Fprintln(os.Stdout, string(data))
	case "json-spdx":
		doc := license.BuildSPDXDocument(result, filepath.Base(rootPath))
		data, err := license.MarshalSPDXJSON(doc)
		if err != nil {
			return fmt.Errorf("failed to marshal SPDX: %w", err)
		}
		fmt.Fprintln(os.Stdout, string(data))
	default:
		printPrettyLicenseSummary(result, sbomPath, vulnetixDir, resultsOnly)
	}

	// ── Severity threshold check ────────────────────────────────────────
	if severityThreshold != "" {
		count := license.CountFindingsAtOrAbove(result.Findings, severityThreshold)
		if count > 0 {
			return &SeverityBreachError{threshold: severityThreshold, count: count}
		}
	}

	return nil
}

// printPrettyLicenseSummary renders a scan-consistent pretty output for license analysis.
func printPrettyLicenseSummary(result *license.AnalysisResult, sbomPath, vulnetixDir string, resultsOnly ...bool) {
	compact := len(resultsOnly) > 0 && resultsOnly[0]

	// In results-only mode, suppress all output when there are no issues.
	if compact && len(result.Findings) == 0 && len(result.Conflicts) == 0 {
		return
	}

	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, display.Divider(t))

	// ── Summary header ──────────────────────────────────────────────────
	fmt.Fprintln(os.Stdout, display.Header(t, "License Analysis"))

	fmt.Fprintf(os.Stdout, "  Packages:   %d\n", result.Summary.TotalPackages)
	fmt.Fprintf(os.Stdout, "  Licenses:   %d distinct\n", len(result.Summary.LicenseCounts))
	fmt.Fprintf(os.Stdout, "  Conflicts:  %d\n", result.Summary.ConflictCount)
	fmt.Fprintf(os.Stdout, "  Findings:   %d\n", len(result.Findings))
	fmt.Fprintln(os.Stdout)

	// Category breakdown.
	categoryOrder := []license.Category{
		license.CategoryPermissive,
		license.CategoryWeakCopyleft,
		license.CategoryStrongCopyleft,
		license.CategoryProprietary,
		license.CategoryPublicDomain,
		license.CategoryUnknown,
	}
	for _, cat := range categoryOrder {
		if count, ok := result.Summary.CategoryCounts[cat]; ok && count > 0 {
			fmt.Fprintf(os.Stdout, "  %s %s: %d\n", categoryIcon(cat), cat, count)
		}
	}
	fmt.Fprintln(os.Stdout)

	// Status badges.
	if result.Summary.OsiApproved > 0 {
		fmt.Fprintf(os.Stdout, "  %s OSI Approved: %d\n", display.CheckMark(t), result.Summary.OsiApproved)
	}
	if result.Summary.FsfLibre > 0 {
		fmt.Fprintf(os.Stdout, "  %s FSF Libre: %d\n", display.CheckMark(t), result.Summary.FsfLibre)
	}
	if result.Summary.Deprecated > 0 {
		fmt.Fprintf(os.Stdout, "  %s Deprecated: %d\n", display.WarningMark(t), result.Summary.Deprecated)
	}
	if result.Summary.Unknown > 0 {
		fmt.Fprintf(os.Stdout, "  %s Unknown: %d\n", display.CrossMark(t), result.Summary.Unknown)
	}
	fmt.Fprintln(os.Stdout)

	// ── Package table (skipped in results-only mode) ────────────────────
	if len(result.Packages) > 0 && !compact {
		cols := []display.Column{
			{Header: "File", MinWidth: 15, MaxWidth: 40, Color: func(s string) string {
				if strings.TrimSpace(s) == "" {
					return s
				}
				return display.Teal(t, s)
			}},
			{Header: "Package", MinWidth: 14, MaxWidth: 36},
			{Header: "Version", MinWidth: 8, MaxWidth: 16},
			{Header: "Ecosystem", MinWidth: 6, MaxWidth: 12},
			{Header: "License", MinWidth: 8, MaxWidth: 24},
			{Header: "Category", MinWidth: 10, MaxWidth: 18, Color: func(s string) string {
				return categoryColor(t, s)
			}},
			{Header: "Source", MinWidth: 6, MaxWidth: 14},
		}

		// Group packages by source file.
		byFile := map[string][]license.PackageLicense{}
		var fileOrder []string
		for _, pkg := range result.Packages {
			if _, seen := byFile[pkg.SourceFile]; !seen {
				fileOrder = append(fileOrder, pkg.SourceFile)
			}
			byFile[pkg.SourceFile] = append(byFile[pkg.SourceFile], pkg)
		}

		var rows [][]string
		for _, file := range fileOrder {
			pkgs := byFile[file]
			sort.Slice(pkgs, func(i, j int) bool {
				return pkgs[i].PackageName < pkgs[j].PackageName
			})
			for i, pkg := range pkgs {
				fileCell := ""
				if i == 0 {
					fileCell = file
				}
				cat := string(license.CategoryUnknown)
				if pkg.Record != nil {
					cat = string(pkg.Record.Category)
				}
				rows = append(rows, []string{
					fileCell,
					pkg.PackageName,
					pkg.PackageVersion,
					pkg.Ecosystem,
					pkg.LicenseSpdxID,
					cat,
					pkg.LicenseSource,
				})
			}
		}

		fmt.Fprintln(os.Stdout, display.Table(t, cols, rows))
	}

	// ── Conflicts table ─────────────────────────────────────────────────
	if len(result.Conflicts) > 0 {
		fmt.Fprintln(os.Stdout, display.Header(t, "License Conflicts"))

		conflictCols := []display.Column{
			{Header: "Severity", MinWidth: 8, MaxWidth: 10, Color: func(s string) string {
				return display.SeverityText(t, s)
			}},
			{Header: "License 1", MinWidth: 12, MaxWidth: 24},
			{Header: "Package 1", MinWidth: 12, MaxWidth: 30},
			{Header: "License 2", MinWidth: 12, MaxWidth: 24},
			{Header: "Package 2", MinWidth: 12, MaxWidth: 30},
			{Header: "Description", MinWidth: 20, MaxWidth: 50},
		}

		var conflictRows [][]string
		for _, c := range result.Conflicts {
			conflictRows = append(conflictRows, []string{
				c.Severity,
				c.License1,
				c.Package1,
				c.License2,
				c.Package2,
				c.Description,
			})
		}

		fmt.Fprintln(os.Stdout, display.Table(t, conflictCols, conflictRows))

		// Show introduced paths for conflicts.
		for _, c := range result.Conflicts {
			if len(c.Package1Paths) > 0 {
				for _, chain := range c.Package1Paths {
					fmt.Fprintf(os.Stdout, "    %s %s (%s): %s\n",
						display.Muted(t, "via"),
						c.Package1, c.License1,
						display.Muted(t, strings.Join(chain, " → ")))
				}
			}
			if len(c.Package2Paths) > 0 {
				for _, chain := range c.Package2Paths {
					fmt.Fprintf(os.Stdout, "    %s %s (%s): %s\n",
						display.Muted(t, "via"),
						c.Package2, c.License2,
						display.Muted(t, strings.Join(chain, " → ")))
				}
			}
		}
	}

	// ── Findings by severity ────────────────────────────────────────────
	if len(result.Findings) > 0 {
		fmt.Fprintln(os.Stdout, display.Header(t, "License Findings"))

		findingCols := []display.Column{
			{Header: "Severity", MinWidth: 8, MaxWidth: 10, Color: func(s string) string {
				return display.SeverityText(t, s)
			}},
			{Header: "ID", MinWidth: 16, MaxWidth: 28},
			{Header: "Package", MinWidth: 14, MaxWidth: 36},
			{Header: "Title", MinWidth: 20, MaxWidth: 60},
		}

		// Sort findings by severity.
		sorted := make([]license.Finding, len(result.Findings))
		copy(sorted, result.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return severityOrd(sorted[i].Severity) < severityOrd(sorted[j].Severity)
		})

		var findingRows [][]string
		for _, f := range sorted {
			findingRows = append(findingRows, []string{
				f.Severity,
				f.ID,
				f.Package.PackageName,
				f.Title,
			})
		}

		fmt.Fprintln(os.Stdout, display.Table(t, findingCols, findingRows))

		// Show introduced paths for findings that have them.
		for _, f := range sorted {
			if len(f.IntroducedPaths) > 0 {
				for _, chain := range f.IntroducedPaths {
					fmt.Fprintf(os.Stdout, "    %s %s: %s\n",
						display.Muted(t, "via"),
						f.Package.PackageName,
						display.Muted(t, strings.Join(chain, " → ")))
				}
			}
		}
	}

	fmt.Fprintln(os.Stdout, display.Divider(t))

	// Summary line (scan-consistent).
	summary := fmt.Sprintf("  %d packages | %d licenses | %s | %s",
		result.Summary.TotalPackages,
		len(result.Summary.LicenseCounts),
		pluralise("conflict", result.Summary.ConflictCount),
		pluralise("finding", len(result.Findings)))
	fmt.Fprintln(os.Stdout, display.Bold(t, summary))
	fmt.Fprintln(os.Stdout)

	// Artefact paths.
	fmt.Fprintf(os.Stdout, "  %s BOM:    %s\n", display.CheckMark(t), sbomPath)
	if !disableMemory {
		fmt.Fprintf(os.Stdout, "  %s Memory: %s\n", display.CheckMark(t), filepath.Join(vulnetixDir, memory.FileName))
	}
	fmt.Fprintln(os.Stdout)
}

func categoryIcon(cat license.Category) string {
	switch cat {
	case license.CategoryPermissive:
		return "🟢"
	case license.CategoryWeakCopyleft:
		return "🟡"
	case license.CategoryStrongCopyleft:
		return "🟠"
	case license.CategoryProprietary:
		return "🔴"
	case license.CategoryPublicDomain:
		return "🔵"
	default:
		return "⚪"
	}
}

func categoryColor(t *display.Terminal, cat string) string {
	switch license.Category(cat) {
	case license.CategoryPermissive:
		return display.Success(t, cat)
	case license.CategoryWeakCopyleft:
		return display.SeverityText(t, "medium")
	case license.CategoryStrongCopyleft:
		return display.SeverityText(t, "high")
	case license.CategoryProprietary:
		return display.SeverityText(t, "critical")
	case license.CategoryPublicDomain:
		return display.Teal(t, cat)
	default:
		return display.Muted(t, cat)
	}
}

func severityOrd(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// writeLicenseMemory persists license findings to .vulnetix/memory.yaml.
func writeLicenseMemory(vulnetixDir string, result *license.AnalysisResult) {
	mem, _ := memory.Load(vulnetixDir)
	if mem == nil {
		mem = &memory.Memory{Version: "1"}
	}

	if mem.Findings == nil {
		mem.Findings = map[string]memory.FindingRecord{}
	}

	for _, f := range result.Findings {
		mem.Findings[f.ID] = memory.FindingRecord{
			Package:         f.Package.PackageName,
			Ecosystem:       f.Package.Ecosystem,
			Severity:        f.Severity,
			Status:          "affected",
			Source:           license.CDXSourceName,
			Versions:         &memory.VersionInfo{Current: f.Package.PackageVersion},
			SourceFiles:     []string{f.Package.SourceFile},
			IntroducedPaths: f.IntroducedPaths,
			PathCount:       f.PathCount,
		}
	}

	if err := memory.Save(vulnetixDir, mem); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml: %v\n", err)
	}
}

// loadLicenseFromMemory reconstructs license output from memory.
func loadLicenseFromMemory(vulnetixDir, outputFmt string) error {
	mem, err := memory.Load(vulnetixDir)
	if err != nil {
		return fmt.Errorf("failed to load memory: %w", err)
	}
	if mem == nil {
		return fmt.Errorf("no memory found at %s (run 'vulnetix license' first)", vulnetixDir)
	}

	// Reconstruct findings from memory.
	var findings []license.Finding
	for id, rec := range mem.Findings {
		if rec.Source != license.CDXSourceName {
			continue
		}
		ver := ""
		if rec.Versions != nil {
			ver = rec.Versions.Current
		}
		findings = append(findings, license.Finding{
			ID:       id,
			Title:    fmt.Sprintf("%s: %s", rec.Severity, rec.Package),
			Severity: rec.Severity,
			Package: license.PackageLicense{
				PackageName:    rec.Package,
				PackageVersion: ver,
				Ecosystem:      rec.Ecosystem,
				SourceFile:     firstOrEmpty(rec.SourceFiles),
			},
			Category: "from-memory",
		})
	}

	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "No license findings in memory.")
		return nil
	}

	result := &license.AnalysisResult{
		Mode:     "from-memory",
		Findings: findings,
		Summary: license.AnalysisSummary{
			LicenseCounts:  map[string]int{},
			CategoryCounts: map[license.Category]int{},
			FindingsBySev:  map[string]int{},
		},
	}
	for _, f := range findings {
		result.Summary.FindingsBySev[f.Severity]++
	}

	switch outputFmt {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(data))
	default:
		sbomPath := filepath.Join(vulnetixDir, "sbom.cdx.json")
		printPrettyLicenseSummary(result, sbomPath, vulnetixDir)
	}

	return nil
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func init() {
	rootCmd.AddCommand(licenseCmd)

	licenseCmd.Flags().String("path", ".", "Directory to scan")
	licenseCmd.Flags().Int("depth", 3, "Max recursion depth")
	licenseCmd.Flags().StringArray("exclude", nil, "Exclude paths matching glob (repeatable)")
	licenseCmd.Flags().String("mode", "inclusive", "Analysis mode: inclusive (default) or individual")
	licenseCmd.Flags().String("allow", "", "Comma-separated allow list of SPDX IDs")
	licenseCmd.Flags().String("allow-file", "", "Path to YAML allow list file")
	licenseCmd.Flags().String("severity", "", "Exit with code 1 if any finding meets or exceeds this severity (low, medium, high, critical)")
	licenseCmd.Flags().StringP("output", "o", "", "Output format: pretty (default), json (CycloneDX), json-spdx (SPDX 2.3)")
	licenseCmd.Flags().Bool("no-progress", false, "Suppress progress indicators")
	licenseCmd.Flags().Bool("from-memory", false, "Reconstruct license output from .vulnetix/memory.yaml without re-scanning")
	licenseCmd.Flags().Bool("dry-run", false, "Detect files and parse packages only — no license evaluation")
	licenseCmd.Flags().Bool("results-only", false, "Only show output when there are findings or conflicts (summary + issues only, no full package table)")

	_ = licenseCmd.RegisterFlagCompletionFunc("mode", cobra.FixedCompletions(
		[]string{"inclusive", "individual"}, cobra.ShellCompDirectiveNoFileComp))
	_ = licenseCmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions(
		[]string{"pretty", "json", "json-spdx"}, cobra.ShellCompDirectiveNoFileComp))
	_ = licenseCmd.RegisterFlagCompletionFunc("severity", cobra.FixedCompletions(
		[]string{"low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp))
	_ = licenseCmd.MarkFlagDirname("path")
	_ = licenseCmd.MarkFlagFilename("allow-file", "yaml", "yml")
}
