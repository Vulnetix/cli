package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/scan"
)

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Analyze package licenses for conflicts and policy compliance",
	Long: `Analyze licenses in your project's dependencies locally.

Manifests are discovered by walking the directory tree, parsed locally,
and each package's license is resolved from manifest fields or an embedded
SPDX license database. When authenticated, license findings are submitted to
Vulnetix so the scan is recorded; unauthenticated scans stay entirely local.

License findings are stored in the CycloneDX SBOM at .vulnetix/sbom.cdx.json
alongside vulnerability findings (neither overwrites the other).

Findings are tracked in .vulnetix/memory.yaml. A finding that disappears from a
later run — the package was removed, or its license changed — is marked resolved
and attested as a CycloneDX VEX entry in the same SBOM. Pass --disable-memory to
turn this off.

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
	// Resolve credentials like the other specialized scans; without this vdbCreds
	// stays nil, so isUnauthenticatedScan() is always true — the SARIF submit is
	// skipped and the "Snapshots are skipped for unauthenticated scans" reminder
	// prints even when the user is authenticated.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		applyScanDisplayFlags(cmd)
		return resolveVDBCredentials(false)
	},
	RunE: runLicense,
}

func runLicense(cmd *cobra.Command, args []string) (retErr error) {
	dctx := display.FromCommand(cmd)
	rootPath, _ := cmd.Flags().GetString("path")
	maxDepth, _ := cmd.Flags().GetInt("depth")
	excludes, _ := cmd.Flags().GetStringArray("exclude")
	mode, _ := cmd.Flags().GetString("mode")
	allowCSV, _ := cmd.Flags().GetString("allow")
	allowFile, _ := cmd.Flags().GetString("allow-file")
	severityThreshold, _ := cmd.Flags().GetString("severity")
	outputFmt, _ := cmd.Flags().GetString("output")
	fromMemory, _ := cmd.Flags().GetBool("from-memory")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	resultsOnly, _ := cmd.Flags().GetBool("results-only")

	switch mode {
	case "inclusive", "individual":
	default:
		return fmt.Errorf("--mode must be one of: inclusive, individual")
	}
	switch outputFmt {
	case "", "pretty", "json", "json-spdx":
	default:
		return fmt.Errorf("--output must be one of: pretty, json, json-spdx")
	}

	vulnetixDir := filepath.Join(rootPath, ".vulnetix")
	progress := dctx.Progress("License analysis", 6)
	progress.SetStage("Discovering package manifests")
	progressComplete := false
	defer func() {
		if progressComplete {
			return
		}
		if retErr != nil {
			progress.Fail("failed")
			return
		}
		progress.Complete("complete")
	}()

	// ── --from-memory path ──────────────────────────────────────────────
	if fromMemory {
		progress.Update(6, "Loading license results from memory")
		if err := loadLicenseFromMemory(vulnetixDir, outputFmt); err != nil {
			return err
		}
		progress.Complete("loaded from memory")
		progressComplete = true
		return nil
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
		progress.Complete("no manifest files found")
		progressComplete = true
		fmt.Fprintln(os.Stderr, "No manifest files found.")
		return nil
	}
	progress.Update(1, fmt.Sprintf("Discovered %d manifest(s)", len(manifests)))

	// ── Parse packages ──────────────────────────────────────────────────
	var allPackages []scan.ScopedPackage
	for i, m := range manifests {
		progress.SetStage(fmt.Sprintf("Parsing manifests %d/%d: %s", i+1, len(manifests), m.RelPath))
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
		progress.Complete("no packages found in manifests")
		progressComplete = true
		fmt.Fprintln(os.Stderr, "No packages found in manifests.")
		return nil
	}
	progress.Update(2, fmt.Sprintf("Parsed %d package(s)", len(allPackages)))

	// ── Dry run ─────────────────────────────────────────────────────────
	if dryRun {
		progress.Complete("dry run complete")
		progressComplete = true
		t := dctx.Term
		fmt.Fprintf(os.Stderr, "%s Found %d manifests, %d packages\n",
			display.CheckMark(t), len(manifests), len(allPackages))
		for _, m := range manifests {
			fmt.Fprintf(os.Stderr, "  • %s (%s)\n", m.RelPath, m.ManifestInfo.Ecosystem)
		}
		return nil
	}

	// ── Server-side license policy via /v2/cli.license ─────────────────
	// POST the detected PURL list so the server can return licenseByPurl
	// overrides and policy_violations driven by the org's subscription.
	// Non-fatal: a 404 or empty response falls through to the local-only
	// license evaluation. Operational chatter gated behind --verbose.
	purls := make([]string, 0, len(allPackages))
	purlSeen := make(map[string]bool, len(allPackages))
	for _, p := range allPackages {
		pu := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		if pu == "" || purlSeen[pu] {
			continue
		}
		purlSeen[pu] = true
		purls = append(purls, pu)
	}
	// Phase-2: /v2/cli.license is now persistence-only — it accepts a SARIF
	// document of license-policy findings rather than returning per-purl
	// license overrides. The post-scan submission happens via
	// postScanSARIF("license", ...) at the end of this command, where the
	// resolved license conflict list has been computed locally.
	_ = purls

	// ── Detect licenses ─────────────────────────────────────────────────
	if verbose {
		fmt.Fprintf(os.Stderr, "Resolving licenses for %d packages...\n", len(allPackages))
	}
	progress.SetStage("Building dependency graph")
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
	progress.Update(3, "Built dependency graph")
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

	progress.SetStage(fmt.Sprintf("Resolving licenses for %d package(s)", len(allPackages)))
	licensedPackages := license.DetectLicenses(allPackages, manifestGroups)

	// Count resolved.
	resolved := 0
	for _, pkg := range licensedPackages {
		if pkg.LicenseSpdxID != "UNKNOWN" {
			resolved++
		}
	}
	fmt.Fprintf(os.Stderr, "  %d/%d licenses resolved\n", resolved, len(licensedPackages))
	progress.Update(4, fmt.Sprintf("Resolved %d/%d license(s)", resolved, len(licensedPackages)))

	// ── Build allow list ────────────────────────────────────────────────
	progress.SetStage("Loading license policy")
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
	progress.SetStage("Evaluating license policy")
	result := license.Evaluate(licensedPackages, license.EvalConfig{
		Mode:              mode,
		AllowedLicenses:   allowedLicenses,
		SeverityThreshold: severityThreshold,
	})

	// Drop license findings covered by an active suppression ("ignore") rule
	// before memory reconcile, BOM merge, persistence and output.
	if set := scanSuppressionSetLoad(rootPath, gitctx.Collect(rootPath)); set != nil && !set.Empty() {
		if kept, n := filterSuppressedLicenseFindings(result.Findings, set); n > 0 {
			result.Findings = kept
			fmt.Fprintf(os.Stderr, "  %d license finding(s) suppressed by ignore rules\n", n)
		}
	}

	// ── Reconcile memory ────────────────────────────────────────────────
	// This runs before MergeBOM, not after. A resolved finding is by definition
	// absent from result.Findings, and MergeBOM drops every vulnerability
	// carrying this source before appending the new ones — so the auto-VEX
	// entries must ride along in the same cdxVulns slice or the next run erases
	// them.
	progress.SetStage("Persisting license results")
	var licenseVEX []cdx.Vulnerability
	gitCtx := gitctx.Collect(rootPath)
	if !disableMemory {
		mem, merr := memory.Load(vulnetixDir)
		if merr != nil || mem == nil {
			mem = &memory.Memory{Version: "1"}
		}
		mem.SetScanContext(scanContextFor(rootPath, gitCtx))
		recordAndReconcileLicense(mem, rootPath, gitCtx, result)
		licenseVEX = licenseVEXFromMemory(mem)
		if err := memory.Save(vulnetixDir, mem); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml: %v\n", err)
		}
	}

	// ── Write to CDX BOM (merge, don't overwrite) ───────────────────────
	sbomPath := filepath.Join(vulnetixDir, "sbom.cdx.json")
	cdxVulns := license.FindingsToCDXVulnerabilities(result.Findings, result.Packages)
	cdxVulns = append(cdxVulns, licenseVEX...)
	if err := license.MergeBOM(sbomPath, cdxVulns, license.CDXSourceName); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not merge license findings into BOM: %v\n", err)
	}

	// Populate license data on BOM components and dependency tree.
	license.PopulateBOMLicenses(sbomPath, result.Packages, manifestGroups)
	progress.Update(5, "Updated CycloneDX license data")

	// ── Phase-2: persist license SARIF to /v2/cli.license ──────────────
	// License findings are package-level (no source line), so snippet capture
	// is not applicable (0). Skipped for unauthenticated scans — the server
	// persists nothing for the shared community credential.
	if !isUnauthenticatedScan() {
		postLicenseSARIF(result, rootPath, 0)
		postScannerGraphInsights(rootPath, "vulnetix-license-graph", gitCtx, os.Stderr)
		progress.Update(6, "Submitted license findings")
	}
	progress.Complete("license analysis complete")
	progressComplete = true

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

	if isUnauthenticatedScan() {
		printCommunitySignupReminder()
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

// legacyLicenseIDPattern matches the run-local counter IDs that license
// findings carried before deterministic keys landed, e.g. "LICENSE-NOT-OSI-004".
var legacyLicenseIDPattern = regexp.MustCompile(`^LICENSE-([A-Z-]+)-\d{3}$`)

// legacyLicensePrefixToCategory maps the old ID prefix onto the rule category
// that FindingID now encodes. LICENSE-CONFLICT is absent: a conflict record
// stores neither license of the pair, so its deterministic key cannot be
// reconstructed and the record is dropped instead.
var legacyLicensePrefixToCategory = map[string]string{
	"UNKNOWN":       "unknown-license",
	"NONSTANDARD":   "non-standard-license",
	"DEPRECATED":    "deprecated-license",
	"NOT-OSI":       "not-osi-approved",
	"COPYLEFT-PROD": "copyleft-in-production",
	"NOT-ALLOWED":   "not-in-allowlist",
}

// migrateLegacyLicenseIDs re-keys license findings that were stored under the
// old counter-based identifiers, preserving each record's triage decision and
// history. Conflict findings cannot be re-keyed and are removed. Returns the
// number of records migrated and dropped.
//
// Without this, the first run after the ID change would see every legacy record
// as "absent from the current scan" and auto-resolve it, emitting a wave of
// false VEX statements.
func migrateLegacyLicenseIDs(mem *memory.Memory) (migrated, dropped int) {
	if mem == nil || mem.Findings == nil {
		return 0, 0
	}
	for id, rec := range mem.Findings {
		if rec.Tool != memory.ToolLicense && rec.Source != license.CDXSourceName {
			continue
		}
		m := legacyLicenseIDPattern.FindStringSubmatch(id)
		if m == nil {
			continue
		}
		category, ok := legacyLicensePrefixToCategory[m[1]]
		if !ok || rec.Package == "" {
			delete(mem.Findings, id)
			dropped++
			continue
		}
		version := ""
		if rec.Versions != nil {
			version = rec.Versions.Current
		}
		newID := license.FindingID(category, license.PackageLicense{
			PackageName:    rec.Package,
			PackageVersion: version,
			Ecosystem:      rec.Ecosystem,
		})
		delete(mem.Findings, id)
		rec.Tool = memory.ToolLicense
		// A record already present under the new key wins — it was written by
		// the current run and carries fresher evidence.
		if _, exists := mem.Findings[newID]; !exists {
			mem.Findings[newID] = rec
		}
		migrated++
	}
	return migrated, dropped
}

// licenseVEXFromMemory renders every resolved license finding in memory as a
// CDX-VEX entry.
//
// It reads memory rather than this run's state changes because
// license.MergeBOM strips all vulnerabilities carrying the license source before
// appending the new ones: an entry emitted only on the run that resolved it
// would be erased by the very next run. Memory is the source of truth, the BOM
// is a projection of it.
//
// Regressed findings are excluded — they are back in result.Findings, so
// FindingsToCDXVulnerabilities already emits an entry under the same bom-ref.
func licenseVEXFromMemory(mem *memory.Memory) []cdx.Vulnerability {
	if mem == nil {
		return nil
	}
	var resolved []memory.StateChange
	for id, rec := range mem.Findings {
		if rec.Tool != memory.ToolLicense || rec.Status != "fixed" {
			continue
		}
		resolved = append(resolved, memory.StateChange{
			CveID:     id,
			Tool:      memory.ToolLicense,
			Package:   rec.Package,
			Ecosystem: rec.Ecosystem,
			NewStatus: "fixed",
			Comment:   autoResolvedDetail(rec),
			Finding:   rec,
		})
	}
	return cdxVEXForChanges(resolved, license.CDXSourceName)
}

// autoResolvedDetail recovers the reason a record was auto-resolved from its
// history, so the VEX detail survives across runs even though StateChange does
// not. Falls back to a generic explanation for records resolved by hand.
func autoResolvedDetail(rec memory.FindingRecord) string {
	for i := len(rec.History) - 1; i >= 0; i-- {
		if rec.History[i].Event == "auto-resolved" && rec.History[i].Detail != "" {
			return rec.History[i].Detail
		}
	}
	return "Package or license condition no longer detected"
}

// licenseFindingRecords converts an evaluation result into the memory records
// for this run, keyed by the deterministic finding ID.
func licenseFindingRecords(result *license.AnalysisResult) map[string]memory.FindingRecord {
	out := make(map[string]memory.FindingRecord, len(result.Findings))
	for _, f := range result.Findings {
		rec := memory.FindingRecord{
			Package:         f.Package.PackageName,
			Ecosystem:       f.Package.Ecosystem,
			Severity:        f.Severity,
			Status:          "affected",
			Source:          license.CDXSourceName,
			Versions:        &memory.VersionInfo{Current: f.Package.PackageVersion},
			IntroducedPaths: f.IntroducedPaths,
			PathCount:       f.PathCount,
		}
		if f.Package.SourceFile != "" {
			rec.SourceFiles = []string{f.Package.SourceFile}
			// Locations keeps license records readable by the tool-agnostic
			// consumers (triage --tool license, dashboards). No line number
			// exists: a license applies to the package, not to a source line.
			rec.Locations = []memory.Location{{File: f.Package.SourceFile}}
		}
		out[f.ID] = rec
	}
	return out
}

// recordAndReconcileLicense records this run's license findings into mem and
// resolves any prior finding that no longer appears. License evaluation
// recomputes the whole dependency set every run, so absence from the current
// result set is proof the package or its offending license condition is gone —
// no on-disk verification is possible or needed.
//
// The caller owns saving mem.
func recordAndReconcileLicense(
	mem *memory.Memory,
	rootPath string,
	gitCtx *gitctx.GitContext,
	result *license.AnalysisResult,
) []memory.StateChange {
	if mem == nil || result == nil {
		return nil
	}
	if migrated, dropped := migrateLegacyLicenseIDs(mem); migrated > 0 || dropped > 0 {
		fmt.Fprintf(os.Stderr,
			"  note: migrated %d license finding(s) to stable identifiers (%d unmigratable conflict record(s) dropped)\n",
			migrated, dropped)
	}
	return reconcileInto(mem, rootPath, gitCtx, memory.ToolLicense,
		licenseFindingRecords(result), reconcileOptions{Mode: memory.ResolveOnAbsence})
}

// loadLicenseFromMemory reconstructs license output from memory.
func loadLicenseFromMemory(vulnetixDir, outputFmt string) error {
	if outputFmt == "json-spdx" {
		return fmt.Errorf("--output json-spdx is not supported with --from-memory; rerun 'vulnetix license' without --from-memory to generate SPDX output")
	}

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
