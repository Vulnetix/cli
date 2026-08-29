package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/bom"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scanopts"
)

// ─────────────────────────────────────────────────────────────────────────
// bom.go — owner file for the `bom` command family: the READ side of SBOMs.
//
// `cdx` (alias `sbom`) writes a document from a scanned working tree. `bom`
// consumes documents this CLI did not necessarily write. Keeping the two
// under separate nouns is the whole reason the split is legible: `vulnetix
// sbom` produces, `vulnetix bom` inspects.
//
// runBOMImport is the shared entry function per the capability-owner rule in
// AGENTS.md. Every subcommand here, and any future caller in the scan engine
// that needs to consume a supplied SBOM rather than discover one, goes through
// it — so a second, weaker parser can never grow inside cmd/scan.go.
// ─────────────────────────────────────────────────────────────────────────

var bomCmd = &cobra.Command{
	Use:   "bom",
	Short: "Read, validate, diff and inspect SBOM documents",
	Long: `Consume SBOM documents — including ones this CLI did not produce.

Where 'vulnetix cdx' (alias 'sbom') generates a CycloneDX document from a
working tree, 'vulnetix bom' reads documents back in: CycloneDX 1.0-1.7 and
SPDX 2.2/2.3, either bare or wrapped in an in-toto attestation (the shape Syft
and BuildKit emit for container SBOMs, which a plain bomFormat check misses).

Everything parsed is normalised into one CycloneDX model, so SPDX input and
CycloneDX input diff, validate and render identically. What the document
originally was is never lost: the format, spec version, envelope and a SHA-256
of the exact bytes supplied are stamped into metadata.properties.

Subcommands:
  import    parse a document, report its inventory, optionally re-emit it
  validate  check a document's structure and field completeness
  diff      compare two documents — the CI change-review gate
  merge     combine documents into one
  tree      walk the dependency graph, forwards or inverted`,
	SilenceUsage: true,
}

func init() {
	bomCmd.AddCommand(bomImportCmd, bomValidateCmd, bomDiffCmd, bomMergeCmd, bomTreeCmd)
	rootCmd.AddCommand(bomCmd)
}

// ── import ──────────────────────────────────────────────────────────────────

var bomImportCmd = &cobra.Command{
	Use:   "import <file|->",
	Short: "Parse an SBOM document and report what it contains",
	Long: `Parse an SBOM and report its inventory.

Accepts CycloneDX 1.0-1.7 and SPDX 2.2/2.3 JSON, bare or inside an in-toto
attestation envelope (DSSE-signed or not). Pass - to read from stdin.

With --out the normalised CycloneDX document is written to a file, which is how
an SPDX document is converted for use with the rest of the CLI.

Examples:
  vulnetix bom import sbom.spdx.json
  vulnetix bom import sbom.spdx.json --out sbom.cdx.json
  syft . -o spdx-json | vulnetix bom import - --out sbom.cdx.json
  vulnetix bom import attestation.intoto.jsonl -o json`,
	Args:         cobra.ExactArgs(1),
	RunE:         runBOMImportCmd,
	SilenceUsage: true,
}

// BOMImportOptions is the options struct for the one entry point into SBOM
// reading. See the file header for why this exists.
type BOMImportOptions struct {
	// Path is the document to read; "-" reads stdin.
	Path string
	// OutPath, when set, receives the normalised CycloneDX document.
	OutPath string
	// Deployment tags the document with where it is deployed and what owns it.
	Deployment scanopts.DeploymentContext
}

// BOMImportResult is what a successful import produced.
type BOMImportResult struct {
	Document *bom.Document
	// Written is the path the normalised document was written to, or "".
	Written string
}

// runBOMImport parses a document and optionally re-emits it. This is the shared
// entry point; every consumer of SBOM input in this CLI calls it.
func runBOMImport(opts BOMImportOptions) (*BOMImportResult, error) {
	var (
		doc *bom.Document
		err error
	)
	if opts.Path == "-" {
		doc, err = bom.LoadReader(os.Stdin, "")
	} else {
		doc, err = bom.Load(opts.Path)
	}
	if err != nil {
		return nil, err
	}

	cdx.ApplyDeploymentContext(doc.BOM, opts.Deployment)

	res := &BOMImportResult{Document: doc}
	if opts.OutPath != "" {
		data, mErr := json.MarshalIndent(doc.BOM, "", "  ")
		if mErr != nil {
			return nil, mErr
		}
		if dir := filepath.Dir(opts.OutPath); dir != "" && dir != "." {
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				return nil, mkErr
			}
		}
		if wErr := os.WriteFile(opts.OutPath, append(data, '\n'), 0o644); wErr != nil {
			return nil, wErr
		}
		res.Written = opts.OutPath
	}
	return res, nil
}

func runBOMImportCmd(cmd *cobra.Command, args []string) error {
	outPath, _ := cmd.Flags().GetString("out")
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}

	res, err := runBOMImport(BOMImportOptions{
		Path:       args[0],
		OutPath:    outPath,
		Deployment: scanopts.DeploymentFromCommand(cmd),
	})
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(bomImportPayload(res))
	}
	renderBOMImport(res)
	return nil
}

// bomImportPayload is the JSON shape of an import.
func bomImportPayload(res *BOMImportResult) map[string]any {
	doc := res.Document
	q := bom.Quality(doc)
	payload := map[string]any{
		"source":          doc.Source,
		"subject":         doc.Name(),
		"components":      len(doc.BOM.Components),
		"dependencies":    len(doc.BOM.Dependencies),
		"vulnerabilities": len(doc.BOM.Vulnerabilities),
		"qualityScore":    q.Score,
	}
	if res.Written != "" {
		payload["written"] = res.Written
	}
	return payload
}

func renderBOMImport(res *BOMImportResult) {
	term := display.NewTerminal()
	doc := res.Document
	src := doc.Source

	fmt.Println(display.Header(term, "SBOM import"))
	fmt.Println()

	label := string(src.Format)
	if src.SpecVersion != "" {
		label += " " + src.SpecVersion
	}
	if src.Envelope != "" {
		label += fmt.Sprintf(" (unwrapped from %s attestation)", src.Envelope)
	}

	rows := [][]string{
		{"Format", label},
		{"Subject", orDash(doc.Name())},
		{"Components", fmt.Sprintf("%d", len(doc.BOM.Components))},
		{"Dependency edges", fmt.Sprintf("%d", countEdges(doc.BOM))},
		{"Vulnerabilities", fmt.Sprintf("%d", len(doc.BOM.Vulnerabilities))},
		{"Digest", "sha256:" + src.Digest},
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Field", MinWidth: 18},
		{Header: "Value"},
	}, rows))

	if res.Written != "" {
		fmt.Println()
		fmt.Printf("%s normalised CycloneDX written to %s\n",
			display.CheckMark(term), display.Bold(term, res.Written))
	}
}

// ── validate ────────────────────────────────────────────────────────────────

var bomValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Check an SBOM's structure and field completeness",
	Long: `Validate an SBOM document.

Two independent checks. The first is structural: can the document be parsed at
its declared spec version. The second is completeness: does each component
actually carry a version, an identifier, a licence, a checksum and a supplier,
and does the document carry an author, a timestamp, a subject and a dependency
graph.

The completeness report is a per-field breakdown, not a badge. A single score
would hide which field is missing, and the missing field is the actionable
part; the score exists only to sort documents against each other.

Exits 1 when the document cannot be parsed, or when --min-score is set and the
completeness score falls below it.

Examples:
  vulnetix bom validate sbom.cdx.json
  vulnetix bom validate sbom.spdx.json --min-score 70
  vulnetix bom validate sbom.cdx.json -o json`,
	Args:         cobra.ExactArgs(1),
	RunE:         runBOMValidate,
	SilenceUsage: true,
}

func runBOMValidate(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	minScore, _ := cmd.Flags().GetInt("min-score")

	doc, err := bom.Load(args[0])
	if err != nil {
		return err
	}
	report := bom.Quality(doc)

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		if err := emitJSON(map[string]any{
			"source":  doc.Source,
			"valid":   true,
			"quality": report,
		}); err != nil {
			return err
		}
	} else {
		renderBOMQuality(doc, report)
	}

	if minScore > 0 && report.Score < minScore {
		return &bomGateError{
			gate:    "sbom-quality",
			message: fmt.Sprintf("SBOM completeness score %d is below the required %d", report.Score, minScore),
		}
	}
	return nil
}

func renderBOMQuality(doc *bom.Document, report *bom.QualityReport) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "SBOM validation"))
	fmt.Println()
	fmt.Printf("%s %s parsed as %s %s (%d components)\n",
		display.CheckMark(term),
		display.Bold(term, filepath.Base(doc.Source.Path)),
		doc.Source.Format, doc.Source.SpecVersion, len(doc.BOM.Components))
	fmt.Println()

	rows := make([][]string, 0, len(report.Document)+len(report.Components))
	for _, f := range append(append([]bom.FieldReport{}, report.Document...), report.Components...) {
		mark := display.CrossMark(term)
		if f.Complete() {
			mark = display.CheckMark(term)
		} else if f.Present > 0 {
			mark = display.WarningMark(term)
		}
		coverage := fmt.Sprintf("%d/%d", f.Present, f.Total)
		rows = append(rows, []string{mark, f.Label, coverage, f.Detail})
	}
	// The mark column is auto-width: display.CheckMark renders a one-cell glyph
	// on a colour terminal and "[OK]" / "[FAIL]" without one, so a fixed width
	// would be wrong in one of the two cases.
	fmt.Print(display.Table(term, []display.Column{
		{Header: ""},
		{Header: "Field", MinWidth: 34},
		{Header: "Coverage", Align: display.AlignRight, MinWidth: 8},
		{Header: "Detail"},
	}, rows))

	fmt.Println()
	fmt.Printf("Completeness score: %s\n", display.Bold(term, fmt.Sprintf("%d/100", report.Score)))
}

// ── diff ────────────────────────────────────────────────────────────────────

var bomDiffCmd = &cobra.Command{
	Use:   "diff <before> <after>",
	Short: "Compare two SBOM documents",
	Long: `Compare two SBOMs and report what changed.

Components are matched by purl first, then bom-ref, then name@version — the
same cascade the CycloneDX merge already uses — so two documents generated by
different tools from the same tree still line up. Version movement is ordered
semantically, so an accidental downgrade reads as a downgrade rather than as an
undifferentiated change.

Reports component additions, removals, upgrades, downgrades and licence
changes; vulnerabilities gained and resolved; and how many dependency-graph
edges moved.

Either side may be CycloneDX or SPDX — comparing an SPDX document against a
CycloneDX one is a supported and useful thing to do, because both normalise to
the same model.

--fail-on makes this a CI change-review gate:
  any                  any component change at all
  added                a component was added
  removed              a component was removed
  downgraded           a component moved backwards
  vuln-added           a vulnerability appeared
  license-regression   a licence changed

Examples:
  vulnetix bom diff before.cdx.json after.cdx.json
  vulnetix bom diff v1.cdx.json v2.spdx.json -o markdown
  vulnetix bom diff base.cdx.json head.cdx.json --fail-on vuln-added`,
	Args:         cobra.ExactArgs(2),
	RunE:         runBOMDiff,
	SilenceUsage: true,
}

func runBOMDiff(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	switch outputFmt {
	case "pretty", "table", "json", "markdown":
	default:
		return fmt.Errorf("--output must be one of: pretty (alias: table), json, markdown")
	}
	failOnRaw, _ := cmd.Flags().GetString("fail-on")
	failOn, err := parseBOMFailOn(failOnRaw)
	if err != nil {
		return err
	}

	from, err := bom.Load(args[0])
	if err != nil {
		return err
	}
	to, err := bom.Load(args[1])
	if err != nil {
		return err
	}
	d := bom.CompareDocuments(from, to)

	ctx := display.FromCommand(cmd)
	switch {
	case outputFmt == "json" || ctx.IsJSON():
		if err := emitJSON(d); err != nil {
			return err
		}
	case outputFmt == "markdown":
		fmt.Print(renderBOMDiffMarkdown(d))
	default:
		renderBOMDiff(d)
	}

	return evaluateBOMDiffGate(d, failOn)
}

// bomFailOn is a parsed --fail-on selection.
type bomFailOn struct {
	any               bool
	added             bool
	removed           bool
	downgraded        bool
	vulnAdded         bool
	licenseRegression bool
}

func (f bomFailOn) empty() bool {
	return !f.any && !f.added && !f.removed && !f.downgraded && !f.vulnAdded && !f.licenseRegression
}

// parseBOMFailOn parses the comma-separated --fail-on value.
func parseBOMFailOn(raw string) (bomFailOn, error) {
	var f bomFailOn
	if raw == "" || raw == "none" {
		return f, nil
	}
	for _, tok := range strings.Split(raw, ",") {
		switch strings.TrimSpace(strings.ToLower(tok)) {
		case "", "none":
		case "any":
			f.any = true
		case "added":
			f.added = true
		case "removed":
			f.removed = true
		case "downgraded":
			f.downgraded = true
		case "vuln-added", "vuln_added", "vulns-added":
			f.vulnAdded = true
		case "license-regression", "license-changed", "license":
			f.licenseRegression = true
		default:
			return f, fmt.Errorf("--fail-on: unknown condition %q (expected: none, any, added, removed, downgraded, vuln-added, license-regression)", tok)
		}
	}
	return f, nil
}

// bomGateError is a policy breach raised by a bom subcommand.
//
// It implements PolicyBreachError so Execute() suppresses the redundant error
// print — the command has already rendered the detail — and so it exits 1 like
// every other gate in the CLI.
type bomGateError struct {
	gate    string
	message string
}

func (e *bomGateError) isPolicyBreach() {}
func (e *bomGateError) Error() string   { return e.message }

// evaluateBOMDiffGate turns a diff into a gate verdict.
func evaluateBOMDiffGate(d *bom.Diff, f bomFailOn) error {
	if f.empty() {
		return nil
	}
	var breaches []string
	s := d.Summary
	switch {
	case f.any && s.Total() > 0:
		breaches = append(breaches, fmt.Sprintf("%d component change(s)", s.Total()))
	}
	if f.added && s.Added > 0 {
		breaches = append(breaches, fmt.Sprintf("%d component(s) added", s.Added))
	}
	if f.removed && s.Removed > 0 {
		breaches = append(breaches, fmt.Sprintf("%d component(s) removed", s.Removed))
	}
	if f.downgraded && s.Downgraded > 0 {
		breaches = append(breaches, fmt.Sprintf("%d component(s) downgraded", s.Downgraded))
	}
	if f.vulnAdded && s.VulnsAdded > 0 {
		breaches = append(breaches, fmt.Sprintf("%d vulnerability(ies) introduced", s.VulnsAdded))
	}
	if f.licenseRegression && s.LicenseChanged > 0 {
		breaches = append(breaches, fmt.Sprintf("%d licence change(s)", s.LicenseChanged))
	}
	if len(breaches) == 0 {
		return nil
	}
	return &bomGateError{gate: "bom-diff", message: "SBOM diff gate breached: " + strings.Join(breaches, "; ")}
}

func renderBOMDiff(d *bom.Diff) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "SBOM diff"))
	fmt.Println()

	if d.Identical {
		fmt.Printf("%s Both inputs are byte-identical (sha256:%s)\n",
			display.CheckMark(term), d.From.Digest[:12])
		return
	}

	s := d.Summary
	fmt.Printf("%s → %s   %d → %d components\n",
		display.Muted(term, sourceLabel(d.From)),
		display.Muted(term, sourceLabel(d.To)),
		s.FromComponents, s.ToComponents)
	fmt.Println()

	if s.Total() == 0 && s.VulnsAdded == 0 && s.VulnsRemoved == 0 {
		fmt.Printf("%s No component or vulnerability changes.\n", display.CheckMark(term))
		return
	}

	if len(d.Components) > 0 {
		rows := make([][]string, 0, len(d.Components))
		for _, c := range d.Components {
			rows = append(rows, []string{
				string(c.Kind),
				preferLabel(c.Name, c.Purl),
				bomVersionCell(c),
				bomLicenseCell(c),
				bomDirectCell(c),
			})
		}
		// No glyph column. display.Table measures width with len() on bytes, so
		// a multi-byte arrow reserves three cells and renders one, shifting
		// every row after it. The Change column already names the change.
		fmt.Print(display.Table(term, []display.Column{
			{Header: "Change", MinWidth: 15, Color: func(s string) string {
				return bomChangeColour(term, s)
			}},
			{Header: "Component", MinWidth: 20, MaxWidth: 40},
			{Header: "Version", MinWidth: 20, MaxWidth: 30},
			{Header: "Licence", MinWidth: 12, MaxWidth: 28},
			{Header: "Direct", MinWidth: 10},
		}, rows))
		fmt.Print("\n\n")
	}

	if len(d.Vulns) > 0 {
		rows := make([][]string, 0, len(d.Vulns))
		for _, v := range d.Vulns {
			verb := "introduced"
			if v.Kind == bom.ChangeRemoved {
				verb = "resolved"
			}
			rows = append(rows, []string{verb, v.ID, orDash(v.Severity)})
		}
		fmt.Println(display.Subheader(term, "Vulnerabilities"))
		fmt.Print(display.Table(term, []display.Column{
			{Header: "Change", MinWidth: 12},
			{Header: "ID", MinWidth: 22},
			{Header: "Severity", Color: bomSeverityColour(term)},
		}, rows))
		fmt.Print("\n\n")
	}

	summary := fmt.Sprintf("%d added · %d removed · %d upgraded · %d downgraded · %d licence · %d vulns in · %d vulns out",
		s.Added, s.Removed, s.Upgraded, s.Downgraded, s.LicenseChanged, s.VulnsAdded, s.VulnsRemoved)
	fmt.Println(display.Bold(term, summary))
	if s.GraphEdgesAdded > 0 || s.GraphEdgesGone > 0 {
		fmt.Println(display.Muted(term, fmt.Sprintf(
			"dependency graph: %d edge(s) added, %d removed", s.GraphEdgesAdded, s.GraphEdgesGone)))
	}
}

func renderBOMDiffMarkdown(d *bom.Diff) string {
	var b strings.Builder
	s := d.Summary

	b.WriteString("## SBOM diff\n\n")
	if d.Identical {
		b.WriteString("Both inputs are byte-identical.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "`%s` → `%s` — %d → %d components\n\n",
		sourceLabel(d.From), sourceLabel(d.To), s.FromComponents, s.ToComponents)

	if s.Total() == 0 && s.VulnsAdded == 0 && s.VulnsRemoved == 0 {
		b.WriteString("No component or vulnerability changes.\n")
		return b.String()
	}

	if len(d.Components) > 0 {
		b.WriteString("| Change | Component | Version | Licence | Direct |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, c := range d.Components {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n",
				c.Kind, preferLabel(c.Name, c.Purl),
				mdCell(bomVersionCell(c)), mdCell(bomLicenseCell(c)), mdCell(bomDirectCell(c)))
		}
		b.WriteString("\n")
	}

	if len(d.Vulns) > 0 {
		b.WriteString("### Vulnerabilities\n\n")
		b.WriteString("| Change | ID | Severity |\n| --- | --- | --- |\n")
		for _, v := range d.Vulns {
			verb := "introduced"
			if v.Kind == bom.ChangeRemoved {
				verb = "resolved"
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", verb, v.ID, mdCell(v.Severity))
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "**%d added · %d removed · %d upgraded · %d downgraded · %d licence · %d vulns in · %d vulns out**\n",
		s.Added, s.Removed, s.Upgraded, s.Downgraded, s.LicenseChanged, s.VulnsAdded, s.VulnsRemoved)
	return b.String()
}

// ── merge ───────────────────────────────────────────────────────────────────

var bomMergeCmd = &cobra.Command{
	Use:   "merge <file> <file...>",
	Short: "Combine SBOM documents into one",
	Long: `Merge two or more SBOMs into a single CycloneDX document.

The merge is purl-keyed and non-destructive: components present in an earlier
document are kept verbatim, later documents fill gaps and contribute new
components, tools, vulnerabilities and dependency edges. Inputs may mix
CycloneDX and SPDX.

Examples:
  vulnetix bom merge app.cdx.json image.spdx.json --out combined.cdx.json
  vulnetix bom merge a.cdx.json b.cdx.json c.cdx.json --out all.cdx.json`,
	Args:         cobra.MinimumNArgs(2),
	RunE:         runBOMMerge,
	SilenceUsage: true,
}

func runBOMMerge(cmd *cobra.Command, args []string) error {
	outPath, _ := cmd.Flags().GetString("out")
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}

	var merged *cdx.BOM
	for _, path := range args {
		doc, err := bom.Load(path)
		if err != nil {
			return err
		}
		// MergeBOMs is the existing, tested purl-keyed merge on the write side.
		// Reusing it is the point — a second merge implementation here would be
		// a second set of conflict rules to keep in step.
		merged = cdx.MergeBOMs(merged, doc.BOM)
	}

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return err
	}
	if outPath != "" {
		if dir := filepath.Dir(outPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		if err := os.WriteFile(outPath, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(map[string]any{
			"inputs":          len(args),
			"components":      len(merged.Components),
			"vulnerabilities": len(merged.Vulnerabilities),
			"written":         outPath,
		})
	}
	if outPath == "" {
		fmt.Println(string(data))
		return nil
	}
	term := display.NewTerminal()
	fmt.Printf("%s merged %d documents into %s (%d components)\n",
		display.CheckMark(term), len(args), display.Bold(term, outPath), len(merged.Components))
	return nil
}

// ── tree ────────────────────────────────────────────────────────────────────

var bomTreeCmd = &cobra.Command{
	Use:   "tree <file>",
	Short: "Walk an SBOM's dependency graph",
	Long: `Render an SBOM's dependency graph as a tree.

The CycloneDX dependency array is a flat edge set — the right shape to store,
the wrong shape to read. This walks it.

--invert is the direction that matters during triage: instead of "what does
this depend on", it answers "what pulls this in", which is the question a
vulnerable transitive package raises.

Cycles are marked and elided rather than followed; dependency graphs do contain
them.

Examples:
  vulnetix bom tree sbom.cdx.json
  vulnetix bom tree sbom.cdx.json --depth 3
  vulnetix bom tree sbom.cdx.json --component lodash --invert
  vulnetix bom tree sbom.cdx.json --component pkg:npm/lodash -o json`,
	Args:         cobra.ExactArgs(1),
	RunE:         runBOMTree,
	SilenceUsage: true,
}

func runBOMTree(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	component, _ := cmd.Flags().GetString("component")
	invert, _ := cmd.Flags().GetBool("invert")
	depth, _ := cmd.Flags().GetInt("depth")

	doc, err := bom.Load(args[0])
	if err != nil {
		return err
	}
	root, err := bom.BuildTree(doc, bom.TreeOptions{
		Root: component, Invert: invert, MaxDepth: depth,
	})
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(root)
	}

	term := display.NewTerminal()
	heading := "Dependency tree"
	if invert {
		heading = "Reverse dependency tree"
	}
	fmt.Println(display.Header(term, heading))
	fmt.Println()
	var b strings.Builder
	renderTreeNode(&b, term, root, "", true, true)
	fmt.Print(b.String())
	fmt.Println()
	fmt.Println(display.Muted(term, fmt.Sprintf("%d nodes", root.Count())))
	return nil
}

// renderTreeNode writes one node and its subtree using box-drawing connectors.
func renderTreeNode(b *strings.Builder, term *display.Terminal, n *bom.TreeNode, prefix string, isLast, isRoot bool) {
	label := n.Name
	if n.Version != "" {
		label += "@" + n.Version
	}
	switch {
	case isRoot:
		b.WriteString(display.Bold(term, label) + "\n")
	default:
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		suffix := ""
		if n.Cycle {
			suffix = " " + display.Muted(term, "(cycle)")
		} else if n.Elided {
			suffix = " " + display.Muted(term, "(…)")
		}
		b.WriteString(prefix + connector + label + suffix + "\n")
	}

	childPrefix := prefix
	if !isRoot {
		if isLast {
			childPrefix += "    "
		} else {
			childPrefix += "│   "
		}
	}
	for i, child := range n.Children {
		renderTreeNode(b, term, child, childPrefix, i == len(n.Children)-1, false)
	}
}

// ── shared flags and helpers ────────────────────────────────────────────────

func init() {
	bomImportCmd.Flags().String("out", "", "Write the normalised CycloneDX document to this path")
	bomImportCmd.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	scanopts.AddDeploymentFlags(bomImportCmd.Flags())

	bomValidateCmd.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	bomValidateCmd.Flags().Int("min-score", 0, "Exit non-zero when the completeness score is below this value (0 disables)")

	bomDiffCmd.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json, markdown")
	bomDiffCmd.Flags().String("fail-on", "none", "Exit non-zero on these changes: none, any, added, removed, downgraded, vuln-added, license-regression (comma-separated)")

	bomMergeCmd.Flags().String("out", "", "Write the merged CycloneDX document to this path (default: stdout)")
	bomMergeCmd.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")

	bomTreeCmd.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	bomTreeCmd.Flags().String("component", "", "Root the tree at this component (purl, bom-ref, name, or substring)")
	bomTreeCmd.Flags().Bool("invert", false, "Show what depends on the component instead of what it depends on")
	bomTreeCmd.Flags().Int("depth", 0, "Maximum tree depth (0 = unlimited)")
}

// validateBOMOutput checks the shared pretty/json --output values.
func validateBOMOutput(format string) error {
	switch format {
	case "pretty", "table", "json":
		return nil
	default:
		return fmt.Errorf("--output must be one of: pretty (alias: table), json")
	}
}

// emitJSON writes an indented JSON payload to stdout.
func emitJSON(payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// countEdges totals the dependency edges in a document.
func countEdges(b *cdx.BOM) int {
	total := 0
	for _, d := range b.Dependencies {
		total += len(d.DependsOn)
	}
	return total
}

// sourceLabel is the shortest useful label for a document source.
func sourceLabel(s bom.SourceInfo) string {
	if s.Path != "" {
		return filepath.Base(s.Path)
	}
	if len(s.Digest) >= 12 {
		return "sha256:" + s.Digest[:12]
	}
	return string(s.Format)
}

// bomChangeColour styles a change label by how much attention it deserves.
//
// Removals and downgrades are the changes most likely to be unintentional, so
// they read as errors; additions and upgrades are the expected outcome of a
// dependency bump.
//
// display.Table hands the Color function the cell already padded to the column
// width, so the padded string is what gets styled (dropping it would collapse
// the column) while the trimmed value is what the switch matches on.
func bomChangeColour(term *display.Terminal, cell string) string {
	switch bom.ChangeKind(strings.TrimSpace(cell)) {
	case bom.ChangeAdded, bom.ChangeUpgraded:
		return display.Success(term, cell)
	case bom.ChangeRemoved, bom.ChangeDowngraded:
		return display.ErrorStyle(term, cell)
	default:
		return display.Accent(term, cell)
	}
}

// bomSeverityColour returns a table cell colouriser for a severity column.
//
// display.SeverityText looks the colour up from the string it is given, and
// display.Table gives it a cell padded to the column width — so the padding has
// to be trimmed for the lookup and re-applied for the render, or every severity
// falls through to the default colour.
func bomSeverityColour(term *display.Terminal) func(string) string {
	return func(cell string) string {
		trimmed := strings.TrimSpace(cell)
		if trimmed == "" || trimmed == "—" {
			return cell
		}
		return display.SeverityText(term, trimmed) + strings.Repeat(" ", len(cell)-len(trimmed))
	}
}

// bomVersionCell renders the version movement for a change row.
func bomVersionCell(c bom.ComponentChange) string {
	switch {
	case c.FromVersion != "" && c.ToVersion != "" && c.FromVersion != c.ToVersion:
		return c.FromVersion + " → " + c.ToVersion
	case c.ToVersion != "":
		return c.ToVersion
	case c.FromVersion != "":
		return c.FromVersion
	default:
		return "—"
	}
}

// bomLicenseCell renders the licence movement for a change row.
func bomLicenseCell(c bom.ComponentChange) string {
	if c.Kind != bom.ChangeLicense {
		return orDash(preferLabel(c.ToLicense, c.FromLicense))
	}
	return orDash(c.FromLicense) + " → " + orDash(c.ToLicense)
}

// bomDirectCell renders directness, which is null when there is no graph to
// answer from — an unmeasurable fact must not render as "no".
func bomDirectCell(c bom.ComponentChange) string {
	if c.Direct == nil {
		return "—"
	}
	if *c.Direct {
		return "direct"
	}
	return "transitive"
}

// mdCell escapes a markdown table cell.
func mdCell(s string) string {
	if s == "" {
		return "—"
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

// preferLabel returns the first non-empty argument.
func preferLabel(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// orDash renders an em dash for an empty value.
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
