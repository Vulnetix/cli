package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/vex"
)

// ─────────────────────────────────────────────────────────────────────────
// vex.go — owner file for the `vex` command family: the READ side of VEX.
//
// internal/triage writes VEX from this CLI's own triage decisions, and
// cmd/reconcile.go emits five variants into .vulnetix/. None of that could read
// a VEX document back in — so the case VEX actually exists for, an upstream
// publishing "this CVE does not affect the configuration we ship", had no way
// to reach a scan.
//
// runVEXPass is the shared entry function per the capability-owner rule in
// AGENTS.md: `vex apply` and the scan engine's --vex-file both call it, so the
// suppression a standalone run computes and the suppression a scan applies can
// never diverge.
// ─────────────────────────────────────────────────────────────────────────

var vexRootCmd = &cobra.Command{
	Use:   "vex",
	Short: "Read, validate and apply VEX statements",
	Long: `Consume VEX documents — including ones this CLI did not produce.

Reads OpenVEX 0.2.0, CycloneDX VEX and CSAF 2.0 VEX, normalising all three into
one statement model so matching and application are the same regardless of who
published the document or in which format.

Matching is not exact-equality on (vulnerability, purl). A statement written
against pkg:npm/foo@1.2.3 also reaches 1.2.4 when the statement scopes a range,
a statement naming a package with no version covers every version of it, and
identifiers given as URLs (a pkg.go.dev vuln link, an NVD link) are reduced to
the bare id before comparison. Exact-equality matching is why VEX so often
appears to do nothing: the statement is simply never applied, with no error.

Every applied statement records why it matched and which document asserted it.
Suppressed findings are annotated and reported, never deleted — a count that
silently went down cannot be audited.

Subcommands:
  apply     apply statements to an SBOM or to stored scan findings
  ls        list statements and what they assert
  validate  check documents for structural and semantic problems
  merge     combine documents, newest statement per product wins`,
	SilenceUsage: true,
}

func init() {
	vexRootCmd.AddCommand(vexApplyCmd, vexLsCmd, vexValidateCmd, vexMergeCmd)
	rootCmd.AddCommand(vexRootCmd)
}

// VEXPassOptions is the options struct for the one entry point into VEX
// application. See the file header for why this exists.
type VEXPassOptions struct {
	// Paths are the VEX files or directories to read.
	Paths []string
	// BOM is the document to apply statements to. Modified in place.
	BOM *cdx.BOM
}

// VEXPassResult is what applying a statement set produced.
type VEXPassResult struct {
	// Result carries the total/effective/suppressed split.
	Result *vex.Result
	// Documents is the number of VEX documents read.
	Documents int
	// Statements is the number of statements indexed.
	Statements int
	// Skipped names files under a supplied directory that were not VEX.
	Skipped []string
	// Problems are validation problems found in the supplied documents.
	Problems map[string][]vex.Problem
}

// runVEXPass reads VEX documents and applies them to a BOM.
//
// This is the shared entry point: `vex apply` and the scan engine both call it.
// A nil BOM is valid — the documents are still read and validated, which is
// what `vex ls` and `vex validate` need.
func runVEXPass(opts VEXPassOptions) (*VEXPassResult, error) {
	docs, skipped, err := vex.LoadAll(opts.Paths)
	if err != nil {
		return nil, err
	}

	res := &VEXPassResult{
		Documents: len(docs),
		Skipped:   skipped,
		Problems:  map[string][]vex.Problem{},
	}
	for _, d := range docs {
		if problems := d.Validate(); len(problems) > 0 {
			res.Problems[d.Path] = problems
		}
	}

	set := vex.NewSet(docs)
	res.Statements = set.Len()
	res.Result = vex.Apply(opts.BOM, set)
	return res, nil
}

// filterVEXSuppressed removes findings a VEX statement closed from the gate input.
//
// The scan engine's gates read enrichedVulns, not the BOM, so annotating the
// document is not enough to stop a suppressed finding from failing a build.
// Filtering here — once, before any gate — is what makes every gate honour VEX
// without each of them having to remember to.
//
// Only not_affected and fixed remove a finding. An `affected` statement adds an
// action statement, which is useful information, but it does not close
// anything; treating it as a suppression would be the exact opposite of what
// the publisher said.
func filterVEXSuppressed(vulns []scan.EnrichedVuln, pass *VEXPassResult) []scan.EnrichedVuln {
	if pass == nil || pass.Result == nil || pass.Result.Suppressed == 0 {
		return vulns
	}
	suppressed := make(map[string]bool, pass.Result.Suppressed)
	for _, a := range pass.Result.Applied {
		if a.Suppressed {
			suppressed[strings.ToUpper(a.VulnID)] = true
		}
	}
	if len(suppressed) == 0 {
		return vulns
	}
	out := make([]scan.EnrichedVuln, 0, len(vulns))
	for _, v := range vulns {
		if suppressed[strings.ToUpper(v.CveID)] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// vexSuppressedCount is how many findings VEX closed, or 0 when none ran.
func vexSuppressedCount(pass *VEXPassResult) int {
	if pass == nil || pass.Result == nil {
		return 0
	}
	return pass.Result.Suppressed
}

// reportVEXPass prints the total/effective/suppressed split during a scan.
//
// Printed to stderr so a `-o json-cyclonedx` run still emits a clean document
// on stdout, and printed at all because a suppressed count that silently
// changed the outcome of a gate is exactly the thing a reviewer needs told.
func reportVEXPass(pass *VEXPassResult) {
	r := pass.Result
	if r == nil || pass.Statements == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\nVEX: %d statement(s) from %d document(s) — %d suppressed, %d effective\n",
		pass.Statements, pass.Documents, r.Suppressed, r.Effective)
	for _, a := range r.Applied {
		if !a.Suppressed {
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-20s %s (%s)\n", a.VulnID, a.Status, sourceName(a.Source))
	}
	if r.Unmatched > 0 {
		fmt.Fprintf(os.Stderr,
			"  note: %d statement(s) matched no finding — check they describe this product\n", r.Unmatched)
	}
}

// ── apply ───────────────────────────────────────────────────────────────────

var vexApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply VEX statements to an SBOM",
	Long: `Apply VEX statements to a CycloneDX or SPDX document.

Each vulnerability entry the statements reach gains a CycloneDX analysis block
naming the status and, for not_affected, the justification — plus namespaced
properties recording which document asserted it, who authored it and on what
basis it matched. Nothing is removed: a suppressed finding stays in the
document, marked.

Counts are reported three ways. Total is every entry. Suppressed is what a
not_affected or fixed statement closed. Effective is what remains, and is the
number a reviewer should act on.

--fail-on-effective turns this into a CI gate on the count that survives VEX,
which is the honest number to gate on.

Examples:
  vulnetix vex apply --vex vendor.openvex.json --bom sbom.cdx.json
  vulnetix vex apply --vex ./vex/ --bom sbom.cdx.json --out annotated.cdx.json
  vulnetix vex apply --vex csaf.json --bom sbom.spdx.json -o json
  vulnetix vex apply --vex ./vex/ --bom sbom.cdx.json --fail-on-effective 0`,
	RunE:         runVEXApply,
	SilenceUsage: true,
}

func runVEXApply(cmd *cobra.Command, args []string) error {
	paths, _ := cmd.Flags().GetStringArray("vex")
	bomPath, _ := cmd.Flags().GetString("bom")
	outPath, _ := cmd.Flags().GetString("out")
	outputFmt, _ := cmd.Flags().GetString("output")
	failOnEffective, _ := cmd.Flags().GetInt("fail-on-effective")

	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("--vex is required: pass one or more VEX files or directories")
	}
	if bomPath == "" {
		return fmt.Errorf("--bom is required: pass the SBOM to apply the statements to")
	}

	// Through runBOMImport, not a direct parse: that is the one entry point
	// into SBOM reading, so `vex apply --bom` gets attestation-envelope
	// unwrapping and SPDX normalisation for free rather than reimplementing a
	// weaker version of both.
	imported, err := runBOMImport(BOMImportOptions{Path: bomPath})
	if err != nil {
		return err
	}
	doc := imported.Document

	pass, err := runVEXPass(VEXPassOptions{Paths: paths, BOM: doc.BOM})
	if err != nil {
		return err
	}

	if outPath != "" {
		data, mErr := json.MarshalIndent(doc.BOM, "", "  ")
		if mErr != nil {
			return mErr
		}
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
		if err := emitJSON(map[string]any{
			"documents":  pass.Documents,
			"statements": pass.Statements,
			"result":     pass.Result,
			"skipped":    pass.Skipped,
			"written":    outPath,
		}); err != nil {
			return err
		}
	} else {
		renderVEXApply(pass, outPath)
	}

	// A negative threshold means the gate is off; zero is a real, and useful,
	// threshold — "no vulnerability may survive VEX".
	if failOnEffective >= 0 && pass.Result.Effective > failOnEffective {
		return &bomGateError{
			gate: "vex-effective",
			message: fmt.Sprintf("%d effective vulnerability(ies) after VEX exceeds the allowed %d",
				pass.Result.Effective, failOnEffective),
		}
	}
	return nil
}

func renderVEXApply(pass *VEXPassResult, outPath string) {
	term := display.NewTerminal()
	r := pass.Result

	fmt.Println(display.Header(term, "VEX applied"))
	fmt.Println()
	fmt.Printf("%s\n\n", display.Muted(term, fmt.Sprintf(
		"%d statement(s) from %d document(s)", pass.Statements, pass.Documents)))

	fmt.Print(display.Table(term, []display.Column{
		{Header: "Vulnerabilities", MinWidth: 18},
		{Header: "Count", Align: display.AlignRight, MinWidth: 7},
		{Header: "Meaning"},
	}, [][]string{
		{"Total", fmt.Sprintf("%d", r.Total), "every entry in the document"},
		{"Suppressed", fmt.Sprintf("%d", r.Suppressed), "closed by a not_affected or fixed statement"},
		{"Annotated", fmt.Sprintf("%d", r.Annotated), "statement attached, still live"},
		{"Effective", fmt.Sprintf("%d", r.Effective), "what remains to act on"},
	}))
	fmt.Print("\n\n")

	if len(r.Applied) > 0 {
		rows := make([][]string, 0, len(r.Applied))
		for _, a := range r.Applied {
			verdict := "annotated"
			if a.Suppressed {
				verdict = "suppressed"
			}
			rows = append(rows, []string{
				a.VulnID, string(a.Status), verdict, string(a.Basis), sourceName(a.Source),
			})
		}
		fmt.Println(display.Subheader(term, "Statements applied"))
		fmt.Print(display.Table(term, []display.Column{
			{Header: "Vulnerability", MinWidth: 20},
			{Header: "Status", MinWidth: 18},
			{Header: "Effect", MinWidth: 11},
			{Header: "Matched on", MinWidth: 20},
			{Header: "Source"},
		}, rows))
		fmt.Print("\n\n")
	}

	// An unmatched statement is the single most common reason VEX appears not
	// to work, so it is surfaced rather than left for the user to deduce from a
	// suppressed count that did not move.
	if r.Unmatched > 0 {
		fmt.Printf("%s %s\n", display.WarningMark(term), display.Muted(term, fmt.Sprintf(
			"%d statement(s) matched no finding in this document — check they describe the same product",
			r.Unmatched)))
	}
	renderVEXProblems(term, pass)

	if outPath != "" {
		fmt.Printf("%s annotated document written to %s\n",
			display.CheckMark(term), display.Bold(term, outPath))
	}
}

// ── ls ──────────────────────────────────────────────────────────────────────

var vexLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List VEX statements and what they assert",
	Long: `List the statements in one or more VEX documents.

Reads OpenVEX, CycloneDX VEX and CSAF VEX. Shows each statement's
vulnerability, status, justification and the product it is scoped to, so a set
of documents can be reviewed before it is trusted to suppress anything.

Examples:
  vulnetix vex ls --vex ./vex/
  vulnetix vex ls --vex vendor.openvex.json -o json
  vulnetix vex ls --vex ./vex/ --status not_affected`,
	RunE:         runVEXLs,
	SilenceUsage: true,
}

func runVEXLs(cmd *cobra.Command, args []string) error {
	paths, _ := cmd.Flags().GetStringArray("vex")
	outputFmt, _ := cmd.Flags().GetString("output")
	statusFilter, _ := cmd.Flags().GetString("status")

	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("--vex is required: pass one or more VEX files or directories")
	}

	docs, skipped, err := vex.LoadAll(paths)
	if err != nil {
		return err
	}

	var statements []vex.Statement
	for _, d := range docs {
		for _, s := range d.Statements {
			if statusFilter != "" && string(s.Status) != statusFilter {
				continue
			}
			statements = append(statements, s)
		}
	}
	sort.SliceStable(statements, func(i, j int) bool {
		if statements[i].VulnID != statements[j].VulnID {
			return statements[i].VulnID < statements[j].VulnID
		}
		return statements[i].Status < statements[j].Status
	})

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(map[string]any{
			"documents":  len(docs),
			"statements": statements,
			"skipped":    skipped,
		})
	}

	term := display.NewTerminal()
	fmt.Println(display.Header(term, "VEX statements"))
	fmt.Println()
	if len(statements) == 0 {
		fmt.Println(display.Muted(term, "No statements matched."))
		return nil
	}

	rows := make([][]string, 0, len(statements))
	for _, s := range statements {
		rows = append(rows, []string{
			s.VulnID,
			string(s.Status),
			orDash(s.Justification),
			orDash(vexProductLabel(s)),
			sourceName(s.Source.Path),
		})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Vulnerability", MinWidth: 20},
		{Header: "Status", MinWidth: 18},
		{Header: "Justification", MinWidth: 24, MaxWidth: 36},
		{Header: "Product", MinWidth: 24, MaxWidth: 40},
		{Header: "Source"},
	}, rows))
	fmt.Print("\n\n")
	fmt.Println(display.Muted(term, fmt.Sprintf(
		"%d statement(s) from %d document(s)", len(statements), len(docs))))
	return nil
}

// ── validate ────────────────────────────────────────────────────────────────

var vexValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check VEX documents for structural and semantic problems",
	Long: `Validate VEX documents.

Structural validity is not enough for VEX. A document can parse cleanly and
still assert nothing usable: a not_affected with no justification (invalid per
OpenVEX — the argument is the whole point of the status), a statement naming no
vulnerability, a status outside the vocabulary, an affected status with no
action statement.

Exits 1 when any problem is fatal — that is, when a statement cannot be used.

Examples:
  vulnetix vex validate --vex vendor.openvex.json
  vulnetix vex validate --vex ./vex/ -o json`,
	RunE:         runVEXValidate,
	SilenceUsage: true,
}

func runVEXValidate(cmd *cobra.Command, args []string) error {
	paths, _ := cmd.Flags().GetStringArray("vex")
	outputFmt, _ := cmd.Flags().GetString("output")

	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("--vex is required: pass one or more VEX files or directories")
	}

	pass, err := runVEXPass(VEXPassOptions{Paths: paths})
	if err != nil {
		return err
	}

	fatal := false
	for _, problems := range pass.Problems {
		if vex.Fatal(problems) {
			fatal = true
		}
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		if err := emitJSON(map[string]any{
			"documents":  pass.Documents,
			"statements": pass.Statements,
			"problems":   pass.Problems,
			"valid":      !fatal,
			"skipped":    pass.Skipped,
		}); err != nil {
			return err
		}
	} else {
		term := display.NewTerminal()
		fmt.Println(display.Header(term, "VEX validation"))
		fmt.Println()
		fmt.Printf("%d statement(s) across %d document(s)\n\n", pass.Statements, pass.Documents)
		renderVEXProblems(term, pass)
		if len(pass.Problems) == 0 {
			fmt.Printf("%s No problems found.\n", display.CheckMark(term))
		}
	}

	if fatal {
		return &bomGateError{gate: "vex-validate", message: "one or more VEX statements are unusable"}
	}
	return nil
}

func renderVEXProblems(term *display.Terminal, pass *VEXPassResult) {
	if len(pass.Problems) == 0 {
		return
	}
	paths := make([]string, 0, len(pass.Problems))
	for p := range pass.Problems {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var rows [][]string
	for _, p := range paths {
		for _, problem := range pass.Problems[p] {
			severity := "warning"
			if problem.Fatal {
				severity = "fatal"
			}
			rows = append(rows, []string{severity, sourceName(p), problem.Message})
		}
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Severity", MinWidth: 9},
		{Header: "Document", MinWidth: 22, MaxWidth: 34},
		{Header: "Problem"},
	}, rows))
	fmt.Print("\n\n")
}

// ── merge ───────────────────────────────────────────────────────────────────

var vexMergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Combine VEX documents into one",
	Long: `Merge VEX documents into a single OpenVEX document.

Statements are keyed by (vulnerability, product); when two documents assert
different things about the same pair, the newer timestamp wins, because VEX is
a running assertion and a later statement supersedes an earlier one.

Inputs may mix OpenVEX, CycloneDX VEX and CSAF VEX; the output is always
OpenVEX 0.2.0.

Examples:
  vulnetix vex merge --vex vendor.openvex.json --vex ours.json --out merged.openvex.json
  vulnetix vex merge --vex ./vex/ --out merged.openvex.json`,
	RunE:         runVEXMerge,
	SilenceUsage: true,
}

func runVEXMerge(cmd *cobra.Command, args []string) error {
	paths, _ := cmd.Flags().GetStringArray("vex")
	outPath, _ := cmd.Flags().GetString("out")
	outputFmt, _ := cmd.Flags().GetString("output")

	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("--vex is required: pass one or more VEX files or directories")
	}

	docs, _, err := vex.LoadAll(paths)
	if err != nil {
		return err
	}
	merged := vex.Merge(docs)

	data, err := vex.WriteOpenVEX(merged, vex.WriteOptions{Tooling: "vulnetix-cli/" + version})
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
			"inputs":     len(docs),
			"statements": len(merged),
			"written":    outPath,
		})
	}
	if outPath == "" {
		fmt.Println(string(data))
		return nil
	}
	term := display.NewTerminal()
	fmt.Printf("%s merged %d document(s) into %s (%d statements)\n",
		display.CheckMark(term), len(docs), display.Bold(term, outPath), len(merged))
	return nil
}

// ── flags and helpers ───────────────────────────────────────────────────────

func init() {
	for _, c := range []*cobra.Command{vexApplyCmd, vexLsCmd, vexValidateCmd, vexMergeCmd} {
		c.Flags().StringArray("vex", nil, "VEX file or directory to read (repeatable)")
		c.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	}
	vexApplyCmd.Flags().String("bom", "", "SBOM to apply the statements to")
	vexApplyCmd.Flags().String("out", "", "Write the annotated CycloneDX document to this path")
	vexApplyCmd.Flags().Int("fail-on-effective", -1,
		"Exit non-zero when more than this many vulnerabilities survive VEX (-1 disables)")

	vexLsCmd.Flags().String("status", "",
		"Only list statements with this status: not_affected, affected, fixed, under_investigation")

	vexMergeCmd.Flags().String("out", "", "Write the merged OpenVEX document to this path (default: stdout)")
}

// vexProductLabel renders a statement's products for a table cell.
func vexProductLabel(s vex.Statement) string {
	labels := make([]string, 0, len(s.Products))
	for _, p := range s.Products {
		if l := preferLabel(p.Purl, p.ID); l != "" {
			labels = append(labels, l)
		}
	}
	if len(labels) == 0 {
		return ""
	}
	sort.Strings(labels)
	if len(labels) > 2 {
		return strings.Join(labels[:2], ", ") + ", …"
	}
	return strings.Join(labels, ", ")
}

// sourceName shortens a document path for display.
func sourceName(path string) string {
	if path == "" {
		return "—"
	}
	return filepath.Base(path)
}
