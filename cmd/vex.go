package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/internal/artifacts"
	"github.com/vulnetix/cli/v4/internal/cdx"
	"github.com/vulnetix/cli/v4/internal/display"
	"github.com/vulnetix/cli/v4/internal/gitctx"
	"github.com/vulnetix/cli/v4/internal/purl"
	"github.com/vulnetix/cli/v4/internal/scan"
	"github.com/vulnetix/cli/v4/internal/suppress"
	"github.com/vulnetix/cli/v4/internal/vex"
	"github.com/vulnetix/cli/v4/pkg/vdb"
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
	// Console are the rules the Vulnetix console holds for the repository that
	// came from VEX statements (see consoleVEXRules). They are applied with the
	// documents, after those, and a statement a document already makes is not
	// counted twice.
	Console []vex.ConsoleRule
	// Org are the organisation's own statements about this scan's findings (see
	// scanOrgVEX), and Repo the repository the scan is in. Each is checked before
	// it can close anything: see vex.CheckOrgStatements.
	Org  []vex.OrgStatement
	Repo string
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
	// ConsoleStatements is how many console statements were applied alongside
	// the documents, ConsoleDuplicates how many were left out because a document
	// or another console rule already made them, and ConsoleSkipped how many
	// rules had no status this CLI reads.
	ConsoleStatements, ConsoleDuplicates, ConsoleSkipped int
	// OrgCheck says what became of the organisation's statements, and OrgHeld
	// names the findings left open because a statement about them was overruled.
	OrgCheck *vex.OrgCheck
	OrgHeld  []vex.HeldFinding
	// Raw holds the exact bytes of every document read, so a caller can send
	// them to Vulnetix unchanged (see ingestVEX).
	Raw []vexRawDocument
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
		if d.Path != "" {
			if data, rerr := os.ReadFile(d.Path); rerr == nil {
				res.Raw = append(res.Raw, vexRawDocument{Path: d.Path, Data: data})
			}
		}
	}

	if len(opts.Console) > 0 {
		console, skippedRules := vex.ConsoleDocument(opts.Console)
		console, dup := vex.DedupeConsole(console, docs)
		res.ConsoleSkipped, res.ConsoleDuplicates = skippedRules, dup
		res.ConsoleStatements = len(console.Statements)
		if res.ConsoleStatements > 0 {
			docs = append(docs, console)
		}
	}

	var held []vex.HeldStatement
	if len(opts.Org) > 0 {
		check := vex.CheckOrgStatements(opts.Org, opts.Repo)
		res.OrgCheck, held = &check, check.Held
		org, _ := vex.DedupeConsole(check.Document, docs)
		if len(org.Statements) > 0 {
			res.ConsoleStatements += len(org.Statements)
			docs = append(docs, org)
		}
	}

	set := vex.NewSet(docs)
	res.Statements = set.Len()
	res.Result = vex.Apply(opts.BOM, set)
	res.OrgHeld = vex.MarkHeld(opts.BOM, held)
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
	// A statement closes one package's finding, not the vulnerability: the same
	// CVE in another package stays. An entry with no purl has only its id.
	byPackage := make(map[string]bool, pass.Result.Suppressed)
	wholeID := make(map[string]bool)
	for _, a := range pass.Result.Applied {
		if !a.Suppressed {
			continue
		}
		id := strings.ToUpper(a.VulnID)
		names, version := purlPackageNames(a.Purl)
		if len(names) == 0 {
			wholeID[id] = true
			continue
		}
		for _, name := range names {
			byPackage[vulnPackageKey(id, name, version)] = true
		}
	}
	if len(byPackage) == 0 && len(wholeID) == 0 {
		return vulns
	}
	out := make([]scan.EnrichedVuln, 0, len(vulns))
	for _, v := range vulns {
		id := strings.ToUpper(v.CveID)
		if wholeID[id] || v.PackageName == "" && hasVulnID(byPackage, id) ||
			byPackage[vulnPackageKey(id, v.PackageName, v.PackageVer)] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// vulnPackageKey identifies one package's finding of a vulnerability.
func vulnPackageKey(id, name, version string) string {
	return id + "\x00" + strings.ToLower(name) + "\x00" + version
}

// hasVulnID reports whether any package's finding of id was closed, for a
// finding that does not say which package it is about.
func hasVulnID(byPackage map[string]bool, id string) bool {
	for key := range byPackage {
		if strings.HasPrefix(key, id+"\x00") {
			return true
		}
	}
	return false
}

// purlPackageNames is every way a finding may spell the package a purl names,
// and its version. purl.PackageName is the ecosystem's own spelling; a namespace
// it leaves out (composer's vendor/pkg) is tried as well.
func purlPackageNames(raw string) (names []string, version string) {
	p, err := purl.Parse(raw)
	if err != nil || p.Name == "" {
		return nil, ""
	}
	names = []string{p.PackageName(), p.Name}
	if p.Namespace != "" {
		names = append(names, p.Namespace+"/"+p.Name)
	}
	return names, p.Version
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
	reportOrgVEXHeld(pass)
	r := pass.Result
	if r == nil || pass.Statements == 0 {
		return
	}
	// "VEX not affected", never "suppressed by rule": a statement is the
	// publisher's assertion about this product, not an ignore rule anyone here
	// wrote, and it is not reported to the server as a rule application.
	if pass.ConsoleStatements > 0 {
		fmt.Fprintf(os.Stderr, "\nVEX: %d statement(s) from %d document(s) and %d from Vulnetix, %d hidden as VEX not affected, %d effective\n",
			pass.Statements-pass.ConsoleStatements, pass.Documents, pass.ConsoleStatements, r.Suppressed, r.Effective)
	} else {
		fmt.Fprintf(os.Stderr, "\nVEX: %d statement(s) from %d document(s), %d hidden as VEX not affected, %d effective\n",
			pass.Statements, pass.Documents, r.Suppressed, r.Effective)
	}
	for _, a := range r.Applied {
		if !a.Suppressed {
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-20s %s (%s)\n", a.VulnID, vexHiddenLabel(a.Status), sourceName(a.Source))
	}
	if r.Unmatched > 0 {
		fmt.Fprintf(os.Stderr,
			"  note: %d statement(s) matched no finding — check they describe this product\n", r.Unmatched)
	}
}

// vexIngestFormat names a document's format in the /v2/cli.vex-ingest
// vocabulary, or "" when it is not a VEX format the server reads. Here, in the
// owner file, so format detection stays in one place (vex_ownership_test.go).
func vexIngestFormat(data []byte) string {
	switch vex.Detect(data) {
	case vex.FormatOpenVEX:
		return "openvex"
	case vex.FormatCycloneDX:
		return "cyclonedx"
	case vex.FormatCSAF:
		return "csaf"
	}
	return ""
}

// vexHiddenLabel is how a finding a VEX statement closed is named in output.
func vexHiddenLabel(status vex.Status) string {
	if status == vex.StatusFixed {
		return "VEX fixed"
	}
	return "VEX not affected"
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
		if err := artifacts.WriteFile(outPath, append(data, '\n'), 0o644, "vex"); err != nil {
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

	if upload, _ := cmd.Flags().GetBool("upload"); upload {
		ensureVDBCredentials()
		if !vexIngestAllowed() {
			fmt.Fprintln(os.Stderr, "  VEX not sent: --upload needs an authenticated CLI (run 'vulnetix auth login')")
		} else {
			ingestVEX(cmd.Context(), vexIngestInput{
				Origin: vdb.VexOriginScanVexFile,
				Docs:   pass.Raw,
				Git:    cwdGitContext(cliGitDir()),
			})
		}
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
		{"VEX not affected", fmt.Sprintf("%d", r.Suppressed), "closed by a not_affected or fixed statement"},
		{"Annotated", fmt.Sprintf("%d", r.Annotated), "statement attached, still live"},
		{"Effective", fmt.Sprintf("%d", r.Effective), "what remains to act on"},
	}))
	fmt.Print("\n\n")

	if len(r.Applied) > 0 {
		rows := make([][]string, 0, len(r.Applied))
		for _, a := range r.Applied {
			verdict := "annotated"
			if a.Suppressed {
				verdict = vexHiddenLabel(a.Status)
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
		if err := artifacts.WriteFile(outPath, append(data, '\n'), 0o644, "vex"); err != nil {
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
	vexApplyCmd.Flags().Bool("upload", false,
		"Send the VEX documents to Vulnetix, which turns their false positive and won't fix statements into suppression rules")

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
	if rest, ok := strings.CutPrefix(path, vex.ConsolePathPrefix); ok {
		return "Vulnetix " + rest
	}
	return filepath.Base(path)
}

// isVEXDocument reports whether data is an OpenVEX, CycloneDX VEX or CSAF VEX
// document. The config and source helpers ask here instead of importing
// internal/vex, so this file stays the one owner of VEX consumption.
func isVEXDocument(data []byte) bool { return vex.Detect(data) != vex.FormatUnknown }

// vexDocumentAuthor parses a VEX file and returns its author.
func vexDocumentAuthor(path string) (string, error) {
	doc, err := vex.Load(path)
	if err != nil {
		return "", err
	}
	return doc.Author, nil
}

// consoleVEXRules are the rules a scan applies as VEX: those the console made
// from a VEX statement (a VexSource of any type, or a VEX document ingested
// from a scan or an upload). Every other rule is an ignore rule, applied by
// internal/suppress.
func consoleVEXRules(rows []vdb.CliSuppression, repo, branch string) []vex.ConsoleRule {
	var out []vex.ConsoleRule
	for _, s := range rows {
		if !isConsoleVEXRule(s) || !s.IsActive {
			continue
		}
		// The server narrows to the repository and branch it is told. A scan
		// that does not know them (outside a git checkout) is told nothing and
		// gets every repository's rules, so a rule scoped to a repository or a
		// branch applies only where the scan knows it is that one.
		if s.RepositoryFullName != "" && !strings.EqualFold(s.RepositoryFullName, repo) {
			continue
		}
		if s.BranchName != "" && !strings.EqualFold(s.BranchName, branch) {
			continue
		}
		out = append(out, vex.ConsoleRule{
			VulnerabilityID: s.VulnerabilityID, ProductPurl: s.ProductPurl, ProductPurlBase: s.ProductPurlBase,
			Status: s.Status, Justification: s.Justification, Reason: s.Reason,
			Source: s.Source, SourceType: s.SourceType, SourceRef: s.SourceRef, DocumentID: s.SourceDocumentID,
			Timestamp: s.StatementTimestamp,
		})
	}
	return out
}

// isConsoleVEXRule reports whether a rule came from a VEX statement.
func isConsoleVEXRule(s vdb.CliSuppression) bool {
	return strings.EqualFold(s.SourceKind, "vex")
}

// scanConsoleVEX is the console's VEX statements for the repository a scan is
// in, when the scan may use them: it is authenticated (community mode asks for
// nothing) and VEX is on (--no-vex turns it off with the documents). The fetch
// is the one the ignore rules already make, started when the scan began.
func scanConsoleVEX(enabled bool, git *gitctx.GitContext, notes io.Writer) []vex.ConsoleRule {
	if !enabled {
		return nil
	}
	data := remoteConsoleVEX(git)
	if len(data.VEX) == 0 {
		return nil
	}
	repo, branch := "", ""
	if git != nil {
		repo, branch = suppress.RepoFullName(git.RemoteURLs), git.CurrentBranch
	}
	if data.VEXTruncated && notes != nil {
		fmt.Fprintln(notes, "  note: Vulnetix holds more VEX statements for this repository than one reply carries; some are not applied here")
	}
	return consoleVEXRules(data.VEX, repo, branch)
}

// orgVEXChunk is how many vulnerabilities one cli.vex call asks about.
const orgVEXChunk = 200

// orgVEXReplyCap is the most statements the server returns for one call.
const orgVEXReplyCap = 500

// orgVEXFetch asks for the organisation's statements about some vulnerabilities.
type orgVEXFetch func(ids []string) (map[string][]vdb.CliOrgVexStatement, error)

// scanOrgVEX reads what the organisation has said about a scan's findings.
//
// Authenticated runs in a known repository only, and not under --no-vex. Best
// effort, and the failure is the safe one: a statement that was not read closes
// nothing, so a finding stays open.
func scanOrgVEX(enabled bool, git *gitctx.GitContext, bom *cdx.BOM, notes io.Writer) []vex.OrgStatement {
	if !enabled || bom == nil || len(bom.Vulnerabilities) == 0 || git == nil || isUnauthenticatedScan() {
		return nil
	}
	repo := suppress.RepoFullName(git.RemoteURLs)
	if repo == "" {
		return nil
	}
	client := newCliClient()
	if client == nil {
		return nil
	}
	env := envForCliWithGit(git)
	return readOrgVEX(func(ids []string) (map[string][]vdb.CliOrgVexStatement, error) {
		resp, err := client.CliOrgVex(env, vdb.CliOrgVexRequest{IDs: ids, Closing: true, Repository: repo})
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, nil
		}
		return resp.Data.OrgStatementsByVuln, nil
	}, vulnIDs(bom), notes)
}

// vulnIDs are the distinct vulnerability ids in a BOM, sorted.
func vulnIDs(bom *cdx.BOM) []string {
	seen := map[string]bool{}
	var ids []string
	for i := range bom.Vulnerabilities {
		if id := bom.Vulnerabilities[i].ID; id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// readOrgVEX fetches ids in chunks and flattens the replies.
func readOrgVEX(fetch orgVEXFetch, ids []string, notes io.Writer) []vex.OrgStatement {
	var out []vex.OrgStatement
	for start := 0; start < len(ids); start += orgVEXChunk {
		end := min(start+orgVEXChunk, len(ids))
		byVuln, err := fetch(ids[start:end])
		if err != nil {
			if notes != nil {
				fmt.Fprintf(notes, "  note: could not read the organisation's VEX statements: %v\n", err)
			}
			return out
		}
		replied := 0
		for id, rows := range byVuln {
			replied += len(rows)
			for _, r := range rows {
				out = append(out, vex.OrgStatement{
					VulnID: id, Status: r.Status, Justification: r.Justification,
					ImpactStatement: r.ImpactStatement, ActionStatement: r.ActionStatement,
					SuppressionUUID: r.SuppressionUUID, Timestamp: r.Timestamp, DocumentID: r.DocumentID,
					Repository: r.RepositoryFullName, Tooling: r.Tooling, Products: r.Products,
				})
			}
		}
		if replied >= orgVEXReplyCap && notes != nil {
			fmt.Fprintln(notes, "  note: Vulnetix holds more VEX statements for these findings than one reply carries; some were not checked")
		}
	}
	return out
}

// orgVEXHeldShown is how many held findings a scan names before summarising.
const orgVEXHeldShown = 5

// reportOrgVEXHeld says which findings stayed open against a statement. The
// statement is on record as closing them, so a reader comparing this scan with
// Vulnetix needs telling why the two disagree.
func reportOrgVEXHeld(pass *VEXPassResult) {
	writeOrgVEXHeld(os.Stderr, pass)
}

func writeOrgVEXHeld(w io.Writer, pass *VEXPassResult) {
	if pass == nil || len(pass.OrgHeld) == 0 {
		return
	}
	var gone, reach int
	for _, h := range pass.OrgHeld {
		if h.Reason == vex.HoldPriorReachability {
			reach++
		} else {
			gone++
		}
	}
	var parts []string
	if gone > 0 {
		parts = append(parts, fmt.Sprintf("%d an earlier scan recorded as gone", gone))
	}
	if reach > 0 {
		parts = append(parts, fmt.Sprintf("%d an earlier scan judged unreachable", reach))
	}
	fmt.Fprintf(w, "\nVEX: %d finding(s) stay open against a statement this run overrules: %s.\n",
		len(pass.OrgHeld), strings.Join(parts, ", "))
	for i, h := range pass.OrgHeld {
		if i == orgVEXHeldShown {
			fmt.Fprintf(w, "  ... and %d more (see %s in the BOM)\n", len(pass.OrgHeld)-i, vex.PropVEXHeld)
			break
		}
		fmt.Fprintf(w, "  %s %s (%s)\n", h.VulnID, h.Purl, h.Reason)
	}
}
