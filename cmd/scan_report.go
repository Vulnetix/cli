package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/pipeline"
	"github.com/vulnetix/cli/v3/internal/report"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/scanopts"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// activeSurface is the parsed output vocabulary for the running command. It is
// a package variable for the same reason showDetectedFiles is: runLocalScan takes
// a pipeline.Options, which is shared with the language server and has no
// business knowing what a terminal is.
var activeSurface scanopts.Surface

// lastSCATier is the plan tier the SCA round-trip reported ("pro" or empty). It
// decides whether a defence lookup asks for rule details or only counts.
var lastSCATier string

// lastSCAUnchecked are the packages the last SCA round-trip could not look up after
// retries. The report says so instead of presenting the rest as the whole answer.
var lastSCAUnchecked []string

// lastSCATierGated is every feature the server said it withheld on this plan,
// across the SCA batches. It is what separates "no fix exists" from "this plan
// was not told".
var lastSCATierGated map[string]bool

// scanReportInput gathers what buildScanReport needs from the scan.
type scanReportInput struct {
	Opts        pipeline.Options
	Root        string
	Vulns       []scan.EnrichedVuln
	Groups      []scan.ManifestGroup
	AllPackages []scan.ScopedPackage
	VEXHidden   int
	Started     time.Time
}

// buildScanReport turns the scan's findings into the report every view reads,
// and runs the defence lookup for the findings that have no fix.
func buildScanReport(ctx context.Context, in scanReportInput) report.Report {
	controls, err := defences.LoadControls(in.Root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: ignoring recorded controls: %v\n", err)
	}
	meta := report.Meta{
		ScannedPackages: len(countUniqueMap(in.AllPackages)),
		Kinds:           scannerKinds(in.Opts),
		VEXSuppressed:   in.VEXHidden,
		Unchecked:       append([]string(nil), lastSCAUnchecked...),
	}
	for _, g := range in.Groups {
		meta.Manifests += len(g.Files)
	}
	if !in.Started.IsZero() {
		meta.Elapsed = time.Since(in.Started)
	}
	rep := report.Build(report.Input{
		Vulns: in.Vulns, Groups: in.Groups, Controls: controls,
		Meta: meta, Strict: in.Opts.Strict,
	})
	attachDefenceLookup(ctx, &rep, in.Opts)
	return rep
}

func scannerKinds(o pipeline.Options) []string {
	var k []string
	add := func(off bool, name string) {
		if !off {
			k = append(k, name)
		}
	}
	add(o.NoSCA, "sca")
	add(o.NoSASTRules, "sast")
	add(o.NoSecrets, "secrets")
	add(o.NoLicenses, "licenses")
	add(o.NoContainers, "containers")
	add(o.NoIAC, "iac")
	return k
}

// defenceLookupTimeout is how long a scan waits for the defence lookup.
const defenceLookupTimeout = 20 * time.Second

// attachDefenceLookup asks the vulnerability database what has been built for
// the findings that have no fix.
//
// It is skipped, and the findings say nothing about defences, when there is
// nothing without a fix, when defences are hidden, or on a dry run that must
// make no API calls. The source is stubbed for now (see internal/defences): it
// reports StateUnavailable, which the renderers print as nothing.
func attachDefenceLookup(ctx context.Context, rep *report.Report, opts pipeline.Options) {
	// Bounded: the lookup is an extra, and a slow answer must not hold the scan.
	ctx, cancel := context.WithTimeout(ctx, defenceLookupTimeout)
	defer cancel()
	if opts.DryRun || activeSurface.Display.Hide["defences"] {
		return
	}
	ids := report.DefenceIDs(*rep)
	noFix := rep.NoFix()
	if len(noFix) == 0 {
		return
	}
	found := map[string]defences.Summary{}
	if len(ids) > 0 {
		var err error
		found, err = defences.DefaultSource().Lookup(ctx, ids, defences.LookupOptions{Pro: paidTier(lastSCATier)})
		if err != nil && !errors.Is(err, defences.ErrNotAvailable) {
			report.AttachDefences(rep, nil, true, shortReason(err))
			return
		}
	}
	report.AttachDefences(rep, found, true, "")
}

func shortReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	s := err.Error()
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}

// gateVulns is the input to the vulnerability gates. Findings the advisory
// itself rules out by version do not fail a build unless --strict, and findings
// covered by an unexpired recorded control do not unless --accept-defended says
// the record counts.
func gateVulns(vulns []scan.EnrichedVuln, opts pipeline.Options, controls defences.ControlSet, now time.Time) []scan.EnrichedVuln {
	if opts.Strict && !opts.AcceptDefended {
		return vulns
	}
	out := make([]scan.EnrichedVuln, 0, len(vulns))
	for _, ev := range vulns {
		if !opts.Strict && !scan.EvaluateVerdict(ev).Verdict.Counts() {
			continue
		}
		if opts.AcceptDefended && hasActiveControl(controls, ev, now) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func hasActiveControl(controls defences.ControlSet, ev scan.EnrichedVuln, now time.Time) bool {
	for _, c := range controls.For(ev.CveID, ev.PackageName) {
		if c.Active(now) {
			return true
		}
	}
	return false
}

// reportTerminal builds the terminal for rendering, honouring --color, --width
// and COLUMNS on top of what was detected.
func reportTerminal(s scanopts.Surface) *display.Terminal {
	t := display.NewTerminal()
	if w, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS"))); err == nil && w >= 30 && !t.IsTTY {
		t.Width = w
	}
	switch s.Color {
	case "never":
		t.ColorProfile = termenv.Ascii
	case "always":
		t.ColorProfile = termenv.ANSI256
		lipgloss.SetColorProfile(termenv.ANSI256)
	}
	return t
}

// inCI reports whether the output is going to a pipeline's log.
func inCI() bool {
	return os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") == "true"
}

// scanViewTable reports whether the legacy eighteen-column table was asked for.
func scanViewTable(s scanopts.Surface) bool { return s.Display.View == report.ViewTable }

// printScanReport draws the report on stdout in the requested view. It returns
// false when --explain matched nothing, so the caller can say so.
func printScanReport(rep report.Report, s scanopts.Surface) bool {
	t := reportTerminal(s)
	o := s.Display
	o.Now = time.Now()

	if s.Explain != "" {
		out, ok := report.RenderExplain(rep, s.Explain, o, t)
		if !ok {
			return false // the caller says so, once, after every kind of finding has been tried
		}
		fmt.Fprint(os.Stdout, out)
		return true
	}

	view := report.ResolveView(o, t, inCI())
	shown := report.Apply(rep, o)
	out := report.Render(view, shown, o, t)
	if out != "" {
		fmt.Fprint(os.Stdout, out)
		if view != report.ViewPlain && !strings.HasSuffix(out, "\n\n") {
			fmt.Fprintln(os.Stdout)
		}
	}

	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Fprint(os.Stdout, report.RenderGitHub(shown))
		appendStepSummary(report.StepSummary(shown))
	}
	return true
}

// appendStepSummary adds Markdown to $GITHUB_STEP_SUMMARY when it is set.
func appendStepSummary(md string) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" || md == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(md + "\n")
}

// scanFlagAliases lets --fix and its siblings resolve to the longer
// --sca-autofix names. It is a true alias, not a second flag: there is one value
// and one place it is read, so the two spellings cannot disagree.
func scanFlagAliases(prev func(*pflag.FlagSet, string) pflag.NormalizedName) func(*pflag.FlagSet, string) pflag.NormalizedName {
	aliases := map[string]string{
		"fix":                "sca-autofix",
		"fix-strategy":       "sca-autofix-strategy",
		"fix-manifest":       "sca-autofix-manifest",
		"fix-max-major-bump": "sca-autofix-max-major-bump",
	}
	return func(f *pflag.FlagSet, name string) pflag.NormalizedName {
		if to, ok := aliases[name]; ok {
			return pflag.NormalizedName(to)
		}
		if prev != nil {
			return prev(f, name)
		}
		return pflag.NormalizedName(name)
	}
}

// scanKinds are the values --only and --skip accept.
var scanKinds = []string{"sca", "sast", "secrets", "licenses", "containers", "iac"}

// scanKindSelection reads --only and --skip. They replace twelve flags: the
// --evaluate-X and --no-X pair for each kind.
func scanKindSelection(cmd *cobra.Command) (only, skip map[string]bool, err error) {
	read := func(name string) ([]string, error) {
		raw, _ := cmd.Flags().GetStringArray(name)
		list := report.ParseList(raw...)
		return list, report.Validate(name, list, scanKinds)
	}
	o, err := read("only")
	if err != nil {
		return nil, nil, err
	}
	s, err := read("skip")
	if err != nil {
		return nil, nil, err
	}
	return report.Set(o), report.Set(s), nil
}

// codeReportFrom converts the rule engine's report into the renderer's.
func codeReportFrom(sr *sast.SASTReport, label string) report.CodeReport {
	cr := report.CodeReport{Label: label, RulesLoaded: sr.RulesLoaded, RulesTotal: sr.RulesTotal}
	for _, f := range sr.Findings {
		cf := report.CodeFinding{
			RuleID: f.RuleID, Severity: f.Severity, Path: f.ArtifactURI,
			Line: f.StartLine, EndLine: f.EndLine, Message: f.Message,
			Snippet: f.Snippet, TestSuite: f.IsTestSuite,
		}
		if m := f.Metadata; m != nil {
			cf.Name, cf.Kind, cf.Description, cf.HelpURI, cf.CWE = m.Name, m.Kind, m.Description, m.HelpURI, m.CWE
			if cf.Severity == "" {
				cf.Severity = m.Severity
			}
		}
		cr.Findings = append(cr.Findings, cf)
	}
	return cr
}

// printCodeReport draws the rule engine's findings in the same grammar as the
// dependency report. A clean run prints nothing under -q or --results-only.
func printCodeReport(sr *sast.SASTReport, label, root string, s scanopts.Surface, resultsOnly bool) {
	if sr == nil {
		return
	}
	if len(sr.Findings) == 0 && (resultsOnly || s.Display.Quiet) {
		return
	}
	t := reportTerminal(s)
	o := s.Display
	cr := codeReportFrom(sr, label)
	switch report.ResolveView(o, t, inCI()) {
	case report.ViewPlain:
		// One line per finding: it reads neither history nor resources.
		fmt.Fprint(os.Stdout, "\n"+report.RenderCodePlain(cr, o, t))
	default:
		enrichCodeReport(&cr, root)
		fmt.Fprint(os.Stdout, "\n"+report.RenderCode(cr, o, t))
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Fprint(os.Stdout, report.RenderCodeGitHub(cr))
	}
}

// printCodeExplain explains the findings a --explain query names among the rule
// engine's results. It reports whether anything matched.
func printCodeExplain(sr *sast.SASTReport, label, root string, s scanopts.Surface) bool {
	cr := codeReportFrom(sr, label)
	enrichCodeReport(&cr, root)
	out, ok := report.RenderCodeExplain(cr, s.Explain, s.Display, reportTerminal(s))
	if ok {
		fmt.Fprint(os.Stdout, out)
	}
	return ok
}

// resolveUnverifiedFindings settles findings whose affected range the scan could
// not compare with a version (a git commit, typically) by reading the advisory's
// own record. It resolves and never invents: what it cannot settle stays
// unverified. A lookup that fails is skipped, not retried, so a flaky network
// costs accuracy and never a scan.
func resolveUnverifiedFindings(enriched []scan.EnrichedVuln, w io.Writer) {
	if len(enriched) == 0 {
		return
	}
	client := newEnrichmentClient()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	// Each wave of lookups goes to the API as one cli.affected-batch request; a
	// lookup it could not answer is asked for on its own, 24 at a time.
	batch := func(ctx context.Context, qs []scan.AffectedQuery) []scan.AffectedAnswer {
		lookups := make([]vdb.AffectedLookup, len(qs))
		for i, q := range qs {
			lookups[i] = vdb.AffectedLookup{ID: q.ID, Params: vdb.V2QueryParams{PackageName: q.PkgName, Ecosystem: q.Ecosystem, Limit: 100}}
		}
		out := make([]scan.AffectedAnswer, len(qs))
		for i, r := range client.V2AffectedBatch(ctx, envForCli(), lookups) {
			out[i] = scan.AffectedAnswer{Data: r.Data, Err: r.Err}
		}
		return out
	}
	st := scan.ResolveUnverifiedBatched(ctx, enriched, func(_ context.Context, id, pkg, eco string) (map[string]any, error) {
		return client.V2AffectedCached(id, vdb.V2QueryParams{PackageName: pkg, Ecosystem: eco, Limit: 100})
	}, batch, 24)
	if st.Failed > 0 {
		fmt.Fprintf(w, "  note: %d version check(s) could not be completed (API error or time budget); those findings keep the verdict they arrived with. Run the scan again to retry.\n", st.Failed)
	}
	if verbose && st.Candidates > 0 {
		fmt.Fprintf(w, "  verified %d unverified finding(s) against the advisory records: %d settled, %d not affected (%d lookups)\n",
			st.Candidates, st.Resolved, st.NotAffected, st.Fetches)
	}
}

func init() {
	// The defence lookup asks for a client when it is first used, because
	// credentials are resolved after packages initialise.
	defences.SetClientFactory(func() defences.API { return newEnrichmentClient() })
}

// paidTier reports whether a plan tier name is Pro or above. The server names
// them pro, teams and business or enterprise; only community is below.
func paidTier(tier string) bool {
	t := strings.ToLower(strings.TrimSpace(tier))
	return t != "" && t != "community" && t != "free"
}
