package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/report"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/scanopts"
	"github.com/vulnetix/cli/v3/internal/triage"
)

// defendCmd is what to do about a finding that has no fix. Virtual patches block
// the request at the edge; countermeasures detect the exploit on a host. This
// command lists what has been built for a vulnerability, saves a rule in the
// file its tool loads, and records that a control is in place so the next scan
// knows.
var defendCmd = &cobra.Command{
	Use:   "defend <advisory-id>",
	Short: "Block rules and detections for a finding that has no fix",
	Long: `Show, save and record the defences built for a vulnerability.

A virtual patch blocks the exploit request at your WAF, sensor or web server. A
countermeasure detects the exploit on a host. They are different promises and
are never mixed: one stops it, the other only tells you it happened. Neither
replaces patching; a virtual patch buys time.

Every rule states the mode it is safe to start in, how likely it is to misfire
and what it does not cover. Those are shown before you save anything.

Reading a finding's defences needs no plan. Rule bodies and downloads need Pro;
without it you see how many exist and in which formats.

Examples:
  vulnetix defend CVE-2025-12345                       # what exists, and what fits your repo
  vulnetix defend CVE-2025-12345 --for modsecurity -o defences/
  vulnetix defend CVE-2025-12345 --for fits -o defences/
  vulnetix defend CVE-2025-12345 --for modsecurity \
      --record "ModSecurity, prod-eu ingress" --until 2027-01-10

Recording writes .vulnetix/controls.json and a VEX statement. The finding stays
affected and stays counted; the next scan lists it under PROTECTED (a blocking
rule) or MONITORED (a detection, or a rule still in log-only mode) until the
control expires. The CLI cannot verify a rule is deployed: the record is your
statement.`,
	Args: cobra.ExactArgs(1),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		surface, err := scanopts.SurfaceFromCommand(cmd)
		if err != nil {
			return err
		}
		activeSurface = surface
		get := func(n string) string { v, _ := cmd.Flags().GetString(n); return strings.TrimSpace(v) }
		return runDefend(cmd.Context(), defendOptions{
			Root: get("path"), ID: strings.TrimSpace(args[0]),
			For: get("for"), OutDir: get("output-dir"),
			Record: get("record"), Until: get("until"), Mode: get("mode"), Lane: get("lane"),
			Package: get("package"), Now: time.Now(),
		}, surface, defences.DefaultSource(), !isUnauthenticatedScan(), os.Stdout, os.Stderr)
	},
}

func init() {
	f := defendCmd.Flags()
	f.String("path", ".", "Project directory whose last scan and repo are read")
	f.String("for", "", "Save rules: a format ("+strings.Join(defendFormats(), ", ")+"), comma-separated; \"fits\" for every format your repo suggests; \"all\"")
	f.StringP("output-dir", "O", "defences", "Directory the rule files are written to")
	f.String("record", "", "Record that a control is in place, in your own words (\"ModSecurity, prod-eu ingress\")")
	f.String("until", "", "Date the recorded control expires, YYYY-MM-DD (default: 90 days)")
	f.String("mode", "", "Mode the rule runs in: block or log (default: the rule's own)")
	f.String("lane", "", "block or detect, when recording without --for")
	f.String("package", "", "Package the control covers, when the last scan does not name it")
	scanopts.AddDisplayFlags(defendCmd)
	_ = defendCmd.RegisterFlagCompletionFunc("for", listCompletionFor(append([]string{"fits", "all"}, defendFormats()...)))
	_ = defendCmd.MarkFlagDirname("path")
	rootCmd.AddCommand(defendCmd)
}

func defendFormats() []string {
	var out []string
	for _, k := range []defences.Kind{
		defences.KindCloudflare, defences.KindAWSWAF, defences.KindSnort, defences.KindSuricata,
		defences.KindModSec, defences.KindNginx, defences.KindRegexL7,
		defences.KindSigma, defences.KindYARA, defences.KindSTIX, defences.KindOpenIOC,
	} {
		out = append(out, defences.Flag(k))
	}
	return out
}

func listCompletionFor(values []string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		prefix, last := "", toComplete
		if i := strings.LastIndex(toComplete, ","); i >= 0 {
			prefix, last = toComplete[:i+1], toComplete[i+1:]
		}
		var out []string
		for _, v := range values {
			if strings.HasPrefix(v, last) {
				out = append(out, prefix+v)
			}
		}
		return out, cobra.ShellCompDirectiveNoSpace | cobra.ShellCompDirectiveNoFileComp
	}
}

type defendOptions struct {
	Root, ID, For, OutDir     string
	Record, Until, Mode, Lane string
	Package                   string
	Now                       time.Time
}

// runDefend is the whole command, with its collaborators injected so it can be
// driven in a test without a network or a terminal.
func runDefend(ctx context.Context, o defendOptions, s scanopts.Surface, src defences.Source, pro bool, stdout, stderr io.Writer) error {
	if o.Root == "" {
		o.Root = "."
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}

	// The last scan tells us which package the advisory is on. It is optional:
	// a person may be looking up an advisory before they have scanned.
	rep, havePrior := storedReport(o.Root)
	var pkgs []report.Package
	if havePrior {
		pkgs = report.FindExplain(rep, o.ID)
	}

	view := report.DefendView{ID: o.ID, PackageLabel: o.ID, Fits: defences.InferStack(o.Root)}
	if len(pkgs) > 0 {
		view.PackageLabel = pkgs[0].Label()
		view.Fix = pkgs[0].Fix
		view.Exploit = exploitSummary(pkgs[0], o.ID)
	}

	// Bounded like the scan's lookup: a slow answer is reported, not waited on forever.
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	lookupID, indexed := defences.Resolve(o.ID)
	switch {
	case !indexed:
		view.Summary = defences.Summary{ID: o.ID, State: defences.StateNotIndexed}
	default:
		found, err := src.Lookup(ctx, []string{lookupID}, defences.LookupOptions{Pro: pro, Detail: true})
		if err != nil {
			view.Summary = defences.Summary{ID: o.ID, State: defences.StateFailed, Reason: shortReason(err)}
		} else if sum, ok := found[lookupID]; ok {
			view.Summary = sum
		} else {
			view.Summary = defences.Summary{ID: o.ID, State: defences.StateFailed, Reason: "no answer"}
		}
	}

	t := reportTerminal(s)
	opts := s.Display
	fmt.Fprint(stdout, report.RenderDefend(view, opts, t))

	if o.For == "" && o.Record == "" {
		return nil
	}

	// Saving and recording both need to know which rules are meant.
	rules, err := selectDefenceRules(view.Summary, o.For, view.Fits)
	if err != nil {
		return err
	}
	if o.For != "" {
		if len(rules) == 0 {
			return fmt.Errorf("no rule to save: %s", noRulesReason(view.Summary))
		}
		if err := saveDefenceRules(ctx, src, rules, o, s, t, stdout); err != nil {
			return err
		}
	}
	if o.Record != "" {
		return recordDefenceControl(o, pkgs, rules, s, t, stdout)
	}
	return nil
}

func noRulesReason(sum defences.Summary) string {
	switch sum.State {
	case defences.StateUnavailable:
		return "defence lookup is not available in this version yet"
	case defences.StateGated:
		return "rule bodies and downloads need a Pro plan (" + pricingHint + ")"
	case defences.StateNone:
		return "nothing is published for " + sum.ID + " yet"
	case defences.StateNotIndexed:
		return sum.ID + " is not an advisory identifier the database can look up"
	}
	return "that format is not among the rules found"
}

const pricingHint = "https://www.vulnetix.com/pricing"

// selectDefenceRules resolves --for to the rules it names. "fits" is every rule
// in a format the repository suggests, "all" is everything, and anything else is
// a comma-separated list of formats.
func selectDefenceRules(sum defences.Summary, forFlag string, fits map[defences.Kind]defences.Hint) ([]defences.Rule, error) {
	forFlag = strings.ToLower(strings.TrimSpace(forFlag))
	all := sum.Rules()
	switch forFlag {
	case "":
		return nil, nil
	case "all":
		return all, nil
	case "fits":
		var out []defences.Rule
		for _, r := range all {
			if _, ok := fits[r.Kind]; ok {
				out = append(out, r)
			}
		}
		if len(out) == 0 && len(all) > 0 {
			return nil, fmt.Errorf("none of the rules is in a format your repo suggests; name one with --for (%s)", strings.Join(kindFlags(all), ", "))
		}
		return out, nil
	}
	want := map[defences.Kind]bool{}
	for _, part := range strings.Split(forFlag, ",") {
		k, ok := defences.ParseFlag(part)
		if !ok {
			return nil, fmt.Errorf("--for: unknown format %q (valid: %s, fits, all)", strings.TrimSpace(part), strings.Join(defendFormats(), ", "))
		}
		want[k] = true
	}
	var out []defences.Rule
	for _, r := range all {
		if want[r.Kind] {
			out = append(out, r)
		}
	}
	return out, nil
}

func kindFlags(rules []defences.Rule) []string {
	var out []string
	for _, r := range rules {
		out = append(out, defences.Flag(r.Kind))
	}
	return out
}

// saveDefenceRules downloads each rule, checks it against the checksum the
// server sent, and writes it under the name its tool expects. A body that does
// not match its checksum is never written.
func saveDefenceRules(ctx context.Context, src defences.Source, rules []defences.Rule, o defendOptions, s scanopts.Surface, t *display.Terminal, w io.Writer) error {
	st := report.NewStyle(t, s.Display)
	dir := o.OutDir
	if dir == "" {
		dir = "defences"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, r := range rules {
		body, err := src.Download(ctx, r)
		if err != nil {
			return fmt.Errorf("downloading %s rule: %w", defences.Name(r.Kind), err)
		}
		sum := sha256.Sum256(body.Content)
		got := hex.EncodeToString(sum[:])
		want := strings.TrimSpace(firstNonBlank(body.SHA256, r.SHA256))
		if want != "" && !strings.EqualFold(want, got) {
			return fmt.Errorf("%s rule failed its checksum (expected %s, got %s); not written", defences.Name(r.Kind), short(want), short(got))
		}
		name := body.FileName
		if name == "" {
			id := r.ArtifactID
			if id == "" {
				id = o.ID
			}
			name = defences.FileName(id, r.Kind)
		}
		path := filepath.Join(dir, filepath.Base(name))
		if err := os.WriteFile(path, body.Content, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(w, "\n %s wrote %s\n", st.Good(st.G.OK), st.Bold(path))
		if want != "" {
			fmt.Fprintf(w, "   sha256 %s %s\n", short(got), st.Good("matches the checksum the database sent"))
		} else {
			fmt.Fprintf(w, "   sha256 %s %s\n", short(got), st.Dim("no checksum was sent to compare with"))
		}
		if m := strings.TrimSpace(r.DeployMode); m != "" {
			fmt.Fprintf(w, "   This rule says it is safe to start in %s mode.\n", st.Warn(m))
		}
		if r.CoverageNotes != "" {
			fmt.Fprintf(w, "   %s\n", st.Dim(r.CoverageNotes))
		}
	}
	if o.Record == "" {
		fmt.Fprintf(w, "\n After you deploy it, record it so the next scan knows:\n   %s\n",
			st.Cmd(fmt.Sprintf("vulnetix defend %s --for %s --record \"<where it runs>\" --until <YYYY-MM-DD>", o.ID, strings.ToLower(o.For))))
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:6] + "…" + h[len(h)-4:]
	}
	return h
}

// recordDefenceControl writes the statement that a control is in place. The
// finding does not stop being affected: this records a claim, with an expiry,
// and says so.
func recordDefenceControl(o defendOptions, pkgs []report.Package, rules []defences.Rule, s scanopts.Surface, t *display.Terminal, w io.Writer) error {
	st := report.NewStyle(t, s.Display)

	lane, kind, err := controlLane(o, rules)
	if err != nil {
		return err
	}
	until := o.Now.Add(defences.DefaultControlLife)
	if o.Until != "" {
		d, perr := time.Parse("2006-01-02", o.Until)
		if perr != nil {
			return fmt.Errorf("--until: expected YYYY-MM-DD, got %q", o.Until)
		}
		// The control lasts through the named day.
		until = d.Add(24*time.Hour - time.Second)
		if !until.After(o.Now) {
			return fmt.Errorf("--until %s is not in the future; a control that has already expired protects nothing", o.Until)
		}
	}
	mode := strings.ToLower(o.Mode)
	if mode != "" && mode != "block" && mode != "log" {
		return fmt.Errorf("--mode: expected block or log, got %q", o.Mode)
	}
	if mode == "" && len(rules) > 0 {
		mode = strings.ToLower(rules[0].DeployMode)
	}

	targets := pkgs
	if len(targets) == 0 {
		if o.Package == "" {
			return fmt.Errorf("the last scan does not list %s on any package; say which with --package", o.ID)
		}
		targets = []report.Package{{Name: o.Package}}
	} else if o.Package != "" {
		var keep []report.Package
		for _, p := range targets {
			if strings.EqualFold(p.Name, o.Package) {
				keep = append(keep, p)
			}
		}
		if len(keep) == 0 {
			return fmt.Errorf("%s is not on package %q in the last scan", o.ID, o.Package)
		}
		targets = keep
	}

	set, err := defences.LoadControls(o.Root)
	if err != nil {
		return err
	}
	sha := ""
	if len(rules) > 0 {
		sha = rules[0].SHA256
	}
	for _, p := range targets {
		set.Upsert(defences.Control{
			VulnID: o.ID, Package: p.Name, Version: p.Version, Ecosystem: p.Ecosystem,
			Lane: lane, Kind: kind, Where: o.Record, RecordedAt: o.Now, Until: until,
			Mode: mode, RuleSHA256: sha,
		})
	}
	if err := set.Save(o.Root); err != nil {
		return err
	}
	vexPath, err := writeControlsVEX(o.Root, set, o.Now)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "\n %s recorded: %s\n", st.Good(st.G.OK), st.Bold(o.Record))
	fmt.Fprintf(w, "   %s for %s, until %s\n", laneNoun(lane, mode), strings.Join(pkgLabels(targets), ", "), until.Format("2006-01-02"))
	fmt.Fprintf(w, "   %s\n", st.Dim(filepath.Join(".vulnetix", "controls.json")+" "+st.G.Sep+" "+vexPath))
	fmt.Fprintf(w, "   %s\n", st.Dim("The finding is still affected and still counted. The CLI cannot verify the rule is deployed."))
	if lane == defences.LaneDetect || mode == "log" {
		fmt.Fprintf(w, "   %s\n", st.Warn("This stops nothing: the next scan lists it under MONITORED, not PROTECTED."))
	}
	return nil
}

func laneNoun(l defences.Lane, mode string) string {
	switch {
	case l == defences.LaneDetect:
		return "Detection"
	case mode == "log":
		return "Block rule in log-only mode"
	}
	return "Block rule"
}

func pkgLabels(pkgs []report.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Label())
	}
	return out
}

// controlLane decides which lane a recorded control belongs to: from the rule
// being saved, else from --for, else from --lane.
func controlLane(o defendOptions, rules []defences.Rule) (defences.Lane, defences.Kind, error) {
	if len(rules) > 0 {
		return defences.LaneOf(rules[0].Kind), rules[0].Kind, nil
	}
	if k, ok := defences.ParseFlag(strings.Split(o.For, ",")[0]); ok && o.For != "" {
		return defences.LaneOf(k), k, nil
	}
	switch strings.ToLower(o.Lane) {
	case "block":
		return defences.LaneBlock, "", nil
	case "detect":
		return defences.LaneDetect, "", nil
	case "":
		return "", "", fmt.Errorf("say what kind of control this is: --for <format> or --lane block|detect")
	}
	return "", "", fmt.Errorf("--lane: expected block or detect, got %q", o.Lane)
}

// writeControlsVEX regenerates the VEX document for every unexpired control.
// Each statement is "affected" with an action naming the control: a virtual
// patch never makes a package unaffected, so it is never written as
// not_affected.
func writeControlsVEX(root string, set defences.ControlSet, now time.Time) (string, error) {
	var findings []*triage.TriageFinding
	for _, c := range set.Controls {
		if !c.Active(now) {
			continue
		}
		findings = append(findings, &triage.TriageFinding{
			CVEID: c.VulnID, Package: c.Package, Ecosystem: c.Ecosystem, InstalledVer: c.Version,
			Status: "affected",
			ActionResponse: fmt.Sprintf("compensating-control: %s %s until %s",
				strings.TrimSpace(c.Where), modeSuffix(c), c.Until.Format("2006-01-02")),
		})
	}
	path := filepath.Join(root, ".vulnetix", "vex-compensating-controls.json")
	if len(findings) == 0 {
		_ = os.Remove(path)
		return path, nil
	}
	data, err := triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{Tooling: "vulnetix-cli defend"})
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, append(data, '\n'), 0o644)
}

func modeSuffix(c defences.Control) string {
	switch {
	case c.Lane == defences.LaneDetect:
		return "(detection only)"
	case !c.Blocks():
		return "(log only)"
	}
	return "(blocking)"
}

// storedReport rebuilds the report from the last scan's BOM. It returns false
// when there is none, which is not an error for `defend`.
func storedReport(root string) (report.Report, bool) {
	data, err := os.ReadFile(filepath.Join(root, ".vulnetix", "sbom.cdx.json"))
	if err != nil {
		return report.Report{}, false
	}
	var bom cdx.BOM
	if json.Unmarshal(data, &bom) != nil || len(bom.Vulnerabilities) == 0 {
		return report.Report{}, false
	}
	comps := map[string]cdx.Component{}
	for _, c := range bom.Components {
		comps[c.BOMRef] = c
	}
	var vulns []scan.EnrichedVuln
	for i := range bom.Vulnerabilities {
		if ev := cdxToEnrichedVuln(&bom.Vulnerabilities[i], comps); ev != nil {
			scan.ComputeEnrichedSeverities(ev)
			vulns = append(vulns, *ev)
		}
	}
	controls, _ := defences.LoadControls(root)
	return report.Build(report.Input{
		Vulns: vulns, Groups: buildGroupsFromMemory(vulns), Controls: controls,
		Meta: report.Meta{Kinds: []string{"sca"}},
	}), true
}

// exploitSummary is the one line under the heading: what is public about this
// vulnerability, from the last scan.
func exploitSummary(p report.Package, id string) string {
	for _, a := range p.Advisories {
		if !strings.EqualFold(a.ID, id) {
			continue
		}
		switch {
		case a.Ev.ExploitIntel != nil && a.Ev.ExploitIntel.ExploitCount > 0:
			n := a.Ev.ExploitIntel.ExploitCount
			txt := fmt.Sprintf("%d public %s", n, map[bool]string{true: "exploit", false: "exploits"}[n == 1])
			if a.Ev.ExploitIntel.HasWeaponized {
				txt += ", weaponized"
			}
			return txt
		case a.KEV:
			return "listed as actively exploited"
		}
	}
	return ""
}
