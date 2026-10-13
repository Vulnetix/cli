package scanopts

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vulnetix/cli/v3/internal/report"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

// AddSurfaceFlags registers the output and gating vocabulary on a scan-family
// command: what to show, what to hide, what to filter, and when to fail.
//
// It is registered by addScanFlags, so sca, sast, secrets, containers, iac and
// scan accept the same words and honour them the same way. The legacy flags that
// these supersede are not removed; they keep working and are hidden from help.
func AddSurfaceFlags(cmd *cobra.Command) {
	AddDisplayFlags(cmd)
	AddGateFlags(cmd)
}

// AddDisplayFlags registers the flags that only change what is shown. A command
// that replays or inspects results (report, defend) takes these and not the
// gates, so a flag that would be silently ignored is never offered.
func AddDisplayFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	f.String("view", "auto", "How to present results: "+strings.Join(report.Views, " | ")+". auto picks plain for a pipe or CI and packages for a terminal.")
	f.StringArray("filter", nil, "Show only findings that match all of: "+strings.Join(report.FilterNames, ", ")+" (comma-separated, repeatable)")
	f.String("min-severity", "", "Hide anything below this severity: low | medium | high | critical. This only changes what is shown; use --fail-on to change the exit code.")
	f.String("sort", "threat", "Order within a group: "+strings.Join(report.SortKeys, " | "))
	f.StringArray("show", nil, "Add to the output: "+strings.Join(report.ShowParts, ", ")+" (comma-separated, repeatable)")
	f.StringArray("hide", nil, "Remove from the output: "+strings.Join(report.HideParts, ", ")+" (comma-separated, repeatable)")
	f.BoolP("quiet", "q", false, "Print findings only; print nothing when clean")
	f.String("explain", "", "Show why a finding applies, with the evidence: an advisory id, a package, or name@version")
	f.String("color", "auto", "Colour output: auto | always | never")
	f.Bool("ascii", false, "Use plain ASCII characters instead of unicode symbols")
	f.Int("width", 0, "Force the output width in columns (default: the terminal's, or COLUMNS)")

	_ = cmd.RegisterFlagCompletionFunc("view", cobra.FixedCompletions(report.Views, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("sort", cobra.FixedCompletions(report.SortKeys, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("color", cobra.FixedCompletions([]string{"auto", "always", "never"}, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("min-severity", cobra.FixedCompletions([]string{"low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("filter", listCompletion(report.FilterNames))
	_ = cmd.RegisterFlagCompletionFunc("show", listCompletion(report.ShowParts))
	_ = cmd.RegisterFlagCompletionFunc("hide", listCompletion(report.HideParts))
}

// AddGateFlags registers the flags that decide the exit code.
func AddGateFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringArray("fail-on", nil, "Exit 1 when any of these hold (comma-separated, repeatable): low | medium | high | critical, kev, exploit=poc|active|weaponized, malware, eol[=severity], unpinned, unprotected, lag=<n>, cooldown=<n>d")
	f.Bool("strict", false, "Also count findings the advisory rules out by version (not affected, likely not affected)")
	f.Bool("accept-defended", false, "Let an unexpired recorded control satisfy the gates for the finding it covers")
	_ = cmd.RegisterFlagCompletionFunc("fail-on", listCompletion(FailOnRules))
}

// listCompletion completes the last element of a comma-separated value.
func listCompletion(values []string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
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

// legacyFlags maps each superseded flag to the words that replace it. They keep
// working; the table drives both the hidden-from-help treatment and the single
// stderr note a person at a terminal gets the first time they use one.
var legacyFlags = map[string]string{
	"severity":              "--fail-on <severity>",
	"block-malware":         "--fail-on malware",
	"block-eol":             "--fail-on eol",
	"block-unpinned":        "--fail-on unpinned",
	"exploits":              "--fail-on exploit=<tier>",
	"version-lag":           "--fail-on lag=<n>",
	"cooldown":              "--fail-on cooldown=<n>d",
	"no-exploits":           "--hide exploits",
	"no-remediation":        "--hide fixes",
	"show-introduced-paths": "--show paths",
	"show-detected":         "--show files",
	"show-all-manifests":    "--show clean",
	"results-only":          "-q",
}

// HideLegacyFlags removes the superseded flags from help without disabling them.
func HideLegacyFlags(cmd *cobra.Command) {
	for name := range legacyFlags {
		if fl := cmd.Flags().Lookup(name); fl != nil {
			fl.Hidden = true
		}
	}
}

// LegacyNotes returns one line for each superseded flag the user actually
// passed. It is empty unless stderr is a terminal and CI is not set: a
// pipeline's logs are not the place to nag.
func LegacyNotes(cmd *cobra.Command) []string {
	if os.Getenv("CI") != "" || !stderrIsTerminal() {
		return nil
	}
	var out []string
	cmd.Flags().Visit(func(fl *pflag.Flag) {
		if repl, ok := legacyFlags[fl.Name]; ok {
			out = append(out, fmt.Sprintf("--%s still works; it is now %s", fl.Name, repl))
		}
	})
	return out
}

func stderrIsTerminal() bool {
	st, err := os.Stderr.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Surface is the parsed output and gating vocabulary.
type Surface struct {
	Display report.Options
	Explain string
	FailOn  FailOn
	// Strict and AcceptDefended mirror the pipeline.Options fields.
	Strict, AcceptDefended bool
	// Color is auto, always or never.
	Color string
}

// SurfaceFromCommand reads and validates the vocabulary registered by
// AddSurfaceFlags. A command that did not register it gets the zero Surface.
func SurfaceFromCommand(cmd *cobra.Command) (Surface, error) {
	var s Surface
	fl := cmd.Flags()
	if fl.Lookup("view") == nil {
		return s, nil
	}
	getS := func(n string) string { v, _ := fl.GetString(n); return v }
	getA := func(n string) []string { v, _ := fl.GetStringArray(n); return v }
	getB := func(n string) bool { v, _ := fl.GetBool(n); return v }

	view := strings.ToLower(strings.TrimSpace(getS("view")))
	if err := report.Validate("view", []string{view}, report.Views); err != nil {
		return s, err
	}
	filters := report.ParseList(getA("filter")...)
	if err := report.Validate("filter", filters, report.FilterNames); err != nil {
		return s, err
	}
	show := report.ParseList(getA("show")...)
	if err := report.Validate("show", show, report.ShowParts); err != nil {
		return s, err
	}
	hide := report.ParseList(getA("hide")...)
	if err := report.Validate("hide", hide, report.HideParts); err != nil {
		return s, err
	}
	sortKey := strings.ToLower(strings.TrimSpace(getS("sort")))
	if err := report.Validate("sort", []string{sortKey}, report.SortKeys); err != nil {
		return s, err
	}
	minSev := strings.ToLower(strings.TrimSpace(getS("min-severity")))
	if minSev != "" && !scaview.SeverityKnown(minSev) {
		return s, fmt.Errorf("--min-severity: unknown value %q (valid: low, medium, high, critical)", minSev)
	}
	color := strings.ToLower(strings.TrimSpace(getS("color")))
	if err := report.Validate("color", []string{color}, []string{"auto", "always", "never"}); err != nil {
		return s, err
	}
	failOn, err := ParseFailOn(getA("fail-on"))
	if err != nil {
		return s, err
	}
	width, _ := fl.GetInt("width")
	if width < 0 {
		return s, fmt.Errorf("--width must be positive")
	}

	// Legacy display switches fold into the same sets, so the renderer reads one
	// vocabulary whichever the user typed.
	showSet, hideSet := report.Set(show), report.Set(hide)
	if getB("no-exploits") {
		hideSet["exploits"] = true
	}
	if getB("no-remediation") {
		hideSet["fixes"] = true
	}
	if getB("show-introduced-paths") || getB("paths") {
		showSet["paths"] = true
	}
	if getB("show-detected") {
		showSet["files"] = true
	}
	if getB("show-all-manifests") {
		showSet["clean"] = true
	}
	verbosity, _ := fl.GetCount("verbose")
	if verbosity > 2 {
		verbosity = 2
	}

	s.Display = report.Options{
		View: view, Filters: filters, MinSeverity: minSev, Sort: sortKey,
		Show: showSet, Hide: hideSet, Verbosity: verbosity,
		Quiet: getB("quiet"),
		ASCII: getB("ascii"), Width: width,
		Command: cmd.Name(),
	}
	s.Explain = strings.TrimSpace(getS("explain"))
	s.FailOn = failOn
	s.Strict = getB("strict")
	s.AcceptDefended = getB("accept-defended")
	s.Color = color
	return s, nil
}

// ParseSet flattens repeatable, comma-separated flag values into a list of
// lower-case words.
func ParseSet(values []string) []string { return report.ParseList(values...) }
