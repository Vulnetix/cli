package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

// Views are the names `--view` accepts. "table" is the legacy eighteen-column
// table; it is drawn by the scan command itself and never reaches this package.
const (
	ViewAuto     = "auto"
	ViewPackages = "packages"
	ViewFindings = "findings"
	ViewTree     = "tree"
	ViewTable    = "table"
	ViewPlain    = "plain"
	ViewJSON     = "json"
)

// Allowed values for the list-valued flags. They are the single source for both
// validation and shell completion.
var (
	Views       = []string{ViewAuto, ViewPackages, ViewFindings, ViewTree, ViewTable, ViewPlain, ViewJSON}
	FilterNames = []string{"kev", "exploited", "reachable", "fixable", "nofix", "defended", "unprotected", "direct", "transitive"}
	ShowParts   = []string{"paths", "files", "clean", "scores", "defences"}
	HideParts   = []string{"fixes", "exploits", "defences", "not-affected"}
	SortKeys    = []string{"threat", "severity", "package"}
)

// Options shape what is shown. None of them changes what is found, counted in
// JSON or SARIF, or gated: they are about the terminal.
type Options struct {
	View        string
	Filters     []string
	MinSeverity string
	Sort        string
	Show, Hide  map[string]bool
	// Verbosity is 0 normally, 1 for -v, 2 for -vv.
	Verbosity int
	Quiet     bool
	ASCII     bool
	// Width forces a width; zero uses the terminal's.
	Width int
	Now   time.Time
	// Command names the subcommand in plain output: "scan", "sca", and so on.
	Command string
}

// ParseList splits a comma-separated flag value.
func ParseList(values ...string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// Validate reports the first value not in allowed, naming every valid one so a
// typo costs one read instead of a trip to the help text.
func Validate(flag string, values, allowed []string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for _, v := range values {
		if !ok[v] {
			return fmt.Errorf("--%s: unknown value %q (valid: %s)", flag, v, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// Set turns a parsed list into a membership set.
func Set(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// ResolveView picks the renderer. An explicit --view wins; otherwise a pipe, a
// file or CI gets the plain renderer and a person at a terminal gets packages.
func ResolveView(o Options, t *display.Terminal, ci bool) string {
	v := strings.ToLower(strings.TrimSpace(o.View))
	if v != "" && v != ViewAuto {
		return v
	}
	if ci || t == nil || !t.IsTTY {
		return ViewPlain
	}
	return ViewPackages
}

// Apply returns the report with the display options applied: filtered, hidden
// and sorted. The input is not modified.
func Apply(r Report, o Options) Report {
	out := Report{Meta: r.Meta}
	for _, p := range r.Packages {
		if p.Group == GroupNotAffected {
			if o.Hide["not-affected"] || len(o.Filters) > 0 {
				continue
			}
			out.Packages = append(out.Packages, p)
			continue
		}
		if o.MinSeverity != "" && scaview.SeverityKnown(o.MinSeverity) &&
			scaview.SeverityRank(p.Severity) > scaview.SeverityRank(o.MinSeverity) {
			continue
		}
		if !matchesAll(p, o.Filters) {
			continue
		}
		out.Packages = append(out.Packages, p)
	}
	if o.Sort != "" && o.Sort != "threat" {
		sortPackages(out.Packages, o.Sort)
	}
	return out
}

func matchesAll(p Package, filters []string) bool {
	for _, f := range filters {
		if !matches(p, f) {
			return false
		}
	}
	return true
}

func matches(p Package, f string) bool {
	switch f {
	case "kev":
		for _, a := range p.Advisories {
			if a.KEV {
				return true
			}
		}
	case "exploited":
		for _, a := range p.Advisories {
			if a.Exploits > 0 {
				return true
			}
		}
	case "reachable":
		for _, s := range p.Signals {
			if s.Label == "reachable" {
				return true
			}
		}
	case "fixable":
		return p.Fix.State == FixAvailable || p.Fix.State == FixPartial
	case "nofix":
		return p.Fix.State == FixNone
	case "defended":
		return p.Group == GroupProtected || p.Group == GroupMonitored
	case "unprotected":
		return p.Fix.State == FixNone && !p.Covered
	case "direct":
		return p.Direct
	case "transitive":
		return !p.Direct
	}
	return false
}

// Unprotected lists the packages with no fix and no recorded, unexpired control:
// the "no fix and no plan" set that `--fail-on unprotected` fails on.
func Unprotected(r Report) []Package {
	var out []Package
	for _, p := range r.Packages {
		if p.Group != GroupNotAffected && p.Group != GroupUnverified && p.Fix.State == FixNone && !p.Covered {
			out = append(out, p)
		}
	}
	return out
}

// SortedNames returns the keys of a set in a stable order, for messages.
func SortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
