package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

// CodeFinding is one finding from the rule engine: static analysis, secrets,
// infrastructure as code or container files. They share a layout because they
// share a shape: a place in a file, a rule, a message.
type CodeFinding struct {
	RuleID   string
	Name     string
	Severity string
	Kind     string // sast | secrets | iac | oci
	Path     string
	Line     int
	EndLine  int
	Message  string
	// Snippet is the matched source. It is never printed for secrets.
	Snippet     string
	Description string
	HelpURI     string
	CWE         []int
	TestSuite   bool
}

// CodeReport is the engine's result, ready to draw.
type CodeReport struct {
	Findings []CodeFinding
	// Label names what ran: "SAST", "Secrets", "IaC", "Containers".
	Label       string
	RulesLoaded int
	RulesTotal  int
}

// codeNeedsAction is the rule for "needs action" among code findings. Unlike a
// dependency there is no exploit or reachability signal to read, so severity is
// the only honest input: critical and high.
func codeNeedsAction(f CodeFinding) bool {
	r := scaview.SeverityRank(f.Severity)
	return r <= scaview.SeverityRank("high")
}

type codeFile struct {
	path     string
	findings []CodeFinding
	worst    int
}

func groupCode(r CodeReport, o Options) ([]codeFile, int, int) {
	byPath := map[string]*codeFile{}
	var order []string
	action, wait := 0, 0
	for _, f := range r.Findings {
		if o.MinSeverity != "" && scaview.SeverityKnown(o.MinSeverity) &&
			scaview.SeverityRank(f.Severity) > scaview.SeverityRank(o.MinSeverity) {
			continue
		}
		cf, ok := byPath[f.Path]
		if !ok {
			cf = &codeFile{path: f.Path, worst: 99}
			byPath[f.Path] = cf
			order = append(order, f.Path)
		}
		cf.findings = append(cf.findings, f)
		if rk := scaview.SeverityRank(f.Severity); rk < cf.worst {
			cf.worst = rk
		}
		if codeNeedsAction(f) {
			action++
		} else {
			wait++
		}
	}
	files := make([]codeFile, 0, len(order))
	for _, p := range order {
		cf := byPath[p]
		sort.SliceStable(cf.findings, func(i, j int) bool {
			a, b := cf.findings[i], cf.findings[j]
			if ra, rb := scaview.SeverityRank(a.Severity), scaview.SeverityRank(b.Severity); ra != rb {
				return ra < rb
			}
			return a.Line < b.Line
		})
		files = append(files, *cf)
	}
	sort.SliceStable(files, func(i, j int) bool {
		if files[i].worst != files[j].worst {
			return files[i].worst < files[j].worst
		}
		return files[i].path < files[j].path
	})
	return files, action, wait
}

// RenderCode draws code findings in the packages view's grammar: a verdict
// line, then the files, worst first, then the next command.
func RenderCode(r CodeReport, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	files, action, wait := groupCode(r, o)
	total := action + wait
	label := strings.TrimSpace(r.Label)
	if label == "" {
		label = "SAST"
	}

	if o.Quiet {
		if total == 0 {
			return ""
		}
		return fmt.Sprintf("%s %s: %s\n", s.Bad(s.G.Fail), label, codeHeadline(total, len(files)))
	}

	var b strings.Builder
	if total == 0 {
		fmt.Fprintf(&b, " %s %s\n", s.Good(s.G.OK), s.Bold("No "+strings.ToLower(label)+" findings"))
		if r.RulesLoaded > 0 {
			fmt.Fprintf(&b, "   %s\n", s.Dim(rulesPhrase(r)+" evaluated"))
		}
		return b.String()
	}

	head := fmt.Sprintf(" %s %s %s", s.Bad(s.G.Fail), s.Bold(label), s.Bold(codeHeadline(total, len(files))))
	var parts []string
	if action > 0 {
		parts = append(parts, s.Bad(fmt.Sprintf("%d need action", action)))
	}
	if wait > 0 {
		parts = append(parts, s.Warn(fmt.Sprintf("%d can wait", wait)))
	}
	counts := strings.Join(parts, " "+s.Dim(s.G.Sep)+" ")
	if gap := s.Width - 1 - vis(head) - vis(counts); gap >= 2 && s.Width >= tierCompact {
		b.WriteString(head + strings.Repeat(" ", min(gap, 10)) + counts + "\n")
	} else {
		b.WriteString(head + "\n   " + counts + "\n")
	}
	if r.RulesLoaded > 0 && s.Width >= tierCompact {
		fmt.Fprintf(&b, "   %s\n", s.Dim(rulesPhrase(r)))
	}

	for _, f := range files {
		b.WriteString("\n " + s.Path(f.path) + "\n")
		b.WriteString(renderCodeFindings(f.findings, o, s))
	}

	first := files[0].findings[0]
	b.WriteString("\n " + s.Bold("NEXT") + "\n")
	cmd := "vulnetix " + o.Command
	if o.Command == "" {
		cmd = "vulnetix scan"
	}
	b.WriteString("   " + s.Cmd(cmd+" --explain "+first.RuleID) + "\n")
	if o.Verbosity == 0 {
		b.WriteString("   " + s.Cmd(cmd+" -v") + pad("", 4) + s.Dim("the matched code") + "\n")
	}
	return b.String()
}

func codeHeadline(findings, files int) string {
	return fmt.Sprintf("%d %s in %s", findings, pluralWord(findings, "finding", "findings"), plural(files, "file"))
}

func rulesPhrase(r CodeReport) string {
	if r.RulesTotal > 0 && r.RulesTotal != r.RulesLoaded {
		return fmt.Sprintf("%d of %d rules", r.RulesLoaded, r.RulesTotal)
	}
	return fmt.Sprintf("%d rules", r.RulesLoaded)
}

// renderCodeFindings draws one file's findings. Identical findings (a rule that
// reports several resources on one line) collapse to ×N; each is still counted
// everywhere else.
func renderCodeFindings(in []CodeFinding, o Options, s *Style) string {
	type row struct {
		f CodeFinding
		n int
	}
	var rows []row
	idx := map[string]int{}
	for _, f := range in {
		key := fmt.Sprintf("%s|%s|%d|%s", f.RuleID, f.Severity, f.Line, f.Message)
		if i, ok := idx[key]; ok {
			rows[i].n++
			continue
		}
		idx[key] = len(rows)
		rows = append(rows, row{f, 1})
	}

	var b strings.Builder
	for _, r := range rows {
		f := r.f
		loc := "-"
		if f.Line > 0 {
			loc = fmt.Sprintf("%d", f.Line)
		}
		sev := SevWord(f.Severity)
		line := fmt.Sprintf("  %s %s %s  %s", pad(s.Dim(loc), 5), s.Sev(f.Severity, s.G.Dot), pad(s.Sev(f.Severity, sev), 8), s.Bold(f.RuleID))
		if r.n > 1 {
			line += s.Dim(fmt.Sprintf("  ×%d", r.n))
		}
		if f.TestSuite {
			line += s.Dim("  test code")
		}
		b.WriteString(line + "\n")
		for _, l := range wrapText(f.Message, s.Width-16) {
			b.WriteString("               " + l + "\n")
		}
		if snip := codeSnippet(f, o, s); snip != "" {
			b.WriteString(snip)
		}
	}
	return b.String()
}

// codeSnippet draws the matched source in a gutter. At the default verbosity it
// is one line; -v shows up to six. A secret's value is never printed: the point
// of a secrets finding is that the value should not travel.
func codeSnippet(f CodeFinding, o Options, s *Style) string {
	if f.Kind == "secrets" {
		if o.Verbosity >= 1 {
			return "               " + s.Dim("the matched value is not shown") + "\n"
		}
		return ""
	}
	if strings.TrimSpace(f.Snippet) == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(f.Snippet, "\n"), "\n")
	limit := 1
	if o.Verbosity >= 1 {
		limit = 6
	}
	var b strings.Builder
	for i, l := range lines {
		if i >= limit {
			b.WriteString("               " + s.Dim(s.G.Bar+" "+s.G.Ellipsis) + "\n")
			break
		}
		l = strings.ReplaceAll(l, "\t", "    ")
		num := ""
		if f.Line > 0 {
			num = fmt.Sprintf("%d", f.Line+i)
		}
		text := s.clip(strings.TrimRight(l, " \r"), max(10, s.Width-24))
		b.WriteString("               " + s.Dim(pad(num, 4)+" "+s.G.Bar) + " " + text + "\n")
	}
	return b.String()
}

// RenderCodePlain is the pipe and CI form: one line per finding.
func RenderCodePlain(r CodeReport, o Options, t *display.Terminal) string {
	s := plainStyle(t, o)
	files, action, wait := groupCode(r, o)
	label := strings.ToLower(strings.TrimSpace(r.Label))
	if label == "" {
		label = "sast"
	}
	cmd := o.Command
	if cmd == "" {
		cmd = "scan"
	}
	_ = s
	var b strings.Builder
	if action+wait == 0 {
		fmt.Fprintf(&b, "vulnetix %s: CLEAN  no %s findings\n", cmd, label)
		return b.String()
	}
	fmt.Fprintf(&b, "vulnetix %s: FINDINGS  %s, %d need action, %d can wait\n\n", cmd, codeHeadlinePlain(action+wait, len(files), label), action, wait)
	for _, f := range files {
		for _, x := range f.findings {
			loc := f.path
			if x.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.path, x.Line)
			}
			fmt.Fprintf(&b, "  %-8s  %s  %s  %s\n", SevWord(x.Severity), loc, x.RuleID, x.Message)
		}
	}
	return b.String()
}

func codeHeadlinePlain(findings, files int, label string) string {
	return fmt.Sprintf("%d %s %s in %s", findings, label, pluralWord(findings, "finding", "findings"), plural(files, "file"))
}

// RenderCodeGitHub emits workflow-command annotations, one per finding, on the
// file and line.
func RenderCodeGitHub(r CodeReport) string {
	var b strings.Builder
	for _, f := range r.Findings {
		level := "warning"
		if codeNeedsAction(f) {
			level = "error"
		}
		props := "file=" + ghProp(f.Path)
		if f.Line > 0 {
			props += fmt.Sprintf(",line=%d", f.Line)
			if f.EndLine > f.Line {
				props += fmt.Sprintf(",endLine=%d", f.EndLine)
			}
		}
		fmt.Fprintf(&b, "::%s %s,title=%s::%s\n", level, props, ghProp(f.RuleID), ghData(f.Message))
	}
	return b.String()
}

// FindCodeExplain returns the findings a --explain query names: a rule id, or a
// file path.
func FindCodeExplain(r CodeReport, query string) []CodeFinding {
	q := strings.ToLower(strings.TrimSpace(query))
	var out []CodeFinding
	for _, f := range r.Findings {
		if strings.ToLower(f.RuleID) == q || strings.ToLower(f.Path) == q {
			out = append(out, f)
		}
	}
	return out
}

// RenderCodeExplain shows the rule behind a finding and where it fired.
func RenderCodeExplain(r CodeReport, query string, o Options, t *display.Terminal) (string, bool) {
	hits := FindCodeExplain(r, query)
	if len(hits) == 0 {
		return "", false
	}
	s := NewStyle(t, o)
	var b strings.Builder
	first := hits[0]
	name := first.Name
	if name == "" {
		name = first.RuleID
	}
	fmt.Fprintf(&b, "\n %s %s %s\n\n", s.Bold(first.RuleID), s.Dim(s.G.Sep), name)
	kv := func(k, v string) { fmt.Fprintf(&b, "   %s %s\n", s.Dim(pad(k, 12)), v) }
	kv("severity", s.Sev(first.Severity, SevWord(first.Severity)))
	if first.Kind != "" {
		kv("kind", first.Kind)
	}
	if first.Description != "" {
		for i, l := range wrapText(first.Description, s.Width-18) {
			k := ""
			if i == 0 {
				k = "about"
			}
			kv(k, l)
		}
	}
	if len(first.CWE) > 0 {
		var ids []string
		for _, c := range first.CWE {
			ids = append(ids, fmt.Sprintf("CWE-%d", c))
		}
		kv("weakness", strings.Join(ids, ", "))
	}
	if first.HelpURI != "" {
		kv("more", s.Cmd(first.HelpURI))
	}
	fmt.Fprintf(&b, "\n   %s\n", s.Bold(fmt.Sprintf("%d %s", len(hits), pluralWord(len(hits), "place", "places"))))
	for _, h := range hits {
		loc := h.Path
		if h.Line > 0 {
			loc = fmt.Sprintf("%s:%d", h.Path, h.Line)
		}
		fmt.Fprintf(&b, "   %s %s\n", s.Path(loc), s.Dim(h.Message))
		verbose := o
		verbose.Verbosity = max(o.Verbosity, 1)
		if snip := codeSnippet(h, verbose, s); snip != "" {
			b.WriteString(snip)
		}
	}
	return b.String(), true
}
