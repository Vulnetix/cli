package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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

	// Resource is the thing the finding sits in: "aws_s3_bucket.logs",
	// "Deployment/api", "service api". ResourceLine is where it starts. The
	// caller reads both from the file; they are empty where a file has no such
	// notion.
	Resource     string
	ResourceLine int

	// Where a secret entered the history, from git blame. Blamed is false when
	// nothing could be asked (not a git tree), so "unknown" is never "clean".
	Blamed bool
	// InHistory marks a copy found in a past commit, not in the working tree.
	InHistory   bool
	Committed   bool
	Commit      string
	CommittedAt time.Time
}

// CodeReport is the engine's result, ready to draw.
type CodeReport struct {
	Findings []CodeFinding
	// Label names what ran: "SAST", "Secrets", "IaC", "Containers".
	Label       string
	RulesLoaded int
	RulesTotal  int
}

// codeNeedsAction is the severity half of "needs action" among code findings.
// Unlike a dependency there is no exploit or reachability signal to read, so
// severity is the only honest input: critical and high. Where the finding sits
// (test code, a vendored tree) decides the rest; see codeGroupOf.
func codeNeedsAction(f CodeFinding) bool {
	r := scaview.SeverityRank(f.Severity)
	return r <= scaview.SeverityRank("high")
}

// The groups say what to do, as they do for packages. A high-severity finding
// in test code or a vendored tree is still counted and still in SARIF, JSON and
// the snapshot; it just does not claim the urgency of the same finding in the
// code that ships.
type codeGroup int

const (
	codeAction codeGroup = iota
	codeWait
	codeTests
	codeVendored
)

// vendoredDirs are path segments that hold someone else's code checked into
// this tree.
var vendoredDirs = map[string]bool{
	"third_party": true, "third-party": true, "thirdparty": true,
	"vendor": true, "vendored": true, "node_modules": true, "bower_components": true,
}

// vendoredRoot returns the directory a vendored path sits under, up to and
// including the vendoring segment ("schemas/third_party/"), or "".
func vendoredRoot(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "./"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if vendoredDirs[strings.ToLower(parts[i])] {
			return strings.Join(parts[:i+1], "/") + "/"
		}
	}
	return ""
}

func codeGroupOf(f CodeFinding, o Options) codeGroup {
	if !codeNeedsAction(f) {
		return codeWait
	}
	if vendoredRoot(f.Path) != "" {
		return codeVendored
	}
	if f.TestSuite && !o.Show["tests"] {
		return codeTests
	}
	return codeAction
}

// codeRule is the unit of the code report: one rule and every place it fired,
// the way a package is the unit of the dependency report.
type codeRule struct {
	id, severity, title string
	places              []CodeFinding
	files               []ruleFile
}

type ruleFile struct {
	path  string
	lines []int
}

type codeView struct {
	action, wait, tests, vendored []*codeRule
	counts                        [4]int
	files                         int
}

func (v codeView) total() int { return v.counts[0] + v.counts[1] + v.counts[2] + v.counts[3] }

func buildCodeView(r CodeReport, o Options) codeView {
	var v codeView
	rules := [4]map[string]*codeRule{{}, {}, {}, {}}
	files := map[string]bool{}
	for _, f := range r.Findings {
		if o.MinSeverity != "" && scaview.SeverityKnown(o.MinSeverity) &&
			scaview.SeverityRank(f.Severity) > scaview.SeverityRank(o.MinSeverity) {
			continue
		}
		g := codeGroupOf(f, o)
		v.counts[g]++
		files[f.Path] = true
		key := f.RuleID + "|" + scaview.NormaliseSeverity(f.Severity)
		cr, ok := rules[g][key]
		if !ok {
			cr = &codeRule{id: f.RuleID, severity: f.Severity, title: ruleTitle(f)}
			rules[g][key] = cr
		}
		cr.places = append(cr.places, f)
	}
	v.files = len(files)
	lists := [4]*[]*codeRule{&v.action, &v.wait, &v.tests, &v.vendored}
	for g, m := range rules {
		out := make([]*codeRule, 0, len(m))
		for _, cr := range m {
			cr.files = ruleFiles(cr.places)
			out = append(out, cr)
		}
		sort.Slice(out, func(i, j int) bool {
			a, b := out[i], out[j]
			if ra, rb := scaview.SeverityRank(a.severity), scaview.SeverityRank(b.severity); ra != rb {
				return ra < rb
			}
			if len(a.places) != len(b.places) {
				return len(a.places) > len(b.places)
			}
			return a.id < b.id
		})
		*lists[g] = out
	}
	return v
}

// ruleFiles groups a rule's places by file, most places first.
func ruleFiles(places []CodeFinding) []ruleFile {
	idx := map[string]int{}
	var out []ruleFile
	for _, p := range places {
		i, ok := idx[p.Path]
		if !ok {
			i = len(out)
			idx[p.Path] = i
			out = append(out, ruleFile{path: p.Path})
		}
		out[i].lines = append(out[i].lines, p.Line)
	}
	for i := range out {
		sort.Ints(out[i].lines)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].lines) != len(out[j].lines) {
			return len(out[i].lines) > len(out[j].lines)
		}
		return out[i].path < out[j].path
	})
	return out
}

// ruleTitle is the short name a rule row carries: the rule's own name, else the
// message up to its first clause, since messages usually go on to the advice.
func ruleTitle(f CodeFinding) string {
	if t := strings.TrimSpace(f.Name); t != "" {
		return t
	}
	m := strings.TrimSpace(f.Message)
	for _, sep := range []string{"; ", " — ", " - "} {
		if i := strings.Index(m, sep); i > 0 {
			m = m[:i]
		}
	}
	return m
}

// RenderCode draws code findings in the packages view's grammar: a verdict
// line, then the rules grouped by what to do, then the next commands.
func RenderCode(r CodeReport, o Options, t *display.Terminal) string {
	switch codeFlavour(r) {
	case flavourSecrets:
		return renderSecrets(r, o, t)
	case flavourIaC:
		return renderResources(r, o, t, false)
	case flavourContainers:
		return renderResources(r, o, t, true)
	}
	s := NewStyle(t, o)
	v := buildCodeView(r, o)
	total := v.total()
	label := codeLabel(r)

	if o.Quiet {
		if total == 0 {
			return ""
		}
		return fmt.Sprintf("%s %s: %s\n", s.Bad(s.G.Fail), label, codeHeadline(total, v.files))
	}

	var b strings.Builder
	if total == 0 {
		fmt.Fprintf(&b, " %s %s\n", s.Good(s.G.OK), s.Bold("No "+strings.ToLower(label)+" findings"))
		if r.RulesLoaded > 0 {
			fmt.Fprintf(&b, "   %s\n", s.Dim(rulesPhrase(r)+" evaluated"))
		}
		return b.String()
	}

	mark := s.Bad(s.G.Fail)
	if v.counts[codeAction] == 0 {
		mark = s.Warn(s.G.Fail)
	}
	head := fmt.Sprintf(" %s %s %s", mark, s.Bold(label), s.Bold(codeHeadline(total, v.files)))
	var parts []string
	if n := v.counts[codeAction]; n > 0 {
		parts = append(parts, s.Bad(fmt.Sprintf("%d need action", n)))
	}
	if n := v.counts[codeWait]; n > 0 {
		parts = append(parts, s.Warn(fmt.Sprintf("%d can wait", n)))
	}
	if n := v.counts[codeTests]; n > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d in tests", n)))
	}
	if n := v.counts[codeVendored]; n > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d vendored", n)))
	}
	counts := strings.Join(parts, " "+s.Dim(s.G.Sep)+" ")
	if gap := s.Width - 1 - vis(head) - vis(counts); gap >= 2 && s.Width >= tierCompact {
		b.WriteString(head + strings.Repeat(" ", min(gap, 10)) + counts + "\n")
	} else {
		b.WriteString(head + "\n   " + counts + "\n")
	}
	var sub []string
	if n := len(v.action); n > 0 {
		sub = append(sub, fmt.Sprintf("%s %s action", plural(n, "rule"), pluralWord(n, "needs", "need")))
	}
	if r.RulesLoaded > 0 {
		sub = append(sub, rulesPhrase(r)+" ran")
	}
	if len(sub) > 0 && s.Width >= tierCompact {
		fmt.Fprintf(&b, "   %s\n", s.Dim(strings.Join(sub, " "+s.G.Sep+" ")))
	}

	if len(v.action) > 0 {
		note := "production code"
		if o.Show["tests"] {
			note = "test code included"
		}
		b.WriteString("\n" + codeSection(s, "NEEDS ACTION", len(v.action), v.counts[codeAction], note))
		for i, cr := range v.action {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(renderRuleBlock(cr, o, s))
		}
	}

	if len(v.wait) > 0 {
		b.WriteString("\n" + codeSection(s, "CAN WAIT", len(v.wait), v.counts[codeWait], "medium and low"))
		limit := len(v.wait)
		if o.Verbosity == 0 && limit > 7 {
			limit = 7
		}
		for _, cr := range v.wait[:limit] {
			b.WriteString(renderRuleLine(cr, s))
		}
		if rest := len(v.wait) - limit; rest > 0 {
			b.WriteString(indentFor(s) + s.Dim(fmt.Sprintf("+ %d more %s %s -v lists every one", rest, pluralWord(rest, "rule", "rules"), s.G.Sep)) + "\n")
		}
	}

	if len(v.tests) > 0 {
		b.WriteString("\n" + codeSectionNote(s, "IN TESTS", fmt.Sprintf("%d high-severity %s %s listed, not ranked",
			v.counts[codeTests], pluralWord(v.counts[codeTests], "place", "places"), s.G.Sep)))
		b.WriteString(ruleTally(v.tests, s))
	}

	if len(v.vendored) > 0 {
		b.WriteString("\n" + codeSectionNote(s, "VENDORED", fmt.Sprintf("%d %s %s third-party files in the tree",
			v.counts[codeVendored], pluralWord(v.counts[codeVendored], "place", "places"), s.G.Sep)))
		b.WriteString(renderVendored(v.vendored, s))
	}

	b.WriteString(codeNext(v, o, s))
	return b.String()
}

func codeLabel(r CodeReport) string {
	if l := strings.TrimSpace(r.Label); l != "" {
		return l
	}
	return "SAST"
}

func codeCommand(o Options) string {
	if o.Command == "" {
		return "vulnetix scan"
	}
	return "vulnetix " + o.Command
}

func indentFor(s *Style) string {
	if s.Width < tierCompact {
		return "   "
	}
	return strings.Repeat(" ", 13)
}

func codeSection(s *Style, title string, rules, places int, note string) string {
	head := " " + s.Bold(title) + s.Dim(" "+s.G.Sep+" "+plural(rules, "rule")+" "+s.G.Sep+" "+plural(places, "place"))
	if note != "" && s.Width >= tierCompact {
		head += s.Dim(" " + s.G.Sep + " " + note)
	}
	return head + "\n " + s.Rule(s.Width-2) + "\n"
}

func codeSectionNote(s *Style, title, note string) string {
	head := " " + s.Bold(title)
	if s.Width >= tierCompact {
		head += s.Dim(" " + s.G.Sep + " " + note)
	}
	return head + "\n " + s.Rule(s.Width-2) + "\n"
}

// placesPhrase is "69 in 20 files", or the one place itself.
func placesPhrase(cr *codeRule) string {
	if len(cr.places) == 1 {
		return placeLoc(cr.places[0])
	}
	return fmt.Sprintf("%d in %s", len(cr.places), plural(len(cr.files), "file"))
}

func placeLoc(f CodeFinding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return f.Path
}

// ruleHead draws " ● HIGH      VNX-GO-014    title ...    69 in 20 files".
func ruleHead(cr *codeRule, right string, s *Style) string {
	dot := s.Sev(cr.severity, s.G.Dot)
	sev := SevWord(cr.severity)
	if s.Width < tierCompact {
		left := " " + dot + " " + s.Sev(cr.severity, sev) + "  " + s.Bold(cr.id)
		if gap := s.Width - 1 - vis(left) - vis(right); gap >= 2 {
			return left + strings.Repeat(" ", gap) + right + "\n"
		}
		return left + "\n   " + right + "\n"
	}
	idW := max(14, len(cr.id)+2)
	left := " " + dot + " " + pad(s.Sev(cr.severity, sev), 10) + pad(s.Bold(cr.id), idW)
	room := codeRowWidth(s) - 1 - vis(left) - vis(right) - 2
	title := s.clip(cr.title, room)
	gap := codeRowWidth(s) - 1 - vis(left) - vis(title) - vis(right)
	return left + title + strings.Repeat(" ", max(2, gap)) + right + "\n"
}

// renderRuleBlock is one NEEDS ACTION rule: its head, the files it fired in
// with their line numbers, and at -v the matched code at its first place.
func renderRuleBlock(cr *codeRule, o Options, s *Style) string {
	var b strings.Builder
	right := placesPhrase(cr)
	if len(cr.places) == 1 {
		right = s.Dim(right)
	}
	b.WriteString(ruleHead(cr, right, s))
	narrow := s.Width < tierCompact
	if narrow {
		b.WriteString("   " + s.clip(cr.title, s.Width-4) + "\n")
	}
	if len(cr.places) > 1 {
		shown := 3
		if narrow {
			shown = 2
		}
		if o.Verbosity >= 1 {
			shown = len(cr.files)
		}
		shown = min(shown, len(cr.files))
		pathW := 0
		for _, f := range cr.files[:shown] {
			pathW = max(pathW, display.Width(f.path))
		}
		ind := indentFor(s)
		pathW = min(pathW+2, s.Width-len(ind)-8)
		for _, f := range cr.files[:shown] {
			line := ind + pad(s.clip(f.path, pathW-2), pathW) + fmt.Sprintf("%3d", len(f.lines))
			if !narrow {
				room := codeRowWidth(s) - 1 - vis(line) - 3
				if nums := lineList(f.lines, room, s); nums != "" {
					line += "   " + s.Dim(nums)
				}
			}
			b.WriteString(line + "\n")
		}
		if rest := len(cr.files) - shown; rest > 0 {
			b.WriteString(ind + s.Dim(fmt.Sprintf("+ %d more %s", rest, pluralWord(rest, "file", "files"))) + "\n")
		}
	}
	if o.Verbosity >= 1 {
		if snip := codeSnippet(cr.places[0], o, s); snip != "" {
			b.WriteString(snip)
		}
	}
	return b.String()
}

// renderRuleLine is one CAN WAIT rule: a single row.
func renderRuleLine(cr *codeRule, s *Style) string {
	return ruleHead(cr, placesPhrase(cr), s)
}

// lineList renders line numbers to fit width: "172 184 340×2 +16".
func lineList(lines []int, width int, s *Style) string {
	type ln struct{ n, c int }
	var uniq []ln
	for _, l := range lines {
		if l <= 0 {
			continue
		}
		if k := len(uniq); k > 0 && uniq[k-1].n == l {
			uniq[k-1].c++
			continue
		}
		uniq = append(uniq, ln{l, 1})
	}
	times := "×"
	if s.G.Ellipsis == "..." {
		times = "x"
	}
	var parts []string
	used := 0
	for i, u := range uniq {
		p := strconv.Itoa(u.n)
		if u.c > 1 {
			p += times + strconv.Itoa(u.c)
		}
		rest := 0
		for _, r := range uniq[i+1:] {
			rest += r.c
		}
		need := len(p)
		if len(parts) > 0 {
			need++
		}
		tail := 0
		if rest > 0 {
			tail = len(" +") + len(strconv.Itoa(rest+u.c))
		}
		if used+need+tail > width {
			left := 0
			for _, r := range uniq[i:] {
				left += r.c
			}
			if len(parts) == 0 {
				return ""
			}
			return strings.Join(parts, " ") + " +" + strconv.Itoa(left)
		}
		parts = append(parts, p)
		used += need
	}
	return strings.Join(parts, " ")
}

// ruleTally is the IN TESTS line: "VNX-GO-014 16 · VNX-327 14 · + 8 more rules".
func ruleTally(rules []*codeRule, s *Style) string {
	ind := indentFor(s)
	room := codeRowWidth(s) - 1 - len(ind)
	sep := " " + s.Dim(s.G.Sep) + " "
	var b strings.Builder
	line := ""
	for i, cr := range rules {
		item := fmt.Sprintf("%s %d", cr.id, len(cr.places))
		rest := len(rules) - i - 1
		more := ""
		if rest > 0 {
			more = fmt.Sprintf(" %s + %d more %s", s.G.Sep, rest, pluralWord(rest, "rule", "rules"))
		}
		cand := item
		if line != "" {
			cand = line + sep + item
		}
		if line != "" && (vis(cand)+len(more) > room || i >= 4) {
			left := len(rules) - i
			line += s.Dim(fmt.Sprintf(" %s + %d more %s", s.G.Sep, left, pluralWord(left, "rule", "rules")))
			break
		}
		line = cand
	}
	b.WriteString(ind + line + "\n")
	return b.String()
}

type vendoredDir struct {
	dir   string
	n     int
	rules []*codeRule
	byID  map[string]int
}

func vendoredDirsOf(rules []*codeRule) []*vendoredDir {
	idx := map[string]*vendoredDir{}
	var out []*vendoredDir
	for _, cr := range rules {
		for _, p := range cr.places {
			root := vendoredRoot(p.Path)
			d, ok := idx[root]
			if !ok {
				d = &vendoredDir{dir: root, byID: map[string]int{}}
				idx[root] = d
				out = append(out, d)
			}
			d.n++
			if _, seen := d.byID[cr.id]; !seen {
				d.rules = append(d.rules, cr)
			}
			d.byID[cr.id]++
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].dir < out[j].dir
	})
	return out
}

func renderVendored(rules []*codeRule, s *Style) string {
	var b strings.Builder
	ind := indentFor(s)
	dirs := vendoredDirsOf(rules)
	pathW := 0
	for _, d := range dirs {
		pathW = max(pathW, display.Width(d.dir))
	}
	pathW = min(pathW+2, s.Width-len(ind)-8)
	for _, d := range dirs {
		line := ind + pad(s.clip(d.dir, pathW-2), pathW) + fmt.Sprintf("%3d", d.n)
		if s.Width >= tierCompact {
			var ids []string
			for _, cr := range d.rules {
				ids = append(ids, fmt.Sprintf("%s ×%d", cr.id, d.byID[cr.id]))
			}
			line += "   " + s.Dim(s.clip(strings.Join(ids, " "+s.G.Sep+" "), max(10, codeRowWidth(s)-1-vis(line)-3)))
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// codeNext is the NEXT block: the commands that take the reader from this
// summary to the detail, one per thing they can do next.
func codeNext(v codeView, o Options, s *Style) string {
	cmd := codeCommand(o)
	type step struct{ cmd, why string }
	var steps []step

	var top *codeRule
	switch {
	case len(v.action) > 0:
		top = v.action[0]
	case len(v.wait) > 0:
		top = v.wait[0]
	case len(v.tests) > 0:
		top = v.tests[0]
	case len(v.vendored) > 0:
		top = v.vendored[0]
	}
	if top != nil {
		why := "the rule, why it matters, and the matched code"
		if n := len(top.places); n > 1 {
			why = fmt.Sprintf("the rule, and all %d places with the matched code", n)
		}
		steps = append(steps, step{cmd + " --explain " + top.id, why})
	}
	if len(v.action) > 1 {
		steps = append(steps, step{cmd + " --explain " + v.action[1].id, "the next rule to look at"})
	}
	if o.Verbosity == 0 {
		why := "one snippet per rule, and every file it fired in"
		if len(v.wait) > 7 {
			why = "one snippet per rule, and every rule that can wait"
		}
		steps = append(steps, step{cmd + " -v", why})
	}
	if len(v.tests) > 0 {
		steps = append(steps, step{cmd + " --show tests", "rank test code with the rest"})
	}
	if len(v.vendored) > 0 {
		if dirs := vendoredDirsOf(v.vendored); len(dirs) > 0 {
			steps = append(steps, step{cmd + " --exclude " + dirs[0].dir, "stop scanning code you did not write"})
		}
	}
	if len(steps) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n " + s.Bold("NEXT") + "\n")
	w := 0
	for _, st := range steps {
		w = max(w, display.Width(st.cmd))
	}
	for _, st := range steps {
		if s.Width < tierCompact || 3+w+2+display.Width(st.why) > s.Width-1 {
			b.WriteString("   " + s.Cmd(st.cmd) + "\n")
			continue
		}
		b.WriteString("   " + pad(s.Cmd(st.cmd), w) + "  " + s.Dim(st.why) + "\n")
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

// codeSnippet draws the matched source in a gutter. At the default verbosity it
// is one line; -v shows up to six. A secret's value is never printed: the point
// of a secrets finding is that the value should not travel.
func codeSnippet(f CodeFinding, o Options, s *Style) string {
	return codeSnippetAt(f, o, s, strings.Repeat(" ", 13))
}

func codeSnippetAt(f CodeFinding, o Options, s *Style, ind string) string {
	if f.Kind == "secrets" {
		if o.Verbosity >= 1 {
			return ind + s.Dim("the matched value is not shown") + "\n"
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
			b.WriteString(ind + s.Dim("     "+s.G.Bar+" "+s.G.Ellipsis) + "\n")
			break
		}
		l = strings.ReplaceAll(l, "\t", "    ")
		num := ""
		if f.Line > 0 {
			num = fmt.Sprintf("%d", f.Line+i)
		}
		text := s.clip(strings.TrimRight(l, " \r"), max(10, s.Width-len(ind)-8))
		b.WriteString(ind + s.Dim(fmt.Sprintf("%4s", num)+" "+s.G.Bar) + " " + text + "\n")
	}
	return b.String()
}

// RenderCodePlain is the pipe and CI form: one line per finding, worst first.
func RenderCodePlain(r CodeReport, o Options, t *display.Terminal) string {
	v := buildCodeView(r, o)
	label := strings.ToLower(codeLabel(r))
	cmd := o.Command
	if cmd == "" {
		cmd = "scan"
	}
	var b strings.Builder
	if v.total() == 0 {
		fmt.Fprintf(&b, "vulnetix %s: CLEAN  no %s findings\n", cmd, label)
		return b.String()
	}
	tally := fmt.Sprintf("%d need action, %d can wait", v.counts[codeAction], v.counts[codeWait])
	if n := v.counts[codeTests]; n > 0 {
		tally += fmt.Sprintf(", %d in tests", n)
	}
	if n := v.counts[codeVendored]; n > 0 {
		tally += fmt.Sprintf(", %d vendored", n)
	}
	fmt.Fprintf(&b, "vulnetix %s: FINDINGS  %s, %s\n\n", cmd, codeHeadlinePlain(v.total(), v.files, label), tally)
	for _, group := range [][]*codeRule{v.action, v.wait, v.tests, v.vendored} {
		for _, cr := range group {
			for _, x := range cr.places {
				fmt.Fprintf(&b, "  %-8s  %s  %s  %s\n", SevWord(x.Severity), placeLoc(x), x.RuleID, x.Message)
			}
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

// RenderCodeExplain shows the rule behind a finding and every place it fired:
// production code first, grouped by file, then test code. A file path query
// explains each rule that fired in that file.
func RenderCodeExplain(r CodeReport, query string, o Options, t *display.Terminal) (string, bool) {
	hits := FindCodeExplain(r, query)
	if len(hits) == 0 {
		return "", false
	}
	s := NewStyle(t, o)
	var order []string
	byRule := map[string][]CodeFinding{}
	for _, h := range hits {
		if _, ok := byRule[h.RuleID]; !ok {
			order = append(order, h.RuleID)
		}
		byRule[h.RuleID] = append(byRule[h.RuleID], h)
	}
	sort.SliceStable(order, func(i, j int) bool {
		return scaview.SeverityRank(byRule[order[i]][0].Severity) < scaview.SeverityRank(byRule[order[j]][0].Severity)
	})
	var b strings.Builder
	for _, id := range order {
		if byRule[id][0].Kind == "secrets" {
			b.WriteString(explainSecret(byRule[id], o, s))
			continue
		}
		b.WriteString(explainRule(byRule[id], o, s))
	}
	b.WriteString(explainNext(order[0], byRule[order[0]][0].Kind, len(byRule[order[0]]), o, s))
	return b.String(), true
}

func explainRule(hits []CodeFinding, o Options, s *Style) string {
	var b strings.Builder
	first := hits[0]
	name := ruleTitle(first)
	if name == "" {
		name = first.RuleID
	}
	fmt.Fprintf(&b, "\n %s  %s  %s\n", s.Bold(first.RuleID), s.Sev(first.Severity, s.G.Dot+" "+SevWord(first.Severity)), name)

	var prod, tests []CodeFinding
	for _, h := range hits {
		if h.TestSuite {
			tests = append(tests, h)
		} else {
			prod = append(prod, h)
		}
	}
	var meta []string
	if first.Kind != "" {
		meta = append(meta, first.Kind)
	}
	meta = append(meta, plural(len(hits), "place"))
	if len(tests) > 0 && len(prod) > 0 {
		meta = append(meta, fmt.Sprintf("%d in production code, %d in tests", len(prod), len(tests)))
	} else if len(tests) > 0 {
		meta = append(meta, "all in tests")
	}
	if len(first.CWE) > 0 {
		var ids []string
		for _, c := range first.CWE {
			ids = append(ids, fmt.Sprintf("CWE-%d", c))
		}
		meta = append(meta, strings.Join(ids, ", "))
	}
	fmt.Fprintf(&b, " %s\n", s.Dim(strings.Join(meta, " "+s.G.Sep+" ")))

	about := strings.TrimSpace(first.Description)
	if about == "" {
		about = strings.TrimSpace(first.Message)
	}
	if about != "" {
		b.WriteString("\n " + s.Bold("WHY IT MATTERS") + "\n")
		for _, l := range wrapText(about, s.Width-6) {
			b.WriteString("   " + l + "\n")
		}
	}
	if first.HelpURI != "" {
		b.WriteString("   " + s.Dim("more ") + s.Cmd(first.HelpURI) + "\n")
	}

	if len(prod) > 0 {
		files := ruleFiles(prod)
		b.WriteString("\n " + s.Bold("WHERE") + s.Dim(fmt.Sprintf(" %s %d in %s", s.G.Sep, len(prod), plural(len(files), "file"))) + "\n")
		b.WriteString(" " + s.Rule(s.Width-2) + "\n")
		b.WriteString(explainPlaces(prod, files, o, s))
	}
	if len(tests) > 0 {
		files := ruleFiles(tests)
		b.WriteString("\n " + s.Bold("IN TESTS") + s.Dim(fmt.Sprintf(" %s %d in %s", s.G.Sep, len(tests), plural(len(files), "file"))) + "\n")
		b.WriteString(" " + s.Rule(s.Width-2) + "\n")
		if o.Verbosity >= 1 || len(prod) == 0 {
			b.WriteString(explainPlaces(tests, files, o, s))
		} else {
			shown := min(3, len(files))
			var items []string
			for _, f := range files[:shown] {
				items = append(items, fmt.Sprintf("%s %d", f.path, len(f.lines)))
			}
			b.WriteString("   " + strings.Join(items, " "+s.Dim(s.G.Sep)+" ") + "\n")
			if rest := len(files) - shown; rest > 0 {
				b.WriteString("   " + s.Dim(fmt.Sprintf("+ %d more %s", rest, pluralWord(rest, "file", "files"))) + "\n")
			}
		}
	}
	return b.String()
}

// explainPlaces lists places by file with the matched code: three per file in
// four files by default, every place at -v.
func explainPlaces(places []CodeFinding, files []ruleFile, o Options, s *Style) string {
	var b strings.Builder
	maxFiles, perFile := 4, 3
	if o.Verbosity >= 1 {
		maxFiles, perFile = len(files), 1<<30
	}
	snipOpts := o
	snipOpts.Verbosity = 0
	byFile := map[string][]CodeFinding{}
	for _, p := range places {
		byFile[p.Path] = append(byFile[p.Path], p)
	}
	shownFiles := min(maxFiles, len(files))
	for i, f := range files[:shownFiles] {
		if i > 0 {
			b.WriteString("\n")
		}
		count := strconv.Itoa(len(f.lines))
		path := s.clip(f.path, s.Width-8-len(count))
		gap := codeRowWidth(s) - 1 - 3 - display.Width(path) - len(count)
		b.WriteString("   " + s.Path(path) + strings.Repeat(" ", max(2, gap)) + count + "\n")
		ps := byFile[f.path]
		sort.SliceStable(ps, func(a, c int) bool { return ps[a].Line < ps[c].Line })
		n := min(perFile, len(ps))
		for _, p := range ps[:n] {
			snip := codeSnippetAt(p, snipOpts, s, "      ")
			if snip == "" {
				loc := "-"
				if p.Line > 0 {
					loc = strconv.Itoa(p.Line)
				}
				snip = "      " + s.Dim(fmt.Sprintf("%4s", loc)+" "+s.G.Bar) + "\n"
			}
			b.WriteString(snip)
		}
		if rest := len(ps) - n; rest > 0 {
			b.WriteString("      " + s.Dim(fmt.Sprintf("+ %d more in this file", rest)) + "\n")
		}
	}
	if rest := len(files) - shownFiles; rest > 0 {
		b.WriteString("\n   " + s.Dim(fmt.Sprintf("+ %d more %s %s add -v to print every place", rest, pluralWord(rest, "file", "files"), s.G.Sep)) + "\n")
	}
	return b.String()
}

func explainNext(id, kind string, n int, o Options, s *Style) string {
	cmd := codeCommand(o)
	type step struct{ cmd, why string }
	var steps []step
	if o.Verbosity == 0 && n > 1 {
		why := "every place, with its code"
		if kind == "secrets" {
			why = "every place, with how it got there"
		}
		steps = append(steps, step{cmd + " --explain " + id + " -v", why})
	}
	steps = append(steps, step{cmd, "back to every rule"})
	var b strings.Builder
	b.WriteString("\n " + s.Bold("NEXT") + "\n")
	w := 0
	for _, st := range steps {
		w = max(w, display.Width(st.cmd))
	}
	for _, st := range steps {
		if s.Width < tierCompact || 3+w+2+display.Width(st.why) > s.Width-1 {
			b.WriteString("   " + s.Cmd(st.cmd) + "\n")
			continue
		}
		b.WriteString("   " + pad(s.Cmd(st.cmd), w) + "  " + s.Dim(st.why) + "\n")
	}
	return b.String()
}

// codeRowWidth is where right-hand columns end: the edge of the section rule,
// so a count lines up under the rule's end rather than at a wide terminal's edge.
func codeRowWidth(s *Style) int {
	return min(s.Width, 98)
}
