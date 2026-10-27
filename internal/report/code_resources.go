package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

// containerFixes are the one-line fixes for the built-in container rules. They
// live here and not in rule metadata because the rules are plain Rego with no
// field for one; a rule without an entry prints no fix line rather than a vague
// one. External packs have none.
var containerFixes = map[string]string{
	"VNX-DOCKER-001": "add USER 65532:65532 after the last RUN",
	"VNX-DOCKER-002": "pin a version tag, and a digest for a reproducible build",
	"VNX-DOCKER-003": "pass it at run time from a secret store; never bake it into a layer",
	"VNX-DOCKER-004": "download it in a RUN step and verify its checksum, or use a pinned COPY --from",
	"VNX-DOCKER-005": "remove privileged; add only the capabilities it needs under cap_add",
	"VNX-DOCKER-006": "use COPY for files in the build context",
	"VNX-DOCKER-007": "add a HEALTHCHECK so the orchestrator can tell the service is up",
	"VNX-DOCKER-008": "pin each package, for example apk add curl=8.5.0-r0",
}

// problem is one thing wrong on a resource. Findings from several rule packs on
// the same line with the same weakness class are the same problem.
type problem struct {
	title, severity, snippet string
	line                     int
	ids                      []string
	places                   []CodeFinding
}

func (p *problem) fix() string {
	for _, id := range p.ids {
		if f, ok := containerFixes[id]; ok {
			return f
		}
	}
	return ""
}

// foldProblems merges findings into problems. Two findings are one problem when
// they sit on the same line and name the same weakness (CWE); without a CWE the
// rule id is all that identifies a weakness, so nothing merges. -v folds nothing.
func foldProblems(fs []CodeFinding, o Options) []*problem {
	idx := map[string]*problem{}
	var out []*problem
	for _, f := range fs {
		key := fmt.Sprintf("%s|%d|%s", f.RuleID, f.Line, f.Path)
		if len(f.CWE) > 0 && o.Verbosity == 0 {
			cwe := append([]int(nil), f.CWE...)
			sort.Ints(cwe)
			key = fmt.Sprintf("%s|%d|%v", f.Path, f.Line, cwe)
		}
		p, ok := idx[key]
		if !ok {
			p = &problem{title: ruleTitle(f), severity: f.Severity, snippet: strings.TrimSpace(f.Snippet), line: f.Line}
			idx[key] = p
			out = append(out, p)
		}
		p.places = append(p.places, f)
		if scaview.SeverityRank(f.Severity) < scaview.SeverityRank(p.severity) {
			p.severity = f.Severity
		}
		seen := false
		for _, id := range p.ids {
			seen = seen || id == f.RuleID
		}
		if !seen {
			p.ids = append(p.ids, f.RuleID)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ra, rb := scaview.SeverityRank(out[i].severity), scaview.SeverityRank(out[j].severity); ra != rb {
			return ra < rb
		}
		return out[i].line < out[j].line
	})
	return out
}

// resBlock is the unit of the iac and containers reports: a resource, or an
// image, with its problems.
type resBlock struct {
	name, path string
	line       int
	problems   []*problem
	findings   int
}

func (b *resBlock) worst() string {
	if len(b.problems) == 0 {
		return "info"
	}
	return b.problems[0].severity
}

func (b *resBlock) countAction() int {
	n := 0
	for _, p := range b.problems {
		if codeNeedsAction(CodeFinding{Severity: p.severity}) {
			n++
		}
	}
	return n
}

func blocksOf(fs []CodeFinding, o Options) []*resBlock {
	idx := map[string]*resBlock{}
	var order []string
	byKey := map[string][]CodeFinding{}
	for _, f := range fs {
		key := f.Path + "|" + f.Resource
		if _, ok := idx[key]; !ok {
			name, line := f.Resource, f.ResourceLine
			if name == "" {
				name, line = f.Path, 0
			}
			idx[key] = &resBlock{name: name, path: f.Path, line: line}
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], f)
	}
	var out []*resBlock
	for _, k := range order {
		b := idx[k]
		b.problems = foldProblems(byKey[k], o)
		b.findings = len(byKey[k])
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := scaview.SeverityRank(a.worst()), scaview.SeverityRank(b.worst()); ra != rb {
			return ra < rb
		}
		if len(a.problems) != len(b.problems) {
			return len(a.problems) > len(b.problems)
		}
		return a.name < b.name
	})
	return out
}

func (b *resBlock) where() string {
	if b.name == b.path {
		return ""
	}
	if b.line > 0 {
		return fmt.Sprintf("%s:%d", b.path, b.line)
	}
	return b.path
}

type resourceView struct {
	action, wait         []*resBlock
	tests                []CodeFinding
	vendored             codeView
	problemsA, problemsW int
	findings, folded     int
	files                map[string]bool
	resources            map[string]bool
}

func buildResourceView(r CodeReport, o Options) resourceView {
	var v resourceView
	v.files, v.resources = map[string]bool{}, map[string]bool{}
	var groups [4][]CodeFinding
	for _, f := range r.Findings {
		if o.MinSeverity != "" && scaview.SeverityKnown(o.MinSeverity) &&
			scaview.SeverityRank(f.Severity) > scaview.SeverityRank(o.MinSeverity) {
			continue
		}
		g := codeGroupOf(f, o)
		groups[g] = append(groups[g], f)
		v.files[f.Path] = true
	}
	v.action = blocksOf(groups[codeAction], o)
	v.wait = blocksOf(groups[codeWait], o)
	for _, bl := range v.action {
		v.problemsA += len(bl.problems)
		v.findings += bl.findings
		v.resources[bl.path+"|"+bl.name] = true
	}
	for _, bl := range v.wait {
		v.problemsW += len(bl.problems)
		v.findings += bl.findings
		v.resources[bl.path+"|"+bl.name] = true
	}
	v.folded = v.findings - v.problemsA - v.problemsW
	v.tests = groups[codeTests]
	vr := r
	vr.Findings = groups[codeVendored]
	v.vendored = buildCodeView(vr, o)
	return v
}

// rowLR puts a right-hand cell at the edge of the section rule, or beneath when
// the two do not fit.
func rowLR(left, right string, s *Style) string {
	if gap := codeRowWidth(s) - 1 - vis(left) - vis(right); gap >= 2 && s.Width >= tierCompact {
		return left + strings.Repeat(" ", gap) + right + "\n"
	}
	return left + "\n" + indentFor(s)[:3] + right + "\n"
}

func renderResources(r CodeReport, o Options, t *display.Terminal, containers bool) string {
	s := NewStyle(t, o)
	v := buildResourceView(r, o)
	label, noun := "IAC", "resource"
	if containers {
		label, noun = "CONTAINERS", "image"
	}
	nTests := len(v.tests)
	nVendored := v.vendored.counts[codeVendored]
	total := v.problemsA + v.problemsW + nTests + nVendored

	if o.Quiet {
		if total == 0 {
			return ""
		}
		return fmt.Sprintf("%s %s: %s\n", s.Bad(s.G.Fail), label, resourceHeadline(v, containers, s.G.Sep))
	}
	var b strings.Builder
	if total == 0 {
		fmt.Fprintf(&b, " %s %s\n", s.Good(s.G.OK), s.Bold("No "+strings.ToLower(codeLabel(r))+" findings"))
		if r.RulesLoaded > 0 {
			fmt.Fprintf(&b, "   %s\n", s.Dim(rulesPhrase(r)+" evaluated"))
		}
		return b.String()
	}

	mark := s.Bad(s.G.Fail)
	if v.problemsA == 0 {
		mark = s.Warn(s.G.Fail)
	}
	head := fmt.Sprintf(" %s %s %s", mark, s.Bold(label), s.Bold(resourceHeadline(v, containers, s.G.Sep)))
	var parts []string
	if v.problemsA > 0 {
		parts = append(parts, s.Bad(fmt.Sprintf("%d %s action", v.problemsA, pluralWord(v.problemsA, "needs", "need"))))
	}
	if v.problemsW > 0 {
		parts = append(parts, s.Warn(fmt.Sprintf("%d can wait", v.problemsW)))
	}
	if nTests > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d in tests", nTests)))
	}
	if nVendored > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d vendored", nVendored)))
	}
	b.WriteString(headLine(head, strings.Join(parts, " "+s.Dim(s.G.Sep)+" "), s))
	var sub []string
	if v.findings > 0 {
		sub = append(sub, plural(v.findings, "finding"))
	}
	if v.folded > 0 {
		sub = append(sub, fmt.Sprintf("%d folded as the same problem", v.folded))
	}
	if r.RulesLoaded > 0 {
		sub = append(sub, rulesPhrase(r)+" ran")
	}
	if len(sub) > 0 && s.Width >= tierCompact {
		fmt.Fprintf(&b, "   %s\n", s.Dim(strings.Join(sub, " "+s.G.Sep+" ")))
	}

	if containers {
		b.WriteString(renderCards(v, o, s))
	} else {
		b.WriteString(renderIaCGroups(v, o, s))
	}

	if nTests > 0 {
		b.WriteString("\n" + codeSectionNote(s, "IN TESTS", fmt.Sprintf("%s %s listed, not ranked", plural(len(v.tests), "finding"), s.G.Sep)))
		b.WriteString(fileTally(v.tests, s))
	}
	if nVendored > 0 {
		b.WriteString("\n" + codeSectionNote(s, "VENDORED", fmt.Sprintf("%s %s third-party files in the tree",
			plural(nVendored, "place"), s.G.Sep)))
		b.WriteString(renderVendored(v.vendored.vendored, s))
	}
	b.WriteString(renderSteps(resourceNext(v, o, s, containers, noun), s))
	return b.String()
}

func resourceHeadline(v resourceView, containers bool, sep string) string {
	problems := v.problemsA + v.problemsW
	if containers {
		// An image with action and wait problems is one image.
		seen := map[string]bool{}
		for _, bl := range append(append([]*resBlock{}, v.action...), v.wait...) {
			seen[bl.path+"|"+bl.name] = true
		}
		cards := len(seen)
		return fmt.Sprintf("%s %s %s", plural(cards, "image"), sep, plural(problems, "problem"))
	}
	return fmt.Sprintf("%s on %s in %s", plural(problems, "problem"), plural(len(v.resources), "resource"), plural(len(v.files), "file"))
}

// fileTally lists files with how many findings each holds.
func fileTally(fs []CodeFinding, s *Style) string {
	count := map[string]int{}
	var order []string
	for _, f := range fs {
		if _, ok := count[f.Path]; !ok {
			order = append(order, f.Path)
		}
		count[f.Path]++
	}
	sort.SliceStable(order, func(i, j int) bool {
		if count[order[i]] != count[order[j]] {
			return count[order[i]] > count[order[j]]
		}
		return order[i] < order[j]
	})
	var b strings.Builder
	ind := indentFor(s)
	shown := min(5, len(order))
	pathW := 0
	for _, p := range order[:shown] {
		pathW = max(pathW, display.Width(p))
	}
	pathW = min(pathW+2, s.Width-len(ind)-14)
	for _, p := range order[:shown] {
		n := count[p]
		b.WriteString(ind + pad(s.Path(s.clip(p, pathW-2)), pathW) + s.Dim(plural(n, "finding")) + "\n")
	}
	if rest := len(order) - shown; rest > 0 {
		b.WriteString(ind + s.Dim(fmt.Sprintf("+ %d more %s", rest, pluralWord(rest, "file", "files"))) + "\n")
	}
	return b.String()
}

// problemCols are the widths shared by every problem row in a section, so the
// columns line up across resources.
type problemCols struct {
	title, snippet int
}

func colsOf(blocks []*resBlock, s *Style) problemCols {
	var c problemCols
	idsW := 0
	for _, bl := range blocks {
		for _, p := range bl.problems {
			c.title = max(c.title, display.Width(p.title))
			c.snippet = max(c.snippet, display.Width(oneLine(p.snippet)))
			idsW = max(idsW, display.Width(strings.Join(p.ids, " "+s.G.Sep+" ")))
		}
	}
	c.title = min(c.title, max(24, codeRowWidth(s)-1-(2+12+2+7)-idsW))
	// The rule ids say which packs agree, so they get their room first; the
	// matched line takes what is left, and goes when little is.
	avail := codeRowWidth(s) - 1 - (2 + 12 + c.title + 2 + 7) - idsW
	c.snippet = min(c.snippet, min(24, avail-2))
	if c.snippet < 10 {
		c.snippet = 0
	}
	return c
}

func oneLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.Join(strings.Fields(s), " ")
}

// problemRow draws one problem: severity, what is wrong, the line that says so,
// where it is and which rules raised it.
func problemRow(p *problem, c problemCols, glyph string, o Options, s *Style) string {
	sev := s.Sev(p.severity, glyph+" "+SevWord(p.severity))
	ids := strings.Join(p.ids, " "+s.G.Sep+" ")
	loc := ""
	if p.line > 0 {
		loc = fmt.Sprintf(":%d", p.line)
	}
	if s.Width < tierCompact {
		out := "  " + sev + "\n"
		out += "    " + s.clip(p.title, s.Width-6) + "\n"
		out += "    " + s.Dim(s.clip(strings.TrimSpace(loc+" "+ids), s.Width-6)) + "\n"
		return out
	}
	left := "  " + pad(sev, 12) + pad(s.clip(p.title, c.title), c.title+2)
	if c.snippet > 0 {
		left += pad(s.Dim(s.clip(oneLine(p.snippet), c.snippet)), c.snippet+2)
	}
	left += pad(s.Dim(loc), 7)
	room := codeRowWidth(s) - 1 - vis(left)
	if room < 12 {
		return "  " + sev + " " + s.clip(p.title, s.Width-14) + "\n" + "    " + s.Dim(s.clip(strings.TrimSpace(loc+" "+ids), s.Width-6)) + "\n"
	}
	return left + s.Dim(s.clip(ids, room)) + "\n"
}

func fixRow(p *problem, s *Style) string {
	f := p.fix()
	if f == "" {
		return ""
	}
	ind := "              "
	if s.Width < tierCompact {
		ind = "    "
	}
	lines := wrapText(f, max(20, codeRowWidth(s)-len(ind)-6))
	var b strings.Builder
	for i, l := range lines {
		if i == 0 {
			b.WriteString(ind + s.Dim("fix: ") + l + "\n")
		} else {
			b.WriteString(ind + "     " + l + "\n")
		}
	}
	return b.String()
}

func blockHead(bl *resBlock, right string, s *Style) string {
	left := " " + s.Bold(s.clip(bl.name, max(10, codeRowWidth(s)-30)))
	if w := bl.where(); w != "" && s.Width >= tierCompact {
		left += "  " + s.Dim(s.clip(w, max(10, codeRowWidth(s)-vis(left)-vis(right)-4)))
	}
	return rowLR(left, right, s)
}

func renderIaCGroups(v resourceView, o Options, s *Style) string {
	var b strings.Builder
	if len(v.action) > 0 {
		b.WriteString("\n" + resourceSection(s, "NEEDS ACTION", fmt.Sprintf("%s on %s", plural(v.problemsA, "problem"), plural(len(v.action), "resource"))))
		cols := colsOf(v.action, s)
		for i, bl := range v.action {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(blockHead(bl, s.Dim(plural(len(bl.problems), "problem")), s))
			for _, p := range bl.problems {
				b.WriteString(problemRow(p, cols, s.G.Dot, o, s))
			}
		}
	}
	if len(v.wait) > 0 {
		b.WriteString("\n" + resourceSection(s, "CAN WAIT", fmt.Sprintf("%s on %s %s medium and low", plural(v.problemsW, "problem"), plural(len(v.wait), "resource"), s.G.Sep)))
		items := waitItems(v.wait)
		limit := len(items)
		if o.Verbosity == 0 && limit > 7 {
			limit = 7
		}
		titleW := 0
		for _, it := range items[:limit] {
			titleW = max(titleW, display.Width(it.title))
		}
		titleW = min(titleW, 44)
		whereW := 0
		for _, it := range items[:limit] {
			if len(it.resources) > 1 {
				whereW = max(whereW, len(fmt.Sprintf("%d resources", len(it.resources))))
			} else {
				whereW = max(whereW, display.Width(it.resources[0]))
			}
		}
		whereW = min(whereW, 28)
		for _, it := range items[:limit] {
			b.WriteString(waitRow(it, titleW, whereW, s))
		}
		if rest := len(items) - limit; rest > 0 {
			b.WriteString(indentFor(s) + s.Dim(fmt.Sprintf("+ %d more %s %s -v lists every one", rest, pluralWord(rest, "rule", "rules"), s.G.Sep)) + "\n")
		}
	}
	return b.String()
}

func resourceSection(s *Style, title, note string) string {
	head := " " + s.Bold(title)
	if s.Width >= tierCompact {
		head += s.Dim(" " + s.G.Sep + " " + note)
	}
	return head + "\n " + s.Rule(s.Width-2) + "\n"
}

// waitItem is one low-urgency problem seen on one or more resources.
type waitItem struct {
	title, severity string
	resources       []string
	ids             []string
	n               int
}

func waitItems(blocks []*resBlock) []*waitItem {
	idx := map[string]*waitItem{}
	var out []*waitItem
	for _, bl := range blocks {
		for _, p := range bl.problems {
			key := strings.ToLower(p.title)
			it, ok := idx[key]
			if !ok {
				it = &waitItem{title: p.title, severity: p.severity}
				idx[key] = it
				out = append(out, it)
			}
			it.n++
			if scaview.SeverityRank(p.severity) < scaview.SeverityRank(it.severity) {
				it.severity = p.severity
			}
			it.resources = append(it.resources, bl.name)
			for _, id := range p.ids {
				dup := false
				for _, have := range it.ids {
					dup = dup || have == id
				}
				if !dup {
					it.ids = append(it.ids, id)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ra, rb := scaview.SeverityRank(out[i].severity), scaview.SeverityRank(out[j].severity); ra != rb {
			return ra < rb
		}
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].title < out[j].title
	})
	return out
}

func waitRow(it *waitItem, titleW, whereW int, s *Style) string {
	where := it.resources[0]
	if len(it.resources) > 1 {
		where = fmt.Sprintf("%d resources", len(it.resources))
	}
	ids := strings.Join(it.ids, " "+s.G.Sep+" ")
	if s.Width < tierCompact {
		return " " + s.Sev(it.severity, s.G.Dot+" "+SevWord(it.severity)) + "\n   " + s.clip(it.title, s.Width-4) + "\n   " + s.Dim(s.clip(where, s.Width-4)) + "\n"
	}
	left := " " + s.Sev(it.severity, s.G.Dot) + " " + pad(s.Sev(it.severity, SevWord(it.severity)), 9) + pad(s.clip(it.title, titleW), titleW+2)
	left += pad(s.clip(where, whereW), whereW+2)
	room := codeRowWidth(s) - 1 - vis(left)
	return left + s.Dim(s.clip(ids, max(8, room))) + "\n"
}

func renderCards(v resourceView, o Options, s *Style) string {
	var b strings.Builder
	// One card per image, with its action and wait problems together.
	byKey := map[string]*resBlock{}
	var cards []*resBlock
	for _, bl := range append(append([]*resBlock{}, v.action...), v.wait...) {
		k := bl.path + "|" + bl.name
		if c, ok := byKey[k]; ok {
			c.problems = append(c.problems, bl.problems...)
			c.findings += bl.findings
			continue
		}
		cp := *bl
		byKey[k] = &cp
		cards = append(cards, &cp)
	}
	for _, c := range cards {
		sort.SliceStable(c.problems, func(i, j int) bool {
			return scaview.SeverityRank(c.problems[i].severity) < scaview.SeverityRank(c.problems[j].severity)
		})
	}
	sort.SliceStable(cards, func(i, j int) bool {
		return scaview.SeverityRank(cards[i].worst()) < scaview.SeverityRank(cards[j].worst())
	})
	cols := colsOf(cards, s)
	for _, c := range cards {
		b.WriteString("\n")
		act := c.countAction()
		right := s.Warn(fmt.Sprintf("%d can wait", len(c.problems)-act))
		if act > 0 {
			right = s.Bad(fmt.Sprintf("%d %s action", act, pluralWord(act, "needs", "need")))
		}
		left := " " + s.Bold(s.clip(c.path, max(10, codeRowWidth(s)-32)))
		if c.name != c.path && s.Width >= tierCompact {
			left += "   " + s.Dim(s.clip(c.name, max(10, codeRowWidth(s)-vis(left)-vis(right)-6)))
		}
		b.WriteString(rowLR(left, right, s))
		b.WriteString(" " + s.Rule(s.Width-2) + "\n")
		for _, p := range c.problems {
			b.WriteString(problemRow(p, cols, s.G.Fail, o, s))
			b.WriteString(fixRow(p, s))
		}
	}
	return b.String()
}

func resourceNext(v resourceView, o Options, s *Style, containers bool, noun string) []nextStep {
	scanner := codeScanner("iac", o)
	if containers {
		scanner = codeScanner("oci", o)
	}
	var steps []nextStep
	blocks := append(append([]*resBlock{}, v.action...), v.wait...)
	seen := map[string]bool{}
	for _, bl := range blocks {
		if len(steps) >= 2 || seen[bl.path] {
			continue
		}
		seen[bl.path] = true
		n := 0
		// A path query explains every rule that fired there, so the command
		// loads every pack those rules came from.
		var ids []string
		for _, other := range blocks {
			if other.path == bl.path {
				n += len(other.problems)
				for _, p := range other.problems {
					ids = append(ids, p.ids...)
				}
			}
		}
		why := fmt.Sprintf("the %s on %s, with the lines", plural(n, "problem"), bl.name)
		if containers {
			why = fmt.Sprintf("the %s on this image, with the lines", plural(n, "problem"))
		}
		steps = append(steps, nextStep{explainCommand(o, scanner, bl.path, ids...), why})
	}
	if !containers && len(blocks) > 0 && len(blocks[0].problems) > 0 {
		p := blocks[0].problems[0]
		steps = append(steps, nextStep{explainCommand(o, scanner, p.ids[0], p.ids[0]), "why it matters, and every place it fires"})
	}
	if o.Verbosity == 0 {
		steps = append(steps, nextStep{rerunCommand(o, "-v"), "every finding with each rule id, nothing folded"})
	}
	if len(v.tests) > 0 {
		steps = append(steps, nextStep{rerunCommand(o, "--show", "tests"), "rank test files with the rest"})
	}
	if dirs := vendoredDirsOf(v.vendored.vendored); len(dirs) > 0 {
		steps = append(steps, nextStep{rerunCommand(o, "--exclude", dirs[0].dir), "stop scanning code you did not write"})
	}
	return steps
}
