package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/display"
)

// Layout tiers. A tier drops whole fields in a fixed order; it never clips a
// package name or a version.
const (
	tierWide    = 100
	tierCompact = 60
)

// RenderPackages draws the default view: a verdict, then packages grouped by
// what to do about them, then the next command.
func RenderPackages(r Report, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	s.fixW = maxFixWidth(r, o, s)
	var b strings.Builder
	counts := r.Counts()

	if o.Quiet {
		return renderQuiet(r, s)
	}

	b.WriteString(renderHeader(r, counts, s))

	for _, g := range groupOrder {
		pkgs := r.InGroup(g)
		if len(pkgs) == 0 {
			continue
		}
		b.WriteString("\n")
		b.WriteString(renderGroupHeader(g, pkgs, s))
		for i, p := range pkgs {
			if i > 0 && g != GroupNotAffected {
				b.WriteString("\n")
			}
			b.WriteString(renderItem(p, g, o, s))
		}
	}

	if next := renderNext(r, counts, o, s); next != "" {
		b.WriteString("\n")
		b.WriteString(next)
	}
	return b.String()
}

func renderHeader(r Report, c Counts, s *Style) string {
	var b strings.Builder
	elapsed := ""
	if r.Meta.Elapsed > 0 {
		elapsed = formatElapsed(r.Meta.Elapsed)
	}

	if c.Packages == 0 {
		if n := len(r.Meta.Unchecked); n > 0 {
			// Nothing found is not "clean" when part of the lookup failed.
			b.WriteString(fmt.Sprintf(" %s %s\n", s.Warn(s.G.Unknown), s.Bold("Incomplete: "+plural(n, "package")+" could not be checked")))
			b.WriteString(s.Dim("   the advisory lookup failed after retries; re-run the scan") + "\n")
			return b.String()
		}
		line := fmt.Sprintf(" %s %s", s.Good(s.G.OK), s.Bold("No vulnerabilities in "+plural(r.Meta.ScannedPackages, "package")))
		if r.Meta.ScannedPackages == 0 {
			line = fmt.Sprintf(" %s %s", s.Good(s.G.OK), s.Bold("No vulnerabilities found"))
		}
		if na := c.ByGroup[GroupNotAffected]; na > 0 {
			line += s.Dim(fmt.Sprintf(" %s %d ruled out by version", s.G.Sep, na))
		}
		if elapsed != "" {
			line += s.Dim(" " + s.G.Sep + " " + elapsed)
		}
		b.WriteString(line + "\n")
		if r.Meta.VEXSuppressed > 0 {
			b.WriteString(s.Dim(fmt.Sprintf("   %d suppressed by VEX", r.Meta.VEXSuppressed)) + "\n")
		}
		return b.String()
	}

	title := fmt.Sprintf(" %s %s", s.Bad(s.G.Fail), s.Bold(advisoriesIn(c)))
	var parts []string
	add := func(g Group, label string, paint func(string) string) {
		if n := c.ByGroup[g]; n > 0 {
			parts = append(parts, paint(fmt.Sprintf("%d %s", n, label)))
		}
	}
	add(GroupAction, "need action", s.Bad)
	add(GroupWait, "can wait", s.Warn)
	add(GroupUnverified, "unverified", s.Warn)
	add(GroupProtected, "protected", s.Defence)
	add(GroupMonitored, "monitored", s.Defence)
	add(GroupNotAffected, "not affected", s.Good)
	counts := strings.Join(parts, " "+s.Dim(s.G.Sep)+" ")

	gap := s.Width - 1 - vis(title) - vis(counts)
	if gap >= 2 && s.Width >= tierCompact {
		if gap > 10 {
			gap = 10
		}
		b.WriteString(title + strings.Repeat(" ", gap) + counts + "\n")
	} else {
		b.WriteString(title + "\n   " + counts + "\n")
	}

	var meta []string
	if r.Meta.ScannedPackages > 0 {
		meta = append(meta, plural(r.Meta.ScannedPackages, "package"))
	}
	if r.Meta.Manifests > 0 {
		meta = append(meta, plural(r.Meta.Manifests, "manifest"))
	}
	if len(r.Meta.Kinds) > 0 {
		meta = append(meta, strings.Join(r.Meta.Kinds, " "))
	}
	if elapsed != "" {
		meta = append(meta, elapsed)
	}
	if r.Meta.VEXSuppressed > 0 {
		meta = append(meta, fmt.Sprintf("%d suppressed by VEX", r.Meta.VEXSuppressed))
	}
	if len(meta) > 0 && s.Width >= tierCompact {
		b.WriteString(s.Dim("   "+strings.Join(meta, " "+s.G.Sep+" ")) + "\n")
	}
	if n := len(r.Meta.Unchecked); n > 0 {
		b.WriteString(s.Warn("   "+plural(n, "package")+" could not be checked (the advisory lookup failed after retries); the list above may be incomplete") + "\n")
	}
	return b.String()
}

func advisoriesIn(c Counts) string {
	adv := "advisories"
	if c.Advisories == 1 {
		adv = "advisory"
	}
	return fmt.Sprintf("%d %s in %s", c.Advisories, adv, plural(c.Packages, "package"))
}

func formatElapsed(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func renderGroupHeader(g Group, pkgs []Package, s *Style) string {
	note := ""
	switch g {
	case GroupWait:
		note = "no known exploit"
		if allReachAssessed(pkgs) {
			note += ", not reachable from your code"
		}
	case GroupUnverified:
		note = "matched by name, version could not be checked"
	case GroupProtected:
		note = "still affected, control recorded"
	case GroupMonitored:
		note = "detection only, nothing is blocked"
	case GroupNotAffected:
		note = "matched by name, ruled out by version"
	}
	head := " " + s.Bold(g.Title()) + s.Dim(" "+s.G.Sep+" "+plural(len(pkgs), "package"))
	if note != "" && s.Width >= tierCompact {
		head += s.Dim(" " + s.G.Sep + " " + note)
	}
	return head + "\n " + s.Rule(s.Width-2) + "\n"
}

// allReachAssessed reports whether reachability actually ran for every advisory.
// "Not reachable" is a claim only when it was checked; absence of data is not.
func allReachAssessed(pkgs []Package) bool {
	any := false
	for _, p := range pkgs {
		for _, a := range p.Advisories {
			any = true
			if !a.Ev.ReachabilityAssessed {
				return false
			}
		}
	}
	return any
}

func renderItem(p Package, g Group, o Options, s *Style) string {
	switch g {
	case GroupNotAffected:
		return renderRuledOut(p, s)
	case GroupProtected, GroupMonitored:
		return renderControlled(p, g, o, s)
	}
	return renderFinding(p, o, s)
}

// fixCell is the "what do I do" column.
func fixCell(p Package, s *Style, o Options) (plain string, painted string) {
	if o.Hide["fixes"] {
		return "", ""
	}
	switch p.Fix.State {
	case FixAvailable:
		if p.Fix.Target == "" {
			return "fix exists", s.Good("fix exists")
		}
		txt := s.G.Arrow + " " + p.Fix.Target
		return txt, s.Good(txt)
	case FixPartial:
		txt := fmt.Sprintf("%s %s (%d of %d)", s.G.Arrow, p.Fix.Target, p.Fix.Clears, p.Fix.Of)
		return txt, s.Warn(txt)
	case FixNone:
		return "no fix", s.Hot("no fix")
	}
	return "", ""
}

func renderFinding(p Package, o Options, s *Style) string {
	var b strings.Builder
	tier := tierOf(s.Width)
	indent := strings.Repeat(" ", 13)
	sev := SevWord(p.Severity)

	label := p.Label()
	_, fixPaint := fixCell(p, s, o)
	meta := metaFor(p, tier, s)

	dot := s.Sev(p.Severity, s.G.Dot)
	if p.Malicious {
		dot = s.Bad(s.G.Dot)
		sev = "MALWARE"
	}

	switch tier {
	case tierNarrow:
		fmt.Fprintf(&b, " %s %s %s\n", dot, s.Sev(p.Severity, sev), s.Bold(label))
		indent = "   "
		if fixPaint != "" {
			fmt.Fprintf(&b, "%s%s\n", indent, fixPaint)
		}
	default:
		labelW := 22
		if tier == tierWideLayout {
			labelW = 28
		}
		if w := display.Width(label); w+2 > labelW {
			labelW = w + 2
		}
		line := fmt.Sprintf(" %s %s  %s", dot, pad(s.Sev(p.Severity, sev), 8), pad(s.Bold(label), labelW))
		line += "  " + pad(fixPaint, max(14, s.fixW))
		if meta != "" {
			room := s.Width - vis(line) - 2
			if room > 4 {
				line += "  " + s.Dim(s.clip(meta, room))
			}
		}
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}

	// Second line: the advisory to name, its verdict if it is not simply
	// "affected", and the signals that made it urgent.
	// At -v the per-advisory detail below carries all of this, so it is not
	// said twice.
	if o.Verbosity == 0 {
		b.WriteString(advisorySummary(p, o, s, tier, indent))
	}

	if o.Show["paths"] && len(p.Via) > 0 {
		fmt.Fprintf(&b, "%s%s\n", indent, s.Dim("via "+strings.Join(p.Via, " "+s.G.Arrow+" ")+" "+s.G.Arrow+" "+p.Name))
	}

	if o.Verbosity >= 1 {
		b.WriteString(renderAdvisoryDetail(p, o, s, indent))
	}

	if p.Lapsed != nil && p.Group != GroupProtected && p.Group != GroupMonitored {
		fmt.Fprintf(&b, "%s%s\n", indent, s.Warn(fmt.Sprintf("control expired %s", p.Lapsed.Until.Format("2006-01-02"))))
	}

	b.WriteString(renderDefenceLines(p, o, s, indent))
	return b.String()
}

// advisorySummary is the line under a package: the advisory to name, its
// verdict if it is not simply "affected", the signals that made it urgent, and
// how many more it stands for.
func advisorySummary(p Package, o Options, s *Style, tier int, indent string) string {
	var b strings.Builder
	top := p.Top()
	var seg []string
	seg = append(seg, top.ID)
	if tag := verdictTag(top, s); tag != "" {
		seg = append(seg, tag)
	}
	for _, sg := range top.Signals {
		if o.Hide["exploits"] && (sg.Label == "PoC exploit" || sg.Label == "weaponized") {
			continue
		}
		seg = append(seg, signalText(sg, s))
	}
	if top.ReachAt != "" && (tier != tierNarrow) {
		seg = append(seg, s.Dim(top.ReachAt))
	}
	if o.Show["scores"] && top.CVSS > 0 {
		seg = append(seg, s.Dim(fmt.Sprintf("CVSS %.1f", top.CVSS)))
	}
	fmt.Fprintf(&b, "%s%s\n", indent, strings.Join(seg, "  "))

	if n := len(p.Advisories) - 1; n > 0 && o.Verbosity == 0 {
		tail := fmt.Sprintf("+ %d more %s", n, pluralWord(n, "advisory", "advisories"))
		if p.Fix.State == FixAvailable && p.Fix.Clears == p.Fix.Of && p.Fix.Target != "" && !o.Hide["fixes"] {
			tail += ", the same upgrade clears " + pluralWord(n, "it", "them")
		}
		fmt.Fprintf(&b, "%s%s\n", indent, s.Dim(tail))
	}
	return b.String()
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func verdictTag(a Advisory, s *Style) string {
	switch a.Verdict.Verdict {
	case "unverified":
		return s.Warn(s.G.Unknown + " unverified")
	case "likely_not_affected":
		return s.Warn(s.G.Unknown + " likely not affected")
	case "not_affected":
		return s.Good(s.G.OK + " not affected")
	}
	return ""
}

func signalText(sg Signal, s *Style) string {
	txt := s.G.Signal + " " + sg.Label
	if sg.Strong {
		return s.Hot(txt)
	}
	return s.Dim(txt)
}

const (
	tierWideLayout = iota
	tierCompactLayout
	tierNarrow
)

func tierOf(width int) int {
	switch {
	case width >= tierWide:
		return tierWideLayout
	case width >= tierCompact:
		return tierCompactLayout
	}
	return tierNarrow
}

func metaFor(p Package, tier int, s *Style) string {
	if tier != tierWideLayout {
		if !p.Direct && len(p.Via) > 0 {
			return "via " + p.Via[len(p.Via)-1]
		}
		return ""
	}
	var parts []string
	if p.Ecosystem != "" {
		parts = append(parts, pad(p.Ecosystem, 6))
	}
	switch {
	case !p.Direct && len(p.Via) > 0:
		parts = append(parts, "via "+p.Via[len(p.Via)-1])
	case p.Source != "":
		src := p.Source
		if p.MoreSources > 0 {
			src += fmt.Sprintf(" +%d", p.MoreSources)
		}
		parts = append(parts, src)
	}
	return strings.TrimRight(strings.Join(parts, " "), " ")
}

func renderRuledOut(p Package, s *Style) string {
	a := p.Top()
	mark := s.Good(s.G.OK)
	tail := ""
	switch a.Verdict.Verdict {
	case "likely_not_affected":
		mark = s.Warn(s.G.Unknown)
	}
	inst := p.Version
	switch {
	case a.Verdict.FixedIn != "" && a.Verdict.Basis != "source":
		tail = fmt.Sprintf("%s is fixed in %s", a.ID, a.Verdict.FixedIn)
		if a.Verdict.Verdict == "likely_not_affected" {
			tail += fmt.Sprintf(" %s you have %s, probably past it", s.G.Sep, inst)
		} else {
			tail += fmt.Sprintf(" %s you are past it", s.G.Sep)
		}
	default:
		tail = fmt.Sprintf("%s does not affect %s", a.ID, inst)
	}
	if n := len(p.RuledOut) - 1; n > 0 {
		tail += fmt.Sprintf(" + %d more", n)
	}
	head := fmt.Sprintf(" %s %s", mark, s.Bold(p.Label()))
	line := head + "   " + tail
	if hint := s.Dim(" " + s.G.Sep + " --explain " + a.ID); vis(line)+vis(hint) < s.Width {
		line += hint
	}
	if vis(line) >= s.Width {
		// Too wide for one line: the package first, the reason beneath it.
		var b strings.Builder
		b.WriteString(head + "\n")
		for _, l := range wrapText(tail, s.Width-5) {
			b.WriteString("   " + l + "\n")
		}
		return b.String()
	}
	return line + "\n"
}

func renderControlled(p Package, g Group, o Options, s *Style) string {
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s  %s\n", s.Defence(s.G.Defence), s.Bold(p.Label()), s.Hot("no fix"))
	fmt.Fprintf(&b, "   %s\n", p.Top().ID)
	for _, c := range p.Controls {
		where := c.Where
		if where == "" {
			where = defences.Name(c.Kind)
		}
		line := where
		if m := modeWords(c.Mode); m != "" {
			line += " (" + m + ")"
		}
		fmt.Fprintf(&b, "   %s\n", line)
		fmt.Fprintf(&b, "   %s\n", s.Dim(fmt.Sprintf("recorded %s %s review by %s", c.RecordedAt.Format("2006-01-02"), s.G.Sep, c.Until.Format("2006-01-02"))))
	}
	b.WriteString("   " + s.Dim("The CLI cannot verify it is deployed. This is your statement.") + "\n")
	return b.String()
}

func modeWords(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "block", "deny":
		return ""
	case "log", "log-only", "monitor":
		return "log only"
	}
	return mode
}

// safeMode is the mode every rule in the lane agrees it is safe to start in.
// When rules disagree it is empty: naming one would be a guess.
func safeMode(l defences.LaneSummary) string {
	mode := ""
	for _, r := range l.Rules {
		m := modeWords(r.DeployMode)
		if m == "" {
			m = strings.ToLower(strings.TrimSpace(r.DeployMode))
		}
		if m == "" {
			continue
		}
		if mode != "" && mode != m {
			return ""
		}
		mode = m
	}
	if mode == "block" {
		return ""
	}
	return mode
}

func kindsText(d *defences.Summary) string {
	var names []string
	for _, k := range d.Block.Kinds() {
		names = append(names, defences.Name(k))
	}
	for _, k := range d.Detect.Kinds() {
		names = append(names, defences.Name(k))
	}
	return strings.Join(names, ", ")
}

func renderNext(r Report, c Counts, o Options, s *Style) string {
	if c.Packages == 0 && c.ByGroup[GroupNotAffected] == 0 {
		return ""
	}
	var rows [][2]string
	fixable := 0
	for _, p := range r.Packages {
		if p.Group != GroupNotAffected && (p.Fix.State == FixAvailable || p.Fix.State == FixPartial) {
			fixable++
		}
	}
	if fixable > 0 {
		rows = append(rows, [2]string{"vulnetix fix", fmt.Sprintf("apply %s", plural(fixable, "upgrade"))})
	}
	if first := firstNamed(r); first != "" {
		rows = append(rows, [2]string{explainCommand(o, packageScanner(o), first), "why each advisory applies, with the evidence"})
	}
	if o.Verbosity == 0 {
		rows = append(rows, [2]string{rerunCommand(o, "-v"), "scores, version checks and match evidence"})
	}
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(" " + s.Bold("NEXT") + "\n")
	w := 0
	for _, r := range rows {
		if len(r[0]) > w {
			w = len(r[0])
		}
	}
	for _, r := range rows {
		line := "   " + s.Cmd(r[0])
		// The description is a courtesy; the command is what matters.
		if desc := pad("", w-len(r[0])+3) + s.Dim(r[1]); vis(line)+vis(desc) <= s.Width {
			line += desc
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func firstNamed(r Report) string {
	for _, p := range r.Packages {
		if p.Group == GroupAction && p.Name != "" {
			return p.Name
		}
	}
	for _, p := range r.Packages {
		if p.Group != GroupNotAffected && p.Name != "" {
			return p.Name
		}
	}
	return ""
}

func renderQuiet(r Report, s *Style) string {
	c := r.Counts()
	if c.Packages == 0 {
		return ""
	}
	if n := c.ByGroup[GroupAction]; n > 0 {
		var items []string
		for _, p := range r.InGroup(GroupAction) {
			if p.Fix.State == FixAvailable && p.Fix.Target != "" {
				items = append(items, fmt.Sprintf("%s %s %s", p.Name, s.G.Arrow, p.Fix.Target))
			} else if p.Fix.State == FixNone {
				items = append(items, p.Name+" (no fix)")
			} else {
				items = append(items, p.Name)
			}
		}
		return fmt.Sprintf("%s %d need action: %s\n", s.Bad(s.G.Fail), n, strings.Join(items, ", "))
	}
	return fmt.Sprintf("%s %s\n", s.Warn(s.G.Fail), advisoriesIn(c))
}

// maxFixWidth is the widest fix cell in the report.
func maxFixWidth(r Report, o Options, s *Style) int {
	w := 0
	for _, p := range r.Packages {
		if plain, _ := fixCell(p, s, o); display.Width(plain) > w {
			w = display.Width(plain)
		}
	}
	return w
}
