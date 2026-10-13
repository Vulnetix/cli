package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/display"
)

// plainStyle is a Style that never emits colour or non-ASCII glyphs.
func plainStyle(t *display.Terminal, o Options) *Style {
	s := NewStyle(t, Options{ASCII: true, Width: o.Width})
	s.color = false
	return s
}

// RenderPlain is the pipe and CI renderer: one line per package, stable columns,
// ASCII only. It is a documented output format, so scripts may rely on it.
func RenderPlain(r Report, o Options, t *display.Terminal) string {
	s := plainStyle(t, o)
	cmd := o.Command
	if cmd == "" {
		cmd = "scan"
	}
	c := r.Counts()
	var b strings.Builder

	if c.Packages == 0 {
		if r.Meta.ScannedPackages > 0 {
			fmt.Fprintf(&b, "vulnetix %s: CLEAN  no vulnerabilities in %s", cmd, plural(r.Meta.ScannedPackages, "package"))
		} else {
			fmt.Fprintf(&b, "vulnetix %s: CLEAN  no vulnerabilities found", cmd)
		}
		if n := c.ByGroup[GroupNotAffected]; n > 0 {
			fmt.Fprintf(&b, ", %d ruled out by version", n)
		}
		b.WriteString("\n")
		if n := c.ByGroup[GroupNotAffected]; n > 0 {
			b.WriteString(renderPlainGroup(r, GroupNotAffected, o, s))
		}
		return b.String()
	}

	parts := []string{
		fmt.Sprintf("%d %s", c.Advisories, pluralWord(c.Advisories, "advisory", "advisories")),
		plural(c.Packages, "package"),
	}
	for _, g := range []struct {
		g     Group
		label string
	}{{GroupAction, "need action"}, {GroupWait, "can wait"}, {GroupUnverified, "unverified"}, {GroupProtected, "protected"}, {GroupMonitored, "monitored"}, {GroupNotAffected, "not affected"}} {
		if n := c.ByGroup[g.g]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, g.label))
		}
	}
	fmt.Fprintf(&b, "vulnetix %s: FINDINGS  %s\n", cmd, strings.Join(parts, ", "))
	for _, g := range groupOrder {
		b.WriteString(renderPlainGroup(r, g, o, s))
	}
	return b.String()
}

func renderPlainGroup(r Report, g Group, o Options, s *Style) string {
	pkgs := r.InGroup(g)
	if len(pkgs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n" + g.Title() + "\n")

	type row struct{ sev, label, ids, sig, src string }
	var rows []row
	for _, p := range pkgs {
		switch g {
		case GroupNotAffected:
			a := p.Top()
			txt := fmt.Sprintf("%s does not affect %s", a.ID, p.Version)
			if a.Verdict.FixedIn != "" && a.Verdict.Basis != "source" {
				txt = fmt.Sprintf("%s fixed in %s (installed %s)", a.ID, a.Verdict.FixedIn, p.Version)
			}
			rows = append(rows, row{"", p.Label(), txt, "", ""})
			continue
		}
		fix := ""
		switch p.Fix.State {
		case FixAvailable:
			if p.Fix.Target != "" {
				fix = " -> " + p.Fix.Target
			}
		case FixPartial:
			fix = fmt.Sprintf(" -> %s (%d of %d)", p.Fix.Target, p.Fix.Clears, p.Fix.Of)
		case FixNone:
			fix = " no fix"
		}
		if o.Hide["fixes"] {
			fix = ""
		}
		ids := p.Top().ID
		if n := len(p.Advisories) - 1; n > 0 {
			ids += fmt.Sprintf(" +%d", n)
		}
		var sig []string
		for _, sg := range p.Top().Signals {
			sig = append(sig, strings.ReplaceAll(sg.Label, " ", "-"))
		}
		if tag := p.Top().Verdict.Verdict; tag == "unverified" {
			sig = append(sig, "unverified")
		}
		if d := plainDefence(p, o); d != "" {
			sig = append(sig, d)
		}
		if g == GroupProtected || g == GroupMonitored {
			for _, c := range p.Controls {
				sig = append(sig, fmt.Sprintf("control:%q until %s", c.Where, c.Until.Format("2006-01-02")))
			}
		}
		src := p.Source
		if !p.Direct && len(p.Via) > 0 {
			src = "via " + p.Via[len(p.Via)-1]
		}
		rows = append(rows, row{SevWord(p.Severity), p.Label() + fix, ids, strings.Join(sig, " "), src})
	}

	w := [4]int{}
	for _, r := range rows {
		w[0] = max(w[0], len(r.sev))
		w[1] = max(w[1], len(r.label))
		w[2] = max(w[2], len(r.ids))
		w[3] = max(w[3], len(r.sig))
	}
	for _, r := range rows {
		line := "  "
		if g != GroupNotAffected {
			line += fmt.Sprintf("%-*s  ", w[0], r.sev)
		}
		line += fmt.Sprintf("%-*s   %-*s", w[1], r.label, w[2], r.ids)
		if g != GroupNotAffected {
			line += fmt.Sprintf("   %-*s   %s", w[3], r.sig, r.src)
		}
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	return b.String()
}

// plainDefence is the PROTECT field: counts per lane, never names, so the line
// stays a fixed shape that a script can match.
func plainDefence(p Package, o Options) string {
	if o.Hide["defences"] || p.Fix.State != FixNone || p.Defence == nil {
		return ""
	}
	d := p.Defence
	switch d.State {
	case defences.StateAvailable:
		return fmt.Sprintf("PROTECT block:%d detect:%d", d.Block.Count, d.Detect.Count)
	case defences.StateGated:
		return fmt.Sprintf("PROTECT block:%d detect:%d (rules need Pro)", d.Block.Count, d.Detect.Count)
	case defences.StateNone:
		return "PROTECT none"
	case defences.StateNotIndexed:
		return "PROTECT not-indexed"
	case defences.StateNotChecked:
		return "PROTECT not-checked"
	case defences.StateFailed:
		return "PROTECT lookup-failed"
	}
	return ""
}

// RenderFindings is the flat view: one line per advisory, grouped like the
// packages view but without collapsing a package's advisories.
func RenderFindings(r Report, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	s.fixW = maxFixWidth(r, o, s)
	var b strings.Builder
	b.WriteString(renderHeader(r, r.Counts(), s))
	for _, g := range groupOrder {
		pkgs := r.InGroup(g)
		if len(pkgs) == 0 {
			continue
		}
		b.WriteString("\n" + renderGroupHeader(g, pkgs, s))
		for _, p := range pkgs {
			advs := p.Advisories
			if g == GroupNotAffected {
				advs = p.RuledOut
			}
			for _, a := range advs {
				fix := ""
				if p.Fix.State == FixAvailable && p.Fix.Target != "" {
					fix = s.Good(s.G.Arrow + " " + p.Fix.Target)
				} else if p.Fix.State == FixNone {
					fix = s.Hot("no fix")
				}
				var sig []string
				for _, sg := range a.Signals {
					sig = append(sig, signalText(sg, s))
				}
				if tag := verdictTag(a, s); tag != "" && g != GroupNotAffected {
					sig = append([]string{tag}, sig...)
				}
				line := fmt.Sprintf(" %s %s  %s  %s  %s", s.Sev(a.Severity, s.G.Dot), pad(s.Sev(a.Severity, SevWord(a.Severity)), 8),
					pad(s.Bold(a.ID), 18), pad(p.Label(), 26), pad(fix, 12))
				if len(sig) > 0 {
					line += " " + strings.Join(sig, " ")
				}
				b.WriteString(strings.TrimRight(line, " ") + "\n")
			}
		}
	}
	return b.String()
}

// RenderTree groups packages under the manifest that declared them.
func RenderTree(r Report, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	s.fixW = maxFixWidth(r, o, s)
	var b strings.Builder
	b.WriteString(renderHeader(r, r.Counts(), s))

	bySource := map[string][]Package{}
	var sources []string
	for _, p := range r.Packages {
		src := p.Source
		if src == "" {
			src = "(unknown source)"
		}
		// The heading names the manifest, so each package does not repeat it.
		p.Source = ""
		if _, ok := bySource[src]; !ok {
			sources = append(sources, src)
		}
		bySource[src] = append(bySource[src], p)
	}
	sort.Strings(sources)
	for _, src := range sources {
		b.WriteString("\n " + s.Path(src) + "\n")
		for _, p := range bySource[src] {
			b.WriteString(renderItem(p, p.Group, o, s))
		}
	}
	return b.String()
}

// Render dispatches on the resolved view.
func Render(view string, r Report, o Options, t *display.Terminal) string {
	// -q wins over the view: a pipe asked for "findings only" gets one line, not
	// the plain listing.
	if o.Quiet {
		s := NewStyle(t, o)
		if view == ViewPlain {
			s = plainStyle(t, o)
		}
		return renderQuiet(r, s)
	}
	switch view {
	case ViewPlain:
		return RenderPlain(r, o, t)
	case ViewFindings:
		return RenderFindings(r, o, t)
	case ViewTree:
		return RenderTree(r, o, t)
	}
	return RenderPackages(r, o, t)
}
