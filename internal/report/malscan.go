package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

// MalscanFinding is one piece of evidence from the malware scan, attributed to
// the installed package it was found in.
type MalscanFinding struct {
	Ecosystem string
	Package   string // "" when the file belongs to no package
	Location  string // where the package is installed: "node_modules"
	Title     string
	RuleID    string
	File      string
	Line      int
	Snippet   string
	Severity  string
	// Class is the engine's grade of the evidence: "evidence" convicts a package,
	// "trigger" and "context" only make it worth a look.
	Class    string
	IOCType  string
	IOCValue string
}

// MalscanTarget is one place dependencies are installed and what was checked in it.
type MalscanTarget struct {
	Ecosystem  string
	Label      string
	UserScoped bool
	Packages   int
	Files      int
}

// MalscanReport is a malware scan, ready to draw.
type MalscanReport struct {
	Findings []MalscanFinding
	Targets  []MalscanTarget
	// Indicators is how many known-bad indicators were loaded to compare with.
	Indicators int
	// FeedsEnabled is false under --no-ioc-feeds, when zero indicators is chosen.
	FeedsEnabled bool
	IncludeHome  bool
	Warnings     []string
}

type malPackage struct {
	eco, name, location string
	severity            string
	convicted           bool
	items               []MalscanFinding
}

type malView struct {
	malicious, suspicious []*malPackage
	checkedPkgs, files    int
	incomplete            []string
}

func (m MalscanReport) view(o Options) malView {
	var v malView
	idx := map[string]*malPackage{}
	var all []*malPackage
	for _, f := range m.Findings {
		name := f.Package
		if name == "" {
			name = f.File
		}
		key := f.Ecosystem + "|" + name
		p, ok := idx[key]
		if !ok {
			p = &malPackage{eco: f.Ecosystem, name: name, location: f.Location, severity: f.Severity}
			idx[key] = p
			all = append(all, p)
		}
		if scaview.SeverityRank(f.Severity) < scaview.SeverityRank(p.severity) {
			p.severity = f.Severity
		}
		if f.Class == "evidence" {
			p.convicted = true
		}
		// Several rules often fire on one line; unless -v they are one row.
		dup := false
		if o.Verbosity == 0 {
			for _, have := range p.items {
				dup = dup || (have.File == f.File && have.Line == f.Line && have.Snippet == f.Snippet && have.Class == f.Class)
			}
		}
		if !dup {
			p.items = append(p.items, f)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if ra, rb := scaview.SeverityRank(all[i].severity), scaview.SeverityRank(all[j].severity); ra != rb {
			return ra < rb
		}
		return all[i].name < all[j].name
	})
	for _, p := range all {
		sort.SliceStable(p.items, func(i, j int) bool {
			ci, cj := p.items[i].Class == "evidence", p.items[j].Class == "evidence"
			if ci != cj {
				return ci
			}
			return scaview.SeverityRank(p.items[i].Severity) < scaview.SeverityRank(p.items[j].Severity)
		})
		if p.convicted {
			v.malicious = append(v.malicious, p)
		} else {
			v.suspicious = append(v.suspicious, p)
		}
	}
	for _, t := range m.Targets {
		v.checkedPkgs += t.Packages
		v.files += t.Files
	}
	switch {
	case len(m.Targets) == 0:
		v.incomplete = append(v.incomplete, "dependencies\tnone installed under this path, so there was nothing to inspect")
	case v.checkedPkgs == 0 && v.files == 0:
		v.incomplete = append(v.incomplete, "dependencies\tthe install directories held no packages or files")
	}
	if m.FeedsEnabled && m.Indicators == 0 {
		v.incomplete = append(v.incomplete, "indicators\tno known-bad indicator definitions are loaded to compare against")
	}
	return v
}

// defang writes an indicator so a terminal or a chat client will not make it a
// link: cdn-update.top becomes cdn-update[.]top.
func defang(s string) string {
	return strings.ReplaceAll(s, ".", "[.]")
}

func (f MalscanFinding) detail() string {
	snip := oneLine(f.Snippet)
	if f.IOCValue != "" {
		snip = strings.ReplaceAll(snip, f.IOCValue, defang(f.IOCValue))
		if snip == "" {
			snip = defang(f.IOCValue)
		}
	}
	return snip
}

func (f MalscanFinding) where() string {
	file := f.File
	// Inside a package the install path says nothing the row above has not.
	if f.Package != "" && f.Location != "" {
		file = strings.TrimPrefix(file, f.Location+"/"+f.Package+"/")
	}
	switch {
	case file == "":
		return ""
	case f.Line > 0:
		return fmt.Sprintf("%s:%d", file, f.Line)
	}
	return file
}

// RenderMalscan draws a malware scan in the same grammar as the other scanners.
// A scan that checked nothing never reads as clean.
func RenderMalscan(m MalscanReport, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	v := m.view(o)
	flagged := len(v.malicious) + len(v.suspicious)
	clean := max(0, v.checkedPkgs-flagged)
	var b strings.Builder

	if o.Quiet && flagged == 0 && len(v.incomplete) == 0 {
		return ""
	}

	switch {
	case len(v.malicious) > 0:
		head := fmt.Sprintf(" %s %s %s", s.Bad(s.G.Fail), s.Bold("MALWARE"), s.Bold("in "+plural(len(v.malicious), "package")))
		parts := []string{s.Bad(fmt.Sprintf("%d malicious", len(v.malicious)))}
		if n := len(v.suspicious); n > 0 {
			parts = append(parts, s.Warn(fmt.Sprintf("%d suspicious", n)))
		}
		if clean > 0 {
			parts = append(parts, s.Dim(fmt.Sprintf("%s clean", commas(clean))))
		}
		b.WriteString(headLine(head, strings.Join(parts, " "+s.Dim(s.G.Sep)+" "), s))
	case len(v.suspicious) > 0:
		head := fmt.Sprintf(" %s %s %s", s.Warn(s.G.Fail), s.Bold("MALWARE"), s.Bold("none proven, "+plural(len(v.suspicious), "package")+" to look at"))
		parts := []string{s.Warn(fmt.Sprintf("%d suspicious", len(v.suspicious)))}
		if clean > 0 {
			parts = append(parts, s.Dim(fmt.Sprintf("%s clean", commas(clean))))
		}
		b.WriteString(headLine(head, strings.Join(parts, " "+s.Dim(s.G.Sep)+" "), s))
	case len(v.incomplete) > 0:
		head := fmt.Sprintf(" %s %s %s", s.Warn("!"), s.Bold("MALWARE"), s.Warn("INCOMPLETE"))
		tail := s.Dim(fmt.Sprintf("%s %s %s %s %s", plural(v.checkedPkgs, "package"), s.G.Sep, plural(v.files, "file"), s.G.Sep, plural(m.Indicators, "indicator")))
		if v.checkedPkgs == 0 && v.files == 0 {
			head += s.Bold(" " + s.G.Sep + " nothing was checked")
		}
		b.WriteString(headLine(head, tail, s))
	default:
		head := fmt.Sprintf(" %s %s %s", s.Good(s.G.OK), s.Bold("MALWARE"), s.Bold("none found in "+plural(v.checkedPkgs, "package")))
		b.WriteString(headLine(head, s.Dim(fmt.Sprintf("%s %s %s known-bad indicators", plural(v.files, "file"), s.G.Sep, commas(m.Indicators))), s))
	}
	if flagged > 0 || len(v.incomplete) == 0 {
		sub := ecosystemTally(m.Targets)
		line := strings.Join(sub, " "+s.G.Sep+" ")
		if line != "" {
			line += " packages"
		}
		if flagged > 0 {
			line += fmt.Sprintf(" %s %s %s %s known-bad indicators", s.G.Sep, plural(v.files, "file"), s.G.Sep, commas(m.Indicators))
		}
		if strings.TrimSpace(line) != "" && s.Width >= tierCompact && flagged > 0 {
			fmt.Fprintf(&b, "   %s\n", s.Dim(strings.TrimSpace(line)))
		}
	} else {
		fmt.Fprintf(&b, "   %s\n", s.Dim("This is not a clean result: there was nothing to compare, or nothing to inspect."))
	}

	if len(v.malicious) > 0 {
		b.WriteString("\n" + malSection(s, "MALICIOUS", plural(len(v.malicious), "package")+" "+s.G.Sep+" remove it before anything installs again"))
		for i, p := range v.malicious {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(renderMalPackage(p, o, s))
		}
		b.WriteString("\n " + s.Bold("WHAT TO DO, IN THIS ORDER") + "\n")
		for i, st := range malSteps(v, m) {
			for j, l := range wrapText(st, s.Width-8) {
				if j == 0 {
					fmt.Fprintf(&b, "   %d  %s\n", i+1, l)
				} else {
					b.WriteString("      " + l + "\n")
				}
			}
		}
	}
	if len(v.suspicious) > 0 {
		b.WriteString("\n" + malSection(s, "SUSPICIOUS", plural(len(v.suspicious), "package")+" "+s.G.Sep+" context, not proof"))
		limit := len(v.suspicious)
		if o.Verbosity == 0 {
			limit = min(limit, 7)
		}
		for _, p := range v.suspicious[:limit] {
			b.WriteString(renderMalPackage(p, o, s))
		}
		if rest := len(v.suspicious) - limit; rest > 0 {
			b.WriteString("   " + s.Dim(fmt.Sprintf("+ %d more %s -v lists every one", rest, s.G.Sep)) + "\n")
		}
	}

	if flagged == 0 && len(m.Targets) > 0 {
		b.WriteString("\n" + malSection(s, "CHECKED", ""))
		b.WriteString(checkedRows(m.Targets, s))
	}
	notChecked := notCheckedRows(m, v, s)
	if notChecked != "" {
		b.WriteString("\n" + malSection(s, "NOT CHECKED", ""))
		b.WriteString(notChecked)
	}

	if o.Verbosity >= 1 && len(m.Warnings) > 0 {
		b.WriteString("\n" + malSection(s, "WARNINGS", ""))
		for _, w := range m.Warnings {
			b.WriteString("   " + s.Dim(s.clip(w, s.Width-6)) + "\n")
		}
	}
	b.WriteString(renderSteps(malNext(m, v, s), s))
	return b.String()
}

func malSection(s *Style, title, note string) string {
	head := " " + s.Bold(title)
	if note != "" && s.Width >= tierCompact {
		head += s.Dim(" " + s.G.Sep + " " + note)
	}
	return head + "\n " + s.Rule(s.Width-2) + "\n"
}

func commas(n int) string {
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// ecosystemTally is "npm 612", "go 401", most packages first.
func ecosystemTally(ts []MalscanTarget) []string {
	n := map[string]int{}
	var order []string
	for _, t := range ts {
		if t.Packages == 0 {
			continue
		}
		if _, ok := n[t.Ecosystem]; !ok {
			order = append(order, t.Ecosystem)
		}
		n[t.Ecosystem] += t.Packages
	}
	sort.SliceStable(order, func(i, j int) bool { return n[order[i]] > n[order[j]] })
	out := make([]string, len(order))
	for i, e := range order {
		out[i] = fmt.Sprintf("%s %s", e, commas(n[e]))
	}
	return out
}

func renderMalPackage(p *malPackage, o Options, s *Style) string {
	var b strings.Builder
	dot := s.Sev(p.severity, s.G.Dot)
	sev := s.Sev(p.severity, SevWord(p.severity))
	name := p.eco + "  " + p.name
	if s.Width < tierCompact {
		fmt.Fprintf(&b, " %s %s\n   %s\n", dot, sev, s.Bold(s.clip(name, s.Width-4)))
	} else {
		left := " " + dot + " " + pad(sev, 10) + s.Bold(name)
		right := s.Dim(p.location)
		b.WriteString(rowLR(left, right, s))
	}
	ind := indentFor(s)
	limit := len(p.items)
	if o.Verbosity == 0 {
		limit = min(limit, 4)
	}
	titleW, whereW := 0, 0
	for _, it := range p.items[:limit] {
		titleW = max(titleW, display.Width(it.Title))
		whereW = max(whereW, display.Width(it.where()))
	}
	titleW, whereW = min(titleW, 30), min(whereW, 30)
	for _, it := range p.items[:limit] {
		if s.Width < tierCompact {
			b.WriteString("   " + s.clip(it.Title, s.Width-4) + "\n")
			b.WriteString("   " + s.Dim(s.clip(strings.TrimSpace(it.where()+" "+it.detail()), s.Width-4)) + "\n")
			continue
		}
		line := ind + pad(s.clip(it.Title, titleW), titleW+2) + pad(s.Path(s.clip(it.where(), whereW)), whereW+2)
		b.WriteString(line + s.Dim(s.clip(it.detail(), max(8, codeRowWidth(s)-1-vis(line)))) + "\n")
	}
	if rest := len(p.items) - limit; rest > 0 {
		b.WriteString(ind + s.Dim(fmt.Sprintf("+ %d more %s -v lists every one", rest, s.G.Sep)) + "\n")
	}
	return b.String()
}

// malSteps are the order to deal with a convicted package in. Install scripts
// run on every machine that installed the package, so removing it is the first
// step and rotating what those machines could read is the second.
func malSteps(v malView, m MalscanReport) []string {
	var names []string
	for _, p := range v.malicious {
		names = append(names, p.name)
	}
	steps := []string{
		fmt.Sprintf("Remove %s from your manifests and reinstall from a clean lockfile. If it is a dependency of something else, drop or pin that.", strings.Join(names, ", ")),
		"Its install script may have run on every machine that installed it. Rotate the credentials those machines could read: package registry and git tokens, cloud keys, CI secrets.",
	}
	var hosts []string
	seen := map[string]bool{}
	for _, p := range v.malicious {
		for _, it := range p.items {
			if it.IOCValue != "" && !seen[it.IOCValue] {
				seen[it.IOCValue] = true
				hosts = append(hosts, defang(it.IOCValue))
			}
		}
	}
	if len(hosts) > 0 {
		steps = append(steps, fmt.Sprintf("Search proxy and CI logs for %s to find which machines reached it.", strings.Join(hosts[:min(3, len(hosts))], ", ")))
	}
	return steps
}

func checkedRows(ts []MalscanTarget, s *Style) string {
	var b strings.Builder
	ecoW, labelW := 0, 0
	for _, t := range ts {
		ecoW = max(ecoW, display.Width(t.Ecosystem))
		labelW = max(labelW, display.Width(t.Label))
	}
	labelW = min(labelW, 34)
	for _, t := range ts {
		if s.Width < tierCompact {
			fmt.Fprintf(&b, "   %s  %s\n", t.Ecosystem, s.clip(t.Label, s.Width-6-len(t.Ecosystem)))
			fmt.Fprintf(&b, "   %s\n", s.Dim(fmt.Sprintf("%s, %s", plural(t.Packages, "package"), plural(t.Files, "file"))))
			continue
		}
		fmt.Fprintf(&b, "   %s%s%s%s\n", pad(t.Ecosystem, ecoW+2), pad(s.clip(t.Label, labelW), labelW+2),
			pad(s.Dim(plural(t.Packages, "package")), 14), s.Dim(plural(t.Files, "file")))
	}
	return b.String()
}

func notCheckedRows(m MalscanReport, v malView, s *Style) string {
	var b strings.Builder
	for _, line := range v.incomplete {
		k, why, _ := strings.Cut(line, "\t")
		b.WriteString("   " + pad(k, 14) + why + "\n")
	}
	if !m.IncludeHome {
		b.WriteString("   " + pad("home caches", 14) + "~/.npm, ~/go/pkg/mod and the other caches, which your tools install from next time\n")
	}
	return b.String()
}

func malNext(m MalscanReport, v malView, s *Style) []nextStep {
	var steps []nextStep
	if len(v.malicious)+len(v.suspicious) > 0 {
		steps = append(steps, nextStep{"vulnetix malscan -o sarif", "every finding with its evidence (also in .vulnetix/malscan.sarif)"})
		steps = append(steps, nextStep{"vulnetix sca --block-malware", "fail the build when a dependency is known malware"})
	}
	if m.FeedsEnabled && m.Indicators == 0 {
		steps = append(steps, nextStep{"vulnetix malscan --fetch-definitions", "download the indicator feeds once; later scans reuse them"})
	}
	if !m.IncludeHome {
		steps = append(steps, nextStep{"vulnetix malscan --include-home", "also check ~/.npm, ~/go/pkg/mod and the other caches"})
	}
	return steps
}
