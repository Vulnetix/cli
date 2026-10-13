package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/scaview"
	"github.com/vulnetix/cli/v3/internal/versions"
)

// Input is everything Build needs. Nothing in it is read from the environment.
type Input struct {
	Vulns    []scan.EnrichedVuln
	Groups   []scan.ManifestGroup
	Controls defences.ControlSet
	Meta     Meta
	// Strict counts not-affected and likely-not-affected findings anyway.
	Strict bool
	Now    time.Time
}

// Build assembles the report. It performs no I/O.
func Build(in Input) Report {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	graphFor := indexGraphs(in.Groups)
	byKey := map[string]*Package{}
	var order []string

	seen := map[string]bool{}
	for _, ev := range in.Vulns {
		key := strings.ToLower(ev.Ecosystem + "|" + ev.PackageName + "@" + ev.PackageVer)
		if ev.PackageName == "" {
			// A floating finding that could not be tied to a component. It still
			// needs to appear; the advisory id is the only handle it has.
			key = "|?|" + ev.CveID
		}
		p, ok := byKey[key]
		if !ok {
			p = &Package{
				Name: ev.PackageName, Version: ev.PackageVer,
				Ecosystem: ev.Ecosystem, Scope: ev.Scope,
				Source: ev.SourceFile, Direct: true,
			}
			if g := graphFor(ev.SourceFile); g != nil {
				p.Direct = g.IsDirect(ev.PackageName)
				if !p.Direct {
					if chain := g.FindPathMemo(ev.PackageName); len(chain) > 1 {
						p.Via = append([]string{}, chain[:len(chain)-1]...)
					}
				}
			}
			byKey[key] = p
			order = append(order, key)
		}

		dup := key + "::" + ev.CveID
		if seen[dup] {
			if ev.SourceFile != "" && ev.SourceFile != p.Source {
				p.MoreSources++
			}
			continue
		}
		seen[dup] = true

		adv := newAdvisory(ev)
		if ev.IsMalicious {
			p.Malicious = true
		}
		if adv.Verdict.Verdict.Counts() || in.Strict {
			p.Advisories = append(p.Advisories, adv)
		} else {
			p.RuledOut = append(p.RuledOut, adv)
		}
	}

	rep := Report{Meta: in.Meta}
	rep.Meta.Strict = in.Strict
	for _, key := range order {
		p := byKey[key]
		p.Advisories = foldAliases(p.Advisories)
		p.RuledOut = foldAliases(p.RuledOut)
		finish(p, in.Controls, now)
		rep.Packages = append(rep.Packages, *p)
	}
	sortPackages(rep.Packages, "threat")
	return rep
}

func indexGraphs(groups []scan.ManifestGroup) func(string) *scan.DepGraph {
	byFile := map[string]*scan.DepGraph{}
	for _, g := range groups {
		for _, f := range g.Files {
			byFile[f] = g.Graph
		}
	}
	return func(file string) *scan.DepGraph { return byFile[file] }
}

func newAdvisory(ev scan.EnrichedVuln) Advisory {
	a := Advisory{
		ID:       ev.CveID,
		Severity: scaview.NormaliseSeverity(firstNonEmpty(ev.MaxSeverity, ev.Severity)),
		CVSS:     firstPositive(ev.CVSSScore, ev.Score),
		EPSS:     ev.EPSSScore,
		KEV:      ev.InCisaKev || ev.InVulnCheckKev || ev.InEuKev,
		Verdict:  scan.EvaluateVerdict(ev),
		Reach:    ev.Reachability,
		Ev:       ev,
	}
	if ev.ExploitIntel != nil {
		a.Exploits = ev.ExploitIntel.ExploitCount
	} else {
		a.Exploits = ev.ExploitCount
	}
	if len(ev.SemanticMatches) > 0 {
		m := ev.SemanticMatches[0]
		a.ReachAt = m.File
		if m.Line > 0 {
			a.ReachAt = m.File + ":" + strconv.Itoa(m.Line)
		}
	}
	if ev.Remediation != nil {
		a.Fix = strings.TrimSpace(ev.Remediation.FixVersion)
		a.FixAvailability = ev.Remediation.FixAvailability
	}
	if a.FixAvailability == "" {
		a.FixAvailability = ev.FixAvailability
	}
	// The advisory's own range is better evidence of a fix than a flag: it can be
	// read, and a bare no_fix contradicts a range like "< 2.32.4". Prefer the
	// recommendation when there is one, then the range's upper bound.
	if a.Fix == "" && a.Verdict.Verdict == scan.VerdictAffected && a.Verdict.Basis == "range" &&
		a.Verdict.FixedInSource == "advisory" && a.Verdict.FixedIn != "" {
		a.Fix = a.Verdict.FixedIn
		a.FixSource = "advisory"
	} else if a.Fix != "" {
		a.FixSource = "recommended"
	}
	a.AnyUpgrade = a.Verdict.AnyUpgradeClears
	a.Signals = advisorySignals(ev, a)
	return a
}

func advisorySignals(ev scan.EnrichedVuln, a Advisory) []Signal {
	var s []Signal
	if ev.IsMalicious {
		s = append(s, Signal{"malware", true})
	}
	if a.KEV {
		s = append(s, Signal{"KEV", true})
	}
	switch {
	case ev.ExploitIntel != nil && ev.ExploitIntel.HasWeaponized:
		s = append(s, Signal{"weaponized", true})
	case a.Exploits > 0:
		s = append(s, Signal{"PoC exploit", true})
	}
	switch strings.ToLower(ev.Reachability) {
	case "direct", "transitive":
		s = append(s, Signal{"reachable", true})
	case "semantic":
		// The symbol-grep fallback seeds the package's own name, so it fires for
		// nearly any dependency that is imported at all. It is worth showing and
		// is not enough on its own to call something urgent.
		s = append(s, Signal{"referenced", false})
	}
	if strings.EqualFold(ev.SSVCDecision, "Act") {
		s = append(s, Signal{"SSVC act", true})
	}
	return s
}

// finish derives everything that depends on the package's full advisory set.
func finish(p *Package, controls defences.ControlSet, now time.Time) {
	sort.SliceStable(p.Advisories, func(i, j int) bool { return advisoryLess(p.Advisories[i], p.Advisories[j]) })
	sort.SliceStable(p.RuledOut, func(i, j int) bool { return advisoryLess(p.RuledOut[i], p.RuledOut[j]) })

	p.Severity = "info"
	for _, a := range p.Advisories {
		if scaview.SeverityRank(a.Severity) < scaview.SeverityRank(p.Severity) {
			p.Severity = a.Severity
		}
	}
	p.Fix = computeFix(*p)

	// Only advisories established as affecting this version raise the package's
	// urgency. When none is established the signals are still collected, for
	// display, but assignGroup will not act on them.
	sigSrc := affectedOnly(p.Advisories)
	if len(sigSrc) == 0 {
		sigSrc = p.Advisories
	}
	seen := map[string]bool{}
	for _, a := range sigSrc {
		for _, sg := range a.Signals {
			if !seen[sg.Label] {
				seen[sg.Label] = true
				p.Signals = append(p.Signals, sg)
			}
		}
		if t := a.Ev.ThreatExposure; t > p.threat {
			p.threat = t
		}
	}
	if p.Malicious {
		p.threat += 1e6
	}

	// Recorded controls: only meaningful where there is no fix.
	if len(p.Advisories) > 0 && p.Fix.State == FixNone {
		covered := true
		for _, a := range p.Advisories {
			active := false
			for _, c := range controls.For(a.ID, p.Name) {
				if c.Active(now) {
					active = true
					p.Controls = appendControl(p.Controls, c)
				} else if p.Lapsed == nil {
					c := c
					p.Lapsed = &c
				}
			}
			if !active {
				covered = false
			}
		}
		p.Covered = covered && len(p.Controls) > 0
	}

	p.Group = assignGroup(*p)
}

func appendControl(list []defences.Control, c defences.Control) []defences.Control {
	for _, e := range list {
		if e.VulnID == c.VulnID && e.Lane == c.Lane && e.Where == c.Where {
			return list
		}
	}
	return append(list, c)
}

func assignGroup(p Package) Group {
	if len(p.Advisories) == 0 {
		return GroupNotAffected
	}
	if p.Covered {
		for _, c := range p.Controls {
			if c.Blocks() {
				return GroupProtected
			}
		}
		return GroupMonitored
	}
	if p.Malicious {
		return GroupAction
	}
	if len(affectedOnly(p.Advisories)) == 0 {
		return GroupUnverified
	}
	for _, s := range p.Signals {
		if s.Strong {
			return GroupAction
		}
	}
	return GroupWait
}

// computeFix settles the package's fix from its advisories. The target is the
// highest version any advisory recommends: it is the lowest one that clears all
// of the advisories that have a recommendation at all.
func computeFix(p Package) Fix {
	if len(p.Advisories) == 0 {
		return Fix{}
	}
	var target *versions.Version
	targetRaw := ""
	withFix, anyUp, noFix, availNoVer := 0, 0, 0, 0
	for _, a := range p.Advisories {
		switch {
		case a.Fix != "":
			withFix++
			if v, err := versions.Parse(a.Fix); err == nil {
				if target == nil || versions.Compare(v, *target) > 0 {
					vv := v
					target = &vv
					targetRaw = a.Fix
				}
			} else if target == nil {
				targetRaw = a.Fix
			}
		case a.AnyUpgrade:
			anyUp++
		case isNoFix(a.FixAvailability):
			noFix++
		case isAvailable(a.FixAvailability):
			availNoVer++
		}
	}
	total := len(p.Advisories)
	cleared := withFix + anyUp
	switch {
	case cleared == 0 && availNoVer == 0 && noFix > 0:
		return Fix{State: FixNone}
	case cleared == 0 && availNoVer > 0:
		return Fix{State: FixAvailable}
	case cleared == 0:
		return Fix{}
	case cleared == total:
		return Fix{State: FixAvailable, Target: targetRaw, Clears: total, Of: total}
	case targetRaw == "" && noFix > 0:
		// Some advisories clear on "any newer release" but none names a version to
		// move to, and others are explicitly unfixed. "Partly fixed, to nothing" is
		// no direction at all, and it hides the defences the no-fix block offers.
		return Fix{State: FixNone}
	default:
		return Fix{State: FixPartial, Target: targetRaw, Clears: cleared, Of: total}
	}
}

func isNoFix(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "no_fix", "no fix", "none", "nofix":
		return true
	}
	return false
}

func isAvailable(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "available", "fix_available", "partial":
		return true
	}
	return false
}

func advisoryLess(a, b Advisory) bool {
	// An advisory known to affect this version outranks one that could not be
	// checked, so the one a package is named by is the one that is established.
	if av, bv := a.Verdict.Verdict == scan.VerdictAffected, b.Verdict.Verdict == scan.VerdictAffected; av != bv {
		return av
	}
	ra, rb := scaview.SeverityRank(a.Severity), scaview.SeverityRank(b.Severity)
	if ra != rb {
		return ra < rb
	}
	if a.KEV != b.KEV {
		return a.KEV
	}
	if ca, cb := scaview.IsCVE(a.ID), scaview.IsCVE(b.ID); ca != cb {
		return ca
	}
	if a.Exploits != b.Exploits {
		return a.Exploits > b.Exploits
	}
	return a.ID > b.ID
}

// sortPackages orders each group's packages; groups themselves print in
// groupOrder, so the sort key is (group, key).
func sortPackages(pkgs []Package, key string) {
	gi := map[Group]int{}
	for i, g := range groupOrder {
		gi[g] = i
	}
	sort.SliceStable(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if gi[a.Group] != gi[b.Group] {
			return gi[a.Group] < gi[b.Group]
		}
		switch key {
		case "package":
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		case "severity":
			if ra, rb := scaview.SeverityRank(a.Severity), scaview.SeverityRank(b.Severity); ra != rb {
				return ra < rb
			}
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		// threat: malware, then strong signals, then severity, then exposure.
		if a.Malicious != b.Malicious {
			return a.Malicious
		}
		if sa, sb := strongCount(a), strongCount(b); sa != sb {
			return sa > sb
		}
		if ra, rb := scaview.SeverityRank(a.Severity), scaview.SeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.threat != b.threat {
			return a.threat > b.threat
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
}

func strongCount(p Package) int {
	n := 0
	for _, s := range p.Signals {
		if s.Strong {
			n++
		}
	}
	return n
}

// Resort reorders the report's packages by "threat", "severity" or "package".
func (r *Report) Resort(key string) { sortPackages(r.Packages, key) }

// DefenceIDs lists the identifiers worth looking up: one entry per indexed
// advisory on each package that has no fix. Duplicates are removed.
func DefenceIDs(r Report) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range r.NoFix() {
		for _, a := range p.Advisories {
			if defences.Indexed(a.ID) && !seen[strings.ToUpper(a.ID)] {
				seen[strings.ToUpper(a.ID)] = true
				out = append(out, a.ID)
			}
		}
	}
	return out
}

// AttachDefences records lookup results on the no-fix packages. found is keyed
// by the identifier that was looked up; a package whose advisories were never
// indexed gets StateNotIndexed rather than being left silent.
func AttachDefences(r *Report, found map[string]defences.Summary, checked bool, reason string) {
	for i := range r.Packages {
		p := &r.Packages[i]
		if p.Group == GroupNotAffected || p.Group == GroupUnverified || p.Fix.State != FixNone {
			continue
		}
		var sums []defences.Summary
		for _, a := range p.Advisories {
			if !defences.Indexed(a.ID) {
				continue
			}
			if p.DefenceID == "" {
				p.DefenceID = a.ID
			}
			if s, ok := found[a.ID]; ok {
				sums = append(sums, s)
			}
		}
		switch {
		case !checked:
			p.Defence = &defences.Summary{ID: p.Top().ID, State: defences.StateNotChecked, Reason: reason}
		case p.DefenceID == "":
			p.Defence = &defences.Summary{ID: p.Top().ID, State: defences.StateNotIndexed}
		case len(sums) == 0:
			p.Defence = &defences.Summary{ID: p.DefenceID, State: defences.StateFailed, Reason: reason}
		default:
			m := MergeSummaries(p.DefenceID, sums)
			p.Defence = &m
		}
	}
}

// MergeSummaries combines per-advisory summaries into one for the package.
func MergeSummaries(id string, in []defences.Summary) defences.Summary {
	out := defences.Summary{ID: id}
	out.Block.ByKind = map[defences.Kind]int{}
	out.Detect.ByKind = map[defences.Kind]int{}
	rank := map[defences.State]int{
		defences.StateAvailable: 6, defences.StateGated: 5, defences.StateNone: 4,
		defences.StateFailed: 3, defences.StateNotChecked: 2, defences.StateUnavailable: 1,
	}
	best := defences.StateUnavailable
	for _, s := range in {
		if rank[s.State] > rank[best] {
			best = s.State
			out.Reason = s.Reason
		}
		add := func(dst *defences.LaneSummary, src defences.LaneSummary) {
			dst.Count += src.Count
			for k, n := range src.ByKind {
				dst.ByKind[k] += n
			}
			dst.Rules = append(dst.Rules, src.Rules...)
		}
		add(&out.Block, s.Block)
		add(&out.Detect, s.Detect)
	}
	out.State = best
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" && !strings.EqualFold(s, "unscored") {
			return s
		}
	}
	return ""
}

func firstPositive(fs ...float64) float64 {
	for _, f := range fs {
		if f > 0 {
			return f
		}
	}
	return 0
}

// affectedOnly returns the advisories established as affecting the installed
// version.
func affectedOnly(in []Advisory) []Advisory {
	var out []Advisory
	for _, a := range in {
		if a.Verdict.Verdict == scan.VerdictAffected {
			out = append(out, a)
		}
	}
	return out
}
