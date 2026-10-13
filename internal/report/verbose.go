package report

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/scaview"
	"github.com/vulnetix/cli/v3/internal/versions"
)

// renderAdvisoryDetail is what -v adds under a package: each advisory with its
// scores and, above all, its version check. The check is the part the old table
// never showed.
func renderAdvisoryDetail(p Package, o Options, s *Style, indent string) string {
	var b strings.Builder
	all := append(append([]Advisory{}, p.Advisories...), p.RuledOut...)
	for i, a := range all {
		b.WriteString("\n")
		head := s.Bold(a.ID) + "  " + s.Sev(a.Severity, SevWord(a.Severity))
		if a.CVSS > 0 {
			head += "  " + s.Dim(fmt.Sprintf("CVSS %.1f", a.CVSS))
		}
		if a.EPSS > 0 {
			head += "  " + s.Dim(fmt.Sprintf("EPSS %.1f%%", a.EPSS*100))
		}
		if d := a.Ev.SSVCDecision; d != "" {
			head += "  " + s.Dim("SSVC "+d)
		}
		if i >= len(p.Advisories) {
			head += "  " + s.Good(s.G.OK+" "+a.Verdict.Verdict.Label())
		}
		for _, sg := range a.Signals {
			head += "  " + signalText(sg, s)
		}
		fmt.Fprintf(&b, "%s%s\n", indent, head)

		kv := func(k, v string) { fmt.Fprintf(&b, "%s  %s %s\n", indent, s.Dim(pad(k, 9)), v) }

		kv("version", a.Verdict.Detail)
		kv("verdict", verdictLine(a, s))
		if a.Verdict.FixedIn != "" {
			src := "advisory"
			if a.Verdict.FixedInSource == "recommended" {
				src = "recommended"
			}
			kv("fixed in", a.Verdict.FixedIn+"  "+s.Dim(src))
		} else if a.Fix != "" {
			kv("fixed in", a.Fix+"  "+s.Dim("recommended"))
		}
		if ex := exploitLine(a); ex != "" {
			kv("exploit", ex)
		}
		if reach := reachLine(a); reach != "" {
			kv("reach", reach)
		}
		if o.Verbosity >= 2 {
			kv("matched", a.Verdict.MatchedBy)
			if a.Ev.Source != "" {
				kv("source", a.Ev.Source)
			}
			if a.Ev.CoalitionESS > 0 {
				kv("CESS", fmt.Sprintf("%.4f", a.Ev.CoalitionESS))
			}
			if a.Ev.Scope != "" {
				kv("scope", a.Ev.Scope)
			}
			var sevs []string
			for _, pair := range [][2]string{{"CVSS", a.Ev.CVSSSeverity}, {"EPSS", a.Ev.EPSSSeverity}, {"SSVC", a.Ev.SSVCSeverity}, {"CESS", a.Ev.CESSeverity}} {
				if pair[1] != "" && !strings.EqualFold(pair[1], "unscored") {
					sevs = append(sevs, pair[0]+" "+scaview.NormaliseSeverity(pair[1]))
				}
			}
			if len(sevs) > 0 {
				kv("severity", strings.Join(sevs, ", "))
			}
		}
	}
	return b.String()
}

func verdictLine(a Advisory, s *Style) string {
	v := a.Verdict
	var verdict string
	switch v.Verdict {
	case "affected":
		verdict = s.Bad("affected")
	case "unverified":
		verdict = s.Warn("unverified")
	case "likely_not_affected":
		verdict = s.Warn("likely not affected")
	case "not_affected":
		verdict = s.Good("not affected")
	}
	how := map[string]string{
		"range":               "range checked",
		"source":              "reported by the source",
		"recommended-fix":     "compared with the recommended fix",
		"none":                "no range to check",
		"unparseable-version": "version not comparable",
	}[v.Basis]
	return strings.TrimSpace(verdict + "  " + s.Dim(how))
}

func exploitLine(a Advisory) string {
	ei := a.Ev.ExploitIntel
	if ei == nil || ei.ExploitCount == 0 {
		if a.KEV {
			return "listed as actively exploited"
		}
		return ""
	}
	parts := []string{fmt.Sprintf("%d known", ei.ExploitCount)}
	if ei.HasWeaponized {
		parts = append(parts, "weaponized")
	}
	if ei.HighestMaturity != "" {
		parts = append(parts, "maturity "+ei.HighestMaturity)
	}
	if len(ei.Sources) > 0 {
		parts = append(parts, strings.Join(ei.Sources, ", "))
	}
	if a.KEV {
		parts = append(parts, "KEV")
	}
	return strings.Join(parts, ", ")
}

func reachLine(a Advisory) string {
	switch strings.ToLower(a.Reach) {
	case "direct":
		return "the vulnerable code is in the installed package and is called"
	case "transitive":
		return "your code calls into the affected package"
	case "semantic":
		if a.ReachAt != "" {
			return a.ReachAt + " (symbol match, lower confidence)"
		}
		return "symbol match in your source (lower confidence)"
	case "unreachable":
		return "analysed, nothing calls it"
	}
	return ""
}

// compareWords describes installed against a reference version in words.
func compareWords(installed, ref string) (cmp string, ok bool) {
	iv, e1 := versions.Parse(installed)
	rv, e2 := versions.Parse(ref)
	if e1 != nil || e2 != nil {
		return "", false
	}
	switch c := versions.Compare(iv, rv); {
	case c > 0:
		return installed + " is newer than " + ref, true
	case c == 0:
		return installed + " is " + ref, true
	default:
		return installed + " is older than " + ref, true
	}
}
