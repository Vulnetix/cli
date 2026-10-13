package report

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
)

// FindExplain returns the packages (and the advisory, when the query named one)
// that a --explain query refers to. The query is an advisory id, a package name
// or name@version, compared case-insensitively. The report passed in must be the
// unfiltered one: explaining a finding the display filters hid is the point.
func FindExplain(r Report, query string) []Package {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var out []Package
	for _, p := range r.Packages {
		name := strings.ToLower(p.Name)
		if name == q || name+"@"+strings.ToLower(p.Version) == q {
			out = append(out, p)
			continue
		}
		for _, a := range append(append([]Advisory{}, p.Advisories...), p.RuledOut...) {
			if advisoryNamed(a, q) {
				p.Advisories = filterByID(p.Advisories, q)
				p.RuledOut = filterByID(p.RuledOut, q)
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func filterByID(in []Advisory, id string) []Advisory {
	var out []Advisory
	for _, a := range in {
		if advisoryNamed(a, id) {
			out = append(out, a)
		}
	}
	return out
}

// RenderExplain shows the working behind each matching finding. It returns false
// when nothing matched.
func RenderExplain(r Report, query string, o Options, t *display.Terminal) (string, bool) {
	pkgs := FindExplain(r, query)
	if len(pkgs) == 0 {
		return "", false
	}
	s := NewStyle(t, o)
	var b strings.Builder
	for i, p := range pkgs {
		if i > 0 {
			b.WriteString("\n " + s.Rule(s.Width-2) + "\n")
		}
		all := append(append([]Advisory{}, p.Advisories...), p.RuledOut...)
		for j, a := range all {
			if j > 0 {
				b.WriteString("\n")
			}
			b.WriteString(explainAdvisory(p, a, o, s))
		}
		if p.Fix.State == FixNone && p.Defence != nil && len(p.Advisories) > 0 {
			b.WriteString("\n" + renderDefenceLines(p, Options{Show: map[string]bool{"defences": true}, Verbosity: 1}, s, "   "))
		}
	}
	return b.String(), true
}

func explainAdvisory(p Package, a Advisory, o Options, s *Style) string {
	var b strings.Builder
	v := a.Verdict
	fmt.Fprintf(&b, "\n %s %s %s\n\n", s.Bold(p.Label()), s.Dim(s.G.Sep), s.Bold(a.ID))
	if len(a.AlsoKnownAs) > 0 {
		fmt.Fprintf(&b, " %s\n\n", s.Dim("also known as "+strings.Join(a.AlsoKnownAs, ", ")))
	}

	var head string
	switch v.Verdict {
	case "affected":
		head = s.Bad(s.G.Fail + " AFFECTED")
	case "unverified":
		head = s.Warn(s.G.Unknown + " UNVERIFIED")
	case "likely_not_affected":
		head = s.Warn(s.G.Unknown + " LIKELY NOT AFFECTED")
	case "not_affected":
		head = s.Good(s.G.OK + " NOT AFFECTED")
	}
	fmt.Fprintf(&b, " %s\n   %s\n\n", head, v.Detail)

	kv := func(k, val string) { fmt.Fprintf(&b, "   %s %s\n", s.Dim(pad(k, 16)), val) }
	if v.Range != "" {
		kv("advisory range", v.Range)
	} else {
		kv("advisory range", s.Dim("none supplied"))
	}
	if v.FixedIn != "" {
		src := "from the advisory"
		if v.FixedInSource == "recommended" {
			src = "the recommended fix"
		}
		kv("fixed in", v.FixedIn+"  "+s.Dim(src))
	}
	inst := v.Installed
	if p.Source != "" {
		inst += "  " + s.Dim(p.Source)
	}
	kv("installed", inst)
	if v.FixedIn != "" {
		if words, ok := compareWords(v.Installed, v.FixedIn); ok {
			kv("check", words)
		}
	}
	kv("matched by", v.MatchedBy)
	kv("confidence", v.Confidence)

	if v.Verdict == "unverified" && v.Basis == "range-not-comparable" {
		kv("check it", s.Cmd("https://osv.dev/vulnerability/"+a.ID)+"  "+s.Dim("the advisory text may name a fixed version"))
	}
	if v.Verdict.Counts() {
		kv("severity", s.Sev(a.Severity, SevWord(a.Severity)))
		if ex := exploitLine(a); ex != "" {
			kv("exploit", ex)
		}
		if re := reachLine(a); re != "" {
			kv("reach", re)
		}
		switch {
		case p.Fix.State == FixAvailable && p.Fix.Target != "":
			kv("upgrade to", s.Good(p.Fix.Target))
		case p.Fix.State == FixPartial:
			kv("upgrade to", s.Warn(fmt.Sprintf("%s (clears %d of %d)", p.Fix.Target, p.Fix.Clears, p.Fix.Of)))
		case p.Fix.State == FixNone:
			kv("upgrade to", s.Hot("no fix"))
		}
		return b.String()
	}

	b.WriteString("\n")
	if o.Verbosity >= 0 {
		fmt.Fprintf(&b, "   %s\n", s.Dim("Not counted by --fail-on. Use --strict to count it."))
	}
	if v.Verdict == "likely_not_affected" {
		fmt.Fprintf(&b, "   %s %s\n", s.Dim("Think it still applies? Count it anyway:"), s.Cmd("vulnetix scan --strict"))
	}
	return b.String()
}
