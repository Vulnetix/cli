package report

import (
	"encoding/json"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// JSONSchema names the shape RenderJSON emits. It changes only by adding fields.
const JSONSchema = "vulnetix/report/v1"

type jsonAdvisory struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	Verdict       string   `json:"verdict"`
	Basis         string   `json:"basis"`
	Confidence    string   `json:"confidence"`
	Range         string   `json:"range,omitempty"`
	FixedIn       string   `json:"fixedIn,omitempty"`
	FixedInSource string   `json:"fixedInSource,omitempty"`
	MatchedBy     string   `json:"matchedBy"`
	Detail        string   `json:"detail"`
	Fix           string   `json:"fix,omitempty"`
	FixSource     string   `json:"fixSource,omitempty"`
	KEV           bool     `json:"kev,omitempty"`
	Exploits      int      `json:"exploits,omitempty"`
	CVSS          float64  `json:"cvss,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	Signals       []string `json:"signals,omitempty"`
}

type jsonPackage struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	Ecosystem  string         `json:"ecosystem"`
	Purl       string         `json:"purl"`
	Source     string         `json:"source,omitempty"`
	Direct     bool           `json:"direct"`
	Via        []string       `json:"via,omitempty"`
	Group      string         `json:"group"`
	Severity   string         `json:"severity"`
	Fix        jsonFix        `json:"fix"`
	Advisories []jsonAdvisory `json:"advisories"`
	RuledOut   []jsonAdvisory `json:"ruledOut,omitempty"`
}

type jsonFix struct {
	State  string `json:"state"`
	Target string `json:"target,omitempty"`
	Clears int    `json:"clears,omitempty"`
	Of     int    `json:"of,omitempty"`
}

type jsonReport struct {
	Schema   string         `json:"schema"`
	Counts   jsonCounts     `json:"counts"`
	Packages []jsonPackage  `json:"packages"`
	Meta     map[string]any `json:"meta"`
}

type jsonCounts struct {
	Advisories int            `json:"advisories"`
	Packages   int            `json:"packages"`
	ByGroup    map[string]int `json:"byGroup"`
}

// RenderJSON is the machine-readable view: every package with its group, fix and,
// for each advisory, the verdict and the working behind it. Findings the verdict
// rules out are included under ruledOut; nothing is dropped.
func RenderJSON(r Report) ([]byte, error) {
	c := r.Counts()
	out := jsonReport{
		Schema: JSONSchema,
		Counts: jsonCounts{Advisories: c.Advisories, Packages: c.Packages, ByGroup: map[string]int{}},
		Meta: map[string]any{
			"scannedPackages": r.Meta.ScannedPackages, "manifests": r.Meta.Manifests,
			"kinds": r.Meta.Kinds, "strict": r.Meta.Strict,
		},
	}
	for g, n := range c.ByGroup {
		out.Counts.ByGroup[string(g)] = n
	}
	for _, p := range r.Packages {
		jp := jsonPackage{
			Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem,
			Purl:   cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem),
			Source: p.Source, Direct: p.Direct, Via: p.Via, Group: string(p.Group), Severity: p.Severity,
			Fix:        jsonFix{State: fixStateName(p.Fix.State), Target: p.Fix.Target, Clears: p.Fix.Clears, Of: p.Fix.Of},
			Advisories: []jsonAdvisory{},
		}
		for _, a := range p.Advisories {
			jp.Advisories = append(jp.Advisories, toJSONAdvisory(a))
		}
		for _, a := range p.RuledOut {
			jp.RuledOut = append(jp.RuledOut, toJSONAdvisory(a))
		}
		out.Packages = append(out.Packages, jp)
	}
	return json.MarshalIndent(out, "", "  ")
}

func toJSONAdvisory(a Advisory) jsonAdvisory {
	ja := jsonAdvisory{
		ID: a.ID, Severity: a.Severity, Verdict: string(a.Verdict.Verdict), Basis: a.Verdict.Basis,
		Confidence: a.Verdict.Confidence, Range: a.Verdict.Range, FixedIn: a.Verdict.FixedIn,
		FixedInSource: a.Verdict.FixedInSource, MatchedBy: a.Verdict.MatchedBy, Detail: a.Verdict.Detail,
		Fix: a.Fix, FixSource: a.FixSource, KEV: a.KEV, Exploits: a.Exploits, CVSS: a.CVSS,
		Aliases: a.AlsoKnownAs,
	}
	for _, s := range a.Signals {
		ja.Signals = append(ja.Signals, s.Label)
	}
	return ja
}

func fixStateName(s FixState) string {
	switch s {
	case FixAvailable:
		return "available"
	case FixPartial:
		return "partial"
	case FixNone:
		return "none"
	}
	return "unknown"
}
