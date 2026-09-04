package lsp

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/v3/internal/lsp/anchor"
	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

// SourceSCA is the Diagnostic.source for dependency findings.
//
// The exact string matters. The extension routes diagnostics into one
// collection per scanner family by matching this against a fixed list, and
// anything it does not recognise is filed as SAST — so a near miss here does
// not fail loudly, it quietly mislabels every dependency finding.
const SourceSCA = "vulnetix-sca"

// scaDiagnosticData is the SCA half of Diagnostic.data.
//
// It carries what a code action needs to build a fix without repeating the
// lookup: which package, at which version, and what the resolved target is.
type scaDiagnosticData struct {
	Purl       string   `json:"purl"`
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	Ecosystem  string   `json:"ecosystem"`
	CveIDs     []string `json:"cveIds,omitempty"`
	TargetVer  string   `json:"targetVersion,omitempty"`
	IsDirect   bool     `json:"isDirect"`
	Transitive bool     `json:"transitive,omitempty"`
}

// SCADiagnostics builds the dependency diagnostics for one document.
func (e *scaEngine) SCADiagnostics(relPath, text string, m SeverityMapping) []protocol.Diagnostic {
	annotations := e.Annotations(relPath, text)
	out := make([]protocol.Diagnostic, 0, len(annotations))

	for i := range annotations {
		a := &annotations[i]
		if !a.Vulnerable() {
			continue
		}
		if diag, ok := e.scaDiagnostic(a, m); ok {
			out = append(out, diag)
		}
	}
	return out
}

func (e *scaEngine) scaDiagnostic(a *scaAnnotation, m SeverityMapping) (protocol.Diagnostic, bool) {
	vulns := a.AllVulns()
	if len(vulns) == 0 {
		return protocol.Diagnostic{}, false
	}

	worst := scaview.WorstSeverity(vulns)
	top := scaview.TopVuln(vulns)

	diag := protocol.Diagnostic{
		Range:    a.Range,
		Severity: severityToLSP(worst, m),
		Source:   SourceSCA,
		// Rendered from the same Subject the hover card uses, so the Problems
		// panel and the card cannot describe one package two ways.
		Message: scaview.Headline(e.subject(a)),
	}

	if top.CveID != "" {
		diag.Code = top.CveID
		if href := advisoryURL(top.CveID); href != "" {
			diag.CodeDescription = &protocol.CodeDescription{Href: href}
		}
	}

	// An end-of-life package gets the deprecated tag, which editors render with
	// a strikethrough. That is the honest signal: the problem is not a version
	// to bump to, it is that nobody is going to publish one.
	if a.Verdict != nil && a.Verdict.Insight != nil && a.Verdict.Insight.IsEOL {
		diag.Tags = append(diag.Tags, protocol.TagDeprecated)
	}

	diag.RelatedInformation = e.scaRelatedInformation(a)

	target := ""
	if a.Verdict != nil {
		target = e.targetVersionFor(a.Verdict)
	}

	data := DiagnosticData{
		FindingID:        scaFindingID(a),
		Tool:             "sca",
		RuleID:           top.CveID,
		AnchorConfidence: string(a.Confidence),
		FixAvailable:     target != "",
		Suppressible:     true,
		SCA: &scaDiagnosticData{
			Purl:       purlOf(a),
			Package:    a.Pkg.Name,
			Version:    a.Pkg.Version,
			Ecosystem:  a.Pkg.Ecosystem,
			CveIDs:     scaview.CVEIDs(vulns),
			TargetVer:  target,
			IsDirect:   a.Pkg.IsDirect,
			Transitive: len(a.Introduced) > 0,
		},
	}
	if raw, err := json.Marshal(data); err == nil {
		diag.Data = raw
	}

	return diag, true
}

// scaRelatedInformation points at the transitive packages rolled up onto this
// line, and at the manifest a finding was declared in when that differs.
func (e *scaEngine) scaRelatedInformation(a *scaAnnotation) []protocol.DiagnosticRelatedInformation {
	if len(a.Introduced) == 0 {
		return nil
	}
	out := make([]protocol.DiagnosticRelatedInformation, 0, len(a.Introduced))
	for _, v := range a.Introduced {
		e.mu.Lock()
		root := e.root
		e.mu.Unlock()
		uri := PathToURI(filepath.Join(root, filepath.FromSlash(v.SourceFile)))
		if uri == "" {
			continue
		}
		out = append(out, protocol.DiagnosticRelatedInformation{
			Location: protocol.Location{
				URI: uri,
				// The precise line inside the other file is not resolved here:
				// it needs that file's text, which the server may not hold. The
				// file itself is the useful part of the link.
				Range: protocol.Range{},
			},
			Message: fmt.Sprintf("%s@%s: %s", v.Name, v.Version, scaview.PluralVulns(len(v.Vulns))),
		})
	}
	return out
}

// targetVersionFor resolves the version a quick fix would move to, or empty
// when Safe-Harbour has not answered or had nothing to offer.
func (e *scaEngine) targetVersionFor(v *scaVerdict) string {
	if v == nil || v.Insight == nil {
		return ""
	}
	cfg := e.settings()
	target, decision := resolveFixTarget(v, cfg)
	if decision.Skipped {
		return ""
	}
	return target
}

func introducedNames(verdicts []*scaVerdict) []string {
	out := make([]string, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, v.Name+"@"+v.Version)
	}
	return out
}

// advisoryURL links an identifier to its canonical public page.
//
// Only formats with a stable, known URL are linked. Guessing one for an
// unrecognised identifier produces a 404, which is worse than no link.
func advisoryURL(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	}
	return ""
}

// scaFindingID is the stable identity of a dependency finding, matching the
// `tool:vuln:purl` shape the protocol's Finding type documents. Stability is
// what lets a client keep selection and expansion state across a rescan.
func scaFindingID(a *scaAnnotation) string {
	top := scaview.TopVuln(a.AllVulns())
	return "sca:" + top.CveID + ":" + purlOf(a)
}

func purlOf(a *scaAnnotation) string {
	if a.Verdict != nil {
		return a.Verdict.Purl
	}
	return ""
}

// scaConfidenceOf exposes the anchor confidence as the protocol string.
func scaConfidenceOf(a *scaAnnotation) string {
	if a.Confidence == "" {
		return string(anchor.ConfidenceToken)
	}
	return string(a.Confidence)
}

// isCVE reports whether an identifier is a CVE rather than a database-specific
// alias such as a GHSA. Used only to break ties between equally severe
// advisories, where the CVE is the more recognisable name.
func isCVE(id string) bool {
	return strings.HasPrefix(id, "CVE-")
}
