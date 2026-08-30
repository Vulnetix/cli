package vex

import (
	"sort"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/cdx"
)

// apply.go folds matched statements onto a CycloneDX document.
//
// The governing rule: a suppressed finding is annotated, never deleted. A VEX
// statement is an argument that a vulnerability does not apply — it is not
// evidence the vulnerability was never there, and a document that quietly loses
// the entry cannot be audited, cannot be re-evaluated when the statement
// expires, and cannot tell a reader why the count went down. So the entry stays
// with an analysis block naming the status, the justification and the document
// that asserted it, and the counts report total, effective and suppressed
// separately.

// statusToCDXState maps a VEX status onto a CycloneDX analysis state.
//
// under_investigation has no CycloneDX equivalent by that name — the state is
// spelled in_triage — and emitting the OpenVEX spelling would fail schema
// validation, which is exactly the bug the shared writer was created to stop.
var statusToCDXState = map[Status]string{
	StatusNotAffected:        "not_affected",
	StatusAffected:           "exploitable",
	StatusFixed:              "resolved",
	StatusUnderInvestigation: "in_triage",
}

// Property names recording VEX provenance on an annotated vulnerability.
//
// Provenance is not decoration. Once a finding is suppressed, the only
// remaining question a reader has is "who said so, and on what grounds" — and
// without these the answer is nowhere in the document.
const (
	PropVEXSource  = "vulnetix:vex/source"
	PropVEXAuthor  = "vulnetix:vex/author"
	PropVEXBasis   = "vulnetix:vex/match-basis"
	PropVEXExplain = "vulnetix:vex/explain"
	PropVEXDocID   = "vulnetix:vex/document-id"
)

// Result reports what applying a statement set did.
type Result struct {
	// Total is every vulnerability entry considered.
	Total int `json:"total"`
	// Effective is the count still live after VEX.
	Effective int `json:"effective"`
	// Suppressed is the count a not_affected or fixed statement closed.
	Suppressed int `json:"suppressed"`
	// Annotated is the count that gained an analysis block without being
	// suppressed — an `affected` statement adds an action statement, which is
	// useful, but does not close anything.
	Annotated int `json:"annotated"`
	// Applied lists each finding a statement reached, for reporting.
	Applied []AppliedStatement `json:"applied,omitempty"`
	// Unmatched is the number of statements that matched no finding. A high
	// count usually means the documents are about a different product, which
	// is worth telling the user rather than silently doing nothing.
	Unmatched int `json:"unmatchedStatements"`
}

// AppliedStatement records one statement reaching one finding.
type AppliedStatement struct {
	VulnID     string     `json:"vulnId"`
	Purl       string     `json:"purl,omitempty"`
	Status     Status     `json:"status"`
	Suppressed bool       `json:"suppressed"`
	Basis      MatchBasis `json:"basis"`
	Explain    string     `json:"explain"`
	Source     string     `json:"source,omitempty"`
}

// SuppressedIDs returns the vulnerability ids VEX closed.
func (r *Result) SuppressedIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range r.Applied {
		if a.Suppressed && !seen[a.VulnID] {
			seen[a.VulnID] = true
			out = append(out, a.VulnID)
		}
	}
	sort.Strings(out)
	return out
}

// Apply folds a statement set into a BOM's vulnerability entries.
//
// The BOM is modified in place: each matched entry gains an analysis block and
// provenance properties. Nothing is removed.
func Apply(bom *cdx.BOM, set *Set) *Result {
	res := &Result{}
	if bom == nil || set.Empty() {
		if bom != nil {
			res.Total = len(bom.Vulnerabilities)
			res.Effective = res.Total
		}
		return res
	}

	// bom-ref → purl, so an `affects` ref resolves to a product identity the
	// statement can be matched against.
	purlByRef := make(map[string]string, len(bom.Components))
	nameVerByRef := make(map[string][2]string, len(bom.Components))
	for i := range bom.Components {
		c := &bom.Components[i]
		if c.BOMRef == "" {
			continue
		}
		if c.Purl != "" {
			purlByRef[c.BOMRef] = c.Purl
		}
		nameVerByRef[c.BOMRef] = [2]string{c.Name, c.Version}
	}

	matchedStatements := map[string]bool{}

	res.Total = len(bom.Vulnerabilities)
	for i := range bom.Vulnerabilities {
		v := &bom.Vulnerabilities[i]

		best, ok := bestMatchForEntry(v, set, purlByRef, nameVerByRef)
		if !ok {
			res.Effective++
			continue
		}

		annotate(v, best)
		matchedStatements[statementKey(best.Statement)] = true

		applied := AppliedStatement{
			VulnID:     v.ID,
			Purl:       firstAffectedPurl(v, purlByRef),
			Status:     best.Statement.Status,
			Suppressed: best.Suppresses(),
			Basis:      best.Basis,
			Explain:    best.Explain,
			Source:     best.Statement.Source.Path,
		}
		res.Applied = append(res.Applied, applied)

		if best.Suppresses() {
			res.Suppressed++
		} else {
			res.Annotated++
			res.Effective++
		}
	}

	for _, st := range set.Statements() {
		if !matchedStatements[statementKey(st)] {
			res.Unmatched++
		}
	}
	return res
}

// bestMatchForEntry finds the statement that best speaks about one entry.
//
// A vulnerability entry can affect several components, and a statement may
// speak about only one of them. Each affected component is tried and the most
// specific match wins, so a statement scoped to one package still applies when
// the entry also names others.
func bestMatchForEntry(
	v *cdx.Vulnerability,
	set *Set,
	purlByRef map[string]string,
	nameVerByRef map[string][2]string,
) (Match, bool) {
	var (
		best  Match
		found bool
	)
	consider := func(f Finding) {
		if m, ok := set.Match(f); ok {
			if !found || better(m, best) {
				best, found = m, true
			}
		}
	}

	if len(v.Affects) == 0 {
		consider(Finding{VulnID: v.ID})
		return best, found
	}
	for _, a := range v.Affects {
		f := Finding{VulnID: v.ID, Purl: purlByRef[a.Ref]}
		if f.Purl == "" && isPurl(a.Ref) {
			f.Purl = a.Ref
		}
		if nv, ok := nameVerByRef[a.Ref]; ok {
			f.Name, f.Version = nv[0], nv[1]
		}
		if f.Version == "" {
			f.Version = purlVersion(f.Purl)
		}
		consider(f)
	}
	return best, found
}

// annotate writes the analysis block and provenance onto an entry.
func annotate(v *cdx.Vulnerability, m Match) {
	st := m.Statement
	state := statusToCDXState[st.Status]
	if state == "" {
		// An unmapped status must not be written into the schema-constrained
		// state field. in_triage is the honest fallback: something was said,
		// but not something this CLI can render as a verdict.
		state = "in_triage"
	}

	analysis := &cdx.Analysis{State: state}
	// justification is only meaningful for not_affected; putting it anywhere
	// else fails CycloneDX schema validation.
	if st.Status == StatusNotAffected && Justifications[st.Justification] {
		analysis.Justification = st.Justification
	}
	analysis.Detail = firstNonEmpty(st.ImpactStatement, st.ActionStatement)
	v.Analysis = analysis

	setProp(v, PropVEXSource, st.Source.Path)
	setProp(v, PropVEXAuthor, st.Source.Author)
	setProp(v, PropVEXBasis, string(m.Basis))
	setProp(v, PropVEXExplain, m.Explain)
	setProp(v, PropVEXDocID, st.Source.DocumentID)
}

// setProp writes or replaces a namespaced property on an entry.
//
// Upsert, not append: applying VEX twice to one document must leave one
// provenance property per name, or the entry asserts two different bases for the
// same suppression and a consumer picks between them arbitrarily.
func setProp(v *cdx.Vulnerability, name, value string) {
	if value == "" {
		return
	}
	v.Properties = cyclonedx.SetProperty(v.Properties, name, value)
}

// firstAffectedPurl returns the first resolvable purl an entry affects.
func firstAffectedPurl(v *cdx.Vulnerability, purlByRef map[string]string) string {
	for _, a := range v.Affects {
		if p, ok := purlByRef[a.Ref]; ok && p != "" {
			return p
		}
		if isPurl(a.Ref) {
			return a.Ref
		}
	}
	return ""
}

func isPurl(s string) bool { return len(s) > 4 && s[:4] == "pkg:" }

// statementKey identifies a statement for the unmatched tally.
func statementKey(st Statement) string {
	key := st.Source.Path + "\x00" + st.VulnID + "\x00" + string(st.Status)
	for _, p := range st.Products {
		key += "\x00" + firstNonEmpty(p.Purl, p.ID)
	}
	return key
}
