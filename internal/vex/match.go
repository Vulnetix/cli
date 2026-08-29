package vex

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/versions"
)

// match.go decides whether a statement speaks about a finding.
//
// The naive implementation compares (vulnerability id, product purl) for exact
// equality. That is what most consumers do, and it is why VEX so often appears
// not to work: a vendor publishes a statement against `pkg:npm/foo@1.2.3`, the
// scan finds `pkg:npm/foo@1.2.4`, and the statement is silently ignored — no
// error, no warning, the finding simply stays open. Worse, a statement written
// against a product with no version at all matches nothing under exact
// equality, even though "no version" means "every version".
//
// So matching is a cascade, and every match records why it matched. A
// suppressed finding must always be explicable: which document, which
// statement, and on what basis.

// Finding is the subset of a scan finding that matching needs.
type Finding struct {
	// VulnID is the vulnerability identifier as the scanner reports it.
	VulnID string
	// Purl identifies the affected component, when known.
	Purl string
	// Name and Version are the fallback identity for a finding with no purl.
	Name    string
	Version string
}

// MatchBasis explains why a statement was applied.
type MatchBasis string

const (
	// BasisExactPurl — the statement names this exact purl, version included.
	BasisExactPurl MatchBasis = "exact-purl"
	// BasisPurlAnyVersion — the statement names the package with no version
	// scope, so it speaks about every version of it.
	BasisPurlAnyVersion MatchBasis = "purl-any-version"
	// BasisPurlVersionListed — the statement lists this version explicitly.
	BasisPurlVersionListed MatchBasis = "purl-version-listed"
	// BasisPurlVersionRange — the finding's version falls inside a range the
	// statement scopes itself to.
	BasisPurlVersionRange MatchBasis = "purl-version-range"
	// BasisSubcomponent — the statement narrows to this purl as a
	// subcomponent of the product it names.
	BasisSubcomponent MatchBasis = "subcomponent"
	// BasisNameVersion — matched on name and version because neither side
	// carried a purl.
	BasisNameVersion MatchBasis = "name-version"
	// BasisDocumentWide — the statement names no product, so it speaks about
	// everything the document describes. The weakest basis, and the one most
	// likely to over-apply, so it loses to every other.
	BasisDocumentWide MatchBasis = "document-wide"
)

// basisRank orders match bases by how specific they are. A more specific
// statement wins when two speak about the same finding.
var basisRank = map[MatchBasis]int{
	BasisExactPurl:         6,
	BasisPurlVersionListed: 5,
	BasisPurlVersionRange:  4,
	BasisSubcomponent:      3,
	BasisNameVersion:       2,
	BasisPurlAnyVersion:    1,
	BasisDocumentWide:      0,
}

// Match is one statement applied to one finding.
type Match struct {
	Statement Statement  `json:"statement"`
	Basis     MatchBasis `json:"basis"`
	// Explain is a human sentence saying why this statement was applied.
	Explain string `json:"explain"`
}

// Suppresses reports whether the matched statement closes the finding.
func (m Match) Suppresses() bool { return m.Statement.Status.Suppresses() }

// Status is the matched statement's assertion.
func (m Match) Status() Status { return m.Statement.Status }

// Set is a queryable collection of statements.
type Set struct {
	statements []Statement
	// byVuln indexes statements by vulnerability id and by every alias, so a
	// finding reported as GHSA-xxxx still matches a statement written against
	// the CVE.
	byVuln map[string][]int
}

// NewSet indexes statements for matching.
func NewSet(docs []*Document) *Set {
	s := &Set{byVuln: map[string][]int{}}
	for _, doc := range docs {
		for _, st := range doc.Statements {
			if st.VulnID == "" {
				continue
			}
			idx := len(s.statements)
			s.statements = append(s.statements, st)
			s.byVuln[strings.ToUpper(st.VulnID)] = append(s.byVuln[strings.ToUpper(st.VulnID)], idx)
			for _, alias := range st.Aliases {
				key := strings.ToUpper(alias)
				s.byVuln[key] = append(s.byVuln[key], idx)
			}
		}
	}
	return s
}

// Len is the number of indexed statements.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.statements)
}

// Empty reports whether the set has no statements.
func (s *Set) Empty() bool { return s.Len() == 0 }

// Statements returns every indexed statement.
func (s *Set) Statements() []Statement {
	if s == nil {
		return nil
	}
	return s.statements
}

// Match finds the statement that best speaks about a finding.
//
// When several statements match, the most specific basis wins; on equal
// specificity the newest timestamp wins, because VEX is a running assertion and
// a later statement supersedes an earlier one about the same thing.
func (s *Set) Match(f Finding) (Match, bool) {
	if s == nil || f.VulnID == "" {
		return Match{}, false
	}
	candidates := s.byVuln[strings.ToUpper(f.VulnID)]
	if len(candidates) == 0 {
		return Match{}, false
	}

	var (
		best  Match
		found bool
	)
	for _, idx := range candidates {
		st := s.statements[idx]
		basis, ok := matchProduct(st, f)
		if !ok {
			continue
		}
		m := Match{Statement: st, Basis: basis, Explain: explain(st, f, basis)}
		if !found || better(m, best) {
			best, found = m, true
		}
	}
	return best, found
}

// better reports whether a beats b for the same finding.
func better(a, b Match) bool {
	ra, rb := basisRank[a.Basis], basisRank[b.Basis]
	if ra != rb {
		return ra > rb
	}
	return a.Statement.Timestamp.After(b.Statement.Timestamp)
}

// matchProduct decides whether a statement's products cover a finding.
func matchProduct(st Statement, f Finding) (MatchBasis, bool) {
	// A statement with no products speaks about whatever the document as a
	// whole describes. That is a real and common shape — a vendor advisory
	// about one product — but it is also the shape most likely to over-apply,
	// so it is the weakest basis rather than an exclusion.
	if len(st.Products) == 0 {
		return BasisDocumentWide, true
	}

	best := MatchBasis("")
	for _, p := range st.Products {
		if basis, ok := matchOneProduct(p, f); ok {
			if best == "" || basisRank[basis] > basisRank[best] {
				best = basis
			}
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func matchOneProduct(p Product, f Finding) (MatchBasis, bool) {
	// Subcomponents are the narrowest claim a statement can make, so they are
	// checked before the product itself.
	for _, sub := range p.Subcomponents {
		if f.Purl != "" && purlEqual(sub, f.Purl) {
			return BasisSubcomponent, true
		}
		if versionlessEqual(sub, f.Purl) && versionMatches(purlVersion(sub), f.Version) {
			return BasisSubcomponent, true
		}
	}

	if p.Purl != "" && f.Purl != "" {
		if purlEqual(p.Purl, f.Purl) {
			return BasisExactPurl, true
		}
		if versionlessEqual(p.Purl, f.Purl) {
			// Same package, different version scope. What the statement says
			// about versions decides whether it reaches this one.
			if v := purlVersion(p.Purl); v != "" && v != f.Version {
				// The purl pins a version that is not this one; only an
				// explicit version list or range can still bring it in.
				if basis, ok := matchVersions(p.Versions, f.Version); ok {
					return basis, true
				}
				return "", false
			}
			if len(p.Versions) == 0 {
				return BasisPurlAnyVersion, true
			}
			return matchVersions(p.Versions, f.Version)
		}
		return "", false
	}

	// Neither side carries a purl: fall back to the product's raw identifier
	// against the finding's name.
	if p.Purl == "" && f.Purl == "" && p.ID != "" && f.Name != "" {
		if strings.EqualFold(p.ID, f.Name) || strings.EqualFold(p.ID, f.Name+"@"+f.Version) {
			if len(p.Versions) == 0 {
				return BasisNameVersion, true
			}
			if _, ok := matchVersions(p.Versions, f.Version); ok {
				return BasisNameVersion, true
			}
		}
	}
	return "", false
}

// matchVersions tests a finding version against a statement's version scope.
//
// An entry is either a literal version or a constraint expression. Trying the
// literal first is deliberate: `1.2.3` is a valid constraint too, and parsing
// it as one would be slower and no more correct.
func matchVersions(entries []string, findingVersion string) (MatchBasis, bool) {
	if len(entries) == 0 {
		return BasisPurlAnyVersion, true
	}
	if findingVersion == "" {
		return "", false
	}
	for _, e := range entries {
		if e == findingVersion {
			return BasisPurlVersionListed, true
		}
	}

	fv, err := versions.Parse(findingVersion)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if !looksLikeRange(e) {
			// Compare as versions so "v1.2.3" and "1.2.3" agree.
			if ev, err := versions.Parse(e); err == nil && versions.Compare(ev, fv) == 0 {
				return BasisPurlVersionListed, true
			}
			continue
		}
		rs, err := versions.ParseRange(e)
		if err != nil {
			continue
		}
		// PseudoBaseEqual, not PseudoStrict: a VEX statement scoping a range of
		// "5.3.2" is a claim about that release, and a consumer running the
		// pseudo-version built from it is running that code. Treating them as
		// distinct would silently drop the statement for every Go module
		// pinned to a commit.
		if rs.Contains(fv, versions.PseudoBaseEqual) {
			return BasisPurlVersionRange, true
		}
	}
	return "", false
}

// looksLikeRange reports whether a version entry is a constraint expression
// rather than a literal version.
func looksLikeRange(s string) bool {
	return strings.ContainsAny(s, "<>=^~*|") || strings.Contains(s, " - ") ||
		strings.HasPrefix(s, "[") || strings.HasPrefix(s, "(")
}

// versionMatches reports whether a pinned version equals a finding version,
// treating an unpinned statement as matching anything.
func versionMatches(stmtVersion, findingVersion string) bool {
	if stmtVersion == "" {
		return true
	}
	if stmtVersion == findingVersion {
		return true
	}
	a, errA := versions.Parse(stmtVersion)
	b, errB := versions.Parse(findingVersion)
	return errA == nil && errB == nil && versions.Compare(a, b) == 0
}

// purlEqual compares two purls for identity, ignoring qualifier ordering.
func purlEqual(a, b string) bool {
	return stripQualifiers(a) == stripQualifiers(b)
}

// versionlessEqual compares two purls ignoring their versions.
func versionlessEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return purlWithoutVersion(a) == purlWithoutVersion(b)
}

// stripQualifiers removes the qualifier and subpath sections of a purl.
func stripQualifiers(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

// purlWithoutVersion strips version, qualifiers and subpath from a purl.
//
// The version separator is the last '@' after the final '/'. Splitting on the
// first '@' collapses every scoped npm package to `pkg:npm/`, which would make
// a statement about one scoped package match all of them.
func purlWithoutVersion(p string) string {
	p = stripQualifiers(p)
	at := strings.LastIndex(p, "@")
	if at > strings.LastIndex(p, "/") {
		return p[:at]
	}
	return p
}

// purlVersion returns the version segment of a purl, or "".
func purlVersion(p string) string {
	p = stripQualifiers(p)
	at := strings.LastIndex(p, "@")
	if at > strings.LastIndex(p, "/") && at+1 < len(p) {
		return p[at+1:]
	}
	return ""
}

// explain renders the human sentence attached to a match.
func explain(st Statement, f Finding, basis MatchBasis) string {
	who := st.Source.Author
	if who == "" {
		who = "an unnamed author"
	}
	where := st.Source.Path
	if where == "" {
		where = string(st.Source.Format)
	}

	subject := f.Purl
	if subject == "" {
		subject = f.Name
	}

	var how string
	switch basis {
	case BasisExactPurl:
		how = fmt.Sprintf("names %s exactly", subject)
	case BasisPurlAnyVersion:
		how = fmt.Sprintf("names %s with no version scope, so it covers every version", productLabel(st))
	case BasisPurlVersionListed:
		how = fmt.Sprintf("lists version %s of %s", f.Version, productLabel(st))
	case BasisPurlVersionRange:
		how = fmt.Sprintf("scopes a version range of %s that contains %s", productLabel(st), f.Version)
	case BasisSubcomponent:
		how = fmt.Sprintf("names %s as a subcomponent", subject)
	case BasisNameVersion:
		how = fmt.Sprintf("names %s by name", subject)
	case BasisDocumentWide:
		how = "names no product, so it applies to everything the document describes"
	default:
		how = "matched"
	}

	return fmt.Sprintf("%s in %s (by %s) %s and asserts %s", st.VulnID, where, who, how, st.Status)
}

// productLabel renders a statement's products for an explanation.
func productLabel(st Statement) string {
	labels := make([]string, 0, len(st.Products))
	for _, p := range st.Products {
		if l := firstNonEmpty(p.Purl, p.ID); l != "" {
			labels = append(labels, l)
		}
	}
	if len(labels) == 0 {
		return "the document subject"
	}
	sort.Strings(labels)
	if len(labels) > 2 {
		labels = append(labels[:2], "…")
	}
	return strings.Join(labels, ", ")
}
