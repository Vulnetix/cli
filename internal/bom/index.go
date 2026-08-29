package bom

import (
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/versions"
)

// index.go answers questions across a set of SBOMs rather than within one.
//
// Four questions, all of which need the corpus and none of which a single
// document can answer:
//
//	where — which documents contain this package, and is it direct there
//	skew  — which packages are at inconsistent versions across the corpus
//	search — find a package, project, vulnerability or licence by name
//	ls    — what documents are here, and what do they describe

// Entry is one component occurrence in one document.
type Entry struct {
	// Document is the SBOM the component was found in.
	Document *Document
	// Component is the component itself.
	Component *cdx.Component
	// Direct reports whether the document's subject depends on it directly.
	// Nil when the document has no dependency graph to answer from — an
	// unmeasurable fact stays null, never false.
	Direct *bool
}

// DocumentSummary describes one document in the corpus.
type DocumentSummary struct {
	Path            string                `json:"path"`
	Subject         string                `json:"subject,omitempty"`
	Version         string                `json:"version,omitempty"`
	Format          Format                `json:"format"`
	SpecVersion     string                `json:"specVersion,omitempty"`
	Components      int                   `json:"components"`
	Vulnerabilities int                   `json:"vulnerabilities"`
	Timestamp       string                `json:"timestamp,omitempty"`
	Deployment      cdx.DeploymentContext `json:"deployment,omitzero"`
}

// Index is a queryable view over a set of documents.
type Index struct {
	docs []*Document
	// byKey groups occurrences under a stable package identity: the versionless
	// purl when there is one, otherwise the lowered name. That key is what makes
	// version skew visible — the whole question is "the same package, different
	// versions", so the key must not include the version.
	byKey map[string][]Entry
	// keyOrder preserves first-seen order for stable output.
	keyOrder []string
}

// NewIndex builds an index over the collected documents.
func NewIndex(docs []*Document) *Index {
	idx := &Index{docs: docs, byKey: map[string][]Entry{}}

	for _, doc := range docs {
		direct := directRefs(doc.BOM)
		for i := range doc.BOM.Components {
			c := &doc.BOM.Components[i]
			key := packageKey(c)
			if key == "" {
				continue
			}
			if _, seen := idx.byKey[key]; !seen {
				idx.keyOrder = append(idx.keyOrder, key)
			}
			idx.byKey[key] = append(idx.byKey[key], Entry{
				Document: doc, Component: c, Direct: directness(direct, c),
			})
		}
	}
	return idx
}

// Documents returns the indexed documents.
func (idx *Index) Documents() []*Document { return idx.docs }

// Summaries describes every document in the corpus.
func (idx *Index) Summaries() []DocumentSummary {
	out := make([]DocumentSummary, 0, len(idx.docs))
	for _, doc := range idx.docs {
		s := DocumentSummary{
			Path:            doc.Source.Path,
			Format:          doc.Source.Format,
			SpecVersion:     doc.Source.SpecVersion,
			Components:      len(doc.BOM.Components),
			Vulnerabilities: len(doc.BOM.Vulnerabilities),
			Deployment:      cdx.DeploymentContextFromBOM(doc.BOM),
		}
		if doc.BOM.Metadata != nil {
			s.Timestamp = doc.BOM.Metadata.Timestamp
			if c := doc.BOM.Metadata.Component; c != nil {
				s.Subject, s.Version = c.Name, c.Version
			}
		}
		out = append(out, s)
	}
	return out
}

// packageKey is a component's identity across documents, version excluded.
func packageKey(c *cdx.Component) string {
	if c.Purl != "" {
		return purlWithoutVersion(c.Purl)
	}
	if c.Name == "" {
		return ""
	}
	// Group is part of the identity where an ecosystem uses one (Maven), so
	// two unrelated artefacts sharing a short name do not merge.
	if c.Group != "" {
		return strings.ToLower(c.Group + ":" + c.Name)
	}
	return strings.ToLower(c.Name)
}

// ── where: blast radius ─────────────────────────────────────────────────────

// Location is one document a package was found in.
type Location struct {
	Path       string                `json:"path"`
	Subject    string                `json:"subject,omitempty"`
	Version    string                `json:"version"`
	Direct     *bool                 `json:"direct,omitempty"`
	Deployment cdx.DeploymentContext `json:"deployment,omitzero"`
}

// BlastRadius is the answer to "who has this package".
type BlastRadius struct {
	// Query is what was asked for.
	Query string `json:"query"`
	// Key is the package identity that matched.
	Key string `json:"key,omitempty"`
	// Name is the component's name as the documents spell it.
	Name string `json:"name,omitempty"`
	// Locations are every document containing it.
	Locations []Location `json:"locations"`
	// Versions are the distinct versions present, ordered.
	Versions []string `json:"versions"`
	// DirectCount and TransitiveCount split the locations by directness.
	// Unknown is where the document had no graph to answer from.
	DirectCount     int `json:"directCount"`
	TransitiveCount int `json:"transitiveCount"`
	UnknownCount    int `json:"unknownCount"`
}

// Where finds every document containing a package.
//
// The selector may be a purl (with or without a version), a bare name, or a
// substring. Exact identities are tried first so that asking for "lodash" does
// not silently answer about "lodash.merge" when both are present.
func (idx *Index) Where(selector string) *BlastRadius {
	br := &BlastRadius{Query: selector}

	key := idx.resolveKey(selector)
	if key == "" {
		return br
	}
	br.Key = key

	versionSet := map[string]bool{}
	for _, e := range idx.byKey[key] {
		if br.Name == "" {
			br.Name = e.Component.Name
		}
		loc := Location{
			Path:       e.Document.Source.Path,
			Version:    e.Component.Version,
			Direct:     e.Direct,
			Deployment: cdx.DeploymentContextFromBOM(e.Document.BOM),
		}
		if e.Document.BOM.Metadata != nil && e.Document.BOM.Metadata.Component != nil {
			loc.Subject = e.Document.BOM.Metadata.Component.Name
		}
		br.Locations = append(br.Locations, loc)

		switch {
		case e.Direct == nil:
			br.UnknownCount++
		case *e.Direct:
			br.DirectCount++
		default:
			br.TransitiveCount++
		}
		if e.Component.Version != "" {
			versionSet[e.Component.Version] = true
		}
	}

	br.Versions = sortedVersions(versionSet)
	sort.SliceStable(br.Locations, func(i, j int) bool {
		return br.Locations[i].Path < br.Locations[j].Path
	})
	return br
}

// resolveKey maps a user selector onto an indexed package key.
func (idx *Index) resolveKey(selector string) string {
	if selector == "" {
		return ""
	}
	// A purl, with or without a version.
	if strings.HasPrefix(selector, "pkg:") {
		key := purlWithoutVersion(selector)
		if _, ok := idx.byKey[key]; ok {
			return key
		}
		return ""
	}
	lower := strings.ToLower(selector)
	if _, ok := idx.byKey[lower]; ok {
		return lower
	}
	// A bare name against purl-keyed entries: match the purl's final segment,
	// so "lodash" finds "pkg:npm/lodash" without matching "pkg:npm/lodash.merge".
	for _, key := range idx.keyOrder {
		if strings.ToLower(lastPurlSegment(key)) == lower {
			return key
		}
	}
	// Last resort: a substring, so a partial name is still useful.
	for _, key := range idx.keyOrder {
		if strings.Contains(strings.ToLower(key), lower) {
			return key
		}
	}
	return ""
}

// lastPurlSegment returns the name portion of a versionless purl.
func lastPurlSegment(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}

// ── skew: the same package at different versions ────────────────────────────

// SkewEntry is one package present at more than one version.
type SkewEntry struct {
	Key      string        `json:"key"`
	Name     string        `json:"name"`
	Versions []SkewVersion `json:"versions"`
	// DocumentCount is how many documents carry it at any version.
	DocumentCount int `json:"documentCount"`
	// DirectCount is how many of those depend on it directly, which is where a
	// version can actually be changed.
	DirectCount int `json:"directCount"`
}

// SkewVersion is one version of a skewed package and where it appears.
type SkewVersion struct {
	Version   string   `json:"version"`
	Documents []string `json:"documents"`
}

// Skew finds packages present at inconsistent versions across the corpus.
//
// This is the "why do we have fifty containerds" question, and it is the one
// that most often has an actionable answer: a package at four versions across
// six services is usually four upgrades nobody sequenced, not four deliberate
// pins.
func (idx *Index) Skew() []SkewEntry {
	var out []SkewEntry

	for _, key := range idx.keyOrder {
		entries := idx.byKey[key]

		byVersion := map[string][]string{}
		docs := map[string]bool{}
		direct := 0
		name := ""
		for _, e := range entries {
			if name == "" {
				name = e.Component.Name
			}
			v := e.Component.Version
			if v == "" {
				// A component with no version cannot be part of a version
				// disagreement, and counting it as one would report skew on
				// every document that omits versions.
				continue
			}
			byVersion[v] = append(byVersion[v], e.Document.Source.Path)
			docs[e.Document.Source.Path] = true
			if e.Direct != nil && *e.Direct {
				direct++
			}
		}
		if len(byVersion) < 2 {
			continue
		}

		entry := SkewEntry{Key: key, Name: name, DocumentCount: len(docs), DirectCount: direct}
		for _, v := range sortedVersionKeys(byVersion) {
			paths := byVersion[v]
			sort.Strings(paths)
			entry.Versions = append(entry.Versions, SkewVersion{Version: v, Documents: dedupeStrings(paths)})
		}
		out = append(out, entry)
	}

	// Most-divergent first: a package at five versions is a bigger problem than
	// one at two, and the list is a work queue.
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Versions) != len(out[j].Versions) {
			return len(out[i].Versions) > len(out[j].Versions)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ── search: faceted lookup ──────────────────────────────────────────────────

// SearchResults are the facets a query matched.
type SearchResults struct {
	Query           string             `json:"query"`
	Components      []ComponentHit     `json:"components,omitempty"`
	Documents       []DocumentSummary  `json:"documents,omitempty"`
	Vulnerabilities []VulnerabilityHit `json:"vulnerabilities,omitempty"`
	Licenses        []LicenseHit       `json:"licenses,omitempty"`
	// Totals are the full counts per facet, before any limit was applied, so a
	// truncated result says how much it truncated.
	Totals map[string]int `json:"totals"`
}

// ComponentHit is a component matching a search.
type ComponentHit struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Versions  []string `json:"versions"`
	Documents int      `json:"documents"`
}

// VulnerabilityHit is a vulnerability matching a search.
type VulnerabilityHit struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	Documents   []string `json:"documents"`
}

// LicenseHit is a licence matching a search.
type LicenseHit struct {
	License    string `json:"license"`
	Components int    `json:"components"`
}

// MinSearchQuery is the shortest query accepted.
//
// One character matches most of a corpus, which is not a search result — it is
// the corpus with extra steps.
const MinSearchQuery = 2

// Search finds components, documents, vulnerabilities and licences by name.
//
// limit bounds each facet independently, so a query matching a thousand
// components still shows the one document and the two vulnerabilities it also
// matched, rather than burying them.
func (idx *Index) Search(query string, limit int) *SearchResults {
	res := &SearchResults{Query: query, Totals: map[string]int{}}
	if len(strings.TrimSpace(query)) < MinSearchQuery {
		return res
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if limit <= 0 {
		limit = 25
	}

	for _, key := range idx.keyOrder {
		entries := idx.byKey[key]
		if !strings.Contains(strings.ToLower(key), q) &&
			!strings.Contains(strings.ToLower(entries[0].Component.Name), q) {
			continue
		}
		res.Totals["components"]++
		if len(res.Components) >= limit {
			continue
		}
		versionSet := map[string]bool{}
		docs := map[string]bool{}
		for _, e := range entries {
			if e.Component.Version != "" {
				versionSet[e.Component.Version] = true
			}
			docs[e.Document.Source.Path] = true
		}
		res.Components = append(res.Components, ComponentHit{
			Key: key, Name: entries[0].Component.Name,
			Versions: sortedVersions(versionSet), Documents: len(docs),
		})
	}

	for _, s := range idx.Summaries() {
		if !strings.Contains(strings.ToLower(s.Subject), q) &&
			!strings.Contains(strings.ToLower(s.Path), q) {
			continue
		}
		res.Totals["documents"]++
		if len(res.Documents) < limit {
			res.Documents = append(res.Documents, s)
		}
	}

	// Vulnerabilities match on id AND description: "log4shell" is how people
	// refer to CVE-2021-44228, and an id-only search finds nothing for it.
	vulnDocs := map[string][]string{}
	vulnMeta := map[string]*cdx.Vulnerability{}
	for _, doc := range idx.docs {
		for i := range doc.BOM.Vulnerabilities {
			v := &doc.BOM.Vulnerabilities[i]
			if !strings.Contains(strings.ToLower(v.ID), q) &&
				!strings.Contains(strings.ToLower(v.Description), q) {
				continue
			}
			if _, seen := vulnMeta[v.ID]; !seen {
				vulnMeta[v.ID] = v
			}
			vulnDocs[v.ID] = append(vulnDocs[v.ID], doc.Source.Path)
		}
	}
	for _, id := range sortedKeys(vulnDocs) {
		res.Totals["vulnerabilities"]++
		if len(res.Vulnerabilities) >= limit {
			continue
		}
		paths := dedupeStrings(vulnDocs[id])
		sort.Strings(paths)
		res.Vulnerabilities = append(res.Vulnerabilities, VulnerabilityHit{
			ID: id, Severity: topSeverity(vulnMeta[id]),
			Description: vulnMeta[id].Description, Documents: paths,
		})
	}

	licenseCounts := map[string]int{}
	for _, doc := range idx.docs {
		for i := range doc.BOM.Components {
			for _, l := range componentLicenses(&doc.BOM.Components[i]) {
				if strings.Contains(strings.ToLower(l), q) {
					licenseCounts[l]++
				}
			}
		}
	}
	for _, l := range sortedKeys(licenseCounts) {
		res.Totals["licenses"]++
		if len(res.Licenses) < limit {
			res.Licenses = append(res.Licenses, LicenseHit{License: l, Components: licenseCounts[l]})
		}
	}

	return res
}

// componentLicenses lists a component's licence identifiers.
func componentLicenses(c *cdx.Component) []string {
	var out []string
	for _, lc := range c.Licenses {
		switch {
		case lc.Expression != "":
			out = append(out, lc.Expression)
		case lc.License != nil && lc.License.ID != "":
			out = append(out, lc.License.ID)
		case lc.License != nil && lc.License.Name != "":
			out = append(out, lc.License.Name)
		}
	}
	return out
}

// ── shared helpers ──────────────────────────────────────────────────────────

// sortedVersions orders a version set semantically, falling back to string
// order for versions that do not parse.
func sortedVersions(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sortVersionSlice(out)
	return out
}

func sortedVersionKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortVersionSlice(out)
	return out
}

// sortVersionSlice orders versions newest-last, in place.
//
// Semantic where both sides parse, lexical otherwise. Mixed sets do occur —
// a git sha beside a tag — and a comparison that panicked or silently reordered
// on one would make the whole list untrustworthy.
func sortVersionSlice(vs []string) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, errA := versions.Parse(vs[i])
		b, errB := versions.Parse(vs[j])
		if errA != nil || errB != nil {
			return vs[i] < vs[j]
		}
		if c := versions.Compare(a, b); c != 0 {
			return c < 0
		}
		return vs[i] < vs[j]
	})
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
