package bom

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// quality.go answers "is this SBOM any good?" as a field-presence report.
//
// It is deliberately mechanical. It checks whether the data a consumer needs is
// actually in the document — every component has a version, an identifier, a
// licence, a supplier; the document has an author, a timestamp, a dependency
// graph. It does not award a framework badge, because the frameworks that
// define minimum elements disagree on the margins and a single number would
// hide which field is actually missing. The per-field breakdown is the useful
// output; the score exists only to sort documents.

// FieldReport is the result for one checked field.
type FieldReport struct {
	// Field is the stable machine name, e.g. "component.version".
	Field string `json:"field"`
	// Label is the human description shown in terminal output.
	Label string `json:"label"`
	// Present counts components (or 1/0 for document-level fields) carrying it.
	Present int `json:"present"`
	// Total is the denominator for Present.
	Total int `json:"total"`
	// Detail explains a shortfall, or is empty when the field is complete.
	Detail string `json:"detail,omitempty"`
}

// Complete reports whether every subject carried the field.
func (f FieldReport) Complete() bool { return f.Total > 0 && f.Present == f.Total }

// Ratio is the fraction of subjects carrying the field, 0 when nothing applied.
func (f FieldReport) Ratio() float64 {
	if f.Total == 0 {
		return 0
	}
	return float64(f.Present) / float64(f.Total)
}

// QualityReport summarises the completeness of an SBOM.
type QualityReport struct {
	// Document-level fields: author, timestamp, subject, unique identifier.
	Document []FieldReport `json:"document"`
	// Component-level fields, each scored across all components.
	Components []FieldReport `json:"components"`
	// ComponentCount is the number of components scored.
	ComponentCount int `json:"componentCount"`
	// Score is the unweighted mean of every field's ratio, 0–100. It is a
	// sorting key, not a grade.
	Score int `json:"score"`
}

// Incomplete returns the fields that are not fully populated, worst first.
func (r *QualityReport) Incomplete() []FieldReport {
	var out []FieldReport
	for _, f := range append(append([]FieldReport{}, r.Document...), r.Components...) {
		if !f.Complete() {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ratio() < out[j].Ratio() })
	return out
}

// Quality scores a document's field completeness.
func Quality(doc *Document) *QualityReport {
	rep := &QualityReport{}
	if doc == nil || doc.BOM == nil {
		return rep
	}
	bom := doc.BOM
	comps := bom.Components
	rep.ComponentCount = len(comps)

	// ── Document level ──────────────────────────────────────────────────────
	meta := bom.Metadata
	docField := func(field, label string, ok bool, detail string) {
		f := FieldReport{Field: field, Label: label, Total: 1}
		if ok {
			f.Present = 1
		} else {
			f.Detail = detail
		}
		rep.Document = append(rep.Document, f)
	}

	docField("document.identifier", "Unique document identifier",
		bom.SerialNumber != "",
		"no serialNumber — consumers cannot tell two revisions apart")
	docField("document.timestamp", "Creation timestamp",
		meta != nil && meta.Timestamp != "",
		"no metadata.timestamp — the document cannot be aged")
	docField("document.author", "Author or tool",
		meta != nil && (len(meta.Authors) > 0 || (meta.Tools != nil && len(meta.Tools.Components) > 0)),
		"no metadata.authors or metadata.tools — provenance of the SBOM itself is unknown")
	docField("document.subject", "Subject component",
		meta != nil && meta.Component != nil && meta.Component.Name != "",
		"no metadata.component — the document does not say what it describes")
	docField("document.dependencies", "Dependency graph",
		len(bom.Dependencies) > 0,
		"no dependencies array — direct and transitive components are indistinguishable")

	if len(comps) == 0 {
		rep.Score = scoreOf(rep)
		return rep
	}

	// ── Component level ─────────────────────────────────────────────────────
	var (
		named     int
		versioned int
		purled    int
		licensed  int
		hashed    int
		supplied  int
	)
	missingVersion := map[string]bool{}
	missingPurl := map[string]bool{}
	missingLicense := map[string]bool{}

	for i := range comps {
		c := &comps[i]
		if c.Name != "" {
			named++
		}
		if c.Version != "" {
			versioned++
		} else {
			missingVersion[componentLabel(c)] = true
		}
		if c.Purl != "" || c.BOMRef != "" {
			purled++
		} else {
			missingPurl[componentLabel(c)] = true
		}
		if hasLicense(c) {
			licensed++
		} else {
			missingLicense[componentLabel(c)] = true
		}
		if len(c.Hashes) > 0 {
			hashed++
		}
		if c.Publisher != "" || c.Group != "" || hasProperty(c, "vulnetix:spdx/supplier") {
			supplied++
		}
	}

	total := len(comps)
	rep.Components = []FieldReport{
		{Field: "component.name", Label: "Component name", Present: named, Total: total,
			Detail: shortfall(named, total)},
		{Field: "component.version", Label: "Component version", Present: versioned, Total: total,
			Detail: examples(missingVersion)},
		{Field: "component.identifier", Label: "Unique identifier (purl or bom-ref)", Present: purled, Total: total,
			Detail: examples(missingPurl)},
		{Field: "component.license", Label: "Licence", Present: licensed, Total: total,
			Detail: examples(missingLicense)},
		{Field: "component.hash", Label: "Cryptographic hash", Present: hashed, Total: total,
			Detail: shortfall(hashed, total)},
		{Field: "component.supplier", Label: "Supplier", Present: supplied, Total: total,
			Detail: shortfall(supplied, total)},
	}

	rep.Score = scoreOf(rep)
	return rep
}

// scoreOf averages every field ratio into a 0–100 score.
func scoreOf(rep *QualityReport) int {
	fields := append(append([]FieldReport{}, rep.Document...), rep.Components...)
	if len(fields) == 0 {
		return 0
	}
	var sum float64
	for _, f := range fields {
		sum += f.Ratio()
	}
	return int((sum / float64(len(fields)) * 100) + 0.5)
}

// hasLicense reports whether a component carries any licence claim.
func hasLicense(c *cdx.Component) bool {
	for _, lc := range c.Licenses {
		if lc.Expression != "" {
			return true
		}
		if lc.License != nil && (lc.License.ID != "" || lc.License.Name != "") {
			return true
		}
	}
	return false
}

// hasProperty reports whether a component carries a named property.
func hasProperty(c *cdx.Component, name string) bool {
	for _, p := range c.Properties {
		if p.Name == name && p.Value != "" {
			return true
		}
	}
	return false
}

// componentLabel is the most identifying label available for a component.
func componentLabel(c *cdx.Component) string {
	switch {
	case c.Purl != "":
		return c.Purl
	case c.Name != "" && c.Version != "":
		return c.Name + "@" + c.Version
	case c.Name != "":
		return c.Name
	case c.BOMRef != "":
		return c.BOMRef
	default:
		return "(unidentified component)"
	}
}

// shortfall renders how many components lack the field.
//
// Phrased as "missing from N of M" rather than "N components without a
// checksum" so the sentence needs no noun pluralisation — the field's own Label
// column already says which field is meant.
func shortfall(present, total int) string {
	missing := total - present
	if missing <= 0 {
		return ""
	}
	return fmt.Sprintf("missing from %d of %d", missing, total)
}

// examples renders the shortfall plus up to three named offenders.
//
// A bare count tells a user their SBOM is deficient; naming the components
// tells them where to look. Three is enough to recognise a pattern (all the OS
// packages, all the vendored ones) without turning the report into a listing.
func examples(missing map[string]bool) string {
	if len(missing) == 0 {
		return ""
	}
	names := make([]string, 0, len(missing))
	for n := range missing {
		names = append(names, n)
	}
	sort.Strings(names)

	head := names
	suffix := ""
	if len(head) > 3 {
		head = head[:3]
		suffix = ", …"
	}
	return fmt.Sprintf("missing from %d: %s%s", len(names), strings.Join(head, ", "), suffix)
}
