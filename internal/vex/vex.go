// Package vex is the read side of VEX: consuming statements this CLI did not
// write.
//
// internal/triage generates OpenVEX and CycloneDX VEX from the CLI's own triage
// decisions. Nothing could read a VEX document back in — so a statement an
// upstream vendor published about their own product, saying a CVE does not
// affect the configuration you actually ship, had no way to reach a scan. That
// is the case VEX exists for, and it was the one case the CLI could not serve.
//
// One statement model. OpenVEX, CycloneDX VEX and CSAF VEX all express the same
// assertion — this vulnerability, against this product, has this status, for
// this reason — in three different shapes. Normalising them here means matching
// and application are written once instead of three times.
package vex

import (
	"fmt"
	"strings"
	"time"
)

// Status is a VEX status label.
//
// The four OpenVEX statuses are the common denominator: CycloneDX's analysis
// states and CSAF's product-status categories both map onto them without loss
// for the purpose that matters here, which is deciding whether a finding is
// still live.
type Status string

const (
	// StatusNotAffected — the product is not affected. Requires a justification.
	StatusNotAffected Status = "not_affected"
	// StatusAffected — the product is affected and no remediation is applied.
	StatusAffected Status = "affected"
	// StatusFixed — the vulnerability has been remediated.
	StatusFixed Status = "fixed"
	// StatusUnderInvestigation — the status is not yet known.
	StatusUnderInvestigation Status = "under_investigation"
)

// Suppresses reports whether a status means the finding is no longer live.
//
// not_affected and fixed are assertions that the finding does not apply;
// affected and under_investigation are not. A suppressed finding is still
// reported and badged — see the total/effective/suppressed split — never
// silently dropped.
func (s Status) Suppresses() bool {
	return s == StatusNotAffected || s == StatusFixed
}

// Valid reports whether the status is one this CLI understands.
func (s Status) Valid() bool {
	switch s {
	case StatusNotAffected, StatusAffected, StatusFixed, StatusUnderInvestigation:
		return true
	}
	return false
}

// Justifications are the OpenVEX impact-analysis justifications.
//
// A not_affected statement without one is invalid per the OpenVEX spec: the
// whole point of the status is the argument behind it, and an unjustified
// "this does not affect us" is an assertion nobody can audit.
var Justifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

// Product identifies what a statement is about.
type Product struct {
	// Purl is the product's package URL, when it has one. This is the field
	// matching actually uses; ID is a fallback for documents that identify
	// products some other way.
	Purl string `json:"purl,omitempty"`
	// ID is the raw product identifier as written in the document.
	ID string `json:"id,omitempty"`
	// Versions are explicit versions the statement is scoped to. Empty means
	// the statement applies to every version of the product.
	Versions []string `json:"versions,omitempty"`
	// Subcomponents are purls the statement narrows to within the product.
	Subcomponents []string `json:"subcomponents,omitempty"`
}

// Statement is one normalised VEX assertion.
type Statement struct {
	// VulnID is the vulnerability identifier, normalised to a bare id.
	VulnID string `json:"vulnId"`
	// Aliases are other identifiers for the same vulnerability.
	Aliases []string `json:"aliases,omitempty"`
	// Status is the assertion.
	Status Status `json:"status"`
	// Justification explains a not_affected status.
	Justification string `json:"justification,omitempty"`
	// ImpactStatement is free text supporting a not_affected status.
	ImpactStatement string `json:"impactStatement,omitempty"`
	// ActionStatement is what the consumer should do about an affected status.
	ActionStatement string `json:"actionStatement,omitempty"`
	// Products are the things this statement is about. Empty means the
	// statement applies to the document's whole subject.
	Products []Product `json:"products,omitempty"`
	// Timestamp is when the assertion was made. Used to pick a winner when two
	// statements cover the same (vulnerability, product).
	Timestamp time.Time `json:"timestamp,omitempty"`
	// Source describes where the statement came from, for attribution in
	// output — a suppressed finding must always be traceable to the document
	// that suppressed it.
	Source StatementSource `json:"source"`
}

// StatementSource attributes a statement to its document.
type StatementSource struct {
	// Path is the file the statement was read from.
	Path string `json:"path,omitempty"`
	// Format is the serialisation it was written in.
	Format Format `json:"format"`
	// DocumentID is the document's own identifier.
	DocumentID string `json:"documentId,omitempty"`
	// Author is who published it.
	Author string `json:"author,omitempty"`
}

// Format identifies a VEX serialisation.
type Format string

const (
	FormatOpenVEX   Format = "openvex"
	FormatCycloneDX Format = "cyclonedx-vex"
	FormatCSAF      Format = "csaf-vex"
	FormatUnknown   Format = "unknown"
)

// Document is a parsed VEX document.
type Document struct {
	Format     Format      `json:"format"`
	ID         string      `json:"id,omitempty"`
	Author     string      `json:"author,omitempty"`
	Path       string      `json:"path,omitempty"`
	Statements []Statement `json:"statements"`
}

// Problem is a validation finding against a document.
type Problem struct {
	// StatementIndex is the position of the offending statement, or -1 for a
	// document-level problem.
	StatementIndex int `json:"statementIndex"`
	// Message describes what is wrong.
	Message string `json:"message"`
	// Fatal marks a problem that makes the statement unusable, as opposed to
	// one that only makes it weaker.
	Fatal bool `json:"fatal"`
}

// Validate checks a document for structural and semantic problems.
//
// Structural validity is not enough for VEX: a document can be schema-valid
// and still assert nothing usable — a not_affected with no justification, a
// statement naming no vulnerability, a status outside the vocabulary. Those
// are what a consumer actually trips over, so they are what this reports.
func (d *Document) Validate() []Problem {
	var problems []Problem
	if len(d.Statements) == 0 {
		problems = append(problems, Problem{
			StatementIndex: -1,
			Message:        "document contains no statements",
			Fatal:          true,
		})
	}
	for i, s := range d.Statements {
		switch {
		case s.VulnID == "":
			problems = append(problems, Problem{i, "statement names no vulnerability", true})
		case !s.Status.Valid():
			problems = append(problems, Problem{i,
				fmt.Sprintf("%s: unknown status %q (expected not_affected, affected, fixed or under_investigation)",
					s.VulnID, s.Status), true})
		}
		if s.Status == StatusNotAffected {
			switch {
			case s.Justification == "" && s.ImpactStatement == "":
				problems = append(problems, Problem{i,
					fmt.Sprintf("%s: not_affected requires a justification or an impact statement", s.VulnID), true})
			case s.Justification != "" && !Justifications[s.Justification]:
				problems = append(problems, Problem{i,
					fmt.Sprintf("%s: %q is not an OpenVEX justification", s.VulnID, s.Justification), false})
			}
		}
		if s.Status == StatusAffected && s.ActionStatement == "" {
			problems = append(problems, Problem{i,
				fmt.Sprintf("%s: affected without an action statement tells a consumer nothing to do", s.VulnID), false})
		}
		if len(s.Products) == 0 {
			problems = append(problems, Problem{i,
				fmt.Sprintf("%s: statement names no product, so it applies to everything the document describes", s.VulnID), false})
		}
	}
	return problems
}

// Fatal reports whether any problem makes a statement unusable.
func Fatal(problems []Problem) bool {
	for _, p := range problems {
		if p.Fatal {
			return true
		}
	}
	return false
}

// normalizeVulnID reduces a vulnerability identifier to its bare form.
//
// Real documents carry the identifier as a URL as often as a bare id —
// https://pkg.go.dev/vuln/GO-2023-1234, https://nvd.nist.gov/.../CVE-2021-1234,
// https://github.com/advisories/GHSA-xxxx. Matching those against a scan's
// bare "GO-2023-1234" fails on every one, and the failure is silent: the
// statement is simply never applied.
func normalizeVulnID(raw string) string {
	id := strings.TrimSpace(raw)
	if id == "" {
		return ""
	}
	if i := strings.IndexAny(id, "?#"); i >= 0 {
		id = id[:i]
	}
	if idx := strings.LastIndex(id, "/"); idx >= 0 && idx < len(id)-1 {
		id = id[idx+1:]
	}
	return strings.TrimSpace(id)
}
