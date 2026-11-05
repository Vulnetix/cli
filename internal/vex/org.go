package vex

import (
	"strings"
	"time"

	"github.com/vulnetix/cli/v4/internal/cdx"
)

// org.go decides which of the organisation's own VEX statements a scan may
// apply.
//
// cli.vex returns every statement the organisation holds for a vulnerability.
// Most are not decisions: they are what an earlier scan derived, and they are
// true of the code that scan saw. A person's decision reaches a scan as a rule
// (console.go); what arrives here without one has to earn the right to close a
// finding this scan has just detected. Closing one on a stale verdict hides a
// live vulnerability, so a statement that cannot be shown to apply leaves the
// finding open and is reported instead.

// Tools that write statements a later scan derives again for itself.
const (
	toolingFinalize = "vulnetix-cli-finalize"
	toolingCLI      = "vulnetix-cli"
)

// PropVEXHeld records, on a finding left open, why a statement did not close it.
const PropVEXHeld = "vulnetix:vex/held"

// OrgStatement is one statement as cli.vex returns it.
type OrgStatement struct {
	VulnID          string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	// SuppressionUUID is set on a statement that also exists as a rule, which
	// the scan already applies through the console.
	SuppressionUUID string
	// Timestamp is when the statement was made, unix seconds or milliseconds.
	Timestamp  int64
	DocumentID string
	// Repository is the repository the statement was made in, when recorded.
	Repository string
	// Tooling is what wrote the statement.
	Tooling string
	// Products are the package URLs the statement is about.
	Products []string
}

// HoldReason says why this scan overrules a statement.
type HoldReason string

const (
	// HoldAbsenceInferred: the statement says an earlier scan no longer saw the
	// finding. This scan sees it, so the premise is false.
	HoldAbsenceInferred HoldReason = "absence-inferred"
	// HoldPriorReachability: the statement is an earlier scan's reachability
	// verdict. Code changes, and this scan judges reachability itself.
	HoldPriorReachability HoldReason = "prior-reachability"
)

// HeldStatement is a statement a scan will not let close a finding.
type HeldStatement struct {
	Statement Statement
	Reason    HoldReason
}

// HeldFinding is a finding left open because a statement about it was held.
type HeldFinding struct {
	VulnID string     `json:"vulnId"`
	Purl   string     `json:"purl,omitempty"`
	Reason HoldReason `json:"reason"`
}

// OrgCheck is what checking the organisation's statements produced.
type OrgCheck struct {
	// Document holds the statements that may close a finding.
	Document *Document
	// Held are the statements this scan overrules.
	Held []HeldStatement
	// OtherRepository, NoRepository and NoProduct count closing statements that
	// cannot be tied to this repository or to a package.
	OtherRepository, NoRepository, NoProduct int
}

// CheckOrgStatements sorts statements into those a scan of repo may apply and
// those it may not. Statements that close nothing are left out: only a closure
// can hide a finding.
func CheckOrgStatements(rows []OrgStatement, repo string) OrgCheck {
	check := OrgCheck{Document: &Document{
		Format: FormatConsole, ID: "vulnetix-org", Author: "Vulnetix organisation", Path: "vulnetix-org",
	}}
	for _, r := range rows {
		status := Status(strings.ToLower(strings.TrimSpace(r.Status)))
		if strings.TrimSpace(r.VulnID) == "" || !status.Valid() || !status.Suppresses() {
			continue
		}
		// Already applied as a rule, with that rule's own scope.
		if r.SuppressionUUID != "" {
			continue
		}
		// With no product a statement matches as document-wide: it would close
		// every package with this vulnerability.
		if len(r.Products) == 0 {
			check.NoProduct++
			continue
		}
		statementRepo := strings.TrimSpace(r.Repository)
		if statementRepo != "" && !strings.EqualFold(statementRepo, repo) {
			check.OtherRepository++
			continue
		}
		st := r.statement(status)
		if reason, held := holdReason(r); held {
			check.Held = append(check.Held, HeldStatement{Statement: st, Reason: reason})
			continue
		}
		if statementRepo == "" {
			check.NoRepository++
			continue
		}
		check.Document.Statements = append(check.Document.Statements, st)
	}
	return check
}

// holdReason reports whether a statement is one a scan derives for itself.
func holdReason(r OrgStatement) (HoldReason, bool) {
	switch strings.ToLower(strings.TrimSpace(r.Tooling)) {
	case toolingFinalize:
		return HoldAbsenceInferred, true
	case toolingCLI:
		if r.Justification == "code_not_reachable" {
			return HoldPriorReachability, true
		}
		return HoldAbsenceInferred, true
	}
	return "", false
}

func (r OrgStatement) statement(status Status) Statement {
	s := Statement{
		VulnID:          strings.TrimSpace(r.VulnID),
		Status:          status,
		Justification:   r.Justification,
		ImpactStatement: r.ImpactStatement,
		ActionStatement: r.ActionStatement,
		Source: StatementSource{
			Path:       ConsolePathPrefix + "OpenVEX/" + r.DocumentID,
			Format:     FormatConsole,
			DocumentID: r.DocumentID,
			Author:     firstNonEmpty(r.Tooling, "Vulnetix organisation"),
		},
	}
	for _, p := range r.Products {
		s.Products = append(s.Products, Product{Purl: p})
	}
	if r.Timestamp > 0 {
		s.Timestamp = statementTime(r.Timestamp)
	}
	return s
}

// statementTime reads a timestamp the server stored in seconds or milliseconds.
func statementTime(ts int64) time.Time {
	if ts > 100_000_000_000 {
		return time.UnixMilli(ts).UTC()
	}
	return time.Unix(ts, 0).UTC()
}

// MarkHeld records on each open finding that a statement about it was held, and
// returns those findings. A finding another statement closed is left alone.
func MarkHeld(bom *cdx.BOM, held []HeldStatement) []HeldFinding {
	if bom == nil || len(held) == 0 {
		return nil
	}
	purlByRef, nameVerByRef := componentIndex(bom)
	var out []HeldFinding
	for _, reason := range []HoldReason{HoldAbsenceInferred, HoldPriorReachability} {
		doc := &Document{}
		for _, h := range held {
			if h.Reason == reason {
				doc.Statements = append(doc.Statements, h.Statement)
			}
		}
		if len(doc.Statements) == 0 {
			continue
		}
		set := NewSet([]*Document{doc})
		for i := range bom.Vulnerabilities {
			v := &bom.Vulnerabilities[i]
			if closedByAnalysis(v) || hasHeldProp(v) {
				continue
			}
			if _, ok := bestMatchForEntry(v, set, purlByRef, nameVerByRef); !ok {
				continue
			}
			setProp(v, PropVEXHeld, string(reason))
			out = append(out, HeldFinding{VulnID: v.ID, Purl: firstAffectedPurl(v, purlByRef), Reason: reason})
		}
	}
	return out
}

func closedByAnalysis(v *cdx.Vulnerability) bool {
	return v.Analysis != nil && (v.Analysis.State == "not_affected" || v.Analysis.State == "resolved")
}

func hasHeldProp(v *cdx.Vulnerability) bool {
	for _, p := range v.Properties {
		if p.Name == PropVEXHeld {
			return true
		}
	}
	return false
}
