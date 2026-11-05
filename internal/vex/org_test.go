package vex

import (
	"testing"

	"github.com/vulnetix/cli/v4/internal/cdx"
)

const orgPurl = "pkg:npm/lodash@4.17.20"

func TestCheckOrgStatements(t *testing.T) {
	base := OrgStatement{VulnID: "CVE-1", Status: "not_affected", Justification: "inline_mitigations_already_exist",
		Repository: "acme/app", Tooling: "Example VEX", Products: []string{orgPurl}}
	with := func(f func(*OrgStatement)) OrgStatement { r := base; f(&r); return r }
	cases := []struct {
		name string
		row  OrgStatement
		// applied, held and the three skip counters.
		applied, held, other, noRepo, noProduct int
		reason                                  HoldReason
	}{
		{name: "a statement about this repository applies", row: base, applied: 1},
		{name: "the repository match ignores case", row: with(func(r *OrgStatement) { r.Repository = "ACME/App" }), applied: 1},
		{name: "fixed closes too", row: with(func(r *OrgStatement) { r.Status = "fixed" }), applied: 1},
		{name: "another repository's says nothing here", row: with(func(r *OrgStatement) { r.Repository = "acme/other" }), other: 1},
		{name: "no repository cannot be tied to this one", row: with(func(r *OrgStatement) { r.Repository = "" }), noRepo: 1},
		{name: "no product would close every package", row: with(func(r *OrgStatement) { r.Products = nil }), noProduct: 1},
		{name: "a rule-backed statement is applied as the rule", row: with(func(r *OrgStatement) { r.SuppressionUUID = "s" })},
		{name: "affected closes nothing", row: with(func(r *OrgStatement) { r.Status = "affected" })},
		{name: "in_triage is not a status this reads", row: with(func(r *OrgStatement) { r.Status = "in_triage" })},
		{name: "absence inferred by the server is held", row: with(func(r *OrgStatement) { r.Tooling = "vulnetix-cli-finalize" }), held: 1, reason: HoldAbsenceInferred},
		{name: "absence inferred with no repository is still held", row: with(func(r *OrgStatement) { r.Tooling = "vulnetix-cli-finalize"; r.Repository = "" }), held: 1, reason: HoldAbsenceInferred},
		{name: "absence inferred by the cli is held", row: with(func(r *OrgStatement) { r.Tooling = "vulnetix-cli"; r.Status = "fixed" }), held: 1, reason: HoldAbsenceInferred},
		{name: "a prior reachability verdict is held", row: with(func(r *OrgStatement) { r.Tooling = "vulnetix-cli"; r.Justification = "code_not_reachable" }), held: 1, reason: HoldPriorReachability},
		{name: "another repository's derived statement is not this scan's to overrule", row: with(func(r *OrgStatement) { r.Tooling = "vulnetix-cli-finalize"; r.Repository = "acme/other" }), other: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := CheckOrgStatements([]OrgStatement{tc.row}, "acme/app")
			if got := len(c.Document.Statements); got != tc.applied {
				t.Errorf("applied = %d, want %d", got, tc.applied)
			}
			if len(c.Held) != tc.held {
				t.Fatalf("held = %d, want %d", len(c.Held), tc.held)
			}
			if tc.held == 1 && c.Held[0].Reason != tc.reason {
				t.Errorf("reason = %s, want %s", c.Held[0].Reason, tc.reason)
			}
			if c.OtherRepository != tc.other || c.NoRepository != tc.noRepo || c.NoProduct != tc.noProduct {
				t.Errorf("skips other=%d noRepo=%d noProduct=%d", c.OtherRepository, c.NoRepository, c.NoProduct)
			}
		})
	}
}

// A statement this run overrules leaves the finding open and says so, on the
// matching package only, and never touches a finding something else closed.
func TestMarkHeld(t *testing.T) {
	bom := &cdx.BOM{
		Components: []cdx.Component{
			{BOMRef: "a", Name: "lodash", Version: "4.17.20", Purl: orgPurl},
			{BOMRef: "b", Name: "express", Version: "4.18.2", Purl: "pkg:npm/express@4.18.2"},
		},
		Vulnerabilities: []cdx.Vulnerability{
			{ID: "CVE-1", Affects: []cdx.Affect{{Ref: "a"}}},
			{ID: "CVE-1", Affects: []cdx.Affect{{Ref: "b"}}},
			{ID: "CVE-2", Affects: []cdx.Affect{{Ref: "a"}}, Analysis: &cdx.Analysis{State: "not_affected"}},
		},
	}
	held := []HeldStatement{
		{Reason: HoldAbsenceInferred, Statement: Statement{VulnID: "CVE-1", Status: StatusNotAffected, Products: []Product{{Purl: orgPurl}}}},
		{Reason: HoldPriorReachability, Statement: Statement{VulnID: "CVE-1", Status: StatusNotAffected, Products: []Product{{Purl: orgPurl}}}},
		{Reason: HoldAbsenceInferred, Statement: Statement{VulnID: "CVE-2", Status: StatusNotAffected, Products: []Product{{Purl: orgPurl}}}},
	}
	got := MarkHeld(bom, held)
	if len(got) != 1 || got[0].VulnID != "CVE-1" || got[0].Purl != orgPurl || got[0].Reason != HoldAbsenceInferred {
		t.Fatalf("held findings = %+v", got)
	}
	if !hasHeldProp(&bom.Vulnerabilities[0]) || hasHeldProp(&bom.Vulnerabilities[1]) || hasHeldProp(&bom.Vulnerabilities[2]) {
		t.Error("the held property is on the wrong entries")
	}
	if bom.Vulnerabilities[0].Analysis != nil {
		t.Error("a held statement must not write an analysis: the finding is open")
	}
}

func TestStatementTimeReadsBothUnits(t *testing.T) {
	if s, ms := statementTime(1793843038), statementTime(1793843038132); s.Unix() != ms.Unix() {
		t.Errorf("seconds %v, milliseconds %v", s, ms)
	}
}
