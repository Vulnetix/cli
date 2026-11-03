package vex

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/cdx"
)

func consoleRule(vuln, purl, status string) ConsoleRule {
	return ConsoleRule{VulnerabilityID: vuln, ProductPurl: purl, Status: status, Justification: "vulnerable_code_not_present",
		Reason: "the vendor says so", Source: "vendor-tea", SourceType: "tea", SourceRef: "stmt-1", DocumentID: "doc-1", Timestamp: 1700000000}
}

func localDoc(statements ...Statement) *Document {
	return &Document{Format: FormatOpenVEX, Path: "local.openvex.json", Statements: statements}
}

func TestConsoleDocument(t *testing.T) {
	doc, skipped := ConsoleDocument([]ConsoleRule{
		consoleRule("CVE-2020-8203", "pkg:npm/lodash@4.17.20", "not_affected"),
		{VulnerabilityID: "CVE-2022-1", ProductPurlBase: "pkg:npm/a", Status: "affected", Reason: "will not fix", Source: "team-git"},
		{VulnerabilityID: "CVE-2022-2", Status: ""},              // no status: not a verdict this package reads
		{VulnerabilityID: "", Status: "not_affected"},            // names nothing
		{VulnerabilityID: "CVE-2022-3", Status: "made_up_state"}, // unknown status
	})
	if skipped != 3 || len(doc.Statements) != 2 {
		t.Fatalf("skipped %d, statements %d, want 3 and 2", skipped, len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Status != StatusNotAffected || s.Justification != "vulnerable_code_not_present" || s.ImpactStatement != "the vendor says so" ||
		len(s.Products) != 1 || s.Products[0].Purl != "pkg:npm/lodash@4.17.20" ||
		s.Source.Path != ConsolePathPrefix+"VexSource/vendor-tea" || s.Source.Format != FormatConsole ||
		s.Source.DocumentID != "doc-1" || !s.Timestamp.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("statement = %+v", s)
	}
	// The version-less product is kept as the console recorded it, and a
	// decision not to fix is an action statement, not an impact statement.
	a := doc.Statements[1]
	if a.Products[0].Purl != "pkg:npm/a" || a.ActionStatement != "will not fix" || a.ImpactStatement != "" {
		t.Errorf("affected statement = %+v", a)
	}
}

// A console statement is applied with the matching, annotation and counts of a
// document, and says where it came from.
func TestConsoleStatementsApplyLikeADocument(t *testing.T) {
	bom := testBOM()
	console, _ := ConsoleDocument([]ConsoleRule{
		consoleRule("CVE-2020-8203", "pkg:npm/lodash@4.17.20", "not_affected"),
		{VulnerabilityID: "CVE-2024-9999", ProductPurl: "pkg:npm/express@4.18.2", Status: "affected", Reason: "accepted", Source: "team-git"},
		consoleRule("CVE-2030-0000", "pkg:npm/unrelated@1.0.0", "not_affected"), // matches no finding
	})
	res := Apply(bom, NewSet([]*Document{console}))

	if res.Suppressed != 1 || res.Annotated != 1 || res.Effective != 3 {
		t.Fatalf("suppressed %d annotated %d effective %d, want 1, 1 and 3", res.Suppressed, res.Annotated, res.Effective)
	}
	// Most console statements match nothing in one repository's scan, which
	// says nothing about the document being about another product.
	if res.Unmatched != 0 {
		t.Errorf("Unmatched = %d, want 0 for console statements", res.Unmatched)
	}
	var lodash *cdx.Vulnerability
	for i := range bom.Vulnerabilities {
		if bom.Vulnerabilities[i].ID == "CVE-2020-8203" {
			lodash = &bom.Vulnerabilities[i]
		}
	}
	if lodash == nil || lodash.Analysis == nil || lodash.Analysis.State != "not_affected" || lodash.Analysis.Justification != "vulnerable_code_not_present" {
		t.Fatalf("lodash analysis = %+v", lodash)
	}
	var source string
	for _, p := range lodash.Properties {
		if p.Name == PropVEXSource {
			source = p.Value
		}
	}
	if !strings.Contains(source, "VexSource/vendor-tea") {
		t.Errorf("provenance source = %q", source)
	}
}

func TestDedupeConsole(t *testing.T) {
	notAffected := func(vuln, purl string) Statement {
		s := Statement{VulnID: vuln, Status: StatusNotAffected}
		if purl != "" {
			s.Products = []Product{{Purl: purl}}
		}
		return s
	}
	for name, tc := range map[string]struct {
		local   []Statement
		console ConsoleRule
		dropped int
	}{
		"the same statement":                                   {[]Statement{notAffected("CVE-1", "pkg:npm/a@1.0.0")}, consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"), 1},
		"case does not matter":                                 {[]Statement{notAffected("cve-1", "PKG:npm/a@1.0.0")}, consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"), 1},
		"a local any-version covers it":                        {[]Statement{notAffected("CVE-1", "pkg:npm/a")}, consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"), 1},
		"a local narrow one does not cover an any-version one": {[]Statement{notAffected("CVE-1", "pkg:npm/a@1.0.0")}, consoleRule("CVE-1", "pkg:npm/a", "not_affected"), 0},
		"another version":                                      {[]Statement{notAffected("CVE-1", "pkg:npm/a@1.0.0")}, consoleRule("CVE-1", "pkg:npm/a@2.0.0", "not_affected"), 0},
		"another status":                                       {[]Statement{{VulnID: "CVE-1", Status: StatusFixed, Products: []Product{{Purl: "pkg:npm/a@1.0.0"}}}}, consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"), 0},
		"another vulnerability":                                {[]Statement{notAffected("CVE-2", "pkg:npm/a@1.0.0")}, consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"), 0},
		"a local statement about an alias": {[]Statement{{VulnID: "GHSA-x", Aliases: []string{"CVE-1"}, Status: StatusNotAffected, Products: []Product{{Purl: "pkg:npm/a@1.0.0"}}}},
			consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"), 1},
		"no product on either side":                    {[]Statement{notAffected("CVE-1", "")}, consoleRule("CVE-1", "", "not_affected"), 1},
		"local document-wide does not cover a product": {[]Statement{notAffected("CVE-1", "")}, consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"), 0},
	} {
		console, _ := ConsoleDocument([]ConsoleRule{tc.console})
		kept, dropped := DedupeConsole(console, []*Document{localDoc(tc.local...)})
		if dropped != tc.dropped || len(kept.Statements) != 1-tc.dropped {
			t.Errorf("%s: dropped %d kept %d, want %d dropped", name, dropped, len(kept.Statements), tc.dropped)
		}
	}

	// The console saying the same thing twice (two sources, or a source and an
	// ingested document) counts once.
	console, _ := ConsoleDocument([]ConsoleRule{
		consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"),
		consoleRule("CVE-1", "pkg:npm/a@1.0.0", "not_affected"),
		consoleRule("CVE-1", "pkg:npm/b@1.0.0", "not_affected"),
	})
	kept, dropped := DedupeConsole(console, nil)
	if dropped != 1 || len(kept.Statements) != 2 {
		t.Errorf("self-duplicates: dropped %d kept %d", dropped, len(kept.Statements))
	}
	if k, d := DedupeConsole(nil, nil); k != nil || d != 0 {
		t.Errorf("nil console = %v, %d", k, d)
	}
}
