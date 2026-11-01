package triage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/vex"
)

type openVEXDoc struct {
	Author     string           `json:"author"`
	Statements []map[string]any `json:"statements"`
}

func renderOpenVEX(t *testing.T, findings []*TriageFinding, opts OpenVEXOptions) ([]byte, openVEXDoc) {
	t.Helper()
	body, err := GenerateOpenVEX(findings, opts)
	if err != nil {
		t.Fatalf("GenerateOpenVEX: %v", err)
	}
	var doc openVEXDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return body, doc
}

func sampleFindings() []*TriageFinding {
	return []*TriageFinding{
		{
			CVEID: "CVE-2024-0001", Package: "left-pad", Ecosystem: "npm", InstalledVer: "1.0.0",
			Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			ActionResponse: "The parser is only called on trusted config.", Severity: "high",
			Decision: &memory.Decision{Choice: "not-affected", Date: "2026-03-04T05:06:07Z"},
		},
		{
			CVEID: "CVE-2024-0002", Package: "requests", Ecosystem: "pypi", InstalledVer: "2.31.0",
			FixedVer: "2.32.0", Status: "affected", Severity: "critical",
		},
		{
			CVEID: "CVE-2024-0003", Package: "github.com/x/y", Ecosystem: "go", InstalledVer: "v1.2.3",
			FixedVer: "v1.2.4", Status: "fixed", ActionResponse: "bumped in #12",
		},
		{
			CVEID: "CVE-2024-0004", Package: "moment", Ecosystem: "npm", InstalledVer: "2.29.4",
			Status: "affected", Justification: "remediation_window_exceeded", ActionResponse: "will_fix",
		},
	}
}

func TestGenerateOpenVEXIsSpecShaped(t *testing.T) {
	_, doc := renderOpenVEX(t, sampleFindings(), OpenVEXOptions{ID: "urn:test:1"})
	if len(doc.Statements) != 4 {
		t.Fatalf("statements = %d, want 4", len(doc.Statements))
	}
	for _, s := range doc.Statements {
		for _, banned := range []string{"action", "fixed_version", "supplier"} {
			if _, ok := s[banned]; ok {
				t.Errorf("%v carries non-standard %q", s["vulnerability"], banned)
			}
		}
		if is, ok := s["impact_statement"].(string); ok && strings.HasPrefix(is, "Severity:") {
			t.Errorf("impact_statement is a severity label: %q", is)
		}
		if j, ok := s["justification"].(string); ok && (s["status"] != "not_affected" || !vex.Justifications[j]) {
			t.Errorf("justification %q on status %v; only OpenVEX justifications on not_affected", j, s["status"])
		}
		products, _ := s["products"].([]any)
		if len(products) != 1 {
			t.Fatalf("%v: products = %v", s["vulnerability"], s["products"])
		}
		p := products[0].(map[string]any)
		if len(p) != 1 {
			t.Errorf("product carries members beyond @id: %v", p)
		}
	}

	byID := map[string]map[string]any{}
	for _, s := range doc.Statements {
		byID[s["vulnerability"].(map[string]any)["name"].(string)] = s
	}

	na := byID["CVE-2024-0001"]
	if na["impact_statement"] != "The parser is only called on trusted config." {
		t.Errorf("impact_statement = %v, want the recorded reason", na["impact_statement"])
	}
	if na["timestamp"] != "2026-03-04T05:06:07Z" {
		t.Errorf("timestamp = %v, want the decision time", na["timestamp"])
	}
	if got := na["products"].([]any)[0].(map[string]any)["@id"]; got != "pkg:npm/left-pad@1.0.0" {
		t.Errorf("product @id = %v, want a versioned purl", got)
	}

	aff := byID["CVE-2024-0002"]
	if aff["status"] != "affected" {
		t.Errorf("status = %v", aff["status"])
	}
	if as, _ := aff["action_statement"].(string); !strings.Contains(as, "2.32.0") {
		t.Errorf("action_statement = %q, want the fix version", as)
	}

	fixed := byID["CVE-2024-0003"]
	if fixed["status"] != "fixed" {
		t.Errorf("fixed was rewritten to %v", fixed["status"])
	}
	if got, _ := fixed["products"].([]any)[0].(map[string]any)["@id"].(string); !strings.HasPrefix(got, "pkg:golang/") || !strings.HasSuffix(got, "@v1.2.3") {
		t.Errorf("go product @id = %q, want a versioned golang purl", got)
	}

	jail := byID["CVE-2024-0004"]
	if jail["action_statement"] != "will_fix" {
		t.Errorf("action_statement = %v", jail["action_statement"])
	}
	if n, _ := jail["status_notes"].(string); !strings.Contains(n, "remediation_window_exceeded") {
		t.Errorf("non-standard justification lost; status_notes = %q", n)
	}
}

// An affected statement carrying a fix version and no justification stays
// affected. The old writer turned it into not_affected, the inverse of what a
// jail verdict means.
func TestGenerateOpenVEXNeverInvertsAffected(t *testing.T) {
	_, doc := renderOpenVEX(t, []*TriageFinding{{
		CVEID: "CVE-2024-0001", Package: "left-pad", Ecosystem: "npm",
		InstalledVer: "1.0.0", FixedVer: "1.3.0", Status: "affected",
	}}, OpenVEXOptions{})
	if s := doc.Statements[0]; s["status"] != "affected" || s["justification"] != nil {
		t.Fatalf("statement = %v, want affected with no justification", s)
	}
}

func TestGenerateOpenVEXAuthor(t *testing.T) {
	_, doc := renderOpenVEX(t, sampleFindings()[:1], OpenVEXOptions{})
	if doc.Author != DefaultOpenVEXAuthor {
		t.Errorf("author = %q, want %q", doc.Author, DefaultOpenVEXAuthor)
	}
	_, doc = renderOpenVEX(t, sampleFindings()[:1], OpenVEXOptions{Author: "ada@example.com"})
	if doc.Author != "ada@example.com" {
		t.Errorf("author = %q", doc.Author)
	}
}

func TestGenerateOpenVEXTimestampFallbacks(t *testing.T) {
	decided := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	_, doc := renderOpenVEX(t, []*TriageFinding{
		{CVEID: "CVE-1", Status: "affected", ActionResponse: "a", DecidedAt: decided},
		{CVEID: "CVE-2", Status: "affected", ActionResponse: "a"},
	}, OpenVEXOptions{})
	if doc.Statements[0]["timestamp"] != "2025-01-02T03:04:05Z" {
		t.Errorf("timestamp = %v, want DecidedAt", doc.Statements[0]["timestamp"])
	}
	ts, _ := doc.Statements[1]["timestamp"].(string)
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("fallback timestamp %q is not RFC3339", ts)
	}
}

// The CLI's own `vex validate` must accept what the CLI writes: no fatal
// problem, and no affected statement without an action statement.
func TestGenerateOpenVEXPassesVexValidate(t *testing.T) {
	body, _ := renderOpenVEX(t, sampleFindings(), OpenVEXOptions{ID: "urn:test:validate"})
	doc, err := vex.LoadBytes(body, "generated.openvex.json")
	if err != nil {
		t.Fatalf("vex.LoadBytes: %v", err)
	}
	if doc.Format != vex.FormatOpenVEX {
		t.Fatalf("format = %q", doc.Format)
	}
	problems := doc.Validate()
	if vex.Fatal(problems) {
		t.Fatalf("fatal problems: %+v", problems)
	}
	for _, p := range problems {
		if strings.Contains(p.Message, "action statement") {
			t.Errorf("affected statement without an action statement: %s", p.Message)
		}
	}
	for _, s := range doc.Statements {
		if len(s.Products) != 1 || s.Products[0].Purl == "" {
			t.Errorf("%s: product purl not read back: %+v", s.VulnID, s.Products)
		}
	}
}
