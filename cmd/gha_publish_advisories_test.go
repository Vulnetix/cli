package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/github"
	"github.com/vulnetix/cli/v3/internal/sast"
)

func advisoryFixtureLog() *sast.SARIFLog {
	sqli := sast.RuleMetadata{ID: "VNX-SQL", Name: "SQL injection", Description: "Query built from input", Severity: "critical", Kind: "sast", CWE: []int{89}}
	xss := sast.RuleMetadata{ID: "VNX-XSS", Name: "XSS", Severity: "high", Kind: "sast", CWE: []int{79}}
	low := sast.RuleMetadata{ID: "VNX-LOW", Name: "Style", Severity: "low", Kind: "sast"}
	sec := sast.RuleMetadata{ID: "VNX-SECRET", Name: "Key", Severity: "critical", Kind: "secrets"}
	findings := []sast.Finding{
		{RuleID: "VNX-SQL", ArtifactURI: "a.py", StartLine: 3, Severity: "critical", Metadata: &sqli},
		{RuleID: "VNX-SQL", ArtifactURI: "b.py", StartLine: 9, Severity: "critical", Metadata: &sqli},
		{RuleID: "VNX-XSS", ArtifactURI: "c.js", StartLine: 1, Severity: "high", Metadata: &xss},
		{RuleID: "VNX-XSS", ArtifactURI: "test/c_test.js", StartLine: 1, Severity: "high", Metadata: &xss, IsTestSuite: true},
		{RuleID: "VNX-LOW", ArtifactURI: "d.py", StartLine: 1, Severity: "low", Metadata: &low},
		{RuleID: "VNX-SECRET", ArtifactURI: "e.env", StartLine: 1, Severity: "critical", Metadata: &sec},
	}
	return sast.BuildSARIF(findings, []sast.RuleMetadata{sqli, xss, low, sec}, "t")
}

func TestAdvisoryGroups(t *testing.T) {
	groups := advisoryGroups([]*sast.SARIFLog{advisoryFixtureLog()}, "high", 10)
	if len(groups) != 2 {
		t.Fatalf("groups %+v", groups)
	}
	if groups[0].RuleID != "VNX-SQL" || len(groups[0].Locations) != 2 || strings.Join(groups[0].CWEs, ",") != "CWE-89" {
		t.Fatalf("first group %+v", groups[0])
	}
	if groups[1].RuleID != "VNX-XSS" || len(groups[1].Locations) != 1 {
		t.Fatalf("a test-suite finding was counted: %+v", groups[1])
	}
	if capped := advisoryGroups([]*sast.SARIFLog{advisoryFixtureLog()}, "high", 1); len(capped) != 1 || capped[0].RuleID != "VNX-SQL" {
		t.Fatalf("cap keeps the worst: %+v", capped)
	}
}

func TestAdvisoriesPublishDedupesAndNeverPublishes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"my-app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	groups := advisoryGroups([]*sast.SARIFLog{advisoryFixtureLog()}, "high", 10)
	var created []github.AdvisoryRequest
	patched := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			// The SQL group already has a draft; the XSS group was published.
			_ = json.NewEncoder(w).Encode([]github.RepositoryAdvisory{
				{GHSAID: "GHSA-sql", State: "draft", Description: "x\n" + github.AdvisoryMarker(groups[0].hash())},
				{GHSAID: "GHSA-xss", State: "published", Description: github.AdvisoryMarker(groups[1].hash())},
			})
		case r.Method == http.MethodPatch:
			raw, _ := io.ReadAll(r.Body)
			if strings.Contains(string(raw), `"state"`) {
				t.Error("an update must never send a state")
			}
			patched = r.URL.Path
			_, _ = io.WriteString(w, `{"ghsa_id":"GHSA-sql","state":"draft"}`)
		case r.Method == http.MethodPost:
			var req github.AdvisoryRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			created = append(created, req)
			_, _ = io.WriteString(w, `{"ghsa_id":"GHSA-new","state":"draft"}`)
		}
	}))
	defer srv.Close()
	client := github.NewClient("tok")
	client.BaseURL = srv.URL
	var out strings.Builder
	err := runAdvisoriesPublish(context.Background(), advisoriesOptions{
		Root: root, Repo: "o/r", Logs: []*sast.SARIFLog{advisoryFixtureLog()}, MinSeverity: "high", Max: 10, Client: client,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if patched != "/repos/o/r/security-advisories/GHSA-sql" {
		t.Fatalf("patched %q", patched)
	}
	if len(created) != 0 {
		t.Fatalf("created duplicates: %+v", created)
	}
	if !strings.Contains(out.String(), "GHSA-xss is published; left alone") {
		t.Fatalf("output %q", out.String())
	}
}

func TestAdvisoryRequestShape(t *testing.T) {
	g := advisoryGroups([]*sast.SARIFLog{advisoryFixtureLog()}, "high", 10)[0]
	req := advisoryRequest(g, github.AdvisoryPackage{Ecosystem: "npm", Name: "my-app"})
	raw, _ := json.Marshal(req)
	if strings.Contains(string(raw), "cvss") {
		t.Fatalf("a CVSS vector must never be sent with a severity: %s", raw)
	}
	if req.Severity != "critical" || req.Vulnerabilities[0].Package.Ecosystem != "npm" || github.MarkerOf(req.Description) != g.hash() {
		t.Fatalf("%+v", req)
	}
	if got := repoPackage(t.TempDir(), "o/r"); got.Ecosystem != "other" || got.Name != "o/r" {
		t.Fatalf("fallback package %+v", got)
	}
}
