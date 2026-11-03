package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const sampleBOM = `{
  "bomFormat": "CycloneDX",
  "metadata": {"component": {"bom-ref": "root"}},
  "components": [
    {"bom-ref": "express", "purl": "pkg:npm/express@4.17.1", "properties": [
      {"name": "vulnetix:source-file", "value": "web/package.json"},
      {"name": "vulnetix:scope", "value": "production"}]},
    {"bom-ref": "qs", "purl": "pkg:npm/qs@6.7.0", "properties": [
      {"name": "vulnetix:source-file", "value": "web/package.json"},
      {"name": "vulnetix:scope", "value": "production"}]},
    {"bom-ref": "jest", "purl": "pkg:npm/jest@29.0.0", "properties": [
      {"name": "vulnetix:source-file", "value": "web/package.json"},
      {"name": "vulnetix:scope", "value": "development"}]},
    {"bom-ref": "requests", "purl": "pkg:pypi/requests@2.31.0", "properties": [
      {"name": "vulnetix:source-file", "value": "requirements.txt"}]},
    {"bom-ref": "nopurl"}
  ],
  "dependencies": [
    {"ref": "root", "dependsOn": ["express", "jest", "requests"]},
    {"ref": "express", "dependsOn": ["qs"]}
  ]
}`

func TestBuildSnapshot(t *testing.T) {
	s, err := BuildSnapshot([]byte(sampleBOM), SnapshotOptions{
		Target:     Target{Repo: "o/r", SHA: "abc", Ref: "refs/heads/main"},
		Correlator: "vulnetix/ci/sca", JobID: "42", DetectorVersion: "v3",
		Now: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.ManifestCount() != 2 || s.PackageCount() != 4 {
		t.Fatalf("manifests %d packages %d", s.ManifestCount(), s.PackageCount())
	}
	web := s.Manifests["web/package.json"]
	if web.File.SourceLocation != "web/package.json" {
		t.Fatalf("source location %+v", web.File)
	}
	ex := web.Resolved["pkg:npm/express@4.17.1"]
	if ex.Relationship != "direct" || ex.Scope != "runtime" || len(ex.Dependencies) != 1 || ex.Dependencies[0] != "pkg:npm/qs@6.7.0" {
		t.Fatalf("express %+v", ex)
	}
	if qs := web.Resolved["pkg:npm/qs@6.7.0"]; qs.Relationship != "indirect" {
		t.Fatalf("qs %+v", qs)
	}
	if jest := web.Resolved["pkg:npm/jest@29.0.0"]; jest.Scope != "development" {
		t.Fatalf("jest %+v", jest)
	}
	if s.Job.Correlator != "vulnetix/ci/sca" || s.Scanned != "2026-11-02T00:00:00Z" || s.SHA != "abc" {
		t.Fatalf("job %+v scanned %s", s.Job, s.Scanned)
	}
}

func TestSubmitSnapshot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repos/o/r/dependency-graph/snapshots" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		var s Snapshot
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil || len(s.Manifests) == 0 {
			t.Errorf("body %v %+v", err, s)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7,"result":"SUCCESS","message":"ok"}`))
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	s, _ := BuildSnapshot([]byte(sampleBOM), SnapshotOptions{Target: Target{Repo: "o/r", SHA: "a", Ref: "refs/heads/main"}})
	res, err := c.SubmitSnapshot(context.Background(), "o/r", s)
	if err != nil || res.ID != 7 || res.Result != "SUCCESS" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGitHubPurlRewritesActions(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:github-actions/actions%2Fdownload-artifact@v8": "pkg:githubactions/actions/download-artifact@v8",
		"pkg:github-actions/actions/checkout@v7":            "pkg:githubactions/actions/checkout@v7",
		"pkg:npm/express@4.17.1":                            "pkg:npm/express@4.17.1",
	} {
		if got := GitHubPurl(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

const actionsBOM = `{
  "bomFormat": "CycloneDX",
  "metadata": {"component": {"bom-ref": "root"}},
  "components": [
    {"bom-ref": "dl", "purl": "pkg:github-actions/actions%2Fdownload-artifact@v8",
     "properties": [{"name": "vulnetix:source-file", "value": ".github/workflows/release.yml"}]},
    {"bom-ref": "express", "purl": "pkg:npm/express@4.17.1",
     "properties": [{"name": "vulnetix:source-file", "value": "package.json"}]}
  ],
  "dependencies": [{"ref": "root", "dependsOn": ["dl", "express"]}]
}`

func TestBuildSnapshotNamesActionsTheWayGitHubDoes(t *testing.T) {
	s, err := BuildSnapshot([]byte(actionsBOM), SnapshotOptions{Target: Target{Repo: "o/r", SHA: "a", Ref: "refs/heads/main"}})
	if err != nil {
		t.Fatal(err)
	}
	m := s.Manifests[".github/workflows/release.yml"]
	if _, ok := m.Resolved["pkg:githubactions/actions/download-artifact@v8"]; !ok {
		t.Fatalf("%+v", m.Resolved)
	}
}

// One package the API refuses must not cost the repository its dependency
// graph: it is dropped and the rest is submitted.
func TestSubmitSnapshotLenientDropsARefusedPackage(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var s Snapshot
		_ = json.NewDecoder(r.Body).Decode(&s)
		for _, m := range s.Manifests {
			for p := range m.Resolved {
				if p == "pkg:weird/thing@1" {
					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write([]byte(`{"message":"invalid package url: in manifest \"a\" decoding \"pkg:weird/thing@1\": invalid package url type: weird"}`))
					return
				}
			}
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":9,"result":"SUCCESS"}`))
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	s := &Snapshot{Manifests: map[string]Manifest{
		"a": {Name: "a", Resolved: map[string]ResolvedPackage{
			"pkg:weird/thing@1": {PackageURL: "pkg:weird/thing@1"},
			"pkg:npm/express@4": {PackageURL: "pkg:npm/express@4", Dependencies: []string{"pkg:weird/thing@1"}},
		}},
		"b": {Name: "b", Resolved: map[string]ResolvedPackage{"pkg:weird/thing@1": {PackageURL: "pkg:weird/thing@1"}}},
	}}
	res, dropped, err := c.SubmitSnapshotLenient(context.Background(), "o/r", s)
	if err != nil || res.ID != 9 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(dropped) != 1 || dropped[0] != "pkg:weird/thing@1" || calls != 2 {
		t.Fatalf("dropped %v calls %d", dropped, calls)
	}
	if len(s.Manifests) != 1 || len(s.Manifests["a"].Resolved["pkg:npm/express@4"].Dependencies) != 0 {
		t.Fatalf("the refused package must leave no trace: %+v", s.Manifests)
	}
}
