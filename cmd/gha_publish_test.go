package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/vulnetix/cli/v3/internal/artifacts"
	"github.com/vulnetix/cli/v3/internal/github"
	"github.com/vulnetix/cli/v3/internal/sast"
)

func TestParseGitHubPublish(t *testing.T) {
	got, err := parseGitHubPublish([]string{"code-scanning", " Code-Scanning ,"})
	if err != nil || len(got) != 2 || got[0] != "code-scanning" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := parseGitHubPublish([]string{"nope"}); err == nil {
		t.Fatal("unknown target accepted")
	}
}

func TestCodeScanningPublishUploadsOneCategoryPerKind(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("import os\nos.system(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := sast.RuleMetadata{ID: "VNX-1", Kind: "sast", Severity: "high"}
	mixed := sast.BuildSARIF([]sast.Finding{{RuleID: "VNX-1", ArtifactURI: "app.py", StartLine: 2, Metadata: &r}}, []sast.RuleMetadata{r}, "t")

	var mu sync.Mutex
	var categories []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(req.Body).Decode(&body)
		raw, _ := base64.StdEncoding.DecodeString(body["sarif"])
		zr, _ := gzip.NewReader(bytes.NewReader(raw))
		doc, _ := io.ReadAll(zr)
		var l sast.SARIFLog
		_ = json.Unmarshal(doc, &l)
		cat := l.Runs[0].AutomationDetails.ID
		mu.Lock()
		categories = append(categories, cat)
		mu.Unlock()
		if cat == "vulnetix/sast/" && l.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] == "" {
			t.Error("sast result uploaded without a line hash")
		}
		if cat == "vulnetix/secrets/" {
			// Fork pull requests get a read-only token.
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":"1"}`)
	}))
	defer srv.Close()
	client := github.NewClient("tok")
	client.BaseURL = srv.URL

	var out strings.Builder
	err := runCodeScanningPublish(context.Background(), codeScanningPublishOptions{
		Root: root, Logs: []*sast.SARIFLog{mixed}, EnsureKinds: []string{"sast", "secrets", "sca"},
		Repo: "o/r", SHA: "abc", Ref: "refs/heads/main", Client: client,
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("a refused upload must be reported, got %v", err)
	}
	if !strings.Contains(out.String(), "security-events: write") {
		t.Fatalf("no permission hint in %q", out.String())
	}
	sort.Strings(categories)
	want := []string{"vulnetix/sast/", "vulnetix/sca/", "vulnetix/secrets/"}
	if strings.Join(categories, ",") != strings.Join(want, ",") {
		t.Fatalf("categories %v, want %v", categories, want)
	}
	for _, k := range []string{"sast", "sca", "secrets"} {
		if _, err := os.Stat(filepath.Join(root, ".vulnetix", "code-scanning", k+".sarif")); err != nil {
			t.Errorf("per-kind file %s: %v", k, err)
		}
	}
}

func TestDependencyGraphPublish(t *testing.T) {
	root := t.TempDir()
	sbom := filepath.Join(root, ".vulnetix", "sbom.cdx.json")
	if err := os.MkdirAll(filepath.Dir(sbom), 0o755); err != nil {
		t.Fatal(err)
	}
	doc := `{"components":[{"bom-ref":"a","purl":"pkg:npm/a@1.0.0","properties":[{"name":"vulnetix:source-file","value":"package.json"}]}]}`
	if err := os.WriteFile(sbom, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	var got github.Snapshot
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":1,"result":"SUCCESS"}`)
	}))
	defer srv.Close()
	client := github.NewClient("tok")
	client.BaseURL = srv.URL
	var out strings.Builder
	err := runDependencyGraphPublish(context.Background(), dependencyGraphPublishOptions{
		Root: root, SBOM: sbom, Correlator: "vulnetix/test/job",
		Repo: "o/r", SHA: "abc", Ref: "refs/heads/main", Client: client,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got.Job.Correlator != "vulnetix/test/job" || got.Manifests["package.json"].Resolved["pkg:npm/a@1.0.0"].PackageURL == "" {
		t.Fatalf("snapshot %+v", got)
	}
	if !strings.Contains(out.String(), "1 package(s) in 1 manifest(s)") {
		t.Fatalf("output %q", out.String())
	}
}

func TestReleaseAssetsFromTheArtifactManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "vx.jsonl")
	t.Setenv(artifacts.EnvVar, manifest)
	// Writers record what they write.
	if err := sast.WriteSARIF(sast.BuildSARIF(nil, nil, "t"), filepath.Join(dir, "sast.sarif")); err != nil {
		t.Fatal(err)
	}
	if err := artifacts.WriteFile(filepath.Join(dir, "sbom.cdx.json.sig"), []byte("sig"), 0o644, ""); err != nil {
		t.Fatal(err)
	}

	var srv *httptest.Server
	var names []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/o/r/releases/tags/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "tag_name": "v1", "upload_url": srv.URL + "/up{?name,label}"})
		case r.URL.Path == "/up":
			names = append(names, r.URL.Query().Get("name"))
			_, _ = io.WriteString(w, `{"id":2,"name":"x"}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	client := github.NewClient("tok")
	client.BaseURL = srv.URL
	var out strings.Builder
	if err := runReleaseAssetsPublish(context.Background(), releaseAssetsOptions{Repo: "o/r", Tag: "v1", Client: client}, &out); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "sast.sarif,sbom.cdx.json.sig" {
		t.Fatalf("attached %v", names)
	}
}

func TestCodeScanningDryRunUploadsNothing(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_REF", "")
	var out strings.Builder
	err := runCodeScanningPublish(context.Background(), codeScanningPublishOptions{
		Root: root, EnsureKinds: []string{"sast"}, DryRun: true,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".vulnetix", "code-scanning", "sast.sarif")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing uploaded") {
		t.Fatalf("output %q", out.String())
	}
}
