package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-sca-match/ghaudit"
)

const ghaTestWorkflow = "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" +
	"      - uses: actions/checkout@v4\n" +
	"      - run: echo \"${{ github.event.pull_request.title }}\"\n"

func ghaTestCheckout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(ghaTestWorkflow), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGHATaskCommandsAreRegistered(t *testing.T) {
	want := map[string]bool{"workflows": false, "actions": false, "settings": false, "org": false, "audit": false, "upload": false, "status": false}
	for _, c := range ghaCmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("gha %s is not registered", name)
		}
	}
}

func TestGHAWorkflowsOfflineJSONAndFailOn(t *testing.T) {
	dir := ghaTestCheckout(t)
	var out, errOut bytes.Buffer
	opt := ghaTaskOptions{format: "json", offline: true, maxActionRefs: 40}
	if err := runGHATask(context.Background(), &out, &errOut, []ghaudit.Task{ghaudit.TaskWorkflows}, dir, opt); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []ghaudit.Finding `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if len(doc.Findings) == 0 || doc.Findings[0].RuleID != "VNX-GH-001" {
		t.Fatalf("expected the injection first, got %+v", doc.Findings)
	}
	opt.failOn = "critical"
	err := runGHATask(context.Background(), &out, &errOut, []ghaudit.Task{ghaudit.TaskWorkflows}, dir, opt)
	if err == nil || !strings.Contains(err.Error(), "at or above critical") {
		t.Fatalf("--fail-on critical should fail, got %v", err)
	}
	opt.failOn = "nonsense"
	if err := runGHATask(context.Background(), &out, &errOut, nil, dir, opt); err == nil {
		t.Fatal("an unknown severity must be rejected")
	}
}

// audit against a fake GitHub: settings facts are collected, local files are
// evaluated as on disk, and their references are resolved through the API.
func TestGHAAuditCollectsFromTheAPI(t *testing.T) {
	dir := ghaTestCheckout(t)
	routes := map[string]any{
		"/repos/acme/app":                                      map[string]any{"full_name": "acme/app", "visibility": "public", "default_branch": "main"},
		"/repos/acme/app/actions/permissions":                  map[string]any{"enabled": true, "allowed_actions": "all"},
		"/repos/acme/app/actions/permissions/workflow":         map[string]any{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": false},
		"/repos/acme/app/rules/branches/main":                  []any{},
		"/repos/acme/app/commits/main":                         map[string]any{"sha": strings.Repeat("a", 40)},
		"/repos/acme/app/git/trees/" + strings.Repeat("a", 40): map[string]any{"tree": []any{map[string]any{"path": ".github/workflows/ci.yml", "type": "blob"}}},
		"/repos/actions/checkout":                              map[string]any{"full_name": "actions/checkout", "default_branch": "main"},
		"/repos/actions/checkout/git/ref/tags/v4":              map[string]any{},
		"/repos/actions/checkout/commits/v4":                   map[string]any{"sha": strings.Repeat("b", 40)},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/app/branches/main/protection" {
			w.WriteHeader(http.StatusNotFound) // "Branch not protected"
			return
		}
		if r.URL.Path == "/repos/acme/app/contents/.github/workflows/ci.yml" {
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(ghaTestWorkflow))})
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()
	t.Setenv("GITHUB_TOKEN", "t0k")
	t.Setenv("GH_TOKEN", "")
	var out, errOut bytes.Buffer
	opt := ghaTaskOptions{format: "json", repo: "acme/app", apiURL: srv.URL, maxActionRefs: 40}
	if err := runGHATask(context.Background(), &out, &errOut, ghaudit.AllTasks, dir, opt); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []ghaudit.Finding `json:"findings"`
		Commit   string            `json:"commit"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]*ghaudit.Finding{}
	for i := range doc.Findings {
		got[doc.Findings[i].RuleID] = &doc.Findings[i]
	}
	for _, id := range []string{"VNX-GH-001", "VNX-GH-201", "VNX-GH-208", "VNX-GH-211", "VNX-GH-101"} {
		if got[id] == nil {
			t.Errorf("expected %s", id)
		}
	}
	if f := got["VNX-GH-101"]; f != nil && (f.Fix == nil || !strings.Contains(f.Fix.Edits[0].Replacement, strings.Repeat("b", 40))) {
		t.Errorf("the unpinned checkout should carry a pin to the resolved SHA: %+v", f.Fix)
	}
	if doc.Commit != strings.Repeat("a", 40) {
		t.Errorf("commit = %q", doc.Commit)
	}
}
