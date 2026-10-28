package ghtasks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRepoFromRemote(t *testing.T) {
	for remote, want := range map[string]string{
		"https://github.com/acme/api.git":   "acme/api",
		"git@github.com:acme/api.git":       "acme/api",
		"ssh://git@github.com/acme/api":     "acme/api",
		"https://gitlab.com/acme/api.git":   "",
		"https://github.com/acme":           "",
		"https://github.com/acme/api/extra": "",
	} {
		if got := RepoFromRemote(remote, ""); got != want {
			t.Errorf("RepoFromRemote(%q) = %q, want %q", remote, got, want)
		}
	}
	if got := RepoFromRemote("git@ghe.example.com:acme/api.git", "ghe.example.com"); got != "acme/api" {
		t.Errorf("GHE remote: %q", got)
	}
	if HostForAPI("https://ghe.example.com/api/v3") != "ghe.example.com" || HostForAPI("") != "github.com" {
		t.Error("HostForAPI")
	}
}

func TestLoadLocalReadsOnlyWhatTheEngineEvaluates(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".github/workflows/ci.yml", "on: push\n")
	write(".github/actions/x/action.yml", "runs: {using: composite, steps: []}\n")
	write(".github/CODEOWNERS", "* @acme\n")
	write("src/action.yml", "not ours")
	write("src/main.go", "package main")
	files, err := LoadLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".github/workflows/ci.yml", ".github/actions/x/action.yml", ".github/CODEOWNERS"} {
		if files[p] == nil {
			t.Errorf("missing %s", p)
		}
	}
	if files["src/main.go"] != nil || files["src/action.yml"] != nil {
		t.Errorf("read files outside .github and the root: %v", files)
	}
}

func TestRESTGetterReportsRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t0k" {
			t.Errorf("no token sent")
		}
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	st, err := NewRESTGetter(srv.URL, "t0k").Get(context.Background(), "/repos/a/b", nil)
	if st != 403 || err != ErrRateLimited {
		t.Fatalf("got %d %v", st, err)
	}
}

// The website's GitHub rule pages are generated from the engine; a rule added
// or reworded there must be regenerated here.
func TestGitHubRuleDocs(t *testing.T) {
	dir := filepath.Join("..", "..", "website", "content", "docs", "github-rules")
	pages := RuleDocs()
	if os.Getenv("GHRULES_UPDATE") != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		old, _ := filepath.Glob(filepath.Join(dir, "*.md"))
		for _, p := range old {
			_ = os.Remove(p)
		}
		for name, body := range pages {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	on, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	if len(on) != len(pages) {
		t.Fatalf("%d pages on disk, %d rules: run GHRULES_UPDATE=1 go test ./internal/ghtasks/", len(on), len(pages))
	}
	for name, body := range pages {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != body {
			t.Fatalf("%s is stale: run GHRULES_UPDATE=1 go test ./internal/ghtasks/", name)
		}
	}
}
