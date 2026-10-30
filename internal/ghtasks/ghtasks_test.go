package ghtasks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
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
		// The primary limit resets in an hour, far past MaxWait: fail at once.
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	g := NewRESTGetter(srv.URL, "t0k")
	start := time.Now()
	st, err := g.Get(context.Background(), "/repos/a/b", nil)
	if st != 403 || err != ErrRateLimited {
		t.Fatalf("got %d %v", st, err)
	}
	if g.Calls != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("waited for a reset beyond MaxWait: %d calls in %s", g.Calls, time.Since(start))
	}
}

// rateLimitedThen refuses the first n requests with the given headers and
// status, then answers {"ok":true}.
func rateLimitedThen(t *testing.T, n int, status int, headers map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if int(calls.Add(1)) <= n {
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestRESTGetterRetriesAfterRetryAfter(t *testing.T) {
	// A secondary rate limit: 403 with Retry-After and requests still remaining.
	srv, calls := rateLimitedThen(t, 2, http.StatusForbidden, map[string]string{"Retry-After": "0", "X-RateLimit-Remaining": "12"})
	var out struct{ OK bool }
	st, err := NewRESTGetter(srv.URL, "").Get(context.Background(), "/x", &out)
	if err != nil || st != 200 || !out.OK {
		t.Fatalf("got %d %v %+v", st, err, out)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestRESTGetterWaitsForReset(t *testing.T) {
	// 429 with the primary limit spent and a reset already due.
	reset := strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10)
	srv, calls := rateLimitedThen(t, 1, http.StatusTooManyRequests, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset})
	st, err := NewRESTGetter(srv.URL, "").Get(context.Background(), "/x", nil)
	if err != nil || st != 200 || calls.Load() != 2 {
		t.Fatalf("got %d %v after %d calls", st, err, calls.Load())
	}
}

func TestRESTGetterBacksOffThenGivesUp(t *testing.T) {
	// Refused for quota every time, with no hint of when to come back.
	srv, calls := rateLimitedThen(t, 1000, http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"})
	g := NewRESTGetter(srv.URL, "")
	g.RetryBase = time.Millisecond
	st, err := g.Get(context.Background(), "/x", nil)
	if st != 403 || err != ErrRateLimited {
		t.Fatalf("got %d %v", st, err)
	}
	if calls.Load() != maxRateRetries+1 {
		t.Fatalf("calls = %d, want %d", calls.Load(), maxRateRetries+1)
	}
}

func TestRESTGetterStopsWaitingWhenCancelled(t *testing.T) {
	srv, calls := rateLimitedThen(t, 1000, http.StatusForbidden, map[string]string{"Retry-After": "30"})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewRESTGetter(srv.URL, "").Get(ctx, "/x", nil)
	if err != ErrRateLimited || calls.Load() != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v, %d calls in %s", err, calls.Load(), time.Since(start))
	}
}

func TestRESTGetterLeavesOtherForbiddenAlone(t *testing.T) {
	// A plain 403 (no permission) is not a rate limit and is not retried.
	srv, calls := rateLimitedThen(t, 1000, http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "4000"})
	st, err := NewRESTGetter(srv.URL, "").Get(context.Background(), "/x", nil)
	if st != 403 || err == nil || errors.Is(err, ErrRateLimited) || calls.Load() != 1 {
		t.Fatalf("got %d %v after %d calls", st, err, calls.Load())
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
