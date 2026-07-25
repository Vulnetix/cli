package ghactx

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// setEnv sets GitHub Actions variables for one test and restores them after.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func writeEvent(t *testing.T, payload string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write event: %v", err)
	}
	return path
}

func TestCollectReturnsNilOutsideActions(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_RUN_ID", "")
	if ci := Collect(context.Background(), Options{NoAPI: true}); ci != nil {
		t.Fatalf("expected nil outside a runner, got %+v", ci)
	}
}

func TestCollectFromEnvironment(t *testing.T) {
	setEnv(t, map[string]string{
		"GITHUB_ACTIONS":          "true",
		"GITHUB_REPOSITORY":       "Vulnetix/vdb-site",
		"GITHUB_REPOSITORY_OWNER": "Vulnetix",
		"GITHUB_RUN_ID":           "30155614396",
		"GITHUB_RUN_NUMBER":       "42",
		"GITHUB_RUN_ATTEMPT":      "2",
		"GITHUB_WORKFLOW":         "Third-Party Scanners",
		"GITHUB_JOB":              "publish",
		"GITHUB_EVENT_NAME":       "push",
		"GITHUB_REF_NAME":         "main",
		"GITHUB_REF_TYPE":         "branch",
		"GITHUB_SHA":              "deadbeef",
		"GITHUB_ACTOR":            "chris",
		"GITHUB_SERVER_URL":       "https://github.com",
		"GITHUB_WORKSPACE":        "/runner/work/vdb-site/vdb-site",
		"RUNNER_OS":               "Linux",
		"RUNNER_ARCH":             "X64",
		"GITHUB_EVENT_PATH":       "",
	})

	ci := Collect(context.Background(), Options{NoAPI: true})
	if ci == nil {
		t.Fatal("expected a context inside a runner")
	}

	// The run id is BIGINT-sized on purpose: it overflows int32.
	if ci.RunID != 30155614396 {
		t.Errorf("runId = %d, want 30155614396", ci.RunID)
	}
	if ci.RunAttempt != 2 {
		t.Errorf("runAttempt = %d, want 2", ci.RunAttempt)
	}
	if ci.Provider != Provider {
		t.Errorf("provider = %q, want %q", ci.Provider, Provider)
	}
	if ci.Workspace != "/runner/work/vdb-site/vdb-site" {
		t.Errorf("workspace = %q", ci.Workspace)
	}
	want := "https://github.com/Vulnetix/vdb-site/actions/runs/30155614396"
	if ci.RunURL != want {
		t.Errorf("runUrl = %q, want %q", ci.RunURL, want)
	}
}

// A missing run attempt is attempt 1, not 0. The analysis key includes the
// attempt, so a zero would make the first publish key differently from its own
// re-run and defeat the idempotency check.
func TestCollectDefaultsRunAttempt(t *testing.T) {
	setEnv(t, map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_RUN_ID":     "7",
		"GITHUB_EVENT_PATH": "",
	})
	ci := Collect(context.Background(), Options{NoAPI: true})
	if ci.RunAttempt != 1 {
		t.Errorf("runAttempt = %d, want 1", ci.RunAttempt)
	}
}

// GITHUB_EVENT_PATH is the only free source for repository id, visibility,
// default branch and licence — none appear in the environment.
func TestEventPayloadFillsRepositoryMetadata(t *testing.T) {
	path := writeEvent(t, `{
	  "repository": {
	    "id": 123456789,
	    "full_name": "Vulnetix/vdb-site",
	    "default_branch": "main",
	    "private": true,
	    "owner": {"login": "Vulnetix", "type": "Organization"},
	    "license": {"spdx_id": "Apache-2.0"}
	  }
	}`)
	setEnv(t, map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_RUN_ID":     "1",
		"GITHUB_EVENT_PATH": path,
	})

	ci := Collect(context.Background(), Options{NoAPI: true})
	if ci.RepositoryID != 123456789 {
		t.Errorf("repositoryId = %d", ci.RepositoryID)
	}
	if ci.DefaultBranch != "main" {
		t.Errorf("defaultBranch = %q", ci.DefaultBranch)
	}
	if ci.LicenseSpdxID != "Apache-2.0" {
		t.Errorf("licenseSpdxId = %q", ci.LicenseSpdxID)
	}
	if ci.OwnerType != "Organization" {
		t.Errorf("ownerType = %q", ci.OwnerType)
	}
	// Older payloads carry `private` but not `visibility`; one must derive the
	// other or private repos look unclassified.
	if ci.Visibility != "private" {
		t.Errorf("visibility = %q, want private (derived from repository.private)", ci.Visibility)
	}
}

// On a pull_request event GITHUB_SHA is the merge commit, which exists in no
// branch. Findings describe the head commit.
func TestPullRequestEventUsesHeadSHAAndRefs(t *testing.T) {
	path := writeEvent(t, `{
	  "repository": {"full_name": "Vulnetix/vdb-site", "visibility": "private"},
	  "pull_request": {
	    "number": 42,
	    "base": {"ref": "main"},
	    "head": {"ref": "feat/thing", "sha": "headsha123"}
	  }
	}`)
	setEnv(t, map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_RUN_ID":     "1",
		"GITHUB_EVENT_NAME": "pull_request",
		"GITHUB_REF_NAME":   "42/merge",
		"GITHUB_SHA":        "mergecommit999",
		"GITHUB_EVENT_PATH": path,
	})

	ci := Collect(context.Background(), Options{NoAPI: true})
	if ci.PullRequestNumber != 42 {
		t.Errorf("pullRequestNumber = %d, want 42", ci.PullRequestNumber)
	}
	if ci.HeadRef != "feat/thing" || ci.BaseRef != "main" {
		t.Errorf("refs = %q/%q, want feat/thing/main", ci.HeadRef, ci.BaseRef)
	}
	if ci.SHA != "headsha123" {
		t.Errorf("sha = %q; the merge commit exists in no branch, the head sha does", ci.SHA)
	}
	// RefName stays as GitHub reported it; the server prefers HeadRef.
	if ci.RefName != "42/merge" {
		t.Errorf("refName = %q, want the raw 42/merge", ci.RefName)
	}
}

// stubLookup records which REST calls were made.
type stubLookup struct {
	run    *RunInfo
	repo   *RepoInfo
	pulls  []PullInfo
	called map[string]int
}

func (s *stubLookup) note(name string) {
	if s.called == nil {
		s.called = map[string]int{}
	}
	s.called[name]++
}

func (s *stubLookup) GetWorkflowRun(context.Context) (*RunInfo, error) {
	s.note("run")
	return s.run, nil
}
func (s *stubLookup) GetRepository(context.Context) (*RepoInfo, error) {
	s.note("repo")
	return s.repo, nil
}
func (s *stubLookup) ListPullsForCommit(context.Context, string) ([]PullInfo, error) {
	s.note("pulls")
	return s.pulls, nil
}

// REST is a fallback. With a complete event payload it must not be called at
// all — a publish job should not spend three round trips on data already on
// disk.
func TestRESTNotCalledWhenEventPayloadIsComplete(t *testing.T) {
	path := writeEvent(t, `{
	  "repository": {"id": 1, "full_name": "a/b", "default_branch": "main", "visibility": "public"},
	  "pull_request": {"number": 3, "base": {"ref": "main"}, "head": {"ref": "x", "sha": "s"}}
	}`)
	setEnv(t, map[string]string{
		"GITHUB_ACTIONS":     "true",
		"GITHUB_RUN_ID":      "1",
		"GITHUB_RUN_NUMBER":  "5",
		"GITHUB_EVENT_NAME":  "pull_request",
		"GITHUB_ACTOR":       "chris",
		"GITHUB_EVENT_PATH":  path,
		"GITHUB_RUN_ATTEMPT": "1",
	})
	// TriggeringActor is unset, which is the one gap left; assert only that the
	// expensive repository lookup is skipped.
	stub := &stubLookup{}
	Collect(context.Background(), Options{Lookup: stub})

	if stub.called["repo"] != 0 {
		t.Errorf("repository lookup ran %d time(s) despite a complete event payload", stub.called["repo"])
	}
	if stub.called["pulls"] != 0 {
		t.Errorf("pull lookup ran %d time(s) despite the event carrying the PR number", stub.called["pulls"])
	}
}

// A workflow_dispatch run has no useful event payload, so REST fills the gaps.
func TestRESTFillsGapsForDispatchRuns(t *testing.T) {
	setEnv(t, map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_RUN_ID":     "99",
		"GITHUB_REPOSITORY": "Vulnetix/vdb-site",
		"GITHUB_EVENT_PATH": "",
		"GITHUB_EVENT_NAME": "",
		"GITHUB_SHA":        "",
	})

	stub := &stubLookup{
		repo: &RepoInfo{ID: 5, Visibility: "private", DefaultBranch: "main", OwnerType: "Organization", LicenseSpdxID: "MIT"},
		run:  &RunInfo{RunNumber: 12, RunAttempt: 3, Event: "workflow_dispatch", HeadSHA: "abc", Actor: "chris", TriggeringActor: "chris"},
	}
	ci := Collect(context.Background(), Options{Lookup: stub})

	if ci.RepositoryID != 5 || ci.DefaultBranch != "main" || ci.LicenseSpdxID != "MIT" {
		t.Errorf("repository metadata not filled from REST: %+v", ci)
	}
	if ci.RunAttempt != 3 {
		t.Errorf("runAttempt = %d; the API is authoritative on a re-run", ci.RunAttempt)
	}
	if ci.EventName != "workflow_dispatch" || ci.SHA != "abc" {
		t.Errorf("run metadata not filled: event=%q sha=%q", ci.EventName, ci.SHA)
	}
}

// A REST failure degrades the context; it must never fail collection.
func TestRESTFailureIsNonFatal(t *testing.T) {
	setEnv(t, map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_RUN_ID":     "1",
		"GITHUB_EVENT_PATH": "",
	})

	warned := 0
	ci := Collect(context.Background(), Options{
		Lookup: failingLookup{},
		Warn:   func(string, ...any) { warned++ },
	})
	if ci == nil {
		t.Fatal("collection must still succeed when the API is unreachable")
	}
	if warned == 0 {
		t.Error("a degraded context must be visible in the log, not silent")
	}
}

type failingLookup struct{}

func (failingLookup) GetWorkflowRun(context.Context) (*RunInfo, error) {
	return nil, context.DeadlineExceeded
}
func (failingLookup) GetRepository(context.Context) (*RepoInfo, error) {
	return nil, context.DeadlineExceeded
}
func (failingLookup) ListPullsForCommit(context.Context, string) ([]PullInfo, error) {
	return nil, context.DeadlineExceeded
}
