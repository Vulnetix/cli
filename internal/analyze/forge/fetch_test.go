package forge

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ghMux is a GitHub Enterprise API (under /api/v3/) answering fixed JSON per
// path. A path with no route is a 404.
func ghMux(routes map[string]string) http.Handler {
	mux := http.NewServeMux()
	for path, body := range routes {
		body := body
		mux.HandleFunc("/api/v3"+path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, body)
		})
	}
	return mux
}

func fakeClient(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	host := startFakeGitHub(t, ghMux(routes))
	c, err := NewClient(testCreds, host)
	require.NoError(t, err)
	return c
}

var (
	t0      = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	at      = func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339) }
	fetchRp = Repo{Owner: "acme", Name: "widgets", DefaultBranch: "main"}
)

func TestFetchPullRequestsHydratesStateReviewsAndResponses(t *testing.T) {
	c := fakeClient(t, map[string]string{
		"/repos/acme/widgets/pulls": `[
			{"number":3,"title":"merged","html_url":"u3","user":{"login":"ann"},"created_at":"` + at(0) + `","updated_at":"` + at(72*time.Hour) + `","merged_at":"` + at(5*time.Hour) + `","closed_at":"` + at(5*time.Hour) + `","merged_by":{"login":"bob"},"additions":10,"deletions":2,"changed_files":1,"comments":2},
			{"number":2,"title":"rejected","user":{"login":"ann"},"created_at":"` + at(0) + `","updated_at":"` + at(48*time.Hour) + `","closed_at":"` + at(6*time.Hour) + `"},
			{"number":1,"title":"too old","user":{"login":"ann"},"created_at":"` + at(-200*time.Hour) + `","updated_at":"` + at(-100*time.Hour) + `"}
		]`,
		"/repos/acme/widgets/issues/3/timeline": `[]`,
		"/repos/acme/widgets/issues/2/timeline": `[]`,
		"/repos/acme/widgets/pulls/3/reviews": `[
			{"user":{"login":"ann"},"state":"COMMENTED","submitted_at":"` + at(30*time.Minute) + `"},
			{"user":{"login":"ci","type":"Bot"},"state":"COMMENTED","submitted_at":"` + at(40*time.Minute) + `"},
			{"user":{"login":"bob"},"state":"APPROVED","submitted_at":"` + at(3*time.Hour) + `"}
		]`,
		"/repos/acme/widgets/pulls/2/reviews": `[]`,
		"/repos/acme/widgets/issues/3/comments": `[
			{"user":{"login":"ann"},"created_at":"` + at(10*time.Minute) + `"},
			{"user":{"login":"dependabot[bot]","type":"Bot"},"created_at":"` + at(20*time.Minute) + `"},
			{"user":{"login":"cid"},"created_at":"` + at(2*time.Hour) + `"}
		]`,
		"/repos/acme/widgets/issues/2/comments": `[]`,
	})

	prs, err := c.FetchPullRequests(context.Background(), fetchRp, t0)
	require.NoError(t, err)
	require.Len(t, prs, 2, "the PR updated before the window ends the walk")

	merged := prs[0]
	require.Equal(t, 3, merged.Number)
	require.Equal(t, "merged", merged.State)
	require.Equal(t, "bob", merged.MergedBy.Login)
	require.Equal(t, 10, merged.Additions)
	require.Len(t, merged.Reviews, 3)
	require.Equal(t, "approved", merged.Reviews[2].State, "review states are lower-cased")
	require.Equal(t, t0.Add(3*time.Hour), merged.FirstReviewAt.UTC(), "the author's own and a bot's review do not count")
	require.Equal(t, t0.Add(2*time.Hour), merged.FirstResponseAt.UTC(), "the first non-author, non-bot comment came before the review")
	require.Equal(t, t0, merged.ReadyForReviewAt.UTC(), "never a draft: ready when opened")

	rejected := prs[1]
	require.Equal(t, "closed", rejected.State, "closed without merging is a rejection, not a merge")
	require.True(t, rejected.MergedAt.IsZero())
	require.True(t, rejected.FirstResponseAt.IsZero())
}

func TestDraftHistorySumsEveryDraftInterval(t *testing.T) {
	c := fakeClient(t, map[string]string{
		"/repos/acme/widgets/pulls": `[{"number":7,"draft":false,"user":{"login":"ann"},"created_at":"` + at(0) + `","updated_at":"` + at(10*time.Hour) + `"}]`,
		"/repos/acme/widgets/issues/7/timeline": `[
			{"event":"convert_to_draft","created_at":"` + at(1*time.Hour) + `"},
			{"event":"ready_for_review","created_at":"` + at(2*time.Hour) + `"},
			{"event":"convert_to_draft","created_at":"` + at(3*time.Hour) + `"},
			{"event":"ready_for_review","created_at":"` + at(5*time.Hour) + `"}
		]`,
		"/repos/acme/widgets/pulls/7/reviews": `[]`,
		"/repos/acme/widgets/issues/7/comments": `[
			{"user":{"login":"bob"},"created_at":"` + at(90*time.Minute) + `"}
		]`,
	})

	prs, err := c.FetchPullRequests(context.Background(), fetchRp, t0)
	require.NoError(t, err)
	require.Len(t, prs, 1)
	p := prs[0]
	require.Equal(t, t0.Add(2*time.Hour), p.ReadyForReviewAt.UTC(), "ready at the first ready_for_review")
	require.Equal(t, int((3 * time.Hour).Seconds()), p.TimeInDraftSeconds, "1h + 2h across both draft cycles")
	require.True(t, p.FirstResponseAt.IsZero(), "a comment before the PR was ready is not a response to it")
}

func TestFetchIssuesSkipsPullRequests(t *testing.T) {
	c := fakeClient(t, map[string]string{
		"/repos/acme/widgets/issues": `[
			{"number":10,"title":"bug","state":"closed","state_reason":"completed","user":{"login":"ann"},"labels":[{"name":"bug"},{"name":"p1"}],"created_at":"` + at(0) + `","closed_at":"` + at(time.Hour) + `"},
			{"number":11,"title":"a PR","user":{"login":"ann"},"pull_request":{"url":"x"},"created_at":"` + at(0) + `"}
		]`,
		"/repos/acme/widgets/issues/10/comments": `[{"user":{"login":"bob"},"created_at":"` + at(30*time.Minute) + `"}]`,
	})

	issues, err := c.FetchIssues(context.Background(), fetchRp, t0)
	require.NoError(t, err)
	require.Len(t, issues, 1, "the PR the issues endpoint returns is not an issue")
	is := issues[0]
	require.Equal(t, 10, is.Number)
	require.Equal(t, "completed", is.StateReason)
	require.Equal(t, []string{"bug", "p1"}, is.Labels)
	require.Equal(t, t0.Add(30*time.Minute), is.FirstResponseAt.UTC())
}

func TestFetchCommitReviews(t *testing.T) {
	c := fakeClient(t, map[string]string{
		// approved on a PR into main
		"/repos/acme/widgets/commits/aaa/pulls": `[
			{"number":20,"html_url":"u20","user":{"login":"ann"},"base":{"ref":"release"}},
			{"number":21,"html_url":"u21","user":{"login":"ann"},"base":{"ref":"main"}}
		]`,
		"/repos/acme/widgets/pulls/21/reviews": `[{"user":{"login":"bob"},"state":"APPROVED","submitted_at":"` + at(0) + `"}]`,
		// a PR into main nobody but the author approved
		"/repos/acme/widgets/commits/bbb/pulls": `[{"number":22,"user":{"login":"ann"},"base":{"ref":"main"}}]`,
		"/repos/acme/widgets/pulls/22/reviews":  `[{"user":{"login":"ann"},"state":"APPROVED","submitted_at":"` + at(0) + `"}]`,
		// no PR into main at all
		"/repos/acme/widgets/commits/ccc/pulls": `[{"number":23,"user":{"login":"ann"},"base":{"ref":"release"}}]`,
		// "ddd" has no route: the lookup fails and the commit is unknown
	})

	got, err := c.FetchCommitReviews(context.Background(), fetchRp, []string{"aaa", "bbb", "ccc", "ddd"})
	require.NoError(t, err)
	require.Equal(t, []CommitReview{
		{SHA: "aaa", PRNumber: 21, PRURL: "u21", Status: "approved"},
		{SHA: "bbb", PRNumber: 22, Status: "review_required"},
		{SHA: "ccc", Status: "unknown"},
		{SHA: "ddd", Status: "unknown"},
	}, got)
}

// fakeGh puts a gh on PATH that runs script.
func fakeGh(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gh"), []byte("#!/bin/sh\n"+script+"\n"), 0o755))
	t.Setenv("PATH", dir)
}

func TestResolveCredentials_GhCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as gh")
	}
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	fakeGh(t, `[ "$1 $2" = "auth token" ] && echo "  from-gh-cli  "`)
	creds, err := ResolveCredentials(context.Background())
	require.NoError(t, err)
	require.Equal(t, "from-gh-cli", creds.Token, "gh's output is trimmed")
	require.Equal(t, "gh CLI", creds.Source)

	for name, script := range map[string]string{
		"gh fails":        "exit 1",
		"gh prints blank": "echo",
	} {
		fakeGh(t, script)
		_, err := ResolveCredentials(context.Background())
		require.ErrorIs(t, err, ErrNoCredentials, name)
	}

	t.Setenv("PATH", t.TempDir()) // no gh at all
	_, err = ResolveCredentials(context.Background())
	require.ErrorIs(t, err, ErrNoCredentials, "gh absent")
}
