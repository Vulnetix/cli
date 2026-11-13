package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v66/github"
	"github.com/stretchr/testify/require"
)

// fakeGitHub serves the three endpoints Check calls, as a GitHub Enterprise
// host would (under /api/v3/), each answering with the status it is given.
type fakeGitHub struct {
	userStatus, repoStatus, rateStatus int
	calls                              []string

	// exhausted answers every endpoint but /rate_limit the way GitHub does once a token's
	// quota is spent: 403, X-RateLimit-Remaining: 0, "API rate limit exceeded".
	exhausted bool
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if f.exhausted && r.URL.Path != "/api/v3/rate_limit" {
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded for installation."}`)
		return
	}
	reply := func(status int, body string) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = fmt.Fprint(w, body)
			return
		}
		_, _ = fmt.Fprintf(w, `{"message":"%s"}`, http.StatusText(status))
	}
	switch r.URL.Path {
	case "/api/v3/user":
		reply(f.userStatus, `{"login":"octocat"}`)
	case "/api/v3/repos/acme/widgets":
		reply(f.repoStatus, `{"name":"widgets","owner":{"login":"acme"}}`)
	case "/api/v3/rate_limit":
		reply(f.rateStatus, `{"resources":{"core":{"limit":5000,"remaining":4321,"reset":1767225600}}}`)
	default:
		http.NotFound(w, r)
	}
}

// startFakeGitHub serves f over TLS and returns the host to pass to Check or NewClient. The
// client Check builds uses http.DefaultTransport, which is pointed at the test
// server's trusted transport for the duration of the test.
func startFakeGitHub(t *testing.T, f http.Handler) string {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	prev := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = prev })
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Host
}

var testCreds = &Credentials{Token: "t0ken", Source: "GH_TOKEN"}
var testRepo = Repo{Owner: "acme", Name: "widgets"}

func TestCheck_UserTokenWithRepoAccess(t *testing.T) {
	host := startFakeGitHub(t, &fakeGitHub{userStatus: 200, repoStatus: 200, rateStatus: 200})

	res, err := Check(context.Background(), testCreds, host, testRepo)
	require.NoError(t, err)
	require.Equal(t, "octocat", res.Login)
	require.Equal(t, "GH_TOKEN", res.Source)
	require.Equal(t, 4321, res.RateLimitRemaining)
	require.Equal(t, 5000, res.RateLimitLimit)
	require.Equal(t, time.Unix(1767225600, 0).UTC(), res.RateLimitResetsAt.UTC())
}

func TestCheck_UserRejectedWithoutRepoIsATokenError(t *testing.T) {
	f := &fakeGitHub{userStatus: 401, repoStatus: 200, rateStatus: 200}
	host := startFakeGitHub(t, f)

	_, err := Check(context.Background(), testCreds, host, Repo{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "GitHub rejected the token from GH_TOKEN")
	require.NotContains(t, f.calls, "/api/v3/repos/acme/widgets", "with no repository there is nothing else to try")
}

// GitHub Actions' GITHUB_TOKEN cannot read /user; reading the repository is
// the validity check, and the result has no login.
func TestCheck_RepositoryScopedToken(t *testing.T) {
	host := startFakeGitHub(t, &fakeGitHub{userStatus: 403, repoStatus: 200, rateStatus: 200})

	res, err := Check(context.Background(), testCreds, host, testRepo)
	require.NoError(t, err)
	require.Empty(t, res.Login)
	require.Equal(t, 4321, res.RateLimitRemaining)
	require.Contains(t, res.String(), "repository-scoped token via GH_TOKEN")
}

func TestCheck_RepositoryScopedTokenWithoutRateLimit(t *testing.T) {
	host := startFakeGitHub(t, &fakeGitHub{userStatus: 403, repoStatus: 200, rateStatus: 500})

	res, err := Check(context.Background(), testCreds, host, testRepo)
	require.NoError(t, err)
	require.Equal(t, CheckResult{Source: "GH_TOKEN"}, *res)
}

func TestCheck_RepositoryScopedTokenThatCannotSeeTheRepo(t *testing.T) {
	host := startFakeGitHub(t, &fakeGitHub{userStatus: 403, repoStatus: 404, rateStatus: 200})

	_, err := Check(context.Background(), testCreds, host, testRepo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "authenticated as repository-scoped token")
}

// A valid user token that cannot see a private repository gets 404, not 403;
// the error must say it is an access problem and name the token and login.
func TestCheck_UserTokenCannotSeeTheRepo(t *testing.T) {
	host := startFakeGitHub(t, &fakeGitHub{userStatus: 200, repoStatus: 404, rateStatus: 200})

	_, err := Check(context.Background(), testCreds, host, testRepo)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "the GitHub token from GH_TOKEN is valid (authenticated as octocat) but cannot read acme/widgets")
	require.Contains(t, msg, "almost certainly\n  an access problem")
}

// A spent quota is "come back later", not an access problem. In GitHub Actions the job token's
// quota is the repository's, and other jobs can spend it first; reporting that as "cannot read
// Vulnetix/cli" sent the reader to check permissions that were fine.
func TestCheck_ExhaustedQuotaIsNotAnAccessError(t *testing.T) {
	for _, repo := range []Repo{testRepo, {}} {
		host := startFakeGitHub(t, &fakeGitHub{exhausted: true})

		_, err := Check(context.Background(), testCreds, host, repo)
		require.ErrorIs(t, err, ErrRateLimited, "repo %+v", repo)
		require.NotContains(t, err.Error(), "cannot read")
		require.Contains(t, err.Error(), "GH_TOKEN")
	}
}

// GITHUB_TOKEN cannot read /user (403, not a rate limit); the repository read is then the one
// that meets the spent quota.
func TestCheck_RepositoryScopedTokenWithExhaustedQuota(t *testing.T) {
	f := &fakeGitHub{userStatus: 403, rateStatus: 200}
	host := startFakeGitHub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.exhausted = r.URL.Path == "/api/v3/repos/acme/widgets"
		f.ServeHTTP(w, r)
	}))

	_, err := Check(context.Background(), testCreds, host, testRepo)
	require.ErrorIs(t, err, ErrRateLimited)
	require.NotContains(t, err.Error(), "cannot read")
}

func TestIsRateLimit_Wrapped(t *testing.T) {
	require.True(t, IsRateLimit(fmt.Errorf("fetch: %w", &github.RateLimitError{})))
	require.False(t, IsRateLimit(fmt.Errorf("fetch: %w", errors.New("boom"))))
}

// The quota is informational: failing to read it does not fail the check.
func TestCheck_RateLimitFailureIsNotFatal(t *testing.T) {
	host := startFakeGitHub(t, &fakeGitHub{userStatus: 200, repoStatus: 200, rateStatus: 500})

	res, err := Check(context.Background(), testCreds, host, testRepo)
	require.NoError(t, err)
	require.Equal(t, CheckResult{Login: "octocat", Source: "GH_TOKEN"}, *res)
}

func TestRepoAccessError(t *testing.T) {
	raw := errors.New("boom")
	resp := func(code int) *github.Response {
		return &github.Response{Response: &http.Response{StatusCode: code}}
	}

	for _, code := range []int{http.StatusNotFound, http.StatusForbidden} {
		err := repoAccessError(testCreds, "octocat", testRepo, resp(code), raw)
		require.Contains(t, err.Error(), "the GitHub token from GH_TOKEN is valid (authenticated as octocat) but cannot read acme/widgets", "status %d", code)
		require.NotErrorIs(t, err, raw, "the access message replaces the bare status")
	}

	for _, r := range []*github.Response{resp(http.StatusInternalServerError), nil} {
		err := repoAccessError(testCreds, "octocat", testRepo, r, raw)
		require.Equal(t, "GitHub could not read acme/widgets: boom", err.Error())
		require.ErrorIs(t, err, raw, "any other failure keeps the raw error")
	}
}

func TestComma(t *testing.T) {
	for n, want := range map[int]string{
		0: "0", 7: "7", 999: "999", 1000: "1,000", 12345: "12,345",
		123456: "123,456", 1234567: "1,234,567",
	} {
		require.Equal(t, want, comma(n), "comma(%d)", n)
	}
}

func TestCheckResultString(t *testing.T) {
	user := CheckResult{Login: "octocat", Source: "gh CLI", RateLimitRemaining: 4321, RateLimitLimit: 5000}
	require.Equal(t, "GitHub authentication: ok (octocat via gh CLI, 4,321/5,000 requests remaining)", user.String())

	scoped := CheckResult{Source: "GITHUB_TOKEN", RateLimitRemaining: 999, RateLimitLimit: 1000}
	require.Equal(t, "GitHub authentication: ok (repository-scoped token via GITHUB_TOKEN, 999/1,000 requests remaining)", scoped.String())
}

func TestNewClientEnterpriseHost(t *testing.T) {
	c, err := NewClient(testCreds, "ghe.example.com")
	require.NoError(t, err)
	require.Equal(t, "https://ghe.example.com/api/v3/", c.GitHub().BaseURL.String())

	c, err = NewClient(testCreds, "github.com")
	require.NoError(t, err)
	require.Equal(t, "https://api.github.com/", c.GitHub().BaseURL.String(), "the public host keeps the default API URL")

	_, err = NewClient(testCreds, "bad host%zz")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "configure GitHub Enterprise host bad host%zz:"), err.Error())
}
