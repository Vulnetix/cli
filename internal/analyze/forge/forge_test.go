package forge

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-github/v66/github"
	"github.com/stretchr/testify/require"
)

func TestResolveCredentials_EnvWinsInOrder(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "from-github-token")
	t.Setenv("GH_TOKEN", "from-gh-token")

	creds, err := ResolveCredentials(context.Background())
	require.NoError(t, err)
	require.Equal(t, "from-github-token", creds.Token,
		"GITHUB_TOKEN wins: inside GitHub Actions it is what CI intends us to use")
	require.Equal(t, "GITHUB_TOKEN", creds.Source, "and the user is told which one won")
}

func TestResolveCredentials_FallsThroughToGhToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "from-gh-token")

	creds, err := ResolveCredentials(context.Background())
	require.NoError(t, err)
	require.Equal(t, "from-gh-token", creds.Token)
	require.Equal(t, "GH_TOKEN", creds.Source)
}

// The error has to tell you how to fix it. An error that says only what went wrong makes the
// reader do work we already know how to do.
func TestErrNoCredentials_TellsYouHowToFixIt(t *testing.T) {
	msg := ErrNoCredentials.Error()
	require.Contains(t, msg, "GITHUB_TOKEN")
	require.Contains(t, msg, "GH_TOKEN")
	require.Contains(t, msg, "gh auth login")
	require.Contains(t, msg, "--no-forge")
}

func TestIsGitHubHost(t *testing.T) {
	require.True(t, IsGitHubHost("github.com"))
	require.True(t, IsGitHubHost("GitHub.com"))
	require.True(t, IsGitHubHost("github.acme-corp.net"), "GitHub Enterprise Server")

	// A GitLab repo must not fail for want of a GitHub token. Refusing to analyze a repo we
	// were never going to call GitHub about would be a bug wearing a security hat.
	require.False(t, IsGitHubHost("gitlab.com"))
	require.False(t, IsGitHubHost("bitbucket.org"))
	require.False(t, IsGitHubHost(""))
}

// The review decision is the heart of the compliance metric, so it gets pinned hard.
func TestReviewDecision(t *testing.T) {
	author := Actor{Login: "ada"}

	t.Run("an approval from somebody else is coverage", func(t *testing.T) {
		require.Equal(t, "approved", reviewDecision([]Review{
			{Reviewer: Actor{Login: "bob"}, State: "approved"},
		}, author))
	})

	t.Run("an approval wins even after changes were requested", func(t *testing.T) {
		// Changes requested, then addressed, then approved. That is a review that worked, not a
		// breach — and reporting it as one would teach people to stop requesting changes.
		require.Equal(t, "approved", reviewDecision([]Review{
			{Reviewer: Actor{Login: "bob"}, State: "changes_requested"},
			{Reviewer: Actor{Login: "bob"}, State: "approved"},
		}, author))
	})

	t.Run("self-approval is not review coverage", func(t *testing.T) {
		require.Equal(t, "review_required", reviewDecision([]Review{
			{Reviewer: Actor{Login: "ada"}, State: "approved"},
		}, author), "approving your own pull request is the thing this metric exists to catch")
	})

	t.Run("a bot approval is not review coverage either", func(t *testing.T) {
		require.Equal(t, "review_required", reviewDecision([]Review{
			{Reviewer: Actor{Login: "some-bot", IsBot: true}, State: "approved"},
		}, author))
	})

	t.Run("no reviews at all", func(t *testing.T) {
		require.Equal(t, "review_required", reviewDecision(nil, author))
	})
}

func TestActorOf_DetectsBots(t *testing.T) {
	bot := actorOf(&github.User{
		Login: github.String("dependabot[bot]"),
		Type:  github.String("Bot"),
	})
	require.True(t, bot.IsBot)

	human := actorOf(&github.User{
		Login: github.String("ada"),
		Type:  github.String("User"),
	})
	require.False(t, human.IsBot)

	require.Equal(t, Actor{}, actorOf(nil), "a nil user must not panic")
}

// The budget stops the collector before the quota runs out, and says why. The three ways to
// get this wrong are all in the prior art: exit(1) and lose the run; sleep for an hour a CI
// job does not have; or return what you have and say nothing, which understates every count
// it touched and looks exactly like a quiet repository.
func TestBudget(t *testing.T) {
	b := newBudget()
	require.False(t, b.Exhausted())
	require.Empty(t, b.Reason(), "a budget that has not run out has nothing to explain")

	b.Observe(&github.Response{Rate: github.Rate{Limit: 5000, Remaining: 4000}})
	require.False(t, b.Exhausted())
	n, known := b.Remaining()
	require.True(t, known)
	require.Equal(t, 4000, n)

	// The reserve exists because this token is usually shared — with other steps in the same
	// CI job, and with other tools. Draining it to zero breaks them, not us.
	b.Observe(&github.Response{Rate: github.Rate{Limit: 5000, Remaining: 50}})
	require.True(t, b.Exhausted(), "we stop while there is still headroom left for everyone else")
	require.Contains(t, b.Reason(), "rate limit")
	require.Equal(t, 2, b.Spent())
}

// Inside GitHub Actions the job token's 1,000 requests an hour belong to the whole repository.
// A forge pass that spent them down to a fixed 100 starved CodeQL's SARIF upload and the
// release dispatch on the same push, so the collector keeps half the limit for them.
func TestBudget_KeepsHalfTheLimitForOtherJobs(t *testing.T) {
	cases := []struct {
		limit, remaining int
		exhausted        bool
	}{
		{1000, 501, false},
		{1000, 500, true},
		{1000, 300, true}, // already below the floor when we start: spend nothing more
		{5000, 2501, false},
		{5000, 2500, true},
		{150, 101, false}, // a small limit still keeps at least the fixed reserve
		{150, 100, true},
	}
	for _, c := range cases {
		b := newBudget()
		b.Observe(&github.Response{Rate: github.Rate{Limit: c.limit, Remaining: c.remaining}})
		require.Equal(t, c.exhausted, b.Exhausted(), "limit %d, remaining %d", c.limit, c.remaining)
		if c.exhausted {
			require.Contains(t, b.Reason(), fmt.Sprintf("%d of %d requests left", c.remaining, c.limit))
		}
	}
}

// A response that carries no rate headers (some enterprise instances) cannot exhaust the
// budget on its own; it is still counted.
func TestBudget_UnknownLimit(t *testing.T) {
	b := newBudget()
	b.Observe(&github.Response{})
	require.False(t, b.Exhausted())
	_, known := b.Remaining()
	require.False(t, known)
	require.Equal(t, 1, b.Spent())
}

func TestIsRateLimit(t *testing.T) {
	require.True(t, IsRateLimit(&github.RateLimitError{}))
	require.True(t, IsRateLimit(&github.AbuseRateLimitError{}))
	require.False(t, IsRateLimit(os.ErrNotExist), "a real failure is not a rate limit, and conflating them makes both harder to diagnose")
	require.False(t, IsRateLimit(nil))
}

// earliest is how "first response" reconciles a comment and a review: whichever came first.
// A zero time means "did not happen", and it must never win — a pull request approved in
// thirty seconds with no comments has a first response of thirty seconds, not of never.
func TestEarliest(t *testing.T) {
	var never time.Time
	early := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	late := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	require.Equal(t, early, earliest(early, late))
	require.Equal(t, early, earliest(late, early))
	require.Equal(t, early, earliest(never, early), "a thing that did not happen never wins")
	require.Equal(t, early, earliest(early, never))
	require.True(t, earliest(never, never).IsZero())
}
