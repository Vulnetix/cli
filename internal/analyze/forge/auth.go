// Package forge talks to the code-hosting platform — today, GitHub.
//
// `analyze` needs it for the metrics that do not exist in a git repository at all: how long
// a pull request waited for its first review, whether a commit that reached the default
// branch was ever approved by anyone, how long an issue sat unanswered. None of that is in
// the object database; it lives in the forge, and without credentials it cannot be known.
//
// Which is why the authentication check runs *before* any scanning starts and fails loudly.
// Discovering at the end of a five-minute analysis that a third of the report is null
// because a token was missing is a waste of the user's time, and a report full of nulls is
// exactly the kind of thing people stop reading.
package forge

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-github/v66/github"
)

// Credentials are a token and the story of where it came from. The source is reported to
// the user because "which of my four possible tokens is this thing actually using" is a
// question people should never have to reverse-engineer.
type Credentials struct {
	Token  string
	Source string // GITHUB_TOKEN | GH_TOKEN | gh CLI
}

// ResolveCredentials finds a GitHub token, in the order a user would expect one to win.
//
//  1. GITHUB_TOKEN — always present inside GitHub Actions, which is where analyze runs in
//     anger. If it is set, it is what CI intends us to use.
//  2. GH_TOKEN — the same idea, the variable the gh CLI itself honours first.
//  3. The gh CLI's own credential store, via `gh auth token`. We shell out rather than
//     reading ~/.config/gh/hosts.yml directly: gh may keep the token in the system keyring
//     instead of that file, and hand-parsing its config would break silently the day it
//     changes storage. Asking gh is the only way to get an answer that stays true.
func ResolveCredentials(ctx context.Context) (*Credentials, error) {
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return &Credentials{Token: v, Source: name}, nil
		}
	}

	if tok, err := ghCLIToken(ctx); err == nil && tok != "" {
		return &Credentials{Token: tok, Source: "gh CLI"}, nil
	}

	return nil, ErrNoCredentials
}

// ErrNoCredentials carries the fix, not just the failure. An error that tells you what went
// wrong and not what to do about it makes the reader do work we already know how to do.
var ErrNoCredentials = fmt.Errorf(`no GitHub credentials found.

  vulnetix analyze reads pull requests, reviews and issues from GitHub to compute review
  coverage, response times, and whether commits reached the default branch unreviewed. None
  of that exists in the git repository itself.

  Authenticate in any one of these ways:

    export GITHUB_TOKEN=<token>     # in GitHub Actions this is already set for you:
                                    #   env:
                                    #     GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    export GH_TOKEN=<token>
    gh auth login                   # the gh CLI's own credentials are picked up

  The token needs read access to the repository's pull requests, issues and contents.

  Or run with --no-forge to skip these metrics entirely. They will be reported as
  "not measured" rather than zero — the report never claims we looked when we did not`)

// repoAccessError explains a token that works but cannot see this repository.
//
// The raw error is "404 Not Found", which is a lie of omission: the repository exists, and
// GitHub says 404 rather than 403 precisely so that it does not confirm the existence of a
// private repo to somebody who cannot read it. Passing that 404 through untranslated sends the
// reader off to check whether they typed the repo name wrong, which they did not.
func repoAccessError(creds *Credentials, login string, repo Repo, resp *github.Response, err error) error {
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}

	if status != http.StatusNotFound && status != http.StatusForbidden {
		return fmt.Errorf("GitHub could not read %s/%s: %w", repo.Owner, repo.Name, err)
	}

	return fmt.Errorf(`the GitHub token from %s is valid (authenticated as %s) but cannot read %s/%s.

  GitHub answers with "404 Not Found" rather than "403 Forbidden" for a private repository the
  token cannot see — it will not confirm that the repository exists. So this is almost certainly
  an access problem, not a typo.

  If it is a fine-grained personal access token, it must list this repository (or its
  organisation) under "Repository access", with read access to Contents, Pull requests, Issues
  and Metadata.

  Fixes, in order of least effort:

    gh auth refresh -s repo        # if you are using the gh CLI's token
    export GITHUB_TOKEN=<token>    # a classic token with the `+"`repo`"+` scope
                                   # in GitHub Actions this is already set, and already
                                   # scoped to the repository it runs in

  Or run with --no-forge to skip GitHub entirely. The pull-request, review and issue metrics
  are then reported as "not measured" rather than zero — the report never claims we looked when
  we did not`, creds.Source, login, repo.Owner, repo.Name)
}

func ghCLIToken(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("gh"); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

// CheckResult is what the startup check learned. RateLimitRemaining is reported because a
// user whose token has 12 requests left should find that out now, not two thousand API
// calls into the run.
type CheckResult struct {
	Login              string
	Source             string
	RateLimitRemaining int
	RateLimitLimit     int
	RateLimitResetsAt  time.Time
}

func (c CheckResult) String() string {
	login := c.Login
	if login == "" {
		login = "repository-scoped token"
	}

	return fmt.Sprintf("GitHub authentication: ok (%s via %s, %s/%s requests remaining)",
		login, c.Source, comma(c.RateLimitRemaining), comma(c.RateLimitLimit))
}

// Check verifies the credentials actually work, before any scanning begins.
//
// Two checks, not one. For user tokens, /user proves the token is valid; for GitHub Actions'
// repository-scoped GITHUB_TOKEN, /user is deliberately forbidden, so repository access is the
// validity check. In both cases the important proof is that the token can see *this
// repository*, because that is where pull requests, reviews and issues are read from.
//
// A fine-grained PAT is valid for the user and still cannot read a private repo it was not
// granted — and GitHub answers that with **404, not 403**, because telling you a private repo
// exists would leak its existence. So a perfectly good token produces "404 Not Found" on a repo
// that is right there in front of you. Discovering that four minutes into a scan, from a raw
// API error, is not a diagnosis anybody can act on.
//
// repo may be zero-valued (owner and name empty), in which case only the token is checked.
func Check(ctx context.Context, creds *Credentials, host string, repo Repo) (*CheckResult, error) {
	client, err := NewClient(creds, host)
	if err != nil {
		return nil, err
	}

	user, _, err := client.gh.Users.Get(ctx, "")
	if err != nil {
		if repo.Owner == "" || repo.Name == "" {
			return nil, fmt.Errorf("GitHub rejected the token from %s: %w", creds.Source, err)
		}

		if _, resp, rerr := client.gh.Repositories.Get(ctx, repo.Owner, repo.Name); rerr != nil {
			return nil, repoAccessError(creds, "repository-scoped token", repo, resp, rerr)
		}

		limits, _, lerr := client.gh.RateLimit.Get(ctx)
		if lerr != nil {
			return &CheckResult{Source: creds.Source}, nil
		}

		core := limits.GetCore()

		return &CheckResult{
			Source:             creds.Source,
			RateLimitRemaining: core.Remaining,
			RateLimitLimit:     core.Limit,
			RateLimitResetsAt:  core.Reset.Time,
		}, nil
	}

	if repo.Owner != "" && repo.Name != "" {
		if _, resp, rerr := client.gh.Repositories.Get(ctx, repo.Owner, repo.Name); rerr != nil {
			return nil, repoAccessError(creds, user.GetLogin(), repo, resp, rerr)
		}
	}

	limits, _, err := client.gh.RateLimit.Get(ctx)
	if err != nil {
		// The token works — we just could not read the quota. Not a reason to fail: report
		// what we know and carry on.
		return &CheckResult{Login: user.GetLogin(), Source: creds.Source}, nil
	}

	core := limits.GetCore()

	return &CheckResult{
		Login:              user.GetLogin(),
		Source:             creds.Source,
		RateLimitRemaining: core.Remaining,
		RateLimitLimit:     core.Limit,
		RateLimitResetsAt:  core.Reset.Time,
	}, nil
}

// Client wraps go-github with the rate-limit discipline this tool needs.
type Client struct {
	gh *github.Client

	// budget stops us mid-way rather than half-completing. A collector that runs out of
	// quota reports what it got and declares what it dropped; it does not fail the command,
	// and it does not pretend the missing items were not there.
	budget *budget
}

func NewClient(creds *Credentials, host string) (*Client, error) {
	http := &http.Client{Timeout: 30 * time.Second}
	gh := github.NewClient(http).WithAuthToken(creds.Token)

	// GitHub Enterprise Server. The public host needs no base-URL override.
	if host != "" && host != "github.com" {
		var err error
		gh, err = gh.WithEnterpriseURLs("https://"+host, "https://"+host)
		if err != nil {
			return nil, fmt.Errorf("configure GitHub Enterprise host %s: %w", host, err)
		}
	}

	return &Client{gh: gh, budget: newBudget()}, nil
}

// GitHub reports the raw client for the calls the collector makes directly.
func (c *Client) GitHub() *github.Client { return c.gh }

// Budget reports the remaining request allowance.
func (c *Client) Budget() *budget { return c.budget }

// IsGitHubHost reports whether a repo host is GitHub. A GitLab repository must not fail for
// want of a GitHub token — refusing to analyze a repo we were never going to call GitHub
// about would be a bug wearing a security hat.
func IsGitHubHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))

	return h == "github.com" || strings.HasPrefix(h, "github.")
}

func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}

	return b.String()
}
