package forge

// Fetching pull requests, issues, reviews and the commit→PR association.
//
// The shapes returned here are deliberately plain: this package knows about GitHub, and the
// collector that consumes it knows about metrics. Keeping the seam there means the day we
// add GitLab, only this package changes.

import (
	"context"
	"strings"
	"time"

	"github.com/google/go-github/v66/github"
)

const perPage = 100

// PullRequest is one PR, with the timestamps the timing metrics anchor on.
type PullRequest struct {
	Number int
	URL    string
	Title  string
	Author Actor
	State  string // open | closed | merged

	CreatedAt time.Time
	ClosedAt  time.Time
	MergedAt  time.Time // zero when the PR was closed without merging. Never a substitute for ClosedAt.
	MergedBy  Actor

	// ReadyForReviewAt is when the PR left draft, derived from its timeline. Response and
	// merge times anchor here rather than at CreatedAt, so time a PR spent as a draft is not
	// charged against the people who reviewed it once it was ready.
	ReadyForReviewAt time.Time

	// TimeInDraftSeconds is summed across *every* draft interval, not just the first — a PR
	// can be flipped back to draft, and pretending it cannot understates the wait.
	TimeInDraftSeconds int

	Additions    int
	Deletions    int
	ChangedFiles int

	FirstResponseAt time.Time // first comment or review by someone who is not the author, and not a bot
	FirstReviewAt   time.Time // first *submitted review*, which is not the same thing as a comment
	CommentCount    int

	Reviews []Review
}

// Review is one submitted review.
type Review struct {
	Reviewer    Actor
	State       string // approved | changes_requested | commented | dismissed
	SubmittedAt time.Time
}

// Issue is one issue (never a PR — GitHub's REST API returns PRs from the issues endpoint,
// and conflating the two double-counts everything).
type Issue struct {
	Number      int
	URL         string
	Title       string
	Author      Actor
	State       string
	StateReason string
	Labels      []string

	CreatedAt       time.Time
	ClosedAt        time.Time
	FirstResponseAt time.Time
}

// Actor is a GitHub account, with the one fact every metric needs to know about it.
type Actor struct {
	Login string
	IsBot bool
}

// CommitReview is the answer to GMA's question: did this commit, which is on the default
// branch, ever get approved by anybody?
type CommitReview struct {
	SHA string

	// PRNumber and PRURL are zero/empty when no pull request could be associated with the
	// commit at all.
	PRNumber int
	PRURL    string

	// Status is one of:
	//   approved          — a PR exists and someone other than the author approved it
	//   changes_requested — a PR exists and the last word on it was "no"
	//   review_required   — a PR exists and nobody approved it
	//   unknown           — no PR could be associated with this commit
	//
	// `unknown` and `review_required` are kept apart on purpose. One means "we could not
	// tell", the other means "we could tell, and it was not reviewed". Collapsing them turns
	// an absence of evidence into an accusation.
	Status string
}

// Repo identifies what we are fetching.
type Repo struct {
	Owner         string
	Name          string
	DefaultBranch string
}

// FetchPullRequests returns every PR updated within the window, newest first, with its
// reviews and the timestamps the metrics need.
//
// Stops early and reports `truncated` when the budget runs out. It never returns a partial
// set silently — the caller checks the budget and declares the shortfall.
func (c *Client) FetchPullRequests(ctx context.Context, repo Repo, since time.Time) ([]PullRequest, error) {
	opts := &github.PullRequestListOptions{
		State:       "all",
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: github.ListOptions{PerPage: perPage},
	}

	var out []PullRequest
	for {
		if c.budget.Exhausted() {
			return out, nil
		}

		prs, resp, err := c.gh.PullRequests.List(ctx, repo.Owner, repo.Name, opts)
		c.budget.Observe(resp)
		if err != nil {
			if IsRateLimit(err) {
				return out, nil
			}

			return out, err
		}

		for _, pr := range prs {
			// Sorted by updated desc, so the first PR older than the window means every PR after
			// it is too.
			if pr.GetUpdatedAt().Time.Before(since) {
				return out, nil
			}

			p, ferr := c.hydratePR(ctx, repo, pr)
			if ferr != nil {
				if IsRateLimit(ferr) {
					return out, nil
				}

				continue
			}
			out = append(out, p)
		}

		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

// hydratePR fills in the things the list endpoint does not tell us: reviews, the first
// response, and the draft history.
func (c *Client) hydratePR(ctx context.Context, repo Repo, pr *github.PullRequest) (PullRequest, error) {
	p := PullRequest{
		Number:       pr.GetNumber(),
		URL:          pr.GetHTMLURL(),
		Title:        pr.GetTitle(),
		Author:       actorOf(pr.GetUser()),
		CreatedAt:    pr.GetCreatedAt().Time,
		ClosedAt:     pr.GetClosedAt().Time,
		MergedAt:     pr.GetMergedAt().Time,
		MergedBy:     actorOf(pr.GetMergedBy()),
		Additions:    pr.GetAdditions(),
		Deletions:    pr.GetDeletions(),
		ChangedFiles: pr.GetChangedFiles(),
		CommentCount: pr.GetComments(),
	}

	switch {
	case !p.MergedAt.IsZero():
		p.State = "merged"
	case !p.ClosedAt.IsZero():
		// Closed and not merged. This PR was rejected, and it stays that way — three of the
		// tools surveyed quietly count a rejection as a close and then compute a "time to
		// merge" for it, which is a number describing something that never happened.
		p.State = "closed"
	default:
		p.State = "open"
	}

	p.ReadyForReviewAt, p.TimeInDraftSeconds = c.draftHistory(ctx, repo, pr)

	reviews, err := c.fetchReviews(ctx, repo, pr.GetNumber())
	if err != nil {
		return p, err
	}
	p.Reviews = reviews

	for _, rv := range reviews {
		if rv.Reviewer.Login == p.Author.Login || rv.Reviewer.IsBot {
			continue
		}
		if p.FirstReviewAt.IsZero() || rv.SubmittedAt.Before(p.FirstReviewAt) {
			p.FirstReviewAt = rv.SubmittedAt
		}
	}

	firstComment, err := c.firstNonAuthorComment(ctx, repo, pr.GetNumber(), p.Author)
	if err != nil && !IsRateLimit(err) {
		return p, err
	}

	// The first response is whichever came first: a comment, or a review. A review is a
	// response; treating only comments as responses would say a PR that was approved in
	// thirty seconds never got one.
	p.FirstResponseAt = earliest(firstComment, p.FirstReviewAt)

	// Anything that happened before the PR was ready for review does not count as a
	// response to it. The reviewer was not being slow; there was nothing to review.
	if !p.ReadyForReviewAt.IsZero() && !p.FirstResponseAt.IsZero() &&
		p.FirstResponseAt.Before(p.ReadyForReviewAt) {
		p.FirstResponseAt = time.Time{}
	}

	return p, nil
}

// draftHistory walks the PR's timeline for draft transitions, and returns when it became
// ready plus the total time it spent in draft across every cycle.
func (c *Client) draftHistory(ctx context.Context, repo Repo, pr *github.PullRequest) (readyAt time.Time, draftSeconds int) {
	// A PR that was never a draft is ready the moment it is opened.
	if !pr.GetDraft() && pr.GetNumber() == 0 {
		return pr.GetCreatedAt().Time, 0
	}

	opts := &github.ListOptions{PerPage: perPage}
	var draftSince time.Time
	created := pr.GetCreatedAt().Time

	// A PR opened as a draft is in draft from the moment it exists.
	if pr.GetDraft() {
		draftSince = created
	}

	for {
		if c.budget.Exhausted() {
			break
		}
		events, resp, err := c.gh.Issues.ListIssueTimeline(ctx, repo.Owner, repo.Name, pr.GetNumber(), opts)
		c.budget.Observe(resp)
		if err != nil {
			break
		}

		for _, e := range events {
			at := e.GetCreatedAt().Time
			switch e.GetEvent() {
			case "convert_to_draft":
				draftSince = at
			case "ready_for_review":
				if readyAt.IsZero() {
					readyAt = at
				}
				if !draftSince.IsZero() {
					draftSeconds += int(at.Sub(draftSince).Seconds())
					draftSince = time.Time{}
				}
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Still open and still in draft: the clock is running. This is the one place an
	// open-ended duration is counted, and the record says so.
	if !draftSince.IsZero() && pr.GetDraft() {
		draftSeconds += int(time.Since(draftSince).Seconds())
	}

	if readyAt.IsZero() && !pr.GetDraft() {
		readyAt = created
	}

	return readyAt, draftSeconds
}

func (c *Client) fetchReviews(ctx context.Context, repo Repo, number int) ([]Review, error) {
	opts := &github.ListOptions{PerPage: perPage}
	var out []Review

	for {
		if c.budget.Exhausted() {
			return out, nil
		}
		rs, resp, err := c.gh.PullRequests.ListReviews(ctx, repo.Owner, repo.Name, number, opts)
		c.budget.Observe(resp)
		if err != nil {
			return out, err
		}
		for _, r := range rs {
			out = append(out, Review{
				Reviewer:    actorOf(r.GetUser()),
				State:       strings.ToLower(r.GetState()),
				SubmittedAt: r.GetSubmittedAt().Time,
			})
		}
		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

// firstNonAuthorComment finds the first comment by somebody other than the author, ignoring
// bots. Both exclusions matter: a PR where the author talks to themselves has not been
// responded to, and a PR where a CI bot posted a status check has not been responded to
// either — but both would show a response time of seconds if you counted them.
func (c *Client) firstNonAuthorComment(ctx context.Context, repo Repo, number int, author Actor) (time.Time, error) {
	opts := &github.IssueListCommentsOptions{
		Sort:        github.String("created"),
		Direction:   github.String("asc"),
		ListOptions: github.ListOptions{PerPage: perPage},
	}

	if c.budget.Exhausted() {
		return time.Time{}, nil
	}

	comments, resp, err := c.gh.Issues.ListComments(ctx, repo.Owner, repo.Name, number, opts)
	c.budget.Observe(resp)
	if err != nil {
		return time.Time{}, err
	}

	for _, cm := range comments {
		a := actorOf(cm.GetUser())
		if a.Login == author.Login || a.IsBot {
			continue
		}

		return cm.GetCreatedAt().Time, nil
	}

	return time.Time{}, nil
}

// FetchIssues returns issues (not PRs) updated within the window.
func (c *Client) FetchIssues(ctx context.Context, repo Repo, since time.Time) ([]Issue, error) {
	opts := &github.IssueListByRepoOptions{
		State:       "all",
		Sort:        "updated",
		Direction:   "desc",
		Since:       since,
		ListOptions: github.ListOptions{PerPage: perPage},
	}

	var out []Issue
	for {
		if c.budget.Exhausted() {
			return out, nil
		}

		issues, resp, err := c.gh.Issues.ListByRepo(ctx, repo.Owner, repo.Name, opts)
		c.budget.Observe(resp)
		if err != nil {
			if IsRateLimit(err) {
				return out, nil
			}

			return out, err
		}

		for _, is := range issues {
			// GitHub returns pull requests from the issues endpoint. Counting them here would
			// double-count every PR — once as a PR and once as an issue — and quietly halve every
			// issue response-time average by mixing in the faster PR population.
			if is.IsPullRequest() {
				continue
			}

			i := Issue{
				Number:      is.GetNumber(),
				URL:         is.GetHTMLURL(),
				Title:       is.GetTitle(),
				Author:      actorOf(is.GetUser()),
				State:       is.GetState(),
				StateReason: is.GetStateReason(),
				CreatedAt:   is.GetCreatedAt().Time,
				ClosedAt:    is.GetClosedAt().Time,
			}
			for _, l := range is.Labels {
				i.Labels = append(i.Labels, l.GetName())
			}

			first, ferr := c.firstNonAuthorComment(ctx, repo, is.GetNumber(), i.Author)
			if ferr != nil && IsRateLimit(ferr) {
				out = append(out, i)

				return out, nil
			}
			i.FirstResponseAt = first

			out = append(out, i)
		}

		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

// FetchCommitReviews answers, for each commit, whether it was ever approved.
//
// This is github-metrics-aggregator's compliance metric and it is the best one in the
// survey: not "were PRs reviewed" but "did anything reach the default branch that nobody
// approved". A repo can have perfect review coverage on its PRs and still have half its
// commits pushed straight to main.
func (c *Client) FetchCommitReviews(ctx context.Context, repo Repo, shas []string) ([]CommitReview, error) {
	out := make([]CommitReview, 0, len(shas))

	for _, sha := range shas {
		if c.budget.Exhausted() {
			return out, nil
		}

		prs, resp, err := c.gh.PullRequests.ListPullRequestsWithCommit(
			ctx, repo.Owner, repo.Name, sha,
			&github.ListOptions{PerPage: perPage},
		)
		c.budget.Observe(resp)
		if err != nil {
			if IsRateLimit(err) {
				return out, nil
			}

			// One commit we cannot resolve is not a reason to abandon the rest. It is recorded as
			// `unknown`, which is what it is.
			out = append(out, CommitReview{SHA: sha, Status: "unknown"})

			continue
		}

		cr := CommitReview{SHA: sha, Status: "unknown"}

		for _, pr := range prs {
			// Only PRs that targeted the default branch. A commit that reached main via a PR into
			// a release branch that was later merged is a different question.
			if pr.GetBase().GetRef() != repo.DefaultBranch {
				continue
			}

			reviews, rerr := c.fetchReviews(ctx, repo, pr.GetNumber())
			if rerr != nil && IsRateLimit(rerr) {
				return out, nil
			}

			status := reviewDecision(reviews, actorOf(pr.GetUser()))

			cr.PRNumber = pr.GetNumber()
			cr.PRURL = pr.GetHTMLURL()
			cr.Status = status

			// An approval anywhere is enough. Keep looking only while we have not found one.
			if status == "approved" {
				break
			}
		}

		out = append(out, cr)
	}

	return out, nil
}

// reviewDecision collapses a PR's reviews into one verdict.
//
// Any approval wins, regardless of what came before it — a "changes requested" that was
// later addressed and approved is a review that worked, not a breach. Self-approval does not
// count, which is the whole point of the metric.
func reviewDecision(reviews []Review, author Actor) string {
	decision := "review_required"

	for _, r := range reviews {
		if r.Reviewer.Login == author.Login || r.Reviewer.IsBot {
			continue
		}
		switch r.State {
		case "approved":
			return "approved"
		case "changes_requested":
			decision = "changes_requested"
		}
	}

	return decision
}

func actorOf(u *github.User) Actor {
	if u == nil {
		return Actor{}
	}

	return Actor{
		Login: u.GetLogin(),
		IsBot: strings.EqualFold(u.GetType(), "Bot") || strings.HasSuffix(u.GetLogin(), "[bot]"),
	}
}

func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case a.Before(b):
		return a
	default:
		return b
	}
}
