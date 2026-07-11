package analyze

// The forge collector: pull requests, issues, reviews, and the compliance metric.
//
// These are the metrics that do not exist in the git object database. A repository knows
// what was committed; only the forge knows what was reviewed, how long it waited, and
// whether anything reached the default branch that nobody approved.
//
// The timing definitions come from issue-metrics, which has the most careful ones in the
// survey, and the care is entirely in the edge cases:
//
//   - A PR's clock starts when it left draft, not when it was opened. Charging a reviewer
//     for the three days an author spent writing the thing is how you get a metric that
//     punishes people for using drafts.
//   - The author's own comments are not a response. Nor are a bot's. Both would give a
//     response time of seconds on a PR nobody has looked at.
//   - A PR closed without merging has no merge time. It has a rejection. Three of the
//     surveyed tools compute a "time to merge" for PRs that were never merged, which is a
//     number describing an event that did not happen.
//
// And the compliance metric is github-metrics-aggregator's, which is the best single metric
// in the whole survey: not "were pull requests reviewed" but "did anything reach the default
// branch that nobody approved". A repository can have flawless review coverage on its PRs
// and still have half its commits pushed straight to main.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/vulnetix/cli/v3/internal/analyze/forge"
)

// maxCommitReviewChecks bounds the compliance pass. Each commit costs at least one API call
// and repos have thousands; the cap is declared in the metric when it bites.
const maxCommitReviewChecks = 300

func collectForge(b *Builder, client *forge.Client, repo forge.Repo, git *gitStats, opts Options, now time.Time, pr reporter) error {
	ctx := context.Background()
	since := now.AddDate(0, 0, -opts.WindowDays)
	window := &MetricWindow{
		Since: since.UTC().Format(time.RFC3339),
		Until: now.UTC().Format(time.RFC3339),
		Label: fmt.Sprintf("last_%d_days", opts.WindowDays),
	}

	// This is the slowest collector by a distance: every pull request costs several API calls
	// (its reviews, its comments, its draft timeline) and every commit costs one more. The
	// request count is reported alongside, because on a busy repository the honest answer to
	// "why is this taking so long" is "it has made 1,400 GitHub calls".
	pr.Stage("Fetching pull requests from GitHub")
	prs, err := client.FetchPullRequests(ctx, repo, since)
	if err != nil {
		return fmt.Errorf("fetch pull requests: %w", err)
	}

	pr.Stage(fmt.Sprintf("Fetching issues from GitHub (%s, %s so far)",
		plural(len(prs), "pull request", "pull requests"),
		plural(client.Budget().Spent(), "API call", "API calls")))
	issues, err := client.FetchIssues(ctx, repo, since)
	if err != nil {
		return fmt.Errorf("fetch issues: %w", err)
	}

	prRefs := emitPullRequests(b, prs, window)
	emitIssues(b, issues, window)

	pr.Stage("Resolving which commits were reviewed")
	emitCommitReview(b, client, repo, git, prRefs, window)

	// If the budget ran out, every count above is short by an unknown amount — and an unknown
	// amount is exactly what must not be silently absorbed. Say it.
	if client.Budget().Exhausted() {
		b.Diagnose(Diagnostic{
			Level: "warning", Collector: "forge",
			Message: client.Budget().Reason(),
		})
	}

	return nil
}

// emitPullRequests writes the PR records and the metrics over them, returning a ref per PR
// URL so the compliance metric can cite the same records rather than duplicating them.
func emitPullRequests(b *Builder, prs []forge.PullRequest, window *MetricWindow) map[string]EvidenceRef {
	refs := make(map[string]EvidenceRef, len(prs))

	var (
		merged     []EvidenceRef
		rejected   []EvidenceRef
		open       []EvidenceRef
		reviewed   []EvidenceRef
		unreviewed []EvidenceRef
		selfMerged []EvidenceRef

		responseSecs []int
		responseRefs []EvidenceRef
		reviewSecs   []int
		reviewRefs   []EvidenceRef
		mergeSecs    []int
		mergeRefs    []EvidenceRef
	)

	for i, pr := range prs {
		rec := &PullRequestRecord{
			ID:           fmt.Sprintf("pr-%d", pr.Number),
			Type:         "pull_request",
			URL:          pr.URL,
			Number:       pr.Number,
			Title:        pr.Title,
			Author:       &Identity{Login: pr.Author.Login, IsBot: pr.Author.IsBot},
			State:        pr.State,
			CreatedAt:    rfc(pr.CreatedAt),
			Additions:    pr.Additions,
			Deletions:    pr.Deletions,
			ChangedFiles: pr.ChangedFiles,
			CommentCount: pr.CommentCount,
			Durations:    &Durations{},
		}
		if !pr.ReadyForReviewAt.IsZero() {
			rec.ReadyForReviewAt = rfc(pr.ReadyForReviewAt)
		}
		if !pr.FirstResponseAt.IsZero() {
			rec.FirstResponseAt = rfc(pr.FirstResponseAt)
		}
		if !pr.FirstReviewAt.IsZero() {
			rec.FirstReviewAt = rfc(pr.FirstReviewAt)
		}
		if !pr.ClosedAt.IsZero() {
			rec.ClosedAt = rfc(pr.ClosedAt)
		}
		// mergedAt stays empty for a PR that was closed without merging. It is not a synonym for
		// closedAt and it never becomes one.
		if !pr.MergedAt.IsZero() {
			rec.MergedAt = rfc(pr.MergedAt)
			rec.MergedBy = &Identity{Login: pr.MergedBy.Login, IsBot: pr.MergedBy.IsBot}
		}
		if pr.TimeInDraftSeconds > 0 {
			rec.TimeInDraftSeconds = &pr.TimeInDraftSeconds
		}
		if pr.State == "open" {
			// A duration measured against "now" grows between runs. Saying so is the difference
			// between a comparable number and a misleading one.
			rec.Durations.OpenEnded = true
		}

		// The anchor. Everything a reviewer could possibly have responded to starts here.
		anchor := pr.ReadyForReviewAt
		if anchor.IsZero() {
			anchor = pr.CreatedAt
		}

		distinctReviewers := map[string]bool{}
		approved := false
		for _, rv := range pr.Reviews {
			if rv.Reviewer.Login == pr.Author.Login || rv.Reviewer.IsBot {
				continue
			}
			distinctReviewers[rv.Reviewer.Login] = true
			if rv.State == "approved" {
				approved = true
			}

			b.AddRecord(fmt.Sprintf("review-%d-%s-%d", pr.Number, rv.Reviewer.Login, rv.SubmittedAt.Unix()),
				&ReviewRecord{
					ID:             fmt.Sprintf("review-%d-%s-%d", pr.Number, rv.Reviewer.Login, rv.SubmittedAt.Unix()),
					Type:           "review",
					PullRequestURL: pr.URL,
					Reviewer:       &Identity{Login: rv.Reviewer.Login, IsBot: rv.Reviewer.IsBot},
					State:          rv.State,
					SubmittedAt:    rfc(rv.SubmittedAt),
				})
		}
		rec.ReviewerCount = len(distinctReviewers)

		switch {
		case approved:
			rec.ApprovalStatus = "approved"
		case len(pr.Reviews) > 0:
			rec.ApprovalStatus = "changes_requested"
		default:
			rec.ApprovalStatus = "review_required"
		}

		if !pr.FirstResponseAt.IsZero() && pr.FirstResponseAt.After(anchor) {
			s := int(pr.FirstResponseAt.Sub(anchor).Seconds())
			rec.Durations.TimeToFirstResponseSeconds = &s
		}
		if !pr.FirstReviewAt.IsZero() && pr.FirstReviewAt.After(anchor) {
			s := int(pr.FirstReviewAt.Sub(anchor).Seconds())
			rec.Durations.TimeToFirstReviewSeconds = &s
		}
		if !pr.MergedAt.IsZero() && pr.MergedAt.After(anchor) {
			s := int(pr.MergedAt.Sub(anchor).Seconds())
			rec.Durations.TimeToMergeSeconds = &s
		}
		if !pr.ClosedAt.IsZero() {
			s := int(pr.ClosedAt.Sub(pr.CreatedAt).Seconds())
			rec.Durations.TimeToCloseSeconds = &s
		}

		ref := b.AddRecord(rec.ID, rec)
		refs[pr.URL] = ref
		_ = i

		switch pr.State {
		case "merged":
			merged = append(merged, ref)
			if len(distinctReviewers) > 0 && approved {
				reviewed = append(reviewed, ref)
			} else {
				unreviewed = append(unreviewed, ref)
			}
			if pr.MergedBy.Login != "" && pr.MergedBy.Login == pr.Author.Login && !approved {
				selfMerged = append(selfMerged, ref)
			}
		case "closed":
			rejected = append(rejected, ref)
		default:
			open = append(open, ref)
		}

		if d := rec.Durations.TimeToFirstResponseSeconds; d != nil {
			responseSecs = append(responseSecs, *d)
			responseRefs = append(responseRefs, ref)
		}
		if d := rec.Durations.TimeToFirstReviewSeconds; d != nil {
			reviewSecs = append(reviewSecs, *d)
			reviewRefs = append(reviewRefs, ref)
		}
		if d := rec.Durations.TimeToMergeSeconds; d != nil {
			mergeSecs = append(mergeSecs, *d)
			mergeRefs = append(mergeRefs, ref)
		}
	}

	all := make([]EvidenceRef, 0, len(prs))
	for _, pr := range prs {
		all = append(all, refs[pr.URL])
	}

	b.Count(Metric{
		ID: "activity.pull_requests.total", Family: "activity", Name: "Pull requests",
		Definition: "Pull requests updated within the history window.",
		Window:     window,
	}, all)

	b.Count(Metric{
		ID: "activity.pull_requests.merged", Family: "activity", Name: "Merged pull requests",
		Definition: "Pull requests that were actually merged. A pull request closed without merging is a rejection, not a merge, and is counted separately.",
		Window:     window,
	}, merged)

	b.Count(Metric{
		ID: "activity.pull_requests.rejected", Family: "activity", Name: "Rejected pull requests",
		Definition: "Pull requests closed without being merged. Counted, rather than dropped — a rejection is data.",
		Window:     window,
	}, rejected)

	b.Count(Metric{
		ID: "activity.pull_requests.open", Family: "activity", Name: "Open pull requests",
		Definition: "Pull requests still open at the time of the scan.",
		Window:     window,
	}, open)

	b.Count(Metric{
		ID: "security.pull_requests.reviewed", Family: "security", Name: "Reviewed merged pull requests",
		Definition: "Merged pull requests with at least one approving review from somebody other than the author. A self-approval is not review coverage.",
		Window:     window,
	}, reviewed)

	b.Count(Metric{
		ID: "security.pull_requests.unreviewed", Family: "security", Name: "Unreviewed merged pull requests",
		Definition: "Merged pull requests with no approving review from anybody other than the author.",
		Window:     window,
		Classification: &Classification{
			Label:      breachClass(len(unreviewed)),
			Thresholds: "0 = clean, 1-5 = minor, 6+ = significant",
		},
	}, unreviewed)

	b.Count(Metric{
		ID: "security.pull_requests.self_merged", Family: "security", Name: "Self-merged pull requests",
		Definition: "Merged pull requests where the author merged their own work with no approving review from anybody else.",
		Window:     window,
	}, selfMerged)

	emitDurationStats(b, "activity.time_to_first_response", "Time to first response",
		"Seconds from a pull request becoming ready for review (not from when it was opened — draft time is not charged to the reviewer) to the first comment or review by somebody other than the author, excluding bots.",
		window, responseSecs, responseRefs)

	emitDurationStats(b, "activity.time_to_first_review", "Time to first review",
		"Seconds from ready-for-review to the first submitted review. A comment is not a review.",
		window, reviewSecs, reviewRefs)

	emitDurationStats(b, "activity.time_to_merge", "Time to merge",
		"Seconds from ready-for-review to merge. Computed only for pull requests that were actually merged; a rejected pull request has no merge time.",
		window, mergeSecs, mergeRefs)

	return refs
}

func emitIssues(b *Builder, issues []forge.Issue, window *MetricWindow) {
	var (
		all       []EvidenceRef
		open      []EvidenceRef
		closed    []EvidenceRef
		noResp    []EvidenceRef
		respSecs  []int
		respRefs  []EvidenceRef
		closeSecs []int
		closeRefs []EvidenceRef
	)

	for _, is := range issues {
		rec := &IssueRecord{
			ID:          fmt.Sprintf("issue-%d", is.Number),
			Type:        "issue",
			URL:         is.URL,
			Number:      is.Number,
			Title:       is.Title,
			Author:      &Identity{Login: is.Author.Login, IsBot: is.Author.IsBot},
			State:       is.State,
			StateReason: is.StateReason,
			Labels:      is.Labels,
			CreatedAt:   rfc(is.CreatedAt),
			Durations:   &Durations{},
		}
		if !is.ClosedAt.IsZero() {
			rec.ClosedAt = rfc(is.ClosedAt)
			s := int(is.ClosedAt.Sub(is.CreatedAt).Seconds())
			rec.Durations.TimeToCloseSeconds = &s
			closeSecs = append(closeSecs, s)
		}
		if !is.FirstResponseAt.IsZero() {
			rec.FirstResponseAt = rfc(is.FirstResponseAt)
			s := int(is.FirstResponseAt.Sub(is.CreatedAt).Seconds())
			rec.Durations.TimeToFirstResponseSeconds = &s
			respSecs = append(respSecs, s)
		}
		if is.State == "open" {
			rec.Durations.OpenEnded = true
		}

		ref := b.AddRecord(rec.ID, rec)
		all = append(all, ref)

		if is.State == "open" {
			open = append(open, ref)
		} else {
			closed = append(closed, ref)
			closeRefs = append(closeRefs, ref)
		}

		if is.FirstResponseAt.IsZero() {
			// Nobody has answered this. Not "response time of zero" — no response at all, which is
			// a fact worth counting on its own rather than dropping out of an average.
			noResp = append(noResp, ref)
		} else {
			respRefs = append(respRefs, ref)
		}
	}

	b.Count(Metric{
		ID: "activity.issues.total", Family: "activity", Name: "Issues",
		Definition: "Issues updated within the history window. Pull requests are excluded — GitHub's issues API returns them, and counting them here would double-count every one.",
		Window:     window,
	}, all)

	b.Count(Metric{
		ID: "activity.issues.open", Family: "activity", Name: "Open issues",
		Definition: "Issues still open at the time of the scan.",
		Window:     window,
	}, open)

	b.Count(Metric{
		ID: "activity.issues.closed", Family: "activity", Name: "Closed issues",
		Definition: "Issues closed within the history window.",
		Window:     window,
	}, closed)

	b.Count(Metric{
		ID: "activity.issues.unanswered", Family: "activity", Name: "Unanswered issues",
		Definition: "Issues with no comment from anybody other than the author, excluding bots. These are excluded from the response-time statistics — an issue nobody answered has no response time, and averaging it in as a zero would say the opposite of the truth.",
		Window:     window,
	}, noResp)

	// closeSecs was appended in the same order as closeRefs.
	emitDurationStats(b, "activity.issues.time_to_close", "Issue time to close",
		"Seconds from an issue being opened to being closed.",
		window, closeSecs, closeRefs)

	emitDurationStats(b, "activity.issues.time_to_first_response", "Issue time to first response",
		"Seconds from an issue being opened to the first comment by somebody other than the author, excluding bots. Issues that were never answered are not in this population.",
		window, respSecs, respRefs)
}

// emitCommitReview is github-metrics-aggregator's compliance metric.
func emitCommitReview(b *Builder, client *forge.Client, repo forge.Repo, git *gitStats,
	prRefs map[string]EvidenceRef, window *MetricWindow) {

	if git == nil || len(git.commits) == 0 {
		b.Unmeasured(Metric{
			ID: "security.commits.unreviewed", Family: "security", Name: "Unreviewed commits on the default branch",
			Definition: "Commits that reached the default branch with no approving review on any associated pull request.",
			Unit:       "count",
		}, "The history walk did not run, so there are no commits to check against the forge.")

		return
	}

	// Only non-merge commits, newest first, capped. A merge commit's review status is the
	// review status of the PR it merged, which we already have.
	shas := make([]string, 0, len(git.commits))
	byShaRef := map[string]EvidenceRef{}
	for _, c := range git.commits {
		if c.ParentCount > 1 {
			continue
		}
		shas = append(shas, c.SHA)
	}

	omitted := 0
	if len(shas) > maxCommitReviewChecks {
		omitted = len(shas) - maxCommitReviewChecks
		shas = shas[:maxCommitReviewChecks]
	}

	// The commit records already exist (the git collector added them); cite them, do not
	// duplicate them. The builder would panic on a duplicate id, which is the point.
	for _, c := range git.commits {
		byShaRef[c.SHA] = EvidenceRef{Kind: "record", RecordID: c.ID}
	}

	results, err := client.FetchCommitReviews(context.Background(), repo, shas)
	if err != nil {
		b.Unmeasured(Metric{
			ID: "security.commits.unreviewed", Family: "security", Name: "Unreviewed commits on the default branch",
			Definition: "Commits that reached the default branch with no approving review on any associated pull request.",
			Unit:       "count",
		}, "Could not resolve commit review status from the forge: "+err.Error())

		return
	}

	var (
		unreviewed []EvidenceRef
		unknown    []EvidenceRef
	)
	for _, r := range results {
		ref, ok := byShaRef[r.SHA]
		if !ok {
			continue
		}
		switch r.Status {
		case "approved":
			// Fine.
		case "unknown":
			// No pull request could be associated. That is not the same as "unreviewed" — it means
			// we could not tell. Reporting it as a breach would turn an absence of evidence into an
			// accusation, so it gets its own metric.
			unknown = append(unknown, ref)
		default:
			unreviewed = append(unreviewed, ref)
		}
	}

	m := Metric{
		ID: "security.commits.unreviewed", Family: "security",
		Name:       "Unreviewed commits on the default branch",
		Definition: "Commits on the default branch whose associated pull request has no approving review from anybody other than the author. Merge commits are excluded — their review status is the pull request's, which is already counted.",
		Window:     window,
		Classification: &Classification{
			Label:      breachClass(len(unreviewed)),
			Thresholds: "0 = clean, 1-5 = minor, 6+ = significant",
		},
		References: []Reference{{
			Title: "github-metrics-aggregator commit_review_status",
			URL:   "https://github.com/abcxyz/github-metrics-aggregator",
		}},
	}

	if omitted > 0 {
		b.CountTruncated(m, unreviewed, omitted, fmt.Sprintf(
			"commit review check capped at %d commits; %d older commits on the default branch were not checked",
			maxCommitReviewChecks, omitted))
	} else {
		b.Count(m, unreviewed)
	}

	b.Count(Metric{
		ID: "security.commits.review_unknown", Family: "security",
		Name:       "Commits with no resolvable pull request",
		Definition: "Commits on the default branch for which no pull request could be found at all. These are NOT counted as unreviewed: we could not tell, and 'we could not tell' is a different claim from 'nobody reviewed it'.",
		Window:     window,
	}, unknown)
}

// emitDurationStats writes mean, median and p90 over a duration population, with the whole
// population as evidence. A statistic without its distribution is a number you cannot argue
// with, which is the same as a number you cannot check.
func emitDurationStats(b *Builder, idPrefix, name, definition string, window *MetricWindow,
	secs []int, refs []EvidenceRef) {

	if len(secs) == 0 {
		b.Unmeasured(Metric{
			ID: idPrefix + ".median", Family: "activity", Name: name + " (median)",
			Definition: definition, Unit: "seconds", Statistic: "median", Window: window,
		}, "No items in the window had this duration, so there is no population to compute a statistic over. This is not a duration of zero.")

		return
	}

	// Sort the values, but keep the refs as the whole population — the evidence is every item
	// the statistic was computed from, not the one at the middle.
	sorted := make([]int, len(secs))
	copy(sorted, secs)
	sort.Ints(sorted)

	b.Statistic(Metric{
		ID: idPrefix + ".median", Family: "activity", Name: name + " (median)",
		Definition: definition, Unit: "seconds", Statistic: "median", Window: window,
	}, float64(median(sorted)), refs)

	b.Statistic(Metric{
		ID: idPrefix + ".p90", Family: "activity", Name: name + " (90th percentile)",
		Definition: definition + " The tail is what people actually experience; the median hides it.",
		Unit:       "seconds", Statistic: "p90", Window: window,
	}, float64(percentile(sorted, 0.90)), refs)

	total := 0
	for _, s := range sorted {
		total += s
	}
	b.Statistic(Metric{
		ID: idPrefix + ".mean", Family: "activity", Name: name + " (mean)",
		Definition: definition, Unit: "seconds", Statistic: "mean", Window: window,
	}, float64(total)/float64(len(sorted)), refs)
}

func breachClass(n int) string {
	switch {
	case n == 0:
		return "clean"
	case n <= 5:
		return "minor"
	default:
		return "significant"
	}
}

func rfc(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return t.UTC().Format(time.RFC3339)
}
