package analyze

// The git-history collector: commits, contributors, activity, bus factor, ownership.
//
// Every metric here is evidenced by the commits and contributors that produced it, which is
// what makes it different from the tools it borrows from. The formulas are theirs and are
// cited where they are used; the trail back to the underlying commits is not.
//
// Three things are done deliberately differently from the prior art:
//
//   - Bus factor's evidence is the whole ranked contributor list, not the N people it names.
//     A bus factor of 2 means nothing without the distribution behind it, and DevStats — which
//     has the best definition of it — reports the number with no way to see the ranking.
//   - Bots are excluded from every human metric and counted separately, rather than being
//     dropped on the floor. A repo where 80% of commits are Dependabot is telling you something.
//   - A cap that is hit is declared. git-intelligence is the only surveyed tool that admits
//     when it gave up; everyone else silently truncates.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

// errStopWalk ends the history walk early. go-git treats storer.ErrStop as "the caller has
// seen enough", not as a failure, so it must not be reported as one.
var errStopWalk = storer.ErrStop

// The development-status ladder, from kospex. Its virtue is that it is one ladder applied to
// everything — repos, contributors, dependency files — so a reader learns it once.
const devStatusThresholds = "<=90d Active, <=180d Aging, <=365d Stale, else Unmaintained"

func developmentStatus(daysSince float64) string {
	switch {
	case daysSince <= 90:
		return "Active"
	case daysSince <= 180:
		return "Aging"
	case daysSince <= 365:
		return "Stale"
	default:
		return "Unmaintained"
	}
}

var coAuthorLine = regexp.MustCompile(`(?im)^\s*co-authored-by:\s*(.+?)\s*<([^>]+)>\s*$`)

type gitStats struct {
	commits      []*CommitRecord
	contributors []*ContributorRecord
	byEmail      map[string]*ContributorRecord

	// Per-file authorship, for ownership and hotspot metrics.
	fileCommits map[string]int
	fileAuthors map[string]map[string]int
	fileFirst   map[string]time.Time
	fileLast    map[string]time.Time

	walked    int
	truncated bool
	window    Window
}

// collectGit walks history once and derives everything that comes from it. One walk, because
// the reference tools that re-walk per metric (gitvoyant re-walks per file, git-intelligence
// re-parses per cache miss) are the ones that fall over on large repositories.
func collectGit(b *Builder, repo *git.Repository, opts Options, now time.Time, pr reporter) (*gitStats, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("resolve HEAD: %w", err)
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	defer iter.Close()

	st := &gitStats{
		byEmail:     map[string]*ContributorRecord{},
		fileCommits: map[string]int{},
		fileAuthors: map[string]map[string]int{},
		fileFirst:   map[string]time.Time{},
		fileLast:    map[string]time.Time{},
	}
	ids := NewIdentitySet()
	since := now.AddDate(0, 0, -opts.WindowDays)

	err = iter.ForEach(func(c *object.Commit) error {
		if st.walked >= opts.MaxCommits {
			st.truncated = true

			return errStopWalk
		}
		if c.Committer.When.Before(since) {
			return errStopWalk
		}
		st.walked++

		// The diff of every commit is the slowest thing this collector does. Reporting the count
		// as it climbs is what tells a reader the tool is working rather than wedged.
		if st.walked%50 == 0 {
			pr.Stage("Walking history (" + plural(st.walked, "commit", "commits") + ")")
		}

		author := ClassifyIdentity(c.Author.Name, c.Author.Email)
		committer := ClassifyIdentity(c.Committer.Name, c.Committer.Email)

		rec := &CommitRecord{
			ID:          "commit-" + c.Hash.String()[:12],
			Type:        "commit",
			SHA:         c.Hash.String(),
			Message:     firstLine(c.Message),
			AuthoredAt:  c.Author.When.UTC().Format(time.RFC3339),
			CommittedAt: c.Committer.When.UTC().Format(time.RFC3339),
			Author:      &author,
			Committer:   &committer,
			ParentCount: c.NumParents(),
			Signature: &Signature{
				Signed: strings.TrimSpace(c.PGPSignature) != "",
				// go-git gives us the signature but verifying it needs the signer's public key,
				// which we do not have. "present but unverified" is the honest answer; claiming
				// "valid" would be a lie and claiming "none" would be a different one.
				Verification: verificationState(c.PGPSignature),
			},
		}

		// Co-authored-by trailers are a first-class contribution signal — DevStats treats them
		// as one and it is right to. A commit with co-authors is evidence for each of them.
		for _, m := range coAuthorLine.FindAllStringSubmatch(c.Message, -1) {
			rec.CoAuthors = append(rec.CoAuthors, ClassifyIdentity(m[1], m[2]))
		}

		cycle := int(c.Committer.When.Sub(c.Author.When).Seconds())
		rec.CycleTimeSeconds = &cycle

		// Paths and line counts, only for non-merge commits: a merge's diff against its first
		// parent attributes the whole branch to the merger, which is how squash-heavy repos end
		// up crediting the person who pressed the button.
		if c.NumParents() <= 1 {
			if stats, serr := c.Stats(); serr == nil {
				for _, s := range stats {
					rec.Insertions += s.Addition
					rec.Deletions += s.Deletion
					rec.Paths = append(rec.Paths, s.Name)

					st.fileCommits[s.Name]++
					if st.fileAuthors[s.Name] == nil {
						st.fileAuthors[s.Name] = map[string]int{}
					}
					st.fileAuthors[s.Name][author.Email]++
					if f, ok := st.fileFirst[s.Name]; !ok || c.Committer.When.Before(f) {
						st.fileFirst[s.Name] = c.Committer.When
					}
					if l, ok := st.fileLast[s.Name]; !ok || c.Committer.When.After(l) {
						st.fileLast[s.Name] = c.Committer.When
					}
				}
				rec.FilesChanged = len(stats)
			}
		}

		st.commits = append(st.commits, rec)

		// Contributor accumulation: the author, plus every co-author. Not the committer — on a
		// rebase or a merge the committer is whoever ran the command, and counting them inflates
		// exactly the people who did the least.
		for _, id := range append([]Identity{author}, rec.CoAuthors...) {
			c2 := ids.Observe(id)
			c2.Commits++
			c2.Insertions += rec.Insertions
			c2.Deletions += rec.Deletions
			at := c.Committer.When
			if c2.FirstSeenAt == "" || at.Before(parseTime(c2.FirstSeenAt)) {
				c2.FirstSeenAt = at.UTC().Format(time.RFC3339)
			}
			if c2.LastSeenAt == "" || at.After(parseTime(c2.LastSeenAt)) {
				c2.LastSeenAt = at.UTC().Format(time.RFC3339)
			}
			if now.Sub(at).Hours() <= 24*90 {
				c2.CommitsInWindow++
			}
		}

		return nil
	})
	if err != nil && err != errStopWalk {
		return nil, fmt.Errorf("walk history: %w", err)
	}

	st.contributors = ids.All()
	for _, c := range st.contributors {
		first, last := parseTime(c.FirstSeenAt), parseTime(c.LastSeenAt)
		tenure := int(last.Sub(first).Seconds())
		c.TenureSeconds = &tenure
		c.Status = strings.ToLower(developmentStatus(now.Sub(last).Hours() / 24))
		st.byEmail[c.Identity.Email] = c
	}

	st.window = Window{
		CommitsWalked: st.walked,
		CommitLimit:   opts.MaxCommits,
	}
	if len(st.commits) > 0 {
		st.window.Until = st.commits[0].CommittedAt
		st.window.Since = st.commits[len(st.commits)-1].CommittedAt
	}

	emitGitMetrics(b, st, opts, now)

	return st, nil
}

func emitGitMetrics(b *Builder, st *gitStats, opts Options, now time.Time) {
	window := &MetricWindow{Since: st.window.Since, Until: st.window.Until,
		Label: fmt.Sprintf("last_%d_days", opts.WindowDays)}

	// Every commit and contributor becomes an evidence record exactly once. Metrics reference
	// them; nothing duplicates them.
	commitRefs := make(map[string]EvidenceRef, len(st.commits))
	for _, c := range st.commits {
		commitRefs[c.SHA] = b.AddRecord(c.ID, c)
	}
	contribRefs := make(map[string]EvidenceRef, len(st.contributors))
	for _, c := range st.contributors {
		contribRefs[c.Identity.Email] = b.AddRecord(c.ID, c)
	}

	// ─── commits ───────────────────────────────────────────────────────────────
	humanCommits := []EvidenceRef{}
	botCommits := []EvidenceRef{}
	agentCommits := []EvidenceRef{}
	signedCommits := []EvidenceRef{}
	mergeCommits := []EvidenceRef{}
	fixCommits := []EvidenceRef{}
	revertCommits := []EvidenceRef{}

	for _, c := range st.commits {
		ref := commitRefs[c.SHA]
		switch {
		case c.Author.BotKind == "ai-agent":
			agentCommits = append(agentCommits, ref)
		case c.Author.IsBot:
			botCommits = append(botCommits, ref)
		default:
			humanCommits = append(humanCommits, ref)
		}
		if c.Signature != nil && c.Signature.Signed {
			signedCommits = append(signedCommits, ref)
		}
		if c.ParentCount > 1 {
			mergeCommits = append(mergeCommits, ref)
		}
		msg := strings.ToLower(c.Message)
		if matchesAny(msg, "fix", "bug", "hotfix", "patch", "repair", "resolve", "correct") {
			fixCommits = append(fixCommits, ref)
		}
		if matchesAny(msg, "revert", "undo", "rollback") {
			revertCommits = append(revertCommits, ref)
		}
	}

	commitMetric := Metric{
		ID: "activity.commits.total", Family: "activity", Name: "Commits",
		Definition: "Commits reachable from HEAD within the history window, including bot and agent commits.",
		Window:     window,
	}
	allCommitRefs := make([]EvidenceRef, 0, len(st.commits))
	for _, c := range st.commits {
		allCommitRefs = append(allCommitRefs, commitRefs[c.SHA])
	}
	if st.truncated {
		// The cap was hit. Say so, say by how much we cannot know, and do not pretend the number
		// is the whole story. We know how many we walked, not how many exist — so the honest
		// statement is that at least one was omitted and the limit is why.
		b.CountTruncated(commitMetric, allCommitRefs, 1,
			fmt.Sprintf("history walk stopped at the --max-commits limit of %d; older commits were not read", opts.MaxCommits))
	} else {
		b.Count(commitMetric, allCommitRefs)
	}

	b.Count(Metric{
		ID: "activity.commits.human", Family: "activity", Name: "Human commits",
		Definition: "Commits whose author was not classified as a bot or an AI agent.",
		Window:     window,
	}, humanCommits)

	b.Count(Metric{
		ID: "activity.commits.bot", Family: "activity", Name: "Bot commits",
		Definition: "Commits authored by a CI, dependency or service bot (see the identity catalog for the rule that classified each).",
		Window:     window,
	}, botCommits)

	b.Count(Metric{
		ID: "activity.commits.ai_agent", Family: "activity", Name: "AI-agent commits",
		Definition: "Commits authored by an AI coding agent. Counted separately from both humans and CI bots, because an agent's commits are neither.",
		Window:     window,
	}, agentCommits)

	b.Count(Metric{
		ID: "security.commits.signed", Family: "security", Name: "Signed commits",
		Definition: "Commits carrying a PGP signature. Presence only — verification needs the signer's public key, which the CLI does not have, so a signed commit is reported as present-but-unverified rather than valid.",
		Window:     window,
	}, signedCommits)

	b.Count(Metric{
		ID: "activity.commits.merge", Family: "activity", Name: "Merge commits",
		Definition: "Commits with more than one parent.",
		Window:     window,
	}, mergeCommits)

	b.Count(Metric{
		ID: "quality.commits.fix", Family: "quality", Name: "Fix commits",
		Definition: "Commits whose subject begins with a corrective word (fix, bug, hotfix, patch, repair, resolve, correct). Depends entirely on commit-message discipline; see the caveat in diagnostics.",
		Window:     window,
	}, fixCommits)

	b.Count(Metric{
		ID: "quality.commits.revert", Family: "quality", Name: "Revert commits",
		Definition: "Commits whose subject begins with revert, undo or rollback — the firefighting signal.",
		Window:     window,
	}, revertCommits)

	// ─── contributors ──────────────────────────────────────────────────────────
	humans := []*ContributorRecord{}
	humanRefs := []EvidenceRef{}
	activeRefs := []EvidenceRef{}
	newRefs := []EvidenceRef{}
	departedRefs := []EvidenceRef{}

	for _, c := range st.contributors {
		if c.Identity.IsBot {
			continue
		}
		humans = append(humans, c)
		ref := contribRefs[c.Identity.Email]
		humanRefs = append(humanRefs, ref)

		last := parseTime(c.LastSeenAt)
		first := parseTime(c.FirstSeenAt)
		daysSinceLast := now.Sub(last).Hours() / 24
		daysSinceFirst := now.Sub(first).Hours() / 24

		if daysSinceLast <= 90 {
			activeRefs = append(activeRefs, ref)
		}
		if daysSinceFirst <= 90 {
			newRefs = append(newRefs, ref)
		}
		// A leaver, per kospex: silent for more than 90 days, but active at some point within the
		// last year. Someone gone for two years is not a recent departure, they are history.
		if daysSinceLast > 90 && daysSinceLast <= 365 {
			departedRefs = append(departedRefs, ref)
		}
	}

	b.Count(Metric{
		ID: "activity.contributors.total", Family: "activity", Name: "Contributors",
		Definition: "Distinct human contributors (commit authors and Co-authored-by trailers) in the history window, after identity merging. Bots and AI agents are excluded.",
		Window:     window,
	}, humanRefs)

	b.Count(Metric{
		ID: "activity.contributors.active", Family: "activity", Name: "Active contributors",
		Definition:     "Human contributors with at least one commit in the last 90 days.",
		Window:         window,
		Classification: &Classification{Label: "Active", Thresholds: devStatusThresholds},
	}, activeRefs)

	b.Count(Metric{
		ID: "activity.contributors.new", Family: "activity", Name: "New contributors",
		Definition: "Human contributors whose first commit in the window was within the last 90 days.",
		Window:     window,
	}, newRefs)

	b.Count(Metric{
		ID: "activity.contributors.departed", Family: "activity", Name: "Departed contributors",
		Definition: "Human contributors silent for more than 90 days but active within the last 365 — the recent-departure signal. Contributors gone longer than a year are excluded as history rather than churn.",
		Window:     window,
	}, departedRefs)

	// ─── bus factor ────────────────────────────────────────────────────────────
	// DevStats' definition: rank contributors by commits descending, take the cumulative share,
	// and find the smallest number of people whose combined share first exceeds 50%.
	//
	// The evidence is the ENTIRE ranked list, not the N people the number names. A bus factor of
	// 2 is meaningless without the distribution that produced it, and every tool that reports
	// the number without the ranking is asking to be believed rather than checked.
	if len(humans) > 0 {
		ranked := make([]*ContributorRecord, len(humans))
		copy(ranked, humans)
		sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Commits > ranked[j].Commits })

		total := 0
		for _, c := range ranked {
			total += c.Commits
		}

		busFactor := 0
		if total > 0 {
			cum := 0
			for i, c := range ranked {
				cum += c.Commits
				if float64(cum)/float64(total) > 0.5 {
					busFactor = i + 1

					break
				}
			}
		}

		rankedRefs := make([]EvidenceRef, 0, len(ranked))
		for _, c := range ranked {
			rankedRefs = append(rankedRefs, contribRefs[c.Identity.Email])
		}

		b.Statistic(Metric{
			ID: "activity.bus_factor.commits", Family: "activity", Name: "Bus factor (commits)",
			Definition:     "The smallest number of contributors whose cumulative share of commits, ranked descending, first exceeds 50% of all commits in the window. Bots excluded. The evidence is the whole ranked contributor list, because the number means nothing without the distribution behind it.",
			Unit:           "count",
			Window:         window,
			Classification: busFactorClass(busFactor),
			References:     []Reference{{Title: "DevStats bus_factor.sql", URL: "https://github.com/cncf/devstats/blob/master/metrics/shared/bus_factor.sql"}},
		}, float64(busFactor), rankedRefs)

		// Top-contributor concentration — the other half of the same question, and the one that
		// makes a bus factor of 1 vivid.
		if total > 0 {
			share := float64(ranked[0].Commits) / float64(total)
			b.Statistic(Metric{
				ID: "activity.ownership.top_contributor_share", Family: "activity",
				Name:       "Top contributor share",
				Definition: "Share of all human commits in the window authored by the single most prolific contributor.",
				Unit:       "ratio", Statistic: "value",
				Window: window,
			}, share, rankedRefs)
		}
	}

	// ─── repository liveness ───────────────────────────────────────────────────
	if len(st.commits) > 0 {
		last := parseTime(st.commits[0].CommittedAt)
		days := now.Sub(last).Hours() / 24
		b.Assertion(Metric{
			ID: "maintainability.repo.status", Family: "maintainability", Name: "Repository status",
			Definition: "Development status from days since the most recent commit. " + devStatusThresholds + ".",
			Unit:       "categorical",
			Classification: &Classification{
				Label:      developmentStatus(days),
				Thresholds: devStatusThresholds,
			},
			References: []Reference{{Title: "kospex development_status", URL: "https://github.com/kospex/kospex"}},
		}, developmentStatus(days), []EvidenceRef{commitRefs[st.commits[0].SHA]})
	}

	// Caveats belong in the report, not in a README nobody reads. git-intelligence is the only
	// surveyed tool that ships them with its output, and it is right to.
	b.Diagnose(Diagnostic{
		Level: "note", Collector: "git", Caveat: true,
		Message: "Squash-merge workflows flatten authorship: commit counts then reflect the person who merged, not the person who wrote the code.",
	})
	b.Diagnose(Diagnostic{
		Level: "note", Collector: "git", Caveat: true,
		Message: "Fix and revert rates depend entirely on how consistently commit messages are written, and are not comparable across repositories with different conventions.",
	})
}

func busFactorClass(n int) *Classification {
	const thresholds = "1 = critical, 2 = at risk, 3-5 = moderate, 6+ = healthy"
	switch {
	case n <= 1:
		return &Classification{Label: "critical", Thresholds: thresholds}
	case n == 2:
		return &Classification{Label: "at risk", Thresholds: thresholds}
	case n <= 5:
		return &Classification{Label: "moderate", Thresholds: thresholds}
	default:
		return &Classification{Label: "healthy", Thresholds: thresholds}
	}
}

func verificationState(sig string) string {
	if strings.TrimSpace(sig) == "" {
		return "none"
	}

	return "unknown"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}

	return strings.TrimSpace(s)
}

func matchesAny(msg string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}

	return false
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)

	return t
}
