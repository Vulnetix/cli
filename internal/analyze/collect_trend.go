package analyze

// Complexity as a time series.
//
// This is gitvoyant's idea and it is the most interesting one in the survey: complexity is
// not a property of a file, it is a trajectory. A file at 40 that has been at 40 for two years
// is fine. A file at 25 that was at 8 six months ago is on fire, and a snapshot cannot tell
// you which is which.
//
// It is also the idea gitvoyant implements wrongly, in two ways worth naming because both are
// easy to repeat:
//
//  1. **It regresses against the commit index, not against time.** `polyfit(range(len(series)),
//     complexity, 1)` — and then reports the slope as complexity "per month". For a file with
//     ten commits in one afternoon and one commit a year later, that number is meaningless. We
//     regress against the actual timestamps and report complexity per day.
//
//  2. **Its "confidence" is a step function of the commit count.** 0.9 if there are ten
//     commits, 0.75 if seven. That is a sample-size heuristic wearing a statistician's coat: it
//     says nothing about whether the points actually lie on the line. We use R² — how much of
//     the variance the trend explains — alongside the sample size, and report both.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/treesitter"
)

const (
	// How many files get the treatment. Walking history per file is expensive, so only the
	// files that matter: the ones that are both complex and busy.
	maxTrendFiles = 25

	// Samples per file. More than this buys precision nobody uses.
	maxTrendSamples = 30

	// Below this, a line through the points is a line through noise.
	minTrendSamples = 5
)

type trendPoint struct {
	at         time.Time
	complexity int
	sha        string
}

// trendInfo is what we learned about one file's trajectory. It rides on the file's graph node
// rather than becoming a record type of its own: a trend is a property of a file, not a
// separate kind of thing, and the node is where a consumer already looks for what we know
// about that file.
type trendInfo struct {
	SlopePerDay float64
	RSquared    float64
	Samples     int
	From        string
	To          string
	Rising      bool
}

type trendStats struct {
	byPath map[string]trendInfo
}

func collectTrend(b *Builder, repo *git.Repository, files *fileStats, git2 *gitStats, opts Options, pr reporter) *trendStats {
	st := &trendStats{byPath: map[string]trendInfo{}}

	if repo == nil || git2 == nil || files == nil {
		b.Unmeasured(Metric{
			ID: "quality.complexity.rising", Family: "quality", Name: "Files with rising complexity",
			Definition: "Files whose cyclomatic complexity is trending upward over the history window.",
			Unit:       "count",
		}, "The history walk or the file pass did not run, so complexity cannot be tracked over time.")

		return st
	}

	// The candidates: complex AND busy. A complex file nobody touches is not getting worse, and
	// a busy file that is trivial does not matter.
	type candidate struct {
		rec   *FileRecord
		score int
	}
	var candidates []candidate
	for _, f := range files.files {
		if f.Complexity == nil || f.Commits < minTrendSamples {
			continue
		}
		candidates = append(candidates, candidate{rec: f, score: *f.Complexity * f.Commits})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}

		return candidates[i].rec.Path < candidates[j].rec.Path
	})
	if len(candidates) > maxTrendFiles {
		candidates = candidates[:maxTrendFiles]
	}

	engine := reachability.NewEngine()
	ctx := context.Background()

	var (
		rising     []EvidenceRef
		allSlopes  []float64
		population []EvidenceRef
	)

	for i, c := range candidates {
		lang := treesitter.LanguageID(c.rec.Language)
		query, ok := decisionQueries[lang]
		if !ok {
			continue
		}

		// Each file here means re-reading it at up to 30 commits and re-parsing every one, so this
		// is the slowest pass per unit of output. Name the file: it is the only stage where a user
		// can tell whether the tool is stuck on something pathological.
		pr.Stage(fmt.Sprintf("Tracking complexity (%d/%d) %s", i+1, len(candidates), c.rec.Path))

		series := sampleComplexity(ctx, engine, repo, c.rec.Path, lang, query, opts)
		if len(series) < minTrendSamples {
			continue
		}

		slope, r2 := fitPerDay(series)

		// Rising: gaining complexity, and the line actually fits. A steep slope through scattered
		// points is not a trend, it is an accident — and reporting it as one is how you send
		// somebody to refactor a file that was never getting worse.
		isRising := slope > 0.01 && r2 >= 0.5

		info := trendInfo{
			SlopePerDay: slope,
			RSquared:    r2,
			Samples:     len(series),
			From:        series[0].at.UTC().Format(time.RFC3339),
			To:          series[len(series)-1].at.UTC().Format(time.RFC3339),
			Rising:      isRising,
		}
		st.byPath[c.rec.Path] = info

		// The evidence is the file's node, which carries the slope, the fit and the sample count.
		// A reader who wants to check the number opens the node and finds the working.
		id := "trend-" + safeID(c.rec.Path)
		ref := b.AddRecord(id, &GraphElementRecord{
			ID:        id,
			Type:      "graph_element",
			ElementID: "file:" + c.rec.Path,
			Element:   "node",
		})

		population = append(population, ref)
		allSlopes = append(allSlopes, slope)

		if isRising {
			rising = append(rising, ref)
		}
	}

	b.Count(Metric{
		ID: "quality.complexity.rising", Family: "quality", Name: "Files with rising complexity",
		Definition: "Files whose cyclomatic complexity is trending upward: a least-squares slope of more than 0.01 per DAY, with R² of at least 0.5 so that the line actually fits the points. The slope is regressed against calendar time, not against the commit index — a file with ten commits in one afternoon and one a year later has a per-commit slope that means nothing.",
		Classification: &Classification{
			Label:      risingClass(len(rising)),
			Thresholds: "slope > 0.01/day and R² >= 0.5",
		},
		References: []Reference{{
			Title: "gitvoyant temporal analysis (whose slope is per-commit, not per-day)",
			URL:   "https://github.com/Cre4T3Tiv3/gitvoyant",
		}},
	}, rising)

	if len(allSlopes) > 0 {
		sort.Float64s(allSlopes)
		mid := allSlopes[len(allSlopes)/2]
		b.Statistic(Metric{
			ID: "quality.complexity.trend_median", Family: "quality",
			Name:       "Median complexity trend",
			Definition: "Median least-squares slope of cyclomatic complexity per day, across the busiest and most complex files. A positive number means the codebase's hot files are getting harder to work in.",
			Unit:       "count", Statistic: "median",
		}, mid, population)
	}

	b.Diagnose(Diagnostic{
		Level: "note", Collector: "trend", Caveat: true,
		Message: fmt.Sprintf(
			"Complexity trends are computed for at most %d files — the most complex and most frequently changed. A file not in that set has no trend in this report, which is not the same as having a flat one.",
			maxTrendFiles),
	})

	return st
}

// sampleComplexity walks a file's own history and measures its complexity at each commit that
// touched it.
func sampleComplexity(ctx context.Context, engine *reachability.Engine, repo *git.Repository,
	path string, lang treesitter.LanguageID, query string, opts Options) []trendPoint {

	head, err := repo.Head()
	if err != nil {
		return nil
	}

	iter, err := repo.Log(&git.LogOptions{From: head.Hash(), FileName: &path})
	if err != nil {
		return nil
	}
	defer iter.Close()

	var out []trendPoint
	since := time.Now().AddDate(0, 0, -opts.WindowDays)

	_ = iter.ForEach(func(c *object.Commit) error {
		if len(out) >= maxTrendSamples {
			return errStopWalk
		}
		if c.Committer.When.Before(since) {
			return errStopWalk
		}

		f, ferr := c.File(path)
		if ferr != nil {
			return nil
		}
		src, cerr := f.Contents()
		if cerr != nil {
			return nil
		}

		matches, qerr := engine.Run(ctx, lang, []byte(src), query)
		if qerr != nil {
			// A commit at which the file did not parse contributes nothing. gitvoyant records it as
			// complexity zero, which drags every trend downward and can turn a rising file into a
			// falling one.
			return nil
		}

		out = append(out, trendPoint{
			at:         c.Committer.When,
			complexity: len(matches) + 1,
			sha:        c.Hash.String(),
		})

		return nil
	})

	// Oldest first, so the regression runs forward through time.
	sort.Slice(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })

	return out
}

// fitPerDay computes a least-squares slope in complexity-per-day, and the R² of the fit.
//
// R² is the honest confidence: it is the proportion of the variance the line explains. A slope
// of +2/day through points scattered everywhere has an R² near zero and should be believed
// about as much. A step function of the sample count — which is what gitvoyant calls confidence
// — cannot distinguish those two cases at all.
func fitPerDay(series []trendPoint) (slopePerDay, r2 float64) {
	n := float64(len(series))
	if n < 2 {
		return 0, 0
	}

	// x in days since the first sample. Regressing against real elapsed time is the whole point.
	origin := series[0].at
	xs := make([]float64, len(series))
	ys := make([]float64, len(series))
	for i, p := range series {
		xs[i] = p.at.Sub(origin).Hours() / 24
		ys[i] = float64(p.complexity)
	}

	var sumX, sumY float64
	for i := range xs {
		sumX += xs[i]
		sumY += ys[i]
	}
	meanX, meanY := sumX/n, sumY/n

	var num, den float64
	for i := range xs {
		dx := xs[i] - meanX
		num += dx * (ys[i] - meanY)
		den += dx * dx
	}
	if den == 0 {
		// Every sample landed at the same instant. There is no time axis to regress against, and
		// pretending otherwise would divide by zero and call the result a trend.
		return 0, 0
	}
	slopePerDay = num / den
	intercept := meanY - slopePerDay*meanX

	var ssRes, ssTot float64
	for i := range xs {
		pred := intercept + slopePerDay*xs[i]
		ssRes += (ys[i] - pred) * (ys[i] - pred)
		ssTot += (ys[i] - meanY) * (ys[i] - meanY)
	}
	if ssTot == 0 {
		// Complexity never changed. A perfectly flat line fits perfectly.
		return 0, 1
	}
	r2 = 1 - ssRes/ssTot
	if math.IsNaN(r2) || math.IsInf(r2, 0) {
		r2 = 0
	}

	return slopePerDay, r2
}

func risingClass(n int) string {
	switch {
	case n == 0:
		return "stable"
	case n <= 3:
		return "watch"
	default:
		return "degrading"
	}
}
