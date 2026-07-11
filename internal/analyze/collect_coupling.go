package analyze

// Change coupling: the files that keep changing together.
//
// This is where the hidden architectural dependencies are. Two files with no import between
// them, in different packages, that nonetheless change in the same commit eighty percent of
// the time, are coupled — and nothing in the code says so. It is one of the few metrics that
// finds something a careful reader of the source would not.
//
// The denominator matters. git-intelligence's formula is
//
//	coChangePercentage = coChanges / min(f1Commits, f2Commits) × 100
//
// and `min` is the right choice: it asks "of the times the *rarer* file changed, how often did
// the other change too", which does not punish a pair merely because one of them is touched
// constantly. Using the total, or the max, would bury every real coupling under the noise of
// whatever file everyone edits.
//
// The naive implementation is O(files²) per commit and explodes on a merge that touches nine
// hundred files. So it has caps — and, unlike almost every tool surveyed, it says when it hits
// them. git-intelligence is the honourable exception there and it is the one to copy.

import (
	"fmt"
	"sort"
)

const (
	// A commit touching more than this is a rename, a reformat, or a vendor drop. It tells you
	// nothing about which files are coupled and it costs O(n²) to find that out.
	maxFilesPerCommit = 60

	// The pair budget. Past this the map is bigger than the insight.
	maxPairKeys = 100000

	// Below this a "coupling" is a coincidence.
	minCoChanges = 3
)

type couplingPair struct {
	A, B    string
	Count   int
	Percent float64
}

// couplingStats carries the coupling edges into the graph. A coupled pair IS an edge — two
// files that must move together — so it belongs in the graph rather than in a record type of
// its own, and the canvas can draw it.
type couplingStats struct {
	edges []Edge
}

func collectCoupling(b *Builder, git *gitStats, files *fileStats) *couplingStats {
	st := &couplingStats{}

	if git == nil || len(git.commits) == 0 {
		b.Unmeasured(Metric{
			ID: "quality.coupling.pairs", Family: "quality", Name: "Coupled file pairs",
			Definition: "Pairs of files that change together in the same commit at least 3 times.",
			Unit:       "count",
		}, "The history walk did not run, so there are no commits to derive co-change from.")

		return st
	}

	type pairKey struct{ a, b string }

	pairs := map[pairKey]int{}
	skippedLarge := 0
	pairBudgetHit := false

	for _, c := range git.commits {
		if len(c.Paths) < 2 {
			continue
		}
		if len(c.Paths) > maxFilesPerCommit {
			skippedLarge++

			continue
		}

		paths := make([]string, len(c.Paths))
		copy(paths, c.Paths)
		sort.Strings(paths)

		for i := 0; i < len(paths); i++ {
			for j := i + 1; j < len(paths); j++ {
				if len(pairs) >= maxPairKeys {
					pairBudgetHit = true

					break
				}
				pairs[pairKey{paths[i], paths[j]}]++
			}
			if pairBudgetHit {
				break
			}
		}
	}

	coupled := []couplingPair{}
	for k, n := range pairs {
		if n < minCoChanges {
			continue
		}

		aCommits := git.fileCommits[k.a]
		bCommits := git.fileCommits[k.b]
		denom := aCommits
		if bCommits < denom {
			denom = bCommits
		}
		if denom == 0 {
			continue
		}

		coupled = append(coupled, couplingPair{
			A: k.a, B: k.b, Count: n,
			Percent: float64(n) / float64(denom) * 100,
		})
	}

	// Strongest coupling first, deterministically.
	sort.Slice(coupled, func(i, j int) bool {
		if coupled[i].Percent != coupled[j].Percent {
			return coupled[i].Percent > coupled[j].Percent
		}
		if coupled[i].Count != coupled[j].Count {
			return coupled[i].Count > coupled[j].Count
		}

		return coupled[i].A+coupled[i].B < coupled[j].A+coupled[j].B
	})

	// Each coupled pair becomes a graph edge and is evidenced by that edge. Two facts, one
	// place: the number in the report and the line on the canvas are the same thing.
	refs := make([]EvidenceRef, 0, len(coupled))
	for _, p := range coupled {
		edgeID := fmt.Sprintf("e:couples:%s--%s", p.A, p.B)
		st.edges = append(st.edges, Edge{
			ID:   edgeID,
			Kind: "couples_with",
			From: "file:" + p.A,
			To:   "file:" + p.B,
			// The co-change strength is the confidence: a pair that moves together 90% of the time
			// is a stronger claim than one that does so 40% of the time, and a consumer filters on
			// exactly that.
			Confidence: p.Percent / 100,
			Resolution: "heuristic",
			Properties: map[string]any{
				"coChanges":  p.Count,
				"percentage": p.Percent,
			},
		})

		id := "coupling-" + safeID(edgeID)
		refs = append(refs, b.AddRecord(id, &GraphElementRecord{
			ID:        id,
			Type:      "graph_element",
			ElementID: edgeID,
			Element:   "edge",
		}))
	}

	m := Metric{
		ID: "quality.coupling.pairs", Family: "quality", Name: "Coupled file pairs",
		Definition: fmt.Sprintf(
			"Pairs of files changed together in at least %d commits. The strength is coChanges / min(commits to either file) × 100 — the minimum, so that a pair is not judged by how often the busier of the two is touched. Commits touching more than %d files are excluded: a nine-hundred-file merge says nothing about which files are coupled.",
			minCoChanges, maxFilesPerCommit),
		Classification: &Classification{
			Label:      couplingClass(coupled),
			Thresholds: ">=70% co-change is strong, >=40% moderate",
		},
		References: []Reference{{
			Title: "git-intelligence change coupling",
			URL:   "https://github.com/chrkaatz/git-intelligence",
		}},
	}

	// The pair budget was exhausted, so there are couplings we never counted. How many, we
	// cannot know — but that we stopped, we can say, and a metric that hides the fact it gave
	// up is the failure mode this whole format exists to prevent.
	if pairBudgetHit {
		b.CountTruncated(m, refs, 1, fmt.Sprintf(
			"the co-change pair budget of %d was exhausted; further pairs were not counted", maxPairKeys))
	} else {
		b.Count(m, refs)
	}

	strong := []EvidenceRef{}
	for i, p := range coupled {
		if p.Percent >= 70 {
			strong = append(strong, refs[i])
		}
	}
	b.Count(Metric{
		ID: "quality.coupling.strong", Family: "quality", Name: "Strongly coupled file pairs",
		Definition: "File pairs that change together at least 70% of the time the rarer of the two changes. These are the hidden architectural dependencies: two files that must move together, with nothing in the code to say so.",
	}, strong)

	if skippedLarge > 0 {
		b.Diagnose(Diagnostic{
			Level: "note", Collector: "coupling",
			Message: fmt.Sprintf(
				"%d commits touching more than %d files were excluded from the co-change analysis. A bulk rename or a vendor drop couples nothing; including them would make every file appear coupled to every other.",
				skippedLarge, maxFilesPerCommit),
		})
	}

	return st
}

func couplingClass(pairs []couplingPair) string {
	strong := 0
	for _, p := range pairs {
		if p.Percent >= 70 {
			strong++
		}
	}
	switch {
	case strong == 0:
		return "low"
	case strong <= 10:
		return "moderate"
	default:
		return "high"
	}
}
