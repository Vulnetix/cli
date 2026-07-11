package analyze

// The file collector: the technology inventory, real cyclomatic complexity, and ownership.
//
// Complexity here is computed, not estimated. git-intelligence uses average diff size as a
// "complexity" proxy and labels it complexity in its UI; that number rises when a file is
// reformatted and falls when it is split, neither of which is a change in complexity. We have
// tree-sitter for 17 languages already wired up in internal/treesitter, so there is no excuse
// for a proxy.
//
// Ownership uses git-intelligence's threshold — a file with at least 3 commits whose top
// author holds 70% or more is a single-maintainer risk — but with the file records as
// evidence, so "we have 14 single-maintainer files" is a list you can open, not a number you
// have to trust.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/treesitter"
)

// decisionQueries count cyclomatic complexity the way gitvoyant does: one point per decision
// point, on a base of 1. The node names differ per grammar; the semantics do not.
//
// A language absent from this map is not silently scored zero — it produces no complexity at
// all, and the diagnostics say which languages were skipped. A zero that means "we did not
// look" is the single most dangerous number a tool like this can emit.
var decisionQueries = map[treesitter.LanguageID]string{
	treesitter.LangGo: `[
		(if_statement) (for_statement) (expression_case) (communication_case) (type_case)
	] @d`,
	treesitter.LangPython: `[
		(if_statement) (while_statement) (for_statement) (except_clause)
		(conditional_expression) (boolean_operator)
	] @d`,
	treesitter.LangJavaScript: `[
		(if_statement) (for_statement) (for_in_statement) (while_statement) (do_statement)
		(switch_case) (catch_clause) (ternary_expression)
	] @d`,
	treesitter.LangTypeScript: `[
		(if_statement) (for_statement) (for_in_statement) (while_statement) (do_statement)
		(switch_case) (catch_clause) (ternary_expression)
	] @d`,
	treesitter.LangJava: `[
		(if_statement) (for_statement) (enhanced_for_statement) (while_statement) (do_statement)
		(switch_block_statement_group) (catch_clause) (ternary_expression)
	] @d`,
	treesitter.LangRuby: `[
		(if) (unless) (while) (until) (for) (case) (rescue) (conditional)
	] @d`,
	treesitter.LangRust: `[
		(if_expression) (while_expression) (for_expression) (loop_expression) (match_arm)
	] @d`,
	treesitter.LangCSharp: `[
		(if_statement) (for_statement) (for_each_statement) (while_statement) (do_statement)
		(switch_section) (catch_clause) (conditional_expression)
	] @d`,
	treesitter.LangPHP: `[
		(if_statement) (for_statement) (foreach_statement) (while_statement) (do_statement)
		(switch_block) (catch_clause) (conditional_expression)
	] @d`,
	treesitter.LangC: `[
		(if_statement) (for_statement) (while_statement) (do_statement) (case_statement)
		(conditional_expression)
	] @d`,
	treesitter.LangCPP: `[
		(if_statement) (for_statement) (while_statement) (do_statement) (case_statement)
		(catch_clause) (conditional_expression)
	] @d`,
}

// skipDirs are never walked. Vendored and generated trees are not this repository's code, and
// counting them makes every metric about somebody else's work.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true, "target": true, ".gradle": true,
	".idea": true, ".vscode": true, ".next": true, ".nuxt": true, "coverage": true,
	".cache": true, "site-packages": true, "third_party": true, ".terraform": true,
}

const maxFileBytes = 1 << 20 // 1 MiB. Past this a source file is generated, not written.

type fileStats struct {
	files []*FileRecord
}

func collectFiles(b *Builder, root string, git *gitStats, opts Options, now time.Time, pr reporter) (*fileStats, error) {
	engine := reachability.NewEngine()
	ctx := context.Background()

	st := &fileStats{}
	skippedLangs := map[string]int{}
	var skippedLarge int

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}

			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		size := int(info.Size())
		if size > maxFileBytes {
			skippedLarge++

			return nil
		}

		lang := treesitter.LanguageForPath(path)
		if lang == "" {
			return nil
		}

		rec := &FileRecord{
			ID:        "file-" + safeID(rel),
			Type:      "file",
			Path:      rel,
			Language:  string(lang),
			SizeBytes: &size,
		}

		src, rerr2 := os.ReadFile(path)
		if rerr2 == nil {
			lines := strings.Count(string(src), "\n") + 1
			rec.Lines = &lines

			query, supported := decisionQueries[lang]
			if !supported {
				skippedLangs[string(lang)]++
			} else if matches, qerr := engine.Run(ctx, lang, src, query); qerr == nil {
				// Cyclomatic complexity: decision points plus one.
				c := len(matches) + 1
				rec.Complexity = &c
			}
		}

		// History-derived facts, if the file has any. A file with no commits in the window is not
		// a file with zero commits — it simply predates the window, and its ownership is unknown
		// from here.
		if git != nil {
			if n, ok := git.fileCommits[rel]; ok {
				rec.Commits = n
				authors := git.fileAuthors[rel]
				rec.Authors = len(authors)

				topEmail, topCount := "", 0
				for email, count := range authors {
					if count > topCount || (count == topCount && email < topEmail) {
						topEmail, topCount = email, count
					}
				}
				if topEmail != "" && n > 0 {
					id := Identity{Email: topEmail}
					if c, ok := git.byEmail[topEmail]; ok {
						id = *c.Identity
					}
					rec.Ownership = &Ownership{
						TopAuthor:       &id,
						TopAuthorShare:  float64(topCount) / float64(n),
						DistinctAuthors: len(authors),
					}
				}
				if t, ok := git.fileFirst[rel]; ok {
					rec.FirstSeenAt = t.UTC().Format(time.RFC3339)
				}
				if t, ok := git.fileLast[rel]; ok {
					rec.LastChangedAt = t.UTC().Format(time.RFC3339)
				}
			}
		}

		st.files = append(st.files, rec)

		// Parsing every file with tree-sitter is the second-slowest pass. Same reason as the
		// history walk: a count that climbs is a tool that is working.
		if len(st.files)%100 == 0 {
			pr.Stage("Reading files (" + plural(len(st.files), "file", "files") + ")")
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk files: %w", err)
	}

	sort.Slice(st.files, func(i, j int) bool { return st.files[i].Path < st.files[j].Path })

	emitFileMetrics(b, st, git, opts, now, skippedLangs, skippedLarge)

	return st, nil
}

func emitFileMetrics(b *Builder, st *fileStats, git *gitStats, opts Options, now time.Time,
	skippedLangs map[string]int, skippedLarge int) {

	refs := make(map[string]EvidenceRef, len(st.files))
	all := make([]EvidenceRef, 0, len(st.files))
	for _, f := range st.files {
		r := b.AddFile(f)
		refs[f.Path] = r
		all = append(all, r)
	}

	b.Count(Metric{
		ID: "business.files.source", Family: "business", Name: "Source files",
		Definition: "Files with a recognised source language, excluding vendored, generated and dependency directories, and files over 1 MiB.",
	}, all)

	// ─── language inventory ────────────────────────────────────────────────────
	byLang := map[string][]EvidenceRef{}
	for _, f := range st.files {
		byLang[f.Language] = append(byLang[f.Language], refs[f.Path])
	}
	langs := make([]string, 0, len(byLang))
	for l := range byLang {
		langs = append(langs, l)
	}
	sort.Strings(langs)

	for _, l := range langs {
		b.Count(Metric{
			ID:         "business.language." + safeMetricSegment(l),
			Family:     "business",
			Name:       "Files in " + l,
			Definition: "Source files detected as " + l + ", by file extension.",
		}, byLang[l])
	}

	// ─── complexity ────────────────────────────────────────────────────────────
	// The median, evidenced by the whole population it was computed over. A median with no
	// distribution behind it is a number you can only take on faith.
	withComplexity := []*FileRecord{}
	for _, f := range st.files {
		if f.Complexity != nil {
			withComplexity = append(withComplexity, f)
		}
	}

	if len(withComplexity) > 0 {
		values := make([]int, 0, len(withComplexity))
		popRefs := make([]EvidenceRef, 0, len(withComplexity))
		for _, f := range withComplexity {
			values = append(values, *f.Complexity)
			popRefs = append(popRefs, refs[f.Path])
		}
		sort.Ints(values)

		b.Statistic(Metric{
			ID: "quality.complexity.median", Family: "quality", Name: "Median file complexity",
			Definition: "Median cyclomatic complexity across source files, counted as decision points plus one (if/for/while/case/catch/ternary/boolean operators), per language, via tree-sitter. Files in languages with no complexity grammar are excluded, not scored zero.",
			Unit:       "count", Statistic: "median",
		}, float64(median(values)), popRefs)

		b.Statistic(Metric{
			ID: "quality.complexity.p90", Family: "quality", Name: "90th-percentile file complexity",
			Definition: "90th-percentile cyclomatic complexity across source files. The tail is where the maintenance cost lives; the median hides it.",
			Unit:       "count", Statistic: "p90",
		}, float64(percentile(values, 0.90)), popRefs)

		// The complex files themselves, as a countable set — this is the actionable one.
		threshold := opts.ComplexityThreshold
		complex := []EvidenceRef{}
		for _, f := range withComplexity {
			if *f.Complexity >= threshold {
				complex = append(complex, refs[f.Path])
			}
		}
		b.Count(Metric{
			ID: "quality.complexity.high", Family: "quality", Name: "Highly complex files",
			Definition: fmt.Sprintf("Source files with cyclomatic complexity of %d or more.", threshold),
			Classification: &Classification{
				Label:      complexityClass(len(complex), len(withComplexity)),
				Thresholds: fmt.Sprintf("complexity >= %d", threshold),
			},
		}, complex)
	}

	// A language we cannot measure is reported as unmeasured, per language. Otherwise a repo
	// that is 90% Swift looks like a repo with no complexity at all.
	if len(skippedLangs) > 0 {
		names := make([]string, 0, len(skippedLangs))
		for l := range skippedLangs {
			names = append(names, l)
		}
		sort.Strings(names)
		b.Diagnose(Diagnostic{
			Level: "warning", Collector: "files", MetricID: "quality.complexity.median",
			Message: "No complexity grammar for: " + strings.Join(names, ", ") +
				". Files in these languages are excluded from the complexity metrics rather than counted as zero.",
		})
	}
	if skippedLarge > 0 {
		b.Diagnose(Diagnostic{
			Level: "note", Collector: "files",
			Message: fmt.Sprintf("%d files over 1 MiB were skipped as generated rather than written.", skippedLarge),
		})
	}

	// ─── ownership ─────────────────────────────────────────────────────────────
	// git-intelligence's single-maintainer rule: at least 3 commits, and the top author holds
	// 70% or more. The evidence is the files themselves, so the number opens into a list.
	if git != nil {
		singleMaintainer := []EvidenceRef{}
		fragmented := []EvidenceRef{}
		for _, f := range st.files {
			if f.Ownership == nil {
				continue
			}
			if f.Commits >= 3 && f.Ownership.TopAuthorShare >= 0.70 {
				singleMaintainer = append(singleMaintainer, refs[f.Path])
			}
			// The opposite failure: a file so many people touch that nobody owns it.
			if f.Commits >= 10 && f.Ownership.DistinctAuthors >= 5 {
				fragmented = append(fragmented, refs[f.Path])
			}
		}

		b.Count(Metric{
			ID: "maintainability.ownership.single_maintainer", Family: "maintainability",
			Name:       "Single-maintainer files",
			Definition: "Files with at least 3 commits in the window where one author holds 70% or more of them. The knowledge concentration risk.",
			Classification: &Classification{
				Label:      ownershipClass(len(singleMaintainer)),
				Thresholds: ">=3 commits and top-author share >=70%",
			},
			References: []Reference{{Title: "git-intelligence SINGLE_MAINTAINER_THRESHOLD", URL: "https://github.com/chrkaatz/git-intelligence"}},
		}, singleMaintainer)

		b.Count(Metric{
			ID: "maintainability.ownership.fragmented", Family: "maintainability",
			Name:       "Fragmented files",
			Definition: "Files with at least 10 commits touched by 5 or more distinct authors — the opposite of concentration, where nobody owns the file.",
		}, fragmented)

		// Hotspots: the files that change most. Churn alone is not a problem — it is normal
		// activity — but churn crossed with complexity is where the cost is.
		hot := []*FileRecord{}
		for _, f := range st.files {
			if f.Commits > 0 && f.Complexity != nil {
				hot = append(hot, f)
			}
		}
		sort.SliceStable(hot, func(i, j int) bool {
			return hot[i].Commits*(*hot[i].Complexity) > hot[j].Commits*(*hot[j].Complexity)
		})

		hotRefs := []EvidenceRef{}
		for _, f := range hot {
			if f.Commits >= 5 && *f.Complexity >= opts.ComplexityThreshold {
				hotRefs = append(hotRefs, refs[f.Path])
			}
		}
		b.Count(Metric{
			ID: "quality.hotspots", Family: "quality", Name: "Hotspots",
			Definition: fmt.Sprintf("Files that are both frequently changed (>=5 commits in the window) and complex (cyclomatic >= %d). Churn alone is normal activity; churn crossed with complexity is where maintenance cost concentrates.", opts.ComplexityThreshold),
		}, hotRefs)
	}
}

func complexityClass(high, total int) string {
	if total == 0 {
		return "unknown"
	}
	share := float64(high) / float64(total)
	switch {
	case share >= 0.20:
		return "high"
	case share >= 0.05:
		return "moderate"
	default:
		return "low"
	}
}

func ownershipClass(n int) string {
	switch {
	case n == 0:
		return "low"
	case n <= 5:
		return "moderate"
	default:
		return "high"
	}
}

// median over a sorted slice. Even-length inputs average the two middle values — Measure's
// helper indexes the middle of an unsorted array and calls the result a median, which it is
// not, and the mistake is invisible in its output.
func median(sorted []int) int {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}

	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// percentile over a sorted slice, by nearest rank.
func percentile(sorted []int, p float64) int {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	i := int(p * float64(n-1))
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}

	return sorted[i]
}

func safeMetricSegment(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("+", "p", "#", "sharp", " ", "_", "-", "_", ".", "_").Replace(s)

	return safeID(s)
}
