// Command sasteff measures the embedded SAST rules: whether each one reports
// the defect it was written for (recall), whether it stays quiet on code that
// only resembles it (precision), what it costs to evaluate, and how often it
// fires on real code.
//
//	sasteff cases    [stem...]          run fixture cases (internal/sast/testdata/efficacy)
//	sasteff secrets                     prove each generated secret rule fires on its own token shape
//	sasteff coverage                    list rules with no positive or no negative case
//	sasteff snapshot -out f.json [-secrets] dir... freeze a corpus for repeatable measurement
//	sasteff perf -snapshot f.json       per-rule compile/eval cost and finding counts
//	sasteff hits -snapshot f.json stem  the findings one rule produces on the corpus
//	sasteff total dir...                full-ruleset wall time through the engine
//	sasteff check -base D -clean f -vuln f stem   cases, corpus hits and cost, original vs current
//	sasteff compare -base D -snapshot f           every rule, original vs current: findings, cost, outliers
//	sasteff bench -snapshot f -labels P=csv stem   score against OWASP Benchmark labels
//	sasteff cofire -snapshot f[,f...]              rule pairs that report the same lines
//
// Every command reads rules from -rules (default internal/sast/rules) on disk,
// so an edited rule is measured without rebuilding. Run from the repository
// root, or pass -rules and -cases.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/sast/efficacy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "cases":
		os.Exit(runCases(args))
	case "secrets":
		os.Exit(runSecrets(args))
	case "coverage":
		os.Exit(runCoverage(args))
	case "snapshot":
		os.Exit(runSnapshot(args))
	case "perf":
		os.Exit(runPerf(args))
	case "hits":
		os.Exit(runHits(args))
	case "total":
		os.Exit(runTotal(args))
	case "bench":
		os.Exit(runBench(args))
	case "check":
		os.Exit(runCheck(args))
	case "compare":
		os.Exit(runCompare(args))
	case "cofire":
		os.Exit(runCofire(args))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sasteff cases|secrets|coverage|snapshot|perf|hits|total [flags] [args]")
	os.Exit(2)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sasteff: "+format+"\n", a...)
	os.Exit(2)
}

func common(fs *flag.FlagSet) (rules, cases *string) {
	rules = fs.String("rules", "internal/sast/rules", "rule directory")
	cases = fs.String("cases", "internal/sast/testdata/efficacy", "fixture case directory")
	return
}

func loadRules(dir string) *efficacy.Rules {
	r, err := efficacy.LoadRules(dir)
	if err != nil {
		fatal("rules: %v", err)
	}
	return r
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if path == "-" {
		os.Stdout.Write(append(b, '\n'))
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal("write %s: %v", path, err)
	}
}

// ── cases ────────────────────────────────────────────────────────────────

func runCases(args []string) int {
	fs := flag.NewFlagSet("cases", flag.ExitOnError)
	rulesDir, casesDir := common(fs)
	jsonOut := fs.String("json", "", "write results as JSON to this path (- for stdout)")
	quiet := fs.Bool("q", false, "print failures and the summary only")
	workers := fs.Int("workers", 8, "cases evaluated concurrently")
	_ = fs.Parse(args)

	rules := loadRules(*rulesDir)
	cs, err := efficacy.LoadCases(*casesDir, fs.Args()...)
	if err != nil {
		fatal("cases: %v", err)
	}
	if len(cs) == 0 {
		fmt.Println("no cases")
		return 1
	}
	results := make([]efficacy.Result, len(cs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, *workers))
	for i := range cs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = efficacy.RunCase(rules, cs[i])
		}(i)
	}
	wg.Wait()

	failed := 0
	for _, r := range results {
		if !r.Pass() {
			failed++
		}
		if !*quiet || !r.Pass() {
			fmt.Println(efficacy.Describe(r))
		}
	}
	sums := efficacy.Summarise(cs, results)
	fmt.Println()
	fmt.Printf("%-34s %5s %4s %4s %4s %4s %7s %9s\n", "rule", "cases", "tp", "fn", "fp", "fail", "recall", "precision")
	for _, s := range sums {
		if *quiet && s.Failed == 0 && len(sums) > 20 {
			continue
		}
		fmt.Printf("%-34s %5d %4d %4d %4d %4d %7.2f %9.2f\n", s.Rule, s.Cases, s.TruePos, s.FalseNeg, s.FalsePos, s.Failed, s.Recall(), s.Precision())
	}
	fmt.Printf("\n%d cases, %d failed, %d rules\n", len(results), failed, len(sums))
	if *jsonOut != "" {
		writeJSON(*jsonOut, map[string]any{"results": results, "summaries": sums})
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// ── secrets ──────────────────────────────────────────────────────────────

func runSecrets(args []string) int {
	fs := flag.NewFlagSet("secrets", flag.ExitOnError)
	rulesDir, _ := common(fs)
	catalog := fs.String("catalog", "internal/sast/secretsgen/catalog.json", "secretsgen catalog")
	jsonOut := fs.String("json", "", "write results as JSON to this path (- for stdout)")
	crossLimit := fs.Int("cross", 3, "report a rule that fires on more than this many other entries' samples")
	suggest := fs.Bool("suggest-entropy", false, "for entries failing on their entropy gate, print the gate random tokens of their shape clear")
	apply := fs.Bool("apply-entropy", false, "write the suggested entropy_min into the catalog (then run secretsgen)")
	_ = fs.Parse(args)

	rules := loadRules(*rulesDir)
	entries, err := efficacy.LoadCatalog(*catalog)
	if err != nil {
		fatal("catalog: %v", err)
	}
	only := map[int]bool{}
	for _, a := range fs.Args() {
		var id int
		if _, err := fmt.Sscanf(strings.TrimPrefix(a, "vnx-sec-"), "%d", &id); err == nil {
			only[id] = true
		}
	}
	if len(only) > 0 {
		var keep []efficacy.CatalogEntry
		for _, e := range entries {
			if only[e.ID] {
				keep = append(keep, e)
			}
		}
		entries = keep
	}
	start := time.Now()
	checks, err := efficacy.CheckSecretsCatalog(rules, entries)
	if err != nil {
		fatal("check: %v", err)
	}
	bad, unmeasured, broad := 0, 0, 0
	for _, c := range checks {
		switch c.Verdict {
		case efficacy.VerdictFail:
			bad++
			fmt.Printf("FAIL %s %s (%d/%d random tokens of its shape reported, median entropy %.2f)\n", c.Rule, c.Name, c.Detected, c.Eligible, c.MedianEntropy)
			for _, p := range c.Problems {
				fmt.Printf("    %s\n", p)
			}
		case efficacy.VerdictUnmeasured:
			unmeasured++
			fmt.Printf("UNMEASURED %s %s: %s%s\n", c.Rule, c.Name, c.Skipped, strings.Join(c.Warnings, "; "))
		}
		if c.FiresOnOthers > *crossLimit {
			broad++
			fmt.Printf("BROAD %s %s reports %d other entries' tokens\n", c.Rule, c.Name, c.FiresOnOthers)
		}
	}
	fmt.Printf("\n%d entries checked in %s: %d fail, %d unmeasured, %d over-broad (> %d other entries)\n", len(checks), time.Since(start).Round(time.Millisecond), bad, unmeasured, broad, *crossLimit)
	if *suggest || *apply {
		suggestEntropy(entries, checks, *catalog, *apply)
	}
	if *jsonOut != "" {
		writeJSON(*jsonOut, checks)
	}
	if bad > 0 {
		return 1
	}
	return 0
}

// suggestEntropy sets each entropy-failing entry's gate just under the 10th
// percentile of the entropy of random tokens of its own shape, so nine in ten
// real credentials clear it, and never below 2.5 bits (English words and
// identifiers sit around 2.5–3.3).
func suggestEntropy(entries []efficacy.CatalogEntry, checks []efficacy.SecretCheck, catalog string, apply bool) {
	byID := map[int]efficacy.CatalogEntry{}
	for _, e := range entries {
		byID[e.ID] = e
	}
	raw, err := os.ReadFile(catalog)
	if err != nil {
		fatal("%v", err)
	}
	text := string(raw)
	changed := 0
	for _, c := range checks {
		if c.Verdict != efficacy.VerdictFail {
			continue
		}
		entropyFail := false
		for _, p := range c.Problems {
			if strings.Contains(p, "entropy gate, which this alphabet") {
				entropyFail = true
			}
		}
		if !entropyFail {
			continue
		}
		e := byID[c.ID]
		p10, err := efficacy.RandomTokenEntropy(e.Pattern, 0.10, 400)
		if err != nil {
			continue
		}
		next := float64(int((p10-0.05)*10)) / 10
		if next < 1.5 {
			next = 1.5
		}
		if next >= e.EntropyMin {
			fmt.Printf("  %s: p10 %.2f does not justify lowering %.1f; the miss is not the gate\n", c.Rule, p10, e.EntropyMin)
			continue
		}
		fmt.Printf("  %s %-50s entropy_min %.1f -> %.1f (random tokens of this shape: p10 %.2f)\n", c.Rule, e.Name, e.EntropyMin, next, p10)
		if apply {
			idRe := regexp.MustCompile(fmt.Sprintf(`"id": %d,`, c.ID))
			loc := idRe.FindStringIndex(text)
			if loc == nil {
				continue
			}
			rest := text[loc[1]:]
			emRe := regexp.MustCompile(`"entropy_min": [0-9.]+`)
			m := emRe.FindStringIndex(rest)
			if m == nil {
				continue
			}
			text = text[:loc[1]+m[0]] + fmt.Sprintf(`"entropy_min": %s`, strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", next), "0"), ".")) + text[loc[1]+m[1]:]
			changed++
		}
	}
	if apply && changed > 0 {
		if err := os.WriteFile(catalog, []byte(text), 0o644); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("updated %d entries in %s; regenerate with: go run ./internal/sast/secretsgen\n", changed, catalog)
	}
}

// ── coverage ─────────────────────────────────────────────────────────────

func runCoverage(args []string) int {
	fs := flag.NewFlagSet("coverage", flag.ExitOnError)
	rulesDir, casesDir := common(fs)
	jsonOut := fs.String("json", "", "write the uncovered list as JSON")
	_ = fs.Parse(args)
	rules := loadRules(*rulesDir)
	cs, err := efficacy.LoadCases(*casesDir)
	if err != nil {
		fatal("cases: %v", err)
	}
	pos, neg := map[string]int{}, map[string]int{}
	for _, c := range cs {
		if c.Positive() {
			pos[c.Rule]++
		} else {
			neg[c.Rule]++
		}
	}
	type row struct {
		Rule      string `json:"rule"`
		Positive  int    `json:"positive"`
		Negative  int    `json:"negative"`
		Generated bool   `json:"generated"`
	}
	var missing []row
	total, generated := 0, 0
	for _, s := range rules.Stems() {
		gen := strings.Contains(rules.ByStem[s], "GENERATED by internal/sast/secretsgen")
		if gen {
			generated++
			continue // covered by `sasteff secrets`
		}
		total++
		if pos[s] == 0 || neg[s] == 0 {
			missing = append(missing, row{s, pos[s], neg[s], gen})
		}
	}
	for _, m := range missing {
		fmt.Printf("%-34s positive=%d negative=%d\n", m.Rule, m.Positive, m.Negative)
	}
	fmt.Printf("\n%d hand-written rules, %d lack a positive or a negative case; %d generated secret rules are checked by `sasteff secrets`\n", total, len(missing), generated)
	if *jsonOut != "" {
		writeJSON(*jsonOut, missing)
	}
	if len(missing) > 0 {
		return 1
	}
	return 0
}

// ── snapshot / perf / hits ───────────────────────────────────────────────

func runSnapshot(args []string) int {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	out := fs.String("out", "", "snapshot file to write")
	secrets := fs.Bool("secrets", false, "build the input as the secrets command does: binary strings and git history")
	_ = fs.Parse(args)
	if *out == "" || fs.NArg() == 0 {
		fatal("snapshot -out FILE [-secrets] DIR...")
	}
	start := time.Now()
	ps, err := efficacy.Snapshot(fs.Args(), *secrets)
	if err != nil {
		fatal("%v", err)
	}
	files, bytes := 0, 0
	for _, p := range ps {
		files += len(p.Input.FileContents)
		for _, c := range p.Input.FileContents {
			bytes += len(c)
		}
	}
	if err := efficacy.SaveSnapshot(*out, ps); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("%d projects, %d files, %.1f MB in %s\n", len(ps), files, float64(bytes)/1e6, time.Since(start).Round(time.Millisecond))
	return 0
}

func runPerf(args []string) int {
	fs := flag.NewFlagSet("perf", flag.ExitOnError)
	rulesDir, _ := common(fs)
	snap := fs.String("snapshot", "", "corpus snapshot")
	reps := fs.Int("reps", 1, "repetitions per project (fastest kept)")
	workers := fs.Int("workers", 0, "rules measured concurrently (default GOMAXPROCS/2)")
	top := fs.Int("top", 40, "rows to print")
	jsonOut := fs.String("json", "", "write all profiles as JSON")
	sortBy := fs.String("sort", "eval", "eval | findings | compile")
	_ = fs.Parse(args)
	if *snap == "" {
		fatal("perf -snapshot FILE")
	}
	ps, err := efficacy.LoadSnapshot(*snap)
	if err != nil {
		fatal("%v", err)
	}
	rules := loadRules(*rulesDir)
	stems := fs.Args()
	if len(stems) == 0 {
		stems = rules.Stems()
	}
	start := time.Now()
	profs, err := efficacy.ProfileRules(rules, stems, ps, efficacy.ProfileOptions{Reps: *reps, Workers: *workers})
	if err != nil {
		fatal("%v", err)
	}
	wall := time.Since(start)
	var sumEval, sumCompile time.Duration
	errs := 0
	for _, p := range profs {
		sumEval += p.Eval
		sumCompile += p.Compile
		if p.Err != "" {
			errs++
		}
	}
	sort.Slice(profs, func(i, j int) bool {
		switch *sortBy {
		case "findings":
			return profs[i].Findings > profs[j].Findings
		case "compile":
			return profs[i].Compile > profs[j].Compile
		}
		return profs[i].Eval > profs[j].Eval
	})
	fmt.Printf("%-34s %-18s %10s %10s %8s %6s\n", "rule", "id", "eval", "compile", "findings", "files")
	for i, p := range profs {
		if i >= *top {
			break
		}
		fmt.Printf("%-34s %-18s %10s %10s %8d %6d %s\n", p.Rule, p.ID, p.Eval.Round(time.Microsecond), p.Compile.Round(time.Microsecond), p.Findings, p.Files, p.Err)
	}
	fmt.Printf("\n%d rules: eval %s total, compile %s total, %d errors, wall %s\n", len(profs), sumEval.Round(time.Millisecond), sumCompile.Round(time.Millisecond), errs, wall.Round(time.Millisecond))
	if *jsonOut != "" {
		writeJSON(*jsonOut, profs)
	}
	return 0
}

func runHits(args []string) int {
	fs := flag.NewFlagSet("hits", flag.ExitOnError)
	rulesDir, _ := common(fs)
	snap := fs.String("snapshot", "", "corpus snapshot")
	maxHits := fs.Int("max", 60, "hits to print")
	_ = fs.Parse(args)
	if *snap == "" || fs.NArg() == 0 {
		fatal("hits -snapshot FILE STEM...")
	}
	ps, err := efficacy.LoadSnapshot(*snap)
	if err != nil {
		fatal("%v", err)
	}
	rules := loadRules(*rulesDir)
	profs, err := efficacy.ProfileRules(rules, fs.Args(), ps, efficacy.ProfileOptions{KeepHits: *maxHits, Workers: 4})
	if err != nil {
		fatal("%v", err)
	}
	for _, p := range profs {
		fmt.Printf("== %s (%s): %d findings in %d files, eval %s %s\n", p.Rule, p.ID, p.Findings, p.Files, p.Eval.Round(time.Microsecond), p.Err)
		var projs []string
		for k := range p.ByProject {
			projs = append(projs, k)
		}
		sort.Strings(projs)
		for _, k := range projs {
			fmt.Printf("   %-28s %d\n", k, p.ByProject[k])
		}
		for _, h := range p.Hits {
			fmt.Printf("   %s/%s:%d | %s\n", h.Project, h.File, h.Line, strings.TrimSpace(h.Snippet))
		}
	}
	return 0
}

// ── compare: every rule, original vs current, over one corpus ────────────

func runCompare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	rulesDir, _ := common(fs)
	baseDir := fs.String("base", "", "rule directory holding the original rules")
	snap := fs.String("snapshot", "", "corpus snapshot")
	kind := fs.String("kind", "sast", "rule kind (sast | secrets | iac | oci | all)")
	workers := fs.Int("workers", 0, "rules measured concurrently")
	slow := fs.Duration("slow", 1500*time.Millisecond, "report a current rule whose eval exceeds this")
	jsonOut := fs.String("json", "", "write rows as JSON")
	_ = fs.Parse(args)
	if *baseDir == "" || *snap == "" {
		fatal("compare -base DIR -snapshot SNAP")
	}
	cur, base := loadRules(*rulesDir), loadRules(*baseDir)
	kindRe := regexp.MustCompile(`"kind"\s*:\s*"` + regexp.QuoteMeta(*kind) + `"`)
	var stems []string
	for _, s := range cur.Stems() {
		if *kind == "all" || kindRe.MatchString(cur.ByStem[s]) {
			stems = append(stems, s)
		}
	}
	var baseStems []string
	for _, s := range stems {
		if _, ok := base.ByStem[s]; ok {
			baseStems = append(baseStems, s)
		}
	}
	ps, err := efficacy.LoadSnapshot(*snap)
	if err != nil {
		fatal("%v", err)
	}
	now, err := efficacy.ProfileRules(cur, stems, ps, efficacy.ProfileOptions{Workers: *workers})
	if err != nil {
		fatal("%v", err)
	}
	was, err := efficacy.ProfileRules(base, baseStems, ps, efficacy.ProfileOptions{Workers: *workers})
	if err != nil {
		fatal("%v", err)
	}
	wasBy := map[string]efficacy.Profile{}
	for _, w := range was {
		wasBy[w.Rule] = w
	}
	type row struct {
		Rule                   string
		Findings, BaseFindings int
		EvalMs, BaseEvalMs     float64
		Err                    string
	}
	var rows []row
	var tf, tbf int
	var te, tbe time.Duration
	var slowRows, regressed []row
	for _, p := range now {
		w := wasBy[p.Rule]
		r := row{p.Rule, p.Findings, w.Findings, float64(p.Eval.Microseconds()) / 1000, float64(w.Eval.Microseconds()) / 1000, p.Err}
		rows = append(rows, r)
		tf += p.Findings
		tbf += w.Findings
		te += p.Eval
		tbe += w.Eval
		if p.Eval > *slow {
			slowRows = append(slowRows, r)
		}
		if w.Eval > 0 && p.Eval > 2*w.Eval && p.Eval-w.Eval > 300*time.Millisecond {
			regressed = append(regressed, r)
		}
	}
	fmt.Printf("%s: %d %s rules\n", filepath.Base(*snap), len(rows), *kind)
	fmt.Printf("  findings  %7d -> %7d\n", tbf, tf)
	fmt.Printf("  eval      %10s -> %10s  (sum over rules)\n", tbe.Round(time.Millisecond), te.Round(time.Millisecond))
	sort.Slice(slowRows, func(i, j int) bool { return slowRows[i].EvalMs > slowRows[j].EvalMs })
	fmt.Printf("\n  slower than %s now (%d):\n", *slow, len(slowRows))
	for _, r := range slowRows {
		fmt.Printf("    %-30s %9.0f ms (orig %9.0f ms)\n", r.Rule, r.EvalMs, r.BaseEvalMs)
	}
	fmt.Printf("\n  more than 2x and 300 ms slower than the original (%d):\n", len(regressed))
	for _, r := range regressed {
		fmt.Printf("    %-30s %9.0f ms (orig %9.0f ms)\n", r.Rule, r.EvalMs, r.BaseEvalMs)
	}
	if *jsonOut != "" {
		writeJSON(*jsonOut, rows)
	}
	return 0
}

// ── check: everything an author needs about a rule, before and after ─────

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	rulesDir, casesDir := common(fs)
	baseDir := fs.String("base", "", "rule directory holding the original rules (before)")
	clean := fs.String("clean", "", "snapshot of ordinary projects (precision)")
	vuln := fs.String("vuln", "", "snapshot of deliberately vulnerable projects (recall)")
	show := fs.Int("show", 25, "hits to print per snapshot for the current rule")
	_ = fs.Parse(args)
	stems := fs.Args()
	if len(stems) == 0 {
		fatal("check [-base DIR] [-clean SNAP] [-vuln SNAP] STEM...")
	}
	cur := loadRules(*rulesDir)
	var base *efficacy.Rules
	if *baseDir != "" {
		base = loadRules(*baseDir)
	}
	cs, err := efficacy.LoadCases(*casesDir, stems...)
	if err != nil {
		fatal("cases: %v", err)
	}
	failed := 0
	type pair struct{ cur, base efficacy.Summary }
	sums := map[string]*pair{}
	for _, which := range []string{"cur", "base"} {
		rules := cur
		if which == "base" {
			if base == nil {
				continue
			}
			rules = base
		}
		results := make([]efficacy.Result, len(cs))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		for i := range cs {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()
				results[i] = efficacy.RunCase(rules, cs[i])
			}(i)
		}
		wg.Wait()
		for _, s := range efficacy.Summarise(cs, results) {
			s := s
			if sums[s.Rule] == nil {
				sums[s.Rule] = &pair{}
			}
			if which == "cur" {
				sums[s.Rule].cur = s
			} else {
				sums[s.Rule].base = s
			}
		}
		if which == "cur" {
			for _, r := range results {
				if !r.Pass() {
					failed++
					fmt.Println(efficacy.Describe(r))
				}
			}
		}
	}
	fmt.Println("\nCASES (current vs original)")
	fmt.Printf("  %-30s %5s %8s %10s %5s   %8s %10s\n", "rule", "cases", "recall", "precision", "fail", "orig.rec", "orig.prec")
	for _, s := range stems {
		p := sums[s]
		if p == nil {
			fmt.Printf("  %-30s no cases\n", s)
			continue
		}
		fmt.Printf("  %-30s %5d %8.2f %10.2f %5d   %8.2f %10.2f\n", s, p.cur.Cases, p.cur.Recall(), p.cur.Precision(), p.cur.Failed, p.base.Recall(), p.base.Precision())
	}

	corpus := func(label, snap string) {
		if snap == "" {
			return
		}
		ps, err := efficacy.LoadSnapshot(snap)
		if err != nil {
			fatal("%v", err)
		}
		now, err := efficacy.ProfileRules(cur, stems, ps, efficacy.ProfileOptions{KeepHits: *show, Workers: 4})
		if err != nil {
			fatal("%v", err)
		}
		var was []efficacy.Profile
		if base != nil {
			var bs []string
			for _, s := range stems {
				if _, ok := base.ByStem[s]; ok {
					bs = append(bs, s)
				}
			}
			was, _ = efficacy.ProfileRules(base, bs, ps, efficacy.ProfileOptions{Workers: 4})
		}
		wasBy := map[string]efficacy.Profile{}
		for _, w := range was {
			wasBy[w.Rule] = w
		}
		fmt.Printf("\n%s CORPUS %s\n", label, filepath.Base(snap))
		for _, p := range now {
			w := wasBy[p.Rule]
			fmt.Printf("  %-30s findings %4d (orig %4d) in %3d files   eval %8s (orig %8s) %s\n", p.Rule, p.Findings, w.Findings, p.Files, p.Eval.Round(time.Millisecond), w.Eval.Round(time.Millisecond), p.Err)
			for _, h := range p.Hits {
				fmt.Printf("      %s/%s:%d | %s\n", h.Project, h.File, h.Line, strings.TrimSpace(h.Snippet))
			}
		}
	}
	corpus("CLEAN", *clean)
	corpus("VULNERABLE", *vuln)
	if failed > 0 {
		fmt.Printf("\n%d case(s) failing\n", failed)
		return 1
	}
	return 0
}

// ── bench (OWASP Benchmark ground truth) ─────────────────────────────────

var cweListRe = regexp.MustCompile(`"cwe"\s*:\s*\[([^\]]*)\]`)

func ruleCWEs(src string) map[int]bool {
	out := map[int]bool{}
	if m := cweListRe.FindStringSubmatch(src); m != nil {
		for _, f := range strings.Split(m[1], ",") {
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(f), "%d", &n); err == nil {
				out[n] = true
			}
		}
	}
	return out
}

type benchLabel struct {
	cwe  int
	real bool
}

func loadBenchLabels(path string) (map[string]benchLabel, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]benchLabel{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 4 {
			continue
		}
		var cwe int
		_, _ = fmt.Sscanf(strings.TrimSpace(f[3]), "%d", &cwe) // a label with no CWE stays 0
		out[strings.TrimSpace(f[0])] = benchLabel{cwe: cwe, real: strings.TrimSpace(f[2]) == "true"}
	}
	return out, nil
}

var benchTestRe = regexp.MustCompile(`(?:^|/)testcode/(BenchmarkTest\d+)\.(java|py)$`)

// runBench scores rules against the OWASP Benchmark's expected results: for
// the test files labelled with one of the rule's CWEs, how many real
// vulnerabilities it reports (TPR) and how many safe files it reports (FPR).
// The Benchmark score is TPR − FPR; reports on files labelled with other CWEs
// are counted separately as off-category.
func runBench(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	rulesDir, _ := common(fs)
	snap := fs.String("snapshot", "", "snapshot containing the Benchmark projects")
	labels := fs.String("labels", "", "project=expectedresults.csv,... (project is the snapshot project name)")
	jsonOut := fs.String("json", "", "write rows as JSON")
	_ = fs.Parse(args)
	if *snap == "" || *labels == "" || fs.NArg() == 0 {
		fatal("bench -snapshot FILE -labels Project=csv,... STEM...")
	}
	byProject := map[string]map[string]benchLabel{}
	for _, kv := range strings.Split(*labels, ",") {
		p, path, ok := strings.Cut(kv, "=")
		if !ok {
			fatal("bad -labels entry %q", kv)
		}
		l, err := loadBenchLabels(path)
		if err != nil {
			fatal("%v", err)
		}
		byProject[p] = l
	}
	ps, err := efficacy.LoadSnapshot(*snap)
	if err != nil {
		fatal("%v", err)
	}
	rules := loadRules(*rulesDir)
	profs, err := efficacy.ProfileRules(rules, fs.Args(), ps, efficacy.ProfileOptions{KeepHits: 1 << 30, Workers: 4})
	if err != nil {
		fatal("%v", err)
	}
	type row struct {
		Rule, Project       string
		CWEs                []int
		TP, FP, FN, TN, Off int
		TPR, FPR, Score     float64
	}
	var rows []row
	fmt.Printf("%-24s %-16s %-12s %5s %5s %5s %5s %6s %6s %6s %6s\n", "rule", "project", "cwe", "tp", "fp", "fn", "tn", "tpr", "fpr", "score", "offcat")
	for _, p := range profs {
		cwes := ruleCWEs(rules.ByStem[p.Rule])
		var cweList []int
		for c := range cwes {
			cweList = append(cweList, c)
		}
		sort.Ints(cweList)
		fired := map[string]map[string]bool{}
		for _, h := range p.Hits {
			if m := benchTestRe.FindStringSubmatch(h.File); m != nil {
				if fired[h.Project] == nil {
					fired[h.Project] = map[string]bool{}
				}
				fired[h.Project][m[1]] = true
			}
		}
		for proj, lab := range byProject {
			r := row{Rule: p.Rule, Project: proj, CWEs: cweList}
			for name, l := range lab {
				f := fired[proj][name]
				if !cwes[l.cwe] {
					if f {
						r.Off++
					}
					continue
				}
				switch {
				case f && l.real:
					r.TP++
				case f && !l.real:
					r.FP++
				case !f && l.real:
					r.FN++
				default:
					r.TN++
				}
			}
			if r.TP+r.FN+r.FP+r.TN == 0 {
				fmt.Printf("%-24s %-16s %-12v no test is labelled with this rule's CWEs (off-category reports: %d)\n", p.Rule, proj, cweList, r.Off)
				continue
			}
			if r.TP+r.FN > 0 {
				r.TPR = float64(r.TP) / float64(r.TP+r.FN)
			}
			if r.FP+r.TN > 0 {
				r.FPR = float64(r.FP) / float64(r.FP+r.TN)
			}
			r.Score = r.TPR - r.FPR
			rows = append(rows, r)
			fmt.Printf("%-24s %-16s %-12v %5d %5d %5d %5d %6.2f %6.2f %6.2f %6d\n", r.Rule, r.Project, cweList, r.TP, r.FP, r.FN, r.TN, r.TPR, r.FPR, r.Score, r.Off)
		}
	}
	if *jsonOut != "" {
		writeJSON(*jsonOut, rows)
	}
	return 0
}

// ── total ────────────────────────────────────────────────────────────────

func runTotal(args []string) int {
	fs := flag.NewFlagSet("total", flag.ExitOnError)
	rulesDir, _ := common(fs)
	kind := fs.String("kind", "sast", "rule kind to load, as the matching subcommand does (sast | secrets | iac | oci | all)")
	depth := fs.Int("depth", 8, "max directory depth")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatal("total DIR...")
	}
	rules := loadRules(*rulesDir)
	var stems []string
	kindRe := regexp.MustCompile(`"kind"\s*:\s*"` + regexp.QuoteMeta(*kind) + `"`)
	for _, s := range rules.Stems() {
		if *kind == "all" || kindRe.MatchString(rules.ByStem[s]) {
			stems = append(stems, s)
		}
	}
	fmt.Printf("%d %s rules\n", len(stems), *kind)
	mods := rules.Modules(stems...)
	var sum time.Duration
	for _, d := range fs.Args() {
		abs, _ := filepath.Abs(d)
		start := time.Now()
		rep, err := sast.NewEngine(mods, abs).Evaluate(sast.EvalOptions{MaxDepth: *depth, IgnoreGit: true, IgnoreBinaries: true, RespectGitignore: true})
		el := time.Since(start)
		sum += el
		if err != nil {
			fmt.Printf("%-40s error: %v\n", filepath.Base(abs), err)
			continue
		}
		fmt.Printf("%-40s %8s %6d findings\n", filepath.Base(abs), el.Round(time.Millisecond), len(rep.Findings))
	}
	fmt.Printf("total %s\n", sum.Round(time.Millisecond))
	return 0
}
