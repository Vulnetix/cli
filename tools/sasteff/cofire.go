package main

import (
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/sast/efficacy"
)

// runCofire finds rules that report the same lines. Two rules that fire on
// one line are one problem reported twice; the report should carry it once.
// For each pair it prints the shared lines and each rule's share of its own
// findings, so a pair where one rule is wholly inside the other stands out.
func runCofire(args []string) int {
	fs := flag.NewFlagSet("cofire", flag.ExitOnError)
	rulesDir, _ := common(fs)
	snaps := fs.String("snapshot", "", "corpus snapshots, comma separated")
	kind := fs.String("kind", "sast", "rule kind (sast | secrets | iac | oci | all)")
	minShared := fs.Int("min", 3, "report pairs sharing at least this many lines")
	workers := fs.Int("workers", 0, "rules measured concurrently")
	jsonOut := fs.String("json", "", "write pairs as JSON")
	_ = fs.Parse(args)
	if *snaps == "" {
		fatal("cofire -snapshot SNAP[,SNAP...]")
	}
	rules := loadRules(*rulesDir)
	kindRe := regexp.MustCompile(`"kind"\s*:\s*"` + regexp.QuoteMeta(*kind) + `"`)
	var stems []string
	for _, s := range rules.Stems() {
		if *kind == "all" || kindRe.MatchString(rules.ByStem[s]) {
			stems = append(stems, s)
		}
	}

	type loc struct {
		proj, file string
		line       int
	}
	byLoc := map[loc][]string{}
	total := map[string]int{}
	for _, path := range strings.Split(*snaps, ",") {
		ps, err := efficacy.LoadSnapshot(path)
		if err != nil {
			fatal("%v", err)
		}
		profs, err := efficacy.ProfileRules(rules, stems, ps, efficacy.ProfileOptions{KeepHits: 1 << 30, Workers: *workers})
		if err != nil {
			fatal("%v", err)
		}
		for _, p := range profs {
			seen := map[loc]bool{}
			for _, h := range p.Hits {
				l := loc{h.Project, h.File, h.Line}
				if seen[l] {
					continue
				}
				seen[l] = true
				byLoc[l] = append(byLoc[l], p.Rule)
				total[p.Rule]++
			}
		}
	}

	type pair struct {
		A, B       string
		Shared     int
		AOnly      int
		BOnly      int
		ShareOfA   float64
		ShareOfB   float64
		SampleFile string
		SampleLine int
	}
	pairs := map[[2]string]*pair{}
	for l, rs := range byLoc {
		sort.Strings(rs)
		for i := 0; i < len(rs); i++ {
			for j := i + 1; j < len(rs); j++ {
				k := [2]string{rs[i], rs[j]}
				p := pairs[k]
				if p == nil {
					p = &pair{A: rs[i], B: rs[j], SampleFile: l.file, SampleLine: l.line}
					pairs[k] = p
				}
				p.Shared++
			}
		}
	}
	var rows []pair
	for _, p := range pairs {
		if p.Shared < *minShared {
			continue
		}
		p.AOnly = total[p.A] - p.Shared
		p.BOnly = total[p.B] - p.Shared
		p.ShareOfA = float64(p.Shared) / float64(total[p.A])
		p.ShareOfB = float64(p.Shared) / float64(total[p.B])
		rows = append(rows, *p)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Shared > rows[j].Shared })
	fmt.Printf("%-22s %-22s %7s %7s %7s %6s %6s  %s\n", "rule a", "rule b", "shared", "a-only", "b-only", "of a", "of b", "sample")
	for _, r := range rows {
		fmt.Printf("%-22s %-22s %7d %7d %7d %5.0f%% %5.0f%%  %s:%d\n", r.A, r.B, r.Shared, r.AOnly, r.BOnly, 100*r.ShareOfA, 100*r.ShareOfB, r.SampleFile, r.SampleLine)
	}
	fmt.Printf("\n%d pairs share at least %d lines\n", len(rows), *minShared)
	if *jsonOut != "" {
		writeJSON(*jsonOut, rows)
	}
	return 0
}
