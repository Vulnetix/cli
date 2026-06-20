package reachability

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// TestMatchAffectedSymbols_ConcurrencyParity proves the parallel symbol-fallback
// scan finds the identical set of hits per CVE as the serial walk —
// VULNETIX_REACHABILITY_CONCURRENCY changes only scheduling. Hits are compared
// as sorted sets (the per-file file-name-hit order is already map-random in both
// paths; file-walk order is preserved by construction). Run with -race.
func TestMatchAffectedSymbols_ConcurrencyParity(t *testing.T) {
	files := map[string]string{
		"pkg/clean.go":           "package y\nfunc clean() { return }\n",
		"lib/vulnerable_file.go": "package z\n// matched by file name only\n",
		"node_modules/skip.go":   "package s\nfunc f() { _ = DangerousCall() }\n",
	}
	for i := range 50 {
		files[fmt.Sprintf("src/f%02d.go", i)] = "package x\nfunc use() { _ = DangerousCall(); _ = other.RiskyModule }\n"
	}
	root := writeTempProject(t, files)
	inputs := []CveSymbols{
		{CveID: "CVE-A", Routines: []string{"DangerousCall"}, Modules: []string{"other.RiskyModule"}, Files: []string{"vulnerable_file.go"}},
		{CveID: "CVE-B", Routines: []string{"DangerousCall"}}, // shares a symbol with CVE-A
	}

	run := func(conc string) map[string][]SymbolMatch {
		t.Setenv("VULNETIX_REACHABILITY_CONCURRENCY", conc)
		res, err := MatchAffectedSymbols(context.Background(), SymbolMatchRequest{ProjectRoot: root, Inputs: inputs})
		if err != nil {
			t.Fatalf("conc=%s: MatchAffectedSymbols: %v", conc, err)
		}
		return res.HitsByCVE
	}

	norm := func(m map[string][]SymbolMatch) string {
		cves := make([]string, 0, len(m))
		for c := range m {
			cves = append(cves, c)
		}
		sort.Strings(cves)
		var b strings.Builder
		for _, c := range cves {
			hits := append([]SymbolMatch(nil), m[c]...)
			sort.Slice(hits, func(i, j int) bool {
				a, z := hits[i], hits[j]
				switch {
				case a.File != z.File:
					return a.File < z.File
				case a.Line != z.Line:
					return a.Line < z.Line
				case a.Symbol != z.Symbol:
					return a.Symbol < z.Symbol
				default:
					return a.Kind < z.Kind
				}
			})
			fmt.Fprintf(&b, "%s: %+v\n", c, hits)
		}
		return b.String()
	}

	serial := norm(run("1"))
	parallel := norm(run("8"))

	if serial == "" {
		t.Fatalf("fixture produced no hits; matcher not exercised")
	}
	if serial != parallel {
		t.Errorf("hit set differs by concurrency:\n--- serial ---\n%s\n--- parallel ---\n%s", serial, parallel)
	}
	if strings.Contains(parallel, "node_modules") {
		t.Errorf("node_modules must be skipped, but appears in hits:\n%s", parallel)
	}
}
