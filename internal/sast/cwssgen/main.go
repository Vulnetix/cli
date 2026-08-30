// Command cwssgen rewrites the "cwss" metadata line of every rule in
// internal/sast/rules from the rule's own severity, CWEs and tags, using the
// shared derivation in vdb-sca-match/cwss.
//
// It exists because the vectors the rules shipped were not CWSS. Across 1208
// rules there were only 11 distinct strings, and nine of their sixteen metrics
// used values CWSS 1.0.1 does not define — AS:L, IN:L and SC:N in every one of
// them, plus CONF and T, which are not CWSS metrics at all. Scored as CWSS they
// all landed between 0.47 and 0.74, so a rule declaring "critical" and one
// declaring "low" both came out "low".
//
// Run via:
//
//	just gen-cwss        # go run ./internal/sast/cwssgen
//
// internal/sast's TestRuleCWSSVectorsAreValid fails the build if a rule's vector
// stops being valid CWSS, so a hand-edited rule cannot reintroduce the problem.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Vulnetix/vdb-sca-match/cwss"
)

var (
	severityRe = regexp.MustCompile(`(?m)^\s*"severity":\s*"([^"]*)",`)
	cweRe      = regexp.MustCompile(`(?m)^\s*"cwe":\s*\[([^\]]*)\],`)
	tagsRe     = regexp.MustCompile(`(?m)^\s*"tags":\s*\[([^\]]*)\],`)
	cwssRe     = regexp.MustCompile(`(?m)^(\s*)"cwss":\s*"[^"]*",`)
	cvssv4Re   = regexp.MustCompile(`(?m)^(\s*)"cvssv4":\s*"[^"]*",`)
	kindRe     = regexp.MustCompile(`(?m)^\s*"kind":\s*"([^"]*)",`)
	quotedRe   = regexp.MustCompile(`"([^"]*)"`)
)

func firstGroup(re *regexp.Regexp, src string) string {
	if m := re.FindStringSubmatch(src); m != nil {
		return m[1]
	}
	return ""
}

func ints(list string) []int {
	var out []int
	for _, f := range strings.Split(list, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func quoted(list string) []string {
	var out []string
	for _, m := range quotedRe.FindAllStringSubmatch(list, -1) {
		if s := strings.TrimSpace(m[1]); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func main() {
	dir := "internal/sast/rules"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.rego"))
	if err != nil || len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "cwssgen: no rules under %s\n", dir)
		os.Exit(1)
	}

	var changed, skipped int
	bands := map[string]int{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cwssgen: %s: %v\n", p, err)
			os.Exit(1)
		}
		src := string(raw)

		severity := firstGroup(severityRe, src)
		if severity == "" {
			// helpers.rego and lib_*.rego carry no rule metadata.
			skipped++
			continue
		}
		vector := cwss.Derive(cwss.Input{
			Severity: severity,
			Kind:     firstGroup(kindRe, src),
			CWEs:     ints(firstGroup(cweRe, src)),
			Tags:     quoted(firstGroup(tagsRe, src)),
		}).Vector()
		bands[mustBand(vector)]++

		line := `"cwss": "` + vector + `",`
		var out string
		switch {
		case cwssRe.MatchString(src):
			out = cwssRe.ReplaceAllString(src, "${1}"+line)
		case cvssv4Re.MatchString(src):
			// No cwss key yet: put it directly after cvssv4, where the others sit.
			out = cvssv4Re.ReplaceAllString(src, "${0}\n${1}"+line)
		default:
			fmt.Fprintf(os.Stderr, "cwssgen: %s: no cwss or cvssv4 line to anchor to\n", p)
			os.Exit(1)
		}
		if out == src {
			continue
		}
		if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "cwssgen: %s: %v\n", p, err)
			os.Exit(1)
		}
		changed++
	}
	fmt.Printf("cwssgen: %d rules rewritten, %d files without rule metadata skipped\n", changed, skipped)
	for _, b := range []string{"critical", "high", "medium", "low", "informational"} {
		if bands[b] > 0 {
			fmt.Printf("  %-14s %d\n", b, bands[b])
		}
	}
}

func mustBand(vector string) string {
	m, err := cwss.Parse(vector)
	if err != nil {
		panic(err)
	}
	return m.Severity()
}
