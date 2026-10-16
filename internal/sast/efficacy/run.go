package efficacy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// Rules is a rule directory read from disk: the shared library modules every
// rule may import, and the rule modules by file stem.
type Rules struct {
	Dir    string
	Shared map[string]string // module name → source (helpers, libraries)
	ByStem map[string]string // rule file stem → source
}

// sharedModules are packages every rule may import; they carry no metadata.
var sharedModules = []string{"helpers.rego", "helpers_flow.rego", "lib_secrets.rego"}

// LoadRules reads a rule directory. Reading from disk (not the embedded FS)
// means an edited rule is measured without rebuilding anything.
func LoadRules(dir string) (*Rules, error) {
	r := &Rules{Dir: dir, Shared: map[string]string{}, ByStem: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	shared := map[string]bool{}
	for _, s := range sharedModules {
		shared[s] = true
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if shared[e.Name()] {
			r.Shared["rules/"+e.Name()] = string(b)
			continue
		}
		r.ByStem[strings.TrimSuffix(e.Name(), ".rego")] = string(b)
	}
	return r, nil
}

// Stems returns the rule stems in order.
func (r *Rules) Stems() []string {
	out := make([]string, 0, len(r.ByStem))
	for s := range r.ByStem {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Modules returns the shared modules plus the named rules, keyed the way the
// engine keys embedded modules.
func (r *Rules) Modules(stems ...string) map[string]string {
	m := make(map[string]string, len(r.Shared)+len(stems))
	usesFlow := false
	for _, s := range stems {
		if src, ok := r.ByStem[s]; ok {
			m["rules/"+s+".rego"] = src
			usesFlow = usesFlow || strings.Contains(src, "helpers.flow_")
		}
	}
	for k, v := range r.Shared {
		// The in-method flow helpers are large: like the engine, include
		// them only when a measured rule calls them.
		if strings.HasSuffix(k, "helpers_flow.rego") && !usesFlow {
			continue
		}
		m[k] = v
	}
	return m
}

// Result is the outcome of one case.
type Result struct {
	Rule    string        `json:"rule"`
	Case    string        `json:"case"`
	Want    []Loc         `json:"want"`
	Got     []Loc         `json:"got"`
	Missing []Loc         `json:"missing,omitempty"` // expected, not reported: a false negative
	Extra   []Loc         `json:"extra,omitempty"`   // reported, not expected: a false positive
	Err     string        `json:"error,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns"`
}

// Pass reports whether the rule reported exactly the expected lines.
func (r Result) Pass() bool { return r.Err == "" && len(r.Missing) == 0 && len(r.Extra) == 0 }

// RunCase writes the case to a temporary directory and scans it with the rule
// through the production engine.
func RunCase(rules *Rules, c Case) Result {
	res := Result{Rule: c.Rule, Case: c.Name, Want: c.Want}
	if _, ok := rules.ByStem[c.Rule]; !ok {
		res.Err = "no rule " + c.Rule + ".rego"
		return res
	}
	tmp, err := os.MkdirTemp("", "sasteff-")
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer os.RemoveAll(tmp)
	for rel, content := range c.Files {
		p := filepath.Join(tmp, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			res.Err = err.Error()
			return res
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			res.Err = err.Error()
			return res
		}
	}
	modules := rules.Modules(c.Rule)
	start := time.Now()
	rep, err := sast.NewEngine(modules, tmp).Evaluate(sast.EvalOptions{MaxDepth: 64, IgnoreGit: true})
	res.Elapsed = time.Since(start)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	seen := map[Loc]bool{}
	for _, f := range rep.Findings {
		l := Loc{f.ArtifactURI, f.StartLine}
		if !seen[l] {
			seen[l] = true
			res.Got = append(res.Got, l)
		}
	}
	sortLocs(res.Got)
	want := map[Loc]bool{}
	for _, w := range c.Want {
		want[w] = true
		if !seen[w] {
			res.Missing = append(res.Missing, w)
		}
	}
	for _, g := range res.Got {
		if !want[g] {
			res.Extra = append(res.Extra, g)
		}
	}
	return res
}

// Summary aggregates results per rule.
type Summary struct {
	Rule          string `json:"rule"`
	Cases         int    `json:"cases"`
	PositiveCases int    `json:"positive_cases"`
	NegativeCases int    `json:"negative_cases"`
	Expected      int    `json:"expected"` // lines the cases mark
	TruePos       int    `json:"tp"`
	FalseNeg      int    `json:"fn"`
	FalsePos      int    `json:"fp"`
	Failed        int    `json:"failed_cases"`
}

// Recall is TP / (TP + FN); 1 when nothing is expected.
func (s Summary) Recall() float64 {
	if s.TruePos+s.FalseNeg == 0 {
		return 1
	}
	return float64(s.TruePos) / float64(s.TruePos+s.FalseNeg)
}

// Precision is TP / (TP + FP); 1 when nothing is reported.
func (s Summary) Precision() float64 {
	if s.TruePos+s.FalsePos == 0 {
		return 1
	}
	return float64(s.TruePos) / float64(s.TruePos+s.FalsePos)
}

// Summarise folds case results into per-rule summaries.
func Summarise(cases []Case, results []Result) []Summary {
	by := map[string]*Summary{}
	for i, r := range results {
		s := by[r.Rule]
		if s == nil {
			s = &Summary{Rule: r.Rule}
			by[r.Rule] = s
		}
		s.Cases++
		if cases[i].Positive() {
			s.PositiveCases++
		} else {
			s.NegativeCases++
		}
		s.Expected += len(r.Want)
		s.FalseNeg += len(r.Missing)
		s.TruePos += len(r.Want) - len(r.Missing)
		s.FalsePos += len(r.Extra)
		if !r.Pass() {
			s.Failed++
		}
	}
	out := make([]Summary, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// Describe renders one result for a human.
func Describe(r Result) string {
	var b strings.Builder
	status := "PASS"
	if !r.Pass() {
		status = "FAIL"
	}
	fmt.Fprintf(&b, "%s %s/%s", status, r.Rule, r.Case)
	if r.Err != "" {
		fmt.Fprintf(&b, "\n    error: %s", r.Err)
	}
	for _, m := range r.Missing {
		fmt.Fprintf(&b, "\n    missed (false negative): %s", m)
	}
	for _, e := range r.Extra {
		fmt.Fprintf(&b, "\n    reported (false positive): %s", e)
	}
	return b.String()
}
