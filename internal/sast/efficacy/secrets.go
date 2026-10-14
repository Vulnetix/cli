package efficacy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// CatalogEntry is the part of a secretsgen catalog entry the checks need.
type CatalogEntry struct {
	ID         int      `json:"id"`
	Category   string   `json:"category"`
	Name       string   `json:"name"`
	Strategy   string   `json:"strategy"`
	Pattern    string   `json:"token_pattern"`
	Keywords   []string `json:"keywords"`
	EntropyMin float64  `json:"entropy_min"`
	Deprecated bool     `json:"deprecated"`
}

// Stem is the generated rule's file stem.
func (e CatalogEntry) Stem() string { return fmt.Sprintf("vnx-sec-%03d", e.ID) }

// LoadCatalog reads secretsgen/catalog.json.
func LoadCatalog(path string) ([]CatalogEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var es []CatalogEntry
	return es, json.Unmarshal(b, &es)
}

// Verdicts for a catalog entry.
const (
	VerdictOK         = "ok"
	VerdictFail       = "fail"       // realistic tokens of the rule's own shape are missed, or a gate is ineffective
	VerdictUnmeasured = "unmeasured" // no pattern-valid sample carries a keyword: needs a realistic example
)

// SecretCheck is the verdict for one catalog entry.
type SecretCheck struct {
	ID            int      `json:"id"`
	Rule          string   `json:"rule"`
	Name          string   `json:"name"`
	Verdict       string   `json:"verdict"`
	Eligible      int      `json:"eligible"` // random samples that carry a keyword and are not placeholders
	Detected      int      `json:"detected"`
	Rate          float64  `json:"rate"`
	KeywordGap    int      `json:"keyword_gap"` // pattern-valid samples the keyword prefilter skips
	MedianEntropy float64  `json:"median_entropy,omitempty"`
	Problems      []string `json:"problems,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
	FiredOnBy     []string `json:"fired_on_by,omitempty"` // other rules that report this entry's tokens
	FiresOnOthers int      `json:"fires_on_others"`       // other entries' tokens this rule reports
	Skipped       string   `json:"skipped,omitempty"`     // the generator could not produce a sample
}

// samplesPerEntry random tokens are drawn for each entry. Real credentials are
// random, so the share of these a rule reports is its recall on its own shape.
const samplesPerEntry = 12

// minRate below which an entry fails: a rule that misses a quarter of
// well-formed random tokens of its own shape misses real ones too.
const minRate = 0.75

// genMode selects how character runs are filled.
type genMode int

const (
	modeHigh        genMode = iota // drawn without replacement: maximal entropy
	modeLowEntropy                 // two characters alternating: entropy 1
	modePlaceholder                // one placeholder character repeated
	modeRandom                     // drawn with replacement: what a real random token looks like
)

// SampleMode is Sample with a fill mode for character runs.
func SampleMode(pattern string, variant int, mode genMode) (full, group string, err error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", "", err
	}
	tree, err := parseSimplified(pattern)
	if err != nil {
		return "", "", err
	}
	for attempt := 0; attempt < 24; attempt++ {
		g := &gen{seed: uint64(variant*7919 + attempt*104729 + 1), mode: mode}
		var b strings.Builder
		g.emit(&b, tree)
		s := b.String()
		m := re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		grp := m[0]
		if len(m) > 1 && m[1] != "" {
			grp = m[1]
		}
		return s, grp, nil
	}
	return "", "", fmt.Errorf("no sample satisfies %q", pattern)
}

// Entropy is the Shannon entropy in bits per byte, as vulnetix.shannon_entropy.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

var stopwordsRe = regexp.MustCompile(`(?s)_stopwords := \[(.*?)\]`)
var quotedRe = regexp.MustCompile(`"([^"]*)"`)

// stopwords reads the placeholder stopword list from lib_secrets.rego, so a
// random sample that happens to contain one ("todo", "none") is set aside as
// chance rather than counted as a miss.
func stopwords(r *Rules) []string {
	src := r.Shared["rules/lib_secrets.rego"]
	m := stopwordsRe.FindStringSubmatch(src)
	if m == nil {
		return nil
	}
	var out []string
	for _, q := range quotedRe.FindAllStringSubmatch(m[1], -1) {
		out = append(out, q[1])
	}
	return out
}

var chanceRunRe = regexp.MustCompile(`(?i)(x{6,}|a{6,}|0{6,}|1{6,}|z{6,})`)

func chancePlaceholder(tok string, stops []string) bool {
	low := strings.ToLower(tok)
	for _, w := range stops {
		if w != "" && strings.Contains(low, w) {
			return true
		}
	}
	if chanceRunRe.MatchString(tok) {
		lowTok := strings.ToLower(tok)
		alnum := 0
		for _, r := range lowTok {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				alnum++
			}
		}
		for _, c := range "xa01z" {
			if alnum > 0 && strings.Count(lowTok, string(c))*10 >= alnum*4 {
				return true
			}
		}
	}
	return strings.HasSuffix(strings.ToUpper(tok), "EXAMPLE")
}

func hasKeyword(line string, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	low := strings.ToLower(line)
	for _, k := range kws {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

// CheckSecretsCatalog proves each generated secret rule reports realistic
// random tokens of its own shape, that its placeholder and entropy gates
// reject what they are meant to, and records which other rules report the
// same token.
func CheckSecretsCatalog(rules *Rules, entries []CatalogEntry) ([]SecretCheck, error) {
	stops := stopwords(rules)
	type planned struct {
		entry      CatalogEntry
		pos        []string // eligible random samples (must be reported)
		posTok     []string
		neg        []string // must not be reported
		negWhy     []string
		keywordGap int
		upperKW    []string
		skipped    string
	}
	var plan []planned
	for _, e := range entries {
		if e.Deprecated {
			continue
		}
		if _, ok := rules.ByStem[e.Stem()]; !ok {
			continue
		}
		p := planned{entry: e}
		patRe, err := regexp.Compile(e.Pattern)
		if err != nil {
			p.skipped = err.Error()
			plan = append(plan, p)
			continue
		}
		for _, k := range e.Keywords {
			if k != strings.ToLower(k) {
				p.upperKW = append(p.upperKW, k)
			}
		}
		seen := map[string]bool{}
		for v := 0; v < samplesPerEntry*4 && len(p.pos) < samplesPerEntry; v++ {
			full, tok, err := SampleMode(e.Pattern, v, modeRandom)
			if err != nil {
				p.skipped = err.Error()
				break
			}
			if seen[full] {
				continue
			}
			seen[full] = true
			if chancePlaceholder(tok, stops) {
				continue
			}
			if !hasKeyword(full, e.Keywords) {
				// Many rules expect the provider name elsewhere on the line (the
				// variable it is assigned to), not inside the token. Test that.
				ctx := e.Keywords[0] + " = " + full
				if !patRe.MatchString(ctx) || !hasKeyword(ctx, e.Keywords) {
					p.keywordGap++
					continue
				}
				full = ctx
			}
			p.pos = append(p.pos, full)
			p.posTok = append(p.posTok, tok)
		}
		if p.skipped == "" {
			if full, grp, err := SampleMode(e.Pattern, 0, modePlaceholder); err == nil && chanceRunRe.MatchString(grp) && hasKeyword(full, e.Keywords) {
				p.neg = append(p.neg, full)
				p.negWhy = append(p.negWhy, "a placeholder token (one character repeated) was reported")
			}
			if e.EntropyMin > 1.2 {
				if full, grp, err := SampleMode(e.Pattern, 0, modeLowEntropy); err == nil && len(grp) >= 8 && hasKeyword(full, e.Keywords) && Entropy(grp) < e.EntropyMin {
					p.neg = append(p.neg, full)
					p.negWhy = append(p.negWhy, fmt.Sprintf("a low-entropy token (%.1f bits) passed the %.1f entropy gate", Entropy(grp), e.EntropyMin))
				}
			}
		}
		plan = append(plan, p)
	}

	in := &sast.ScanInput{FileSet: map[string]bool{}, DirsByLanguage: map[string][]string{}, FileContents: map[string]string{}, ScanRoot: "/catalog"}
	posFile := func(id int) string { return fmt.Sprintf("conf/pos-%04d.conf", id) }
	negFile := func(id int) string { return fmt.Sprintf("conf/neg-%04d.conf", id) }
	var stems []string
	for _, p := range plan {
		stems = append(stems, p.entry.Stem())
		if len(p.pos) > 0 {
			in.FileSet[posFile(p.entry.ID)] = true
			in.FileContents[posFile(p.entry.ID)] = strings.Join(p.pos, "\n") + "\n"
		}
		if len(p.neg) > 0 {
			in.FileSet[negFile(p.entry.ID)] = true
			in.FileContents[negFile(p.entry.ID)] = strings.Join(p.neg, "\n") + "\n"
		}
	}
	hits, err := EvalSharded(rules, stems, in)
	if err != nil {
		return nil, err
	}
	byFile := map[string]map[string]bool{}
	for stem, hs := range hits {
		for _, h := range hs {
			if byFile[h.File] == nil {
				byFile[h.File] = map[string]bool{}
			}
			byFile[h.File][stem] = true
		}
	}

	out := make([]SecretCheck, 0, len(plan))
	for _, p := range plan {
		e := p.entry
		c := SecretCheck{ID: e.ID, Rule: e.Stem(), Name: e.Name, Eligible: len(p.pos), KeywordGap: p.keywordGap, Skipped: p.skipped}
		for _, k := range p.upperKW {
			c.Problems = append(c.Problems, fmt.Sprintf("keyword %q is not lower-case; the prefilter lower-cases the line, so it never matches", k))
		}
		own := map[int]bool{}
		others := map[string]bool{}
		for _, h := range hits[e.Stem()] {
			switch {
			case h.File == posFile(e.ID):
				own[h.Line] = true
			case h.File == negFile(e.ID):
				if h.Line-1 < len(p.negWhy) {
					c.Problems = append(c.Problems, p.negWhy[h.Line-1])
				}
			case strings.HasPrefix(h.File, "conf/pos-"):
				others[h.File] = true
			}
		}
		c.FiresOnOthers = len(others)
		c.Detected = len(own)
		if c.Eligible > 0 {
			c.Rate = float64(c.Detected) / float64(c.Eligible)
		}
		var ents []float64
		for _, t := range p.posTok {
			ents = append(ents, Entropy(t))
		}
		sort.Float64s(ents)
		if len(ents) > 0 {
			c.MedianEntropy = math.Round(ents[len(ents)/2]*100) / 100
		}
		if c.Eligible > 0 && c.Rate < minRate {
			c.Problems = append(c.Problems, diagnoseMiss(e, p.posTok, own, stops))
		}
		if p.keywordGap > 0 {
			c.Warnings = append(c.Warnings, fmt.Sprintf("%d pattern-valid token(s) carry none of the keywords %v: the pattern is broader than the prefilter", p.keywordGap, e.Keywords))
		}
		for stem := range byFile[posFile(e.ID)] {
			if stem != e.Stem() {
				c.FiredOnBy = append(c.FiredOnBy, stem)
			}
		}
		sort.Strings(c.FiredOnBy)
		switch {
		case c.Skipped != "":
			c.Verdict = VerdictUnmeasured
		case len(c.Problems) > 0:
			c.Verdict = VerdictFail
		case c.Eligible == 0:
			c.Verdict = VerdictUnmeasured
			c.Warnings = append(c.Warnings, "no random token of this shape carries a keyword; the entry needs a pattern whose required text implies its keyword")
		default:
			c.Verdict = VerdictOK
		}
		out = append(out, c)
	}
	return out, nil
}

// diagnoseMiss explains why realistic tokens are missed.
func diagnoseMiss(e CatalogEntry, toks []string, own map[int]bool, stops []string) string {
	below := 0
	var missed []string
	for i, t := range toks {
		if own[i+1] {
			continue
		}
		missed = append(missed, t)
		if e.EntropyMin > 0 && Entropy(t) < e.EntropyMin {
			below++
		}
	}
	rate := 1 - float64(len(missed))/float64(len(toks))
	if below > 0 && below*2 >= len(missed) {
		return fmt.Sprintf("reports %.0f%% of random tokens of its own shape: %d of %d misses are under the %.1f entropy gate, which this alphabet and length rarely reach", rate*100, below, len(missed), e.EntropyMin)
	}
	shape := ""
	if len(missed) > 0 {
		shape = redactSample(missed[0])
	}
	return fmt.Sprintf("reports %.0f%% of random tokens of its own shape; the misses pass the entropy gate, so the placeholder filter or the pattern itself rejects them (e.g. %s)", rate*100, shape)
}

// redactSample keeps a sample recognisable without printing a full token.
func redactSample(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:16] + "…(" + fmt.Sprint(len(s)) + " chars)"
}

// EvalSharded evaluates many rules against one input, compiling them in
// parallel shards as the engine does, and returns each rule's hits.
func EvalSharded(rules *Rules, stems []string, in *sast.ScanInput) (map[string][]Hit, error) {
	value, err := ast.InterfaceToValue(in)
	if err != nil {
		return nil, err
	}
	n := max(1, runtime.GOMAXPROCS(0))
	shards := make([][]string, n)
	for i, s := range stems {
		shards[i%n] = append(shards[i%n], s)
	}
	out := map[string][]Hit{}
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for _, shard := range shards {
		if len(shard) == 0 {
			continue
		}
		wg.Add(1)
		go func(shard []string) {
			defer wg.Done()
			got, err := evalStems(rules, shard, value)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for k, v := range got {
				out[k] = v
			}
		}(shard)
	}
	wg.Wait()
	return out, firstErr
}

func evalStems(rules *Rules, stems []string, value ast.Value) (map[string][]Hit, error) {
	ctx := context.Background()
	mods := rules.Modules(stems...)
	parsed := map[string]*ast.Module{}
	for name, src := range mods {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, err
		}
		parsed[name] = m
	}
	compiler := ast.NewCompiler()
	compiler.Compile(parsed)
	if compiler.Failed() {
		return nil, compiler.Errors
	}
	out := map[string][]Hit{}
	pq, err := rego.New(rego.Compiler(compiler), rego.Query("data.vulnetix.rules")).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := pq.Eval(ctx, rego.EvalParsedInput(value))
	if err != nil {
		return nil, err
	}
	pkgOf := map[string]string{}
	for _, s := range stems {
		pkgOf[packageName(rules.ByStem[s])] = s
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return out, nil
	}
	tree, _ := rs[0].Expressions[0].Value.(map[string]any)
	for pkg, data := range tree {
		stem := pkgOf[pkg]
		if stem == "" {
			continue
		}
		one := rego.ResultSet{{Expressions: []*rego.ExpressionValue{{Value: map[string]any{pkg: data}}}}}
		out[stem] = findingsOf(one)
	}
	return out, nil
}

var pkgRe = regexp.MustCompile(`(?m)^package\s+vulnetix\.rules\.([A-Za-z0-9_]+)`)

func packageName(src string) string {
	if m := pkgRe.FindStringSubmatch(src); m != nil {
		return m[1]
	}
	return ""
}

// RandomTokenEntropy returns the q-quantile of the entropy of n random tokens
// of the pattern's capture group: the threshold below which a real credential
// of this shape almost always falls.
func RandomTokenEntropy(pattern string, q float64, n int) (float64, error) {
	var es []float64
	for v := 0; v < n*3 && len(es) < n; v++ {
		_, tok, err := SampleMode(pattern, 1000+v, modeRandom)
		if err != nil {
			return 0, err
		}
		es = append(es, Entropy(tok))
	}
	if len(es) == 0 {
		return 0, fmt.Errorf("no samples")
	}
	sort.Float64s(es)
	return es[int(float64(len(es)-1)*q)], nil
}
