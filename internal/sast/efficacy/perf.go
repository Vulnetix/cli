package efficacy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/secretscan"
)

// Project is one scanned tree in a corpus snapshot. Projects are kept apart
// rather than merged under a prefix so that root-anchored rules (a path that
// starts with ".github/", a Dockerfile at the top) see the layout they would
// see in a real scan.
type Project struct {
	Name  string          `json:"name"`
	Root  string          `json:"root"`
	Input *sast.ScanInput `json:"input"`
}

// Snapshot builds the scan input for each corpus directory the way the sast
// command does: gitignore respected, text up to 1 MiB, binaries skipped. With
// secrets it is built the way the secrets command does instead: binaries read
// for their strings and the git history merged in, up to the command's
// default limits, which is most of what a secrets rule evaluates.
func Snapshot(dirs []string, secrets bool) ([]Project, error) {
	var out []Project
	for _, d := range dirs {
		abs, err := filepath.Abs(d)
		if err != nil {
			return nil, err
		}
		in, err := sast.BuildScanInputWithOptions(abs, sast.BuildOptions{
			MaxDepth:         64,
			IgnoreGit:        !secrets,
			IgnoreBinaries:   !secrets,
			RespectGitignore: true,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d, err)
		}
		sast.LoadFileContentsWithOptions(in, sast.LoadOptions{MaxFileSize: 1 << 20, IgnoreBinaries: !secrets})
		if secrets {
			entries, err := secretscan.ScanGitHistory(abs, secretscan.GitHistoryOptions{MaxCommits: 500, MaxFiles: 5000, MaxFileBytes: 4 << 20})
			if err != nil {
				return nil, fmt.Errorf("%s: git history: %w", d, err)
			}
			sast.MergeGitHistoryEntries(in, entries)
		}
		out = append(out, Project{Name: filepath.Base(abs), Root: abs, Input: in})
	}
	return out, nil
}

// SaveSnapshot and LoadSnapshot persist a corpus so repeated measurements do
// not walk and read thousands of files each time.
func SaveSnapshot(path string, ps []Project) error {
	b, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func LoadSnapshot(path string) ([]Project, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ps []Project
	return ps, json.Unmarshal(b, &ps)
}

// Hit is one finding on a corpus project.
type Hit struct {
	Project string `json:"project"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// Profile is the measurement of one rule over a corpus.
type Profile struct {
	Rule      string         `json:"rule"`
	ID        string         `json:"id"`
	Compile   time.Duration  `json:"compile_ns"`
	Eval      time.Duration  `json:"eval_ns"` // sum over projects of the fastest repetition
	Findings  int            `json:"findings"`
	Files     int            `json:"files"` // distinct files with a finding
	ByProject map[string]int `json:"by_project,omitempty"`
	Hits      []Hit          `json:"hits,omitempty"`
	Err       string         `json:"error,omitempty"`
}

// ProfileOptions controls Profile.
type ProfileOptions struct {
	Reps     int // repetitions per project; the fastest is kept (default 1)
	Workers  int // concurrent rules (default GOMAXPROCS/2)
	KeepHits int // hits to keep per rule (0 keeps none)
}

type parsedProject struct {
	name  string
	value ast.Value
}

// ProfileRules compiles and evaluates each rule on its own against every
// project and reports its cost and its findings.
func ProfileRules(rules *Rules, stems []string, projects []Project, opts ProfileOptions) ([]Profile, error) {
	if opts.Reps < 1 {
		opts.Reps = 1
	}
	if opts.Workers < 1 {
		opts.Workers = max(1, runtime.GOMAXPROCS(0)/2)
	}
	parsed := make([]parsedProject, 0, len(projects))
	for _, p := range projects {
		v, err := ast.InterfaceToValue(p.Input)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name, err)
		}
		parsed = append(parsed, parsedProject{p.Name, v})
	}

	out := make([]Profile, len(stems))
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Workers)
	for i, stem := range stems {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, stem string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = profileOne(rules, stem, parsed, opts)
		}(i, stem)
	}
	wg.Wait()
	return out, nil
}

func profileOne(rules *Rules, stem string, projects []parsedProject, opts ProfileOptions) Profile {
	p := Profile{Rule: stem, ID: RuleID(rules.ByStem[stem]), ByProject: map[string]int{}}
	ctx := context.Background()
	mods := rules.Modules(stem)

	start := time.Now()
	parsed := map[string]*ast.Module{}
	for name, src := range mods {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			p.Err = err.Error()
			return p
		}
		parsed[name] = m
	}
	compiler := ast.NewCompiler()
	compiler.Compile(parsed)
	if compiler.Failed() {
		p.Err = compiler.Errors.Error()
		return p
	}
	pq, err := rego.New(rego.Compiler(compiler), rego.Query("data.vulnetix.rules")).PrepareForEval(ctx)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	p.Compile = time.Since(start)

	files := map[string]bool{}
	for _, proj := range projects {
		var best time.Duration
		var rs rego.ResultSet
		for r := 0; r < opts.Reps; r++ {
			t := time.Now()
			got, err := pq.Eval(ctx, rego.EvalParsedInput(proj.value))
			d := time.Since(t)
			if err != nil {
				p.Err = err.Error()
				return p
			}
			if r == 0 || d < best {
				best = d
			}
			rs = got
		}
		p.Eval += best
		for _, h := range findingsOf(rs) {
			p.Findings++
			p.ByProject[proj.name]++
			files[proj.name+"/"+h.File] = true
			if len(p.Hits) < opts.KeepHits {
				h.Project = proj.name
				p.Hits = append(p.Hits, h)
			}
		}
	}
	p.Files = len(files)
	return p
}

// findingsOf walks data.vulnetix.rules the way the engine does, applying the
// engine's per-finding scope so the counts are the counts a scan reports.
func findingsOf(rs rego.ResultSet) []Hit {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil
	}
	tree, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil
	}
	var out []Hit
	for _, pkg := range tree {
		pm, ok := pkg.(map[string]any)
		if !ok {
			continue
		}
		var meta sast.RuleMetadata
		if raw, ok := pm["metadata"]; ok {
			b, _ := json.Marshal(raw)
			_ = json.Unmarshal(b, &meta)
		}
		fs, _ := pm["findings"].([]any)
		seen := map[string]bool{}
		for _, f := range fs {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			file, _ := fm["artifact_uri"].(string)
			snip, _ := fm["snippet"].(string)
			line := 0
			switch n := fm["start_line"].(type) {
			case json.Number:
				v, _ := n.Int64()
				line = int(v)
			case float64:
				line = int(n)
			case int:
				line = n
			}
			if !sast.FindingApplies(&meta, file, snip) {
				continue
			}
			key := fmt.Sprintf("%s:%d", file, line)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(snip) > 200 {
				snip = snip[:200]
			}
			out = append(out, Hit{File: file, Line: line, Snippet: snip})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}
