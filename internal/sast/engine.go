package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/vulnetix/cli/v3/internal/secretscan"
)

// Sharded compilation tuning. Compiling the full embedded rule set (~1900
// modules) into one OPA compiler is the dominant fixed cost of a scan (~85s on
// this host) and is single-threaded; evaluation then scales with files on top.
// Rules live in independent `vulnetix.rules.<id>` packages, so splitting them
// across N compilers and evaluating each shard concurrently against the shared
// input produces the identical union of findings while using all cores.
const (
	shardMinRules = 64 // below this, a single compile is cheaper than sharding
	shardMaxCount = 16 // ceiling on concurrent compiler+eval shards
)

// Engine compiles Rego modules and evaluates them against a filesystem scan.
type Engine struct {
	modules  map[string]string // filename → rego source
	scanRoot string

	// Compiling ~3000 embedded modules is the dominant fixed cost; a process
	// that both lists and evaluates rules would otherwise pay it twice. Cache
	// the compiled result so all rules compile exactly once per Engine.
	compileOnce sync.Once
	compiler    *ast.Compiler
	compileErr  error
}

// EvalOptions configures the SAST evaluation.
type EvalOptions struct {
	MaxDepth int
	Excludes []string

	// IgnoreGit, IgnoreGlobs, IgnoreBinaries, GitHistory, etc. are
	// forwarded to BuildScanInputWithOptions / LoadFileContentsWithOptions
	// so the secrets subcommand can enable binary and history scanning
	// without affecting the generic scan command's behaviour.
	IgnoreGit            bool
	IgnoreGlobs          []string
	IgnoreBinaries       bool
	GitHistory           bool
	GitHistoryMaxCommits int
	GitHistoryMaxFiles   int
	MinStringLength      int
}

// NewEngine constructs an Engine with the given Rego modules.
func NewEngine(modules map[string]string, scanRoot string) *Engine {
	return &Engine{modules: modules, scanRoot: scanRoot}
}

// compile parses and compiles all loaded Rego modules, caching the result so
// repeated ListRules/Evaluate calls on the same Engine compile only once.
func (e *Engine) compile() (*ast.Compiler, error) {
	e.compileOnce.Do(func() {
		e.compiler, e.compileErr = e.doCompile()
	})
	return e.compiler, e.compileErr
}

// doCompile performs the actual parse + compile of all loaded Rego modules.
func (e *Engine) doCompile() (*ast.Compiler, error) {
	return compileModules(e.modules)
}

// compileModules parses and compiles a set of Rego modules into a fresh
// compiler. Stateless so it can run concurrently across shards.
func compileModules(modules map[string]string) (*ast.Compiler, error) {
	parsed := make(map[string]*ast.Module, len(modules))
	for name, src := range modules {
		mod, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{
			RegoVersion: ast.RegoV1,
		})
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		parsed[name] = mod
	}

	compiler := ast.NewCompiler()
	compiler.Compile(parsed)
	if compiler.Failed() {
		return nil, fmt.Errorf("compile: %v", compiler.Errors)
	}
	return compiler, nil
}

// ListRules extracts metadata from all loaded rule packages without running detection.
// Used for --list-default-rules.
func (e *Engine) ListRules() ([]RuleMetadata, error) {
	compiler, err := e.compile()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	r := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("eval metadata: %w", err)
	}

	return extractAllMetadata(rs)
}

// Evaluate runs all loaded Rego policies against the filesystem at scanRoot.
func (e *Engine) Evaluate(opts EvalOptions) (*SASTReport, error) {
	// Build OPA input from filesystem.
	scanInput, err := BuildScanInputWithOptions(e.scanRoot, BuildOptions{
		MaxDepth:             opts.MaxDepth,
		Excludes:             opts.Excludes,
		IgnoreGit:            opts.IgnoreGit,
		IgnoreGlobs:          opts.IgnoreGlobs,
		IgnoreBinaries:       opts.IgnoreBinaries,
		GitHistory:           opts.GitHistory,
		GitHistoryMaxCommits: opts.GitHistoryMaxCommits,
		GitHistoryMaxFiles:   opts.GitHistoryMaxFiles,
	})
	if err != nil {
		return nil, fmt.Errorf("build scan input: %w", err)
	}

	// Check if any rule references input.file_contents; if so, load contents.
	if needsFileContents(e.modules) {
		LoadFileContentsWithOptions(scanInput, LoadOptions{
			MaxFileSize:     1 << 20, // 1 MiB cap on raw text
			IgnoreBinaries:  opts.IgnoreBinaries,
			MinStringLength: opts.MinStringLength,
		})
		if opts.GitHistory && !opts.IgnoreGit {
			entries, herr := secretscan.ScanGitHistory(e.scanRoot, secretscan.GitHistoryOptions{
				MaxCommits:   opts.GitHistoryMaxCommits,
				MaxFiles:     opts.GitHistoryMaxFiles,
				MaxFileBytes: 4 << 20,
			})
			if herr == nil && len(entries) > 0 {
				MergeGitHistoryEntries(scanInput, entries)
			}
		}
	}

	// Partition shared modules (helpers) from independent rule packages and
	// decide how many shards to run. Each shard compiles helpers + its rule
	// subset and evaluates against the shared, read-only input; the union of
	// per-shard findings is identical to a single combined evaluation.
	shared, rules := partitionModules(e.modules)
	n := shardCount(len(rules))
	if n <= 1 {
		return evalModules(e.modules, scanInput)
	}

	shards := shardModules(rules, n)
	reports := make([]*SASTReport, len(shards))
	errs := make([]error, len(shards))
	var wg sync.WaitGroup
	for i := range shards {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mods := make(map[string]string, len(shared)+len(shards[i]))
			maps.Copy(mods, shared)
			maps.Copy(mods, shards[i])
			reports[i], errs[i] = evalModules(mods, scanInput)
		}(i)
	}
	wg.Wait()

	// A compile/eval error in any shard is fatal, matching the previous
	// all-or-nothing single-compile behaviour.
	for _, e := range errs {
		if e != nil {
			return nil, e
		}
	}

	var allRules []RuleMetadata
	var allFindings []Finding
	for _, rep := range reports {
		if rep == nil {
			continue
		}
		allRules = append(allRules, rep.Rules...)
		allFindings = append(allFindings, rep.Findings...)
	}
	// Deterministic order across shards/runs (the single-eval path was already
	// map-order, so callers must not depend on order; this just makes it stable).
	sortFindings(allFindings)

	return &SASTReport{
		Findings:    allFindings,
		Rules:       allRules,
		RulesLoaded: len(allRules),
	}, nil
}

// evalModules compiles the given modules and evaluates them against scanInput,
// returning the rules and findings for that module set. Used per shard and for
// the single-shard fast path.
func evalModules(modules map[string]string, scanInput any) (*SASTReport, error) {
	compiler, err := compileModules(modules)
	if err != nil {
		return nil, err
	}
	r := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
		rego.Input(scanInput),
	)
	rs, err := r.Eval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	rules, err := extractAllMetadata(rs)
	if err != nil {
		return nil, err
	}
	findings, err := extractAllFindings(rs, rules)
	if err != nil {
		return nil, err
	}
	return &SASTReport{Findings: findings, Rules: rules, RulesLoaded: len(rules)}, nil
}

// partitionModules splits modules into shared (helpers/libraries, included in
// every shard) and independent rule packages (sharded across compilers).
func partitionModules(modules map[string]string) (shared, rules map[string]string) {
	shared = map[string]string{}
	rules = map[string]string{}
	for name, src := range modules {
		if strings.Contains(src, "package vulnetix.rules.") {
			rules[name] = src
		} else {
			shared[name] = src
		}
	}
	return shared, rules
}

// shardModules distributes rule modules round-robin (by sorted name, for
// determinism) into n maps.
func shardModules(rules map[string]string, n int) []map[string]string {
	names := make([]string, 0, len(rules))
	for k := range rules {
		names = append(names, k)
	}
	sort.Strings(names)
	shards := make([]map[string]string, n)
	for i := range shards {
		shards[i] = map[string]string{}
	}
	for i, name := range names {
		shards[i%n][name] = rules[name]
	}
	return shards
}

// shardCount picks the number of concurrent compile+eval shards: bounded by
// cores, the shard ceiling, and a minimum rules-per-shard so tiny rule sets
// (e.g. a single --rule) keep the cheaper single-compile path. VULNETIX_SAST_SHARDS
// overrides it (1 forces the single-compile parity baseline).
func shardCount(nRules int) int {
	if v := strings.TrimSpace(os.Getenv("VULNETIX_SAST_SHARDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			if n > nRules {
				n = nRules
			}
			return max(n, 1)
		}
	}
	if nRules <= shardMinRules {
		return 1
	}
	n := min(runtime.GOMAXPROCS(0), shardMaxCount)
	if byMin := nRules / shardMinRules; byMin >= 1 {
		n = min(n, byMin)
	}
	return max(n, 1)
}

// sortFindings orders findings deterministically by rule, file, line, message.
func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ArtifactURI != b.ArtifactURI {
			return a.ArtifactURI < b.ArtifactURI
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.Message < b.Message
	})
}

// extractAllMetadata walks the data.vulnetix.rules result tree and extracts
// the "metadata" object from each rule package.
func extractAllMetadata(rs rego.ResultSet) ([]RuleMetadata, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}

	rulesTree, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", rs[0].Expressions[0].Value)
	}

	var rules []RuleMetadata
	for _, pkgData := range rulesTree {
		pkgMap, ok := pkgData.(map[string]any)
		if !ok {
			continue
		}
		metaRaw, ok := pkgMap["metadata"]
		if !ok {
			continue
		}
		var meta RuleMetadata
		if err := remarshal(metaRaw, &meta); err != nil {
			continue
		}
		if meta.ID == "" {
			continue
		}
		rules = append(rules, meta)
	}
	return rules, nil
}

// extractAllFindings walks the result tree and extracts "findings" sets.
func extractAllFindings(rs rego.ResultSet, rules []RuleMetadata) ([]Finding, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}

	rulesTree, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, nil
	}

	// Build a lookup from rule ID → *RuleMetadata.
	metaByID := make(map[string]*RuleMetadata, len(rules))
	for i := range rules {
		metaByID[rules[i].ID] = &rules[i]
	}

	var findings []Finding
	for _, pkgData := range rulesTree {
		pkgMap, ok := pkgData.(map[string]any)
		if !ok {
			continue
		}
		findingsRaw, ok := pkgMap["findings"]
		if !ok {
			continue
		}

		// findings is a set (returned as []any by OPA).
		findingsSlice, ok := findingsRaw.([]any)
		if !ok {
			continue
		}
		for _, fRaw := range findingsSlice {
			var f Finding
			if err := remarshal(fRaw, &f); err != nil {
				continue
			}
			if f.RuleID == "" {
				continue
			}
			f.Metadata = metaByID[f.RuleID]

			// Derive level from metadata if not set by the finding.
			if f.Level == "" && f.Metadata != nil {
				f.Level = f.Metadata.EffectiveLevel()
			}
			// Derive severity from metadata if not set.
			if f.Severity == "" && f.Metadata != nil {
				f.Severity = f.Metadata.Severity
			}

			f.Fingerprint = Fingerprint(f.RuleID, f.ArtifactURI, f.StartLine)
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// needsFileContents checks if any module source references input.file_contents.
func needsFileContents(modules map[string]string) bool {
	for _, src := range modules {
		if strings.Contains(src, "input.file_contents") {
			return true
		}
	}
	return false
}

// remarshal converts an any to a typed struct via JSON round-trip.
func remarshal(src any, dst any) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}
