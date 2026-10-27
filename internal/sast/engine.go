package sast

import (
	"context"
	"encoding/json"
	"fmt"
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

// Sharded compilation tuning. One OPA compiler is single-threaded: the full
// embedded rule set (~1900 modules) compiles in about 1.7s in one, 0.3s across
// 16 (session.go measured it). Rules live in independent
// `vulnetix.rules.<id>` packages, so splitting them across compilers and
// evaluating each concurrently produces the identical union of findings. Rules
// that read one file at a time are split further, by file batch (eval_units.go).
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

	// RespectGitignore prunes files/dirs matched by .gitignore. The
	// sast/secrets/containers/iac commands set it true by default; the
	// user opts out with --<mode>-include-ignored.
	RespectGitignore bool

	// CacheDir, when set, keeps the findings of per-file rules between runs so
	// an unchanged file is not evaluated again (result_cache.go). CacheSalt
	// identifies the CLI build in the cache key.
	CacheDir  string
	CacheSalt string
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
		RespectGitignore:     opts.RespectGitignore,
	})
	if err != nil {
		return nil, fmt.Errorf("build scan input: %w", err)
	}

	// Drop rules whose declared languages are entirely absent from the repo: they
	// can never fire, so skipping them avoids their (dominant) compile cost and
	// their eval cost. Universal/unknown rules are kept. Opt out with
	// VULNETIX_SAST_NO_LANG_FILTER for debugging or exhaustive runs.
	modules := e.modules
	if os.Getenv("VULNETIX_SAST_NO_LANG_FILTER") == "" {
		modules = filterModulesByLanguage(e.modules, scanInput.FileSet)
	}

	// Check if any surviving rule references input.file_contents; if so, load them.
	var degradations []string
	if needsFileContents(modules) {
		LoadFileContentsWithOptions(scanInput, LoadOptions{
			MaxFileSize:     1 << 20, // 1 MiB cap on raw text
			IgnoreBinaries:  opts.IgnoreBinaries,
			MinStringLength: opts.MinStringLength,
		})
		// Files present in the walk but absent from the content map were not
		// content-scanned (oversized, unreadable, or binary with the strings
		// pass disabled). Say so instead of letting "no findings" read as
		// "fully scanned".
		skipped := 0
		for p := range scanInput.FileSet {
			if _, ok := scanInput.FileContents[p]; !ok {
				skipped++
			}
		}
		if skipped > 0 {
			degradations = append(degradations, fmt.Sprintf(
				"%d file(s) were not content-scanned (over the 1 MiB text cap, unreadable, or binary)", skipped))
		}
		if opts.GitHistory && !opts.IgnoreGit {
			entries, herr := secretscan.ScanGitHistory(e.scanRoot, secretscan.GitHistoryOptions{
				MaxCommits:   opts.GitHistoryMaxCommits,
				MaxFiles:     opts.GitHistoryMaxFiles,
				MaxFileBytes: 4 << 20,
			})
			if herr != nil {
				degradations = append(degradations, "git history was not scanned: "+herr.Error())
			} else if len(entries) > 0 {
				MergeGitHistoryEntries(scanInput, entries)
			}
		}
	}

	// Partition shared modules (helpers) from independent rule packages and
	// decide how many shards to run. Each shard compiles helpers + its rule
	// subset and evaluates against the shared, read-only input; the union of
	// per-shard findings is identical to a single combined evaluation.
	shared, rules := partitionModules(modules)
	n := shardCount(len(rules))

	// Each rule sees only the file contents it can report on. A finding on a
	// file outside a rule's declared languages, or on prose for a source-code
	// rule, is discarded by findingApplies after evaluation, so evaluating the
	// rule against those files is pure cost: most of the embedded rules test
	// every line of every file. Rules are grouped by scope and each group gets
	// an input whose FileContents holds only in-scope files; FileSet stays
	// complete so existence checks ("is go.sum present") are unchanged.
	//
	// Within a group, a rule whose findings each come from one file's text
	// (classifyReach) is compiled once and evaluated a batch of files at a time
	// across the workers, so one large group no longer runs on one core while
	// the rest sit idle, and OPA's per-evaluation memo only ever holds one
	// batch. Every other rule runs once over its whole scope, sharded as before.
	idx := indexModules(modules)
	terms, err := newRegoInput(scanInput)
	if err != nil {
		return nil, err
	}
	cache := newCacheRun(opts, scanInput, modules)
	var units []*evalUnit
	for _, g := range groupByScope(rules) {
		in := scopedInput(scanInput, g.scope)
		perFile, cacheable, whole := map[string]string{}, map[string]string{}, map[string]string{}
		for name, src := range g.rules {
			r := idx.reach[name]
			switch {
			case perFileBatching && r.perFile && !r.usesTree && cache != nil:
				cacheable[name] = src
			case perFileBatching && r.perFile:
				perFile[name] = src
			default:
				whole[name] = src
			}
		}
		if len(perFile) > 0 {
			units = append(units, &evalUnit{mods: withShared(idx.sharedFor(shared, perFile), perFile), batches: fileBatches(in, batchBytes)})
		}
		if len(cacheable) > 0 {
			units = append(units, &evalUnit{
				mods:      withShared(idx.sharedFor(shared, cacheable), cacheable),
				batches:   batchPaths(cache.missesOf(in), in.FileContents, batchBytes),
				cacheable: true,
			})
		}
		k := 1
		if n > 1 && len(whole) > 0 {
			k = max(1, (n*len(whole)+len(rules)/2)/len(rules))
		}
		for _, shard := range shardModules(whole, min(k, len(whole))) {
			if len(shard) > 0 {
				units = append(units, &evalUnit{mods: withShared(idx.sharedFor(shared, shard), shard), batches: [][]string{inputPaths(in)}})
			}
		}
	}

	reports, err := runUnits(units, terms, evalWorkers())
	if err != nil {
		return nil, err
	}

	var allRules []RuleMetadata
	var allFindings []Finding
	for _, rep := range reports {
		allRules = append(allRules, rep.Rules...)
		allFindings = append(allFindings, rep.Findings...)
	}
	allFindings = append(allFindings, cache.finish(units, reports)...)
	// Deterministic order across shards/runs (the single-eval path was already
	// map-order, so callers must not depend on order; this just makes it stable).
	sortFindings(allFindings)

	hits, evaluated := cache.counts()
	return &SASTReport{
		Findings:       allFindings,
		Rules:          allRules,
		RulesLoaded:    len(allRules),
		Degradations:   degradations,
		CachedFiles:    hits,
		EvaluatedFiles: evaluated,
	}, nil
}

// evalModules compiles the given modules and evaluates them against input,
// returning the rules and findings for that module set. Used per shard and for
// the single-shard fast path.
func evalModules(modules map[string]string, input ast.Value) (*SASTReport, error) {
	compiler, err := compileModules(modules)
	if err != nil {
		return nil, err
	}
	r := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
		rego.ParsedInput(input),
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

// flowModuleMarker identifies the shared in-method data-flow helpers
// (rules/helpers_flow.rego). They are a large part of the compile cost, and
// only a handful of injection rules call them, so a shard includes them only
// when one of its rules does.
const flowModuleMarker = "In-method data-flow helpers"

func isFlowModule(src string) bool {
	return strings.Contains(src, flowModuleMarker) && strings.Contains(src, "package vulnetix.helpers")
}

// shardUsesFlow reports whether any rule in the shard calls helpers.flow_*.
func shardUsesFlow(shard map[string]string) bool {
	for _, src := range shard {
		if strings.Contains(src, "helpers.flow_") {
			return true
		}
	}
	return false
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
			if f.Metadata != nil && !findingApplies(f.Metadata, f.ArtifactURI, f.Snippet) {
				continue
			}

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
