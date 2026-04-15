package sast

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine compiles Rego modules and evaluates them against a filesystem scan.
type Engine struct {
	modules  map[string]string // filename → rego source
	scanRoot string
}

// EvalOptions configures the SAST evaluation.
type EvalOptions struct {
	MaxDepth int
	Excludes []string
}

// NewEngine constructs an Engine with the given Rego modules.
func NewEngine(modules map[string]string, scanRoot string) *Engine {
	return &Engine{modules: modules, scanRoot: scanRoot}
}

// compile parses and compiles all loaded Rego modules.
func (e *Engine) compile() (*ast.Compiler, error) {
	parsed := make(map[string]*ast.Module, len(e.modules))
	for name, src := range e.modules {
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
	compiler, err := e.compile()
	if err != nil {
		return nil, err
	}

	// Build OPA input from filesystem.
	scanInput, err := BuildScanInput(e.scanRoot, opts.MaxDepth, opts.Excludes)
	if err != nil {
		return nil, fmt.Errorf("build scan input: %w", err)
	}

	// Check if any rule references input.file_contents; if so, load contents.
	if needsFileContents(e.modules) {
		LoadFileContents(scanInput, 1<<20) // 1MB max
	}

	ctx := context.Background()

	// Evaluate all rules in one query.
	r := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
		rego.Input(scanInput),
	)

	rs, err := r.Eval(ctx)
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

	return &SASTReport{
		Findings:    findings,
		Rules:       rules,
		RulesLoaded: len(rules),
	}, nil
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
