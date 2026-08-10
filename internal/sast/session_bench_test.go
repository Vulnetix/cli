package sast

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Benchmarks for the language-server warm-state design.
//
// engine.go:20-25 claims compiling the full embedded rule set costs ~85s on one
// host and dominates a scan. Everything in the LSP design (hot/full tier split,
// the compile cache, PrepareForEval, the 8s first-diagnostics budget) is priced
// off that number, so it needs measuring rather than quoting.
//
// These are slow by construction. Run them deliberately:
//
//	go test ./internal/sast/ -run '^$' -bench 'Compile|Prepare' -benchtime 1x -timeout 60m
//	go test ./internal/sast/ -run '^$' -bench 'EvalWarm|BuildScanInput' -benchtime 3x -timeout 30m
//
// -benchtime 1x matters for the compile benchmarks: the default 1s target would
// run a ~85s operation for many iterations.

// benchModules loads the full embedded corpus once per process.
var (
	benchModulesOnce sync.Once
	benchModules     map[string]string
	benchModulesErr  error
)

func embeddedModules(tb testing.TB) map[string]string {
	tb.Helper()
	benchModulesOnce.Do(func() {
		benchModules, benchModulesErr = LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	})
	if benchModulesErr != nil {
		tb.Fatalf("load embedded modules: %v", benchModulesErr)
	}
	return benchModules
}

// BenchmarkCompileAll is the headline number: one compiler, every embedded
// rule, no language filter and no sharding. This is the worst case a cold
// daemon would pay if none of the warm-state work existed.
func BenchmarkCompileAll(b *testing.B) {
	modules := embeddedModules(b)
	b.ReportMetric(float64(len(modules)), "modules")
	b.ResetTimer()
	for b.Loop() {
		if _, err := compileModules(modules); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompileSharded measures the existing partition+shard strategy at
// each shard count. shardCount() caps at shardMaxCount=16, so this brackets the
// achievable parallel compile.
func BenchmarkCompileSharded(b *testing.B) {
	modules := embeddedModules(b)
	shared, rules := partitionModules(modules)
	for _, n := range []int{2, 4, 8, 16} {
		b.Run(fmt.Sprintf("shards=%d", n), func(b *testing.B) {
			shards := shardModules(rules, n)
			b.ResetTimer()
			for b.Loop() {
				compileShardsParallel(b, shared, shards)
			}
		})
	}
}

// compileShardsParallel mirrors what Evaluate() does per call today: build each
// shard's module map and compile them concurrently.
func compileShardsParallel(b *testing.B, shared map[string]string, shards []map[string]string) {
	b.Helper()
	errs := make([]error, len(shards))
	var wg sync.WaitGroup
	for i := range shards {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mods := make(map[string]string, len(shared)+len(shards[i]))
			maps.Copy(mods, shared)
			maps.Copy(mods, shards[i])
			_, errs[i] = compileModules(mods)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchLanguageFileSets are the repo shapes the hot tier has to serve. The
// language filter (language_filter.go:351) drops rules whose declared languages
// are absent, and it is the single largest lever on compile cost, so the hot
// tier's viability depends on how much it removes per shape.
var benchLanguageFileSets = map[string]map[string]bool{
	"go":     {"go.mod": true, "main.go": true, "internal/a/a.go": true},
	"node":   {"package.json": true, "src/index.js": true, "src/app.ts": true},
	"python": {"pyproject.toml": true, "app/main.py": true, "app/util.py": true},
	"java":   {"pom.xml": true, "src/main/java/A.java": true},
	"polyglot": {
		"go.mod": true, "main.go": true,
		"package.json": true, "src/index.ts": true,
		"pyproject.toml": true, "app/main.py": true,
		"pom.xml": true, "src/main/java/A.java": true,
		"Cargo.toml": true, "src/lib.rs": true,
		"Dockerfile": true, "infra/main.tf": true,
	},
}

// BenchmarkCompileFiltered is the number that actually prices the hot tier:
// compile cost after the language filter, per repo shape.
func BenchmarkCompileFiltered(b *testing.B) {
	modules := embeddedModules(b)
	for _, name := range []string{"go", "node", "python", "java", "polyglot"} {
		b.Run(name, func(b *testing.B) {
			filtered := filterModulesByLanguage(modules, benchLanguageFileSets[name])
			b.ReportMetric(float64(len(filtered)), "modules")
			b.ReportMetric(float64(len(filtered))/float64(len(modules))*100, "%%kept")
			b.ResetTimer()
			for b.Loop() {
				if _, err := compileModules(filtered); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPrepareForEval measures preparation alone, against an already
// compiled corpus. The warm design pays this once per shard per rule set; if it
// is a significant fraction of compile, the tier-swap budget has to absorb it.
func BenchmarkPrepareForEval(b *testing.B) {
	modules := filterModulesByLanguage(embeddedModules(b), benchLanguageFileSets["go"])
	compiler, err := compileModules(modules)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if _, err := rego.New(
			rego.Compiler(compiler),
			rego.Query("data.vulnetix.rules"),
		).PrepareForEval(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEvalWarm is the keystroke-path number: a prepared query already in
// memory, evaluated against N files. The LSP budget is <150ms p95 for a single
// file (files=1) and <12s p95 for a 5k-file workspace re-scan.
func BenchmarkEvalWarm(b *testing.B) {
	modules := filterModulesByLanguage(embeddedModules(b), benchLanguageFileSets["go"])
	compiler, err := compileModules(modules)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	pq, err := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
	).PrepareForEval(ctx)
	if err != nil {
		b.Fatal(err)
	}

	for _, n := range []int{1, 10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			in := syntheticScanInput(n)
			b.ResetTimer()
			for b.Loop() {
				if _, err := pq.Eval(ctx, rego.EvalInput(in)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEvalWarmByKind attributes warm evaluation cost to rule kind.
//
// This is the benchmark that decides the language-server hot path. The
// repo-wide language filter keeps ~1,232 of 1,899 modules on a Go repo, but
// 1,092 of those are `kind: secrets`, which are language-agnostic and
// therefore never filtered out. Every one of them iterates
// `input.file_contents`, so the cost of evaluating a single edited file is
// dominated by rules that have nothing to do with that file's language.
//
// If secrets are the bulk of it, the keystroke path should evaluate sast/iac/
// oci kinds only and defer secrets to save, which is a far larger lever than
// caching a compile that costs under two seconds.
func BenchmarkEvalWarmByKind(b *testing.B) {
	all := filterModulesByLanguage(embeddedModules(b), benchLanguageFileSets["go"])
	ctx := context.Background()

	sets := map[string]map[string]string{
		"all":            all,
		"sast-only":      FilterModulesToKinds(all, []string{KindSAST}),
		"secrets-only":   FilterModulesToKinds(all, []string{KindSecrets}),
		"without-secret": FilterModulesToKinds(all, InteractiveKinds),
	}

	for _, name := range []string{"all", "sast-only", "secrets-only", "without-secret"} {
		modules := sets[name]
		compiler, err := compileModules(modules)
		if err != nil {
			b.Fatalf("%s: %v", name, err)
		}
		pq, err := rego.New(
			rego.Compiler(compiler),
			rego.Query("data.vulnetix.rules"),
		).PrepareForEval(ctx)
		if err != nil {
			b.Fatalf("%s: %v", name, err)
		}
		for _, n := range []int{1, 100} {
			b.Run(fmt.Sprintf("%s/files=%d", name, n), func(b *testing.B) {
				b.ReportMetric(float64(len(modules)), "modules")
				in := syntheticScanInput(n)
				b.ResetTimer()
				for b.Loop() {
					if _, err := pq.Eval(ctx, rego.EvalInput(in)); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkBuildScanInput measures the filesystem walk, which the LSP repeats
// on didChangeWatchedFiles and which needs a ctx-aware variant to be
// cancellable (there is no cancellation in filepath.WalkDir today).
func BenchmarkBuildScanInput(b *testing.B) {
	for _, n := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			root := syntheticRepo(b, n)
			b.ResetTimer()
			for b.Loop() {
				in, err := BuildScanInputWithOptions(root, BuildOptions{MaxDepth: 10})
				if err != nil {
					b.Fatal(err)
				}
				if len(in.FileSet) == 0 {
					b.Fatal("empty file set")
				}
			}
		})
	}
}

// syntheticScanInput builds an in-memory input of n Go-ish files with no
// content designed to fire a rule, so the measurement is evaluation throughput
// rather than finding-extraction cost.
func syntheticScanInput(n int) *ScanInput {
	fileSet := make(map[string]bool, n+1)
	contents := make(map[string]string, n+1)
	fileSet["go.mod"] = true
	contents["go.mod"] = "module example.com/bench\n\ngo 1.25\n"
	for i := range n {
		p := fmt.Sprintf("pkg/p%03d/file%05d.go", i%100, i)
		fileSet[p] = true
		contents[p] = fmt.Sprintf(
			"package p%03d\n\nimport \"fmt\"\n\nfunc F%05d(s string) string {\n\treturn fmt.Sprintf(\"%%s-%d\", s)\n}\n",
			i%100, i, i)
	}
	return &ScanInput{
		FileSet:        fileSet,
		DirsByLanguage: map[string][]string{"go": {"."}},
		FileContents:   contents,
		ScanRoot:       "/bench",
	}
}

// syntheticRepo materialises n files on disk, spread across directories so the
// walk sees a realistic tree rather than one flat directory.
func syntheticRepo(tb testing.TB, n int) string {
	tb.Helper()
	root := tb.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/bench\n\ngo 1.25\n"), 0o644); err != nil {
		tb.Fatal(err)
	}
	body := []byte("package p\n\nfunc F() {}\n")
	const perDir = 50
	for i := range n {
		dir := filepath.Join(root, "pkg", fmt.Sprintf("d%04d", i/perDir))
		if i%perDir == 0 {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				tb.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d.go", i)), body, 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	return root
}

// TestBenchFixturesAreSane keeps the benchmark helpers honest without paying
// the benchmark cost: it runs in normal `just test` and fails if the corpus
// stops loading, the language filter stops filtering, or the synthetic repo
// stops producing a walkable tree.
func TestBenchFixturesAreSane(t *testing.T) {
	modules := embeddedModules(t)
	if len(modules) < 1000 {
		t.Fatalf("embedded corpus looks wrong: %d modules", len(modules))
	}

	full := len(modules)
	for name, fileSet := range benchLanguageFileSets {
		kept := len(filterModulesByLanguage(modules, fileSet))
		if kept == 0 || kept > full {
			t.Fatalf("%s: filter kept %d of %d modules", name, kept, full)
		}
		t.Logf("%-9s keeps %4d/%d modules (%.1f%%)", name, kept, full, float64(kept)/float64(full)*100)
	}

	if in := syntheticScanInput(10); len(in.FileSet) != 11 {
		t.Fatalf("syntheticScanInput(10) produced %d files", len(in.FileSet))
	}

	root := syntheticRepo(t, 100)
	in, err := BuildScanInputWithOptions(root, BuildOptions{MaxDepth: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(in.FileSet) < 100 {
		t.Fatalf("walk of a 100-file repo found %d files", len(in.FileSet))
	}

	// Guards the assumption the warm design rests on: the query prepares
	// against a real (filtered) slice of the corpus, not just synthetic rules.
	compiler, err := compileModules(filterModulesByLanguage(modules, benchLanguageFileSets["go"]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
	).PrepareForEval(context.Background()); err != nil {
		t.Fatalf("PrepareForEval on the real embedded corpus: %v", err)
	}
	var _ *ast.Compiler = compiler
}
