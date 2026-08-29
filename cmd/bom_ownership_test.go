package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────
// bom_ownership_test.go — the capability-owner lock for SBOM reading.
//
// AGENTS.md: every capability has exactly one owner, reached through one entry
// function that both the owner's subcommand and the scan engine call. The
// license stage is the cautionary tale — it grew a weaker fixed-policy fork
// inside cmd/scan.go because nothing stopped it.
//
// SBOM parsing is the same shape of risk. It is easy to reach for
// json.Unmarshal on a document in a hurry, and a second parser would silently
// skip the envelope unwrapping, the SPDX mapping and the source stamping that
// internal/bom does. These tests fail when that starts.
// ─────────────────────────────────────────────────────────────────────────

// parseCmdFile parses one file in this package for AST inspection.
func parseCmdFile(t *testing.T, name string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return fset, f
}

// bomFamilyFiles are the files that collectively own SBOM reading.
//
// They are one capability split for readability, not several owners: every one
// of them parses through internal/bom's loader, so all of them unwrap
// attestation envelopes, normalise SPDX and stamp source provenance. The rule
// that matters is that nothing outside this set parses an SBOM.
var bomFamilyFiles = map[string]bool{
	"bom.go":        true,
	"bom_corpus.go": true,
	"bom_enrich.go": true,
}

// TestBOMParsingHasOneOwner asserts that nothing outside the bom command family
// parses an SBOM. A file reaching for encoding/json on a document, or calling
// the loader directly, is the beginning of a second parser — and the second
// parser is always the one that forgets the envelope unwrapping.
func TestBOMParsingHasOneOwner(t *testing.T) {
	const bomPkg = `"github.com/vulnetix/cli/v3/internal/bom"`

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if bomFamilyFiles[name] || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), bomPkg) {
			t.Errorf("%s imports internal/bom directly. SBOM reading is owned by the bom "+
				"command family (%v) and reached through runBOMImport / runBOMCorpus; a "+
				"call site outside it is a second parser that will not unwrap attestation "+
				"envelopes or stamp source provenance.",
				name, sortedFamilyFiles())
		}
	}
}

// sortedFamilyFiles renders the family for an error message.
func sortedFamilyFiles() []string {
	out := make([]string, 0, len(bomFamilyFiles))
	for f := range bomFamilyFiles {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// TestCorpusIsReachedThroughItsEntryPoint asserts every corpus query builds its
// index through the one function, so they all agree about what the corpus
// contains and all report the same unreadable documents.
func TestCorpusIsReachedThroughItsEntryPoint(t *testing.T) {
	data, err := os.ReadFile("bom_corpus.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if strings.Count(body, "bom.Collect(") != 1 {
		t.Errorf("bom.Collect is called %d times in bom_corpus.go; it must be called once, "+
			"from runBOMCorpus, or two queries can disagree about what is in the corpus",
			strings.Count(body, "bom.Collect("))
	}
	if strings.Count(body, "bom.NewIndex(") != 1 {
		t.Errorf("bom.NewIndex is called %d times; it must be called once, from runBOMCorpus",
			strings.Count(body, "bom.NewIndex("))
	}
}

// TestBOMSubcommandsUseTheEntryPoint asserts the import path is the shared
// options-struct function rather than a per-subcommand parse.
func TestBOMSubcommandsUseTheEntryPoint(t *testing.T) {
	_, f := parseCmdFile(t, "bom.go")

	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runBOMImport" {
			return true
		}
		found = true
		if fn.Type.Params.NumFields() != 1 {
			t.Errorf("runBOMImport takes %d parameters; it must take exactly one "+
				"options struct so adding an input does not touch every caller",
				fn.Type.Params.NumFields())
			return false
		}
		param := fn.Type.Params.List[0]
		ident, ok := param.Type.(*ast.Ident)
		if !ok || ident.Name != "BOMImportOptions" {
			t.Errorf("runBOMImport parameter is %v, want BOMImportOptions", param.Type)
		}
		return false
	})
	if !found {
		t.Fatal("runBOMImport not found in bom.go; it is the entry point AGENTS.md requires")
	}
}

// TestBOMCommandsRegistered pins the subcommand set, so a subcommand cannot be
// added to the tree without also being visible here and in the generated
// command manifest.
func TestBOMCommandsRegistered(t *testing.T) {
	want := map[string]bool{
		// Single-document.
		"import": false, "validate": false, "diff": false, "merge": false, "tree": false,
		// Corpus.
		"ls": false, "where": false, "skew": false, "search": false,
		// Enrichment.
		"enrich": false,
	}
	for _, sub := range bomCmd.Commands() {
		name := sub.Name()
		if _, expected := want[name]; !expected {
			t.Errorf("unexpected `bom %s` subcommand; add it to this test and to the docs", name)
			continue
		}
		want[name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("`bom %s` is not registered", name)
		}
	}
}
