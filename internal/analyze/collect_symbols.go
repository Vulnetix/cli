package analyze

// The structural code graph: symbols and imports.
//
// Structural, and deliberately only structural. Functions, classes, methods, interfaces, the
// file that contains each, and the imports between files in this repository. Every one of
// those resolves exactly — a definition is where the parser says it is, and an import either
// names a file in this repo or it does not.
//
// What is NOT here is the call graph. GitNexus needed a seven-step lookup, an evidence-weight
// table and a deterministic tie-break cascade to resolve calls, and even then its own docs
// admit the ID instability that follows. A call edge that is wrong is worse than a call edge
// that is missing, because a graph you cannot trust is a graph nobody uses. Calls come later,
// with the resolver they need.
//
// The one idea worth taking from GitNexus wholesale is the unified capture tag: every
// language's query emits the same capture names, so nothing downstream ever branches on
// language.

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/treesitter"
)

// symbolQueries extract definitions and imports. Different grammars, different node names,
// identical capture names — `@definition.function`, `@definition.class`,
// `@definition.method`, `@definition.interface`, `@import.source`, and `@name` for the
// identifier.
var symbolQueries = map[treesitter.LanguageID]string{
	treesitter.LangGo: `
		(function_declaration name: (identifier) @name) @definition.function
		(method_declaration name: (field_identifier) @name) @definition.method
		(type_declaration (type_spec name: (type_identifier) @name type: (struct_type))) @definition.class
		(type_declaration (type_spec name: (type_identifier) @name type: (interface_type))) @definition.interface
		(import_spec path: (interpreted_string_literal) @import.source)
	`,
	treesitter.LangPython: `
		(function_definition name: (identifier) @name) @definition.function
		(class_definition name: (identifier) @name) @definition.class
		(import_from_statement module_name: (dotted_name) @import.source)
		(import_statement name: (dotted_name) @import.source)
	`,
	treesitter.LangJavaScript: `
		(function_declaration name: (identifier) @name) @definition.function
		(class_declaration name: (identifier) @name) @definition.class
		(method_definition name: (property_identifier) @name) @definition.method
		(import_statement source: (string) @import.source)
	`,
	treesitter.LangTypeScript: `
		(function_declaration name: (identifier) @name) @definition.function
		(class_declaration name: (type_identifier) @name) @definition.class
		(method_definition name: (property_identifier) @name) @definition.method
		(interface_declaration name: (type_identifier) @name) @definition.interface
		(import_statement source: (string) @import.source)
	`,
	treesitter.LangJava: `
		(class_declaration name: (identifier) @name) @definition.class
		(interface_declaration name: (identifier) @name) @definition.interface
		(method_declaration name: (identifier) @name) @definition.method
		(import_declaration (scoped_identifier) @import.source)
	`,
	treesitter.LangRuby: `
		(method name: (identifier) @name) @definition.method
		(class name: (constant) @name) @definition.class
		(module name: (constant) @name) @definition.class
	`,
	treesitter.LangRust: `
		(function_item name: (identifier) @name) @definition.function
		(struct_item name: (type_identifier) @name) @definition.class
		(trait_item name: (type_identifier) @name) @definition.interface
		(use_declaration argument: (scoped_identifier) @import.source)
	`,
	treesitter.LangCSharp: `
		(class_declaration name: (identifier) @name) @definition.class
		(interface_declaration name: (identifier) @name) @definition.interface
		(method_declaration name: (identifier) @name) @definition.method
		(using_directive (qualified_name) @import.source)
	`,
	treesitter.LangPHP: `
		(function_definition name: (name) @name) @definition.function
		(class_declaration name: (name) @name) @definition.class
		(interface_declaration name: (name) @name) @definition.interface
		(method_declaration name: (name) @name) @definition.method
	`,
}

// maxSymbolsPerRepo bounds the graph. A monorepo has hundreds of thousands of symbols and
// nobody is going to look at them all; when the cap bites, the graph says so rather than
// presenting a partial picture as a whole one.
const maxSymbolsPerRepo = 20000

type symbolStats struct {
	nodes []Node
	edges []Edge

	// filesParsed and langsSkipped exist so the report can say what it could not read. A
	// language with no query produces no symbols — which must not look like a language with
	// no code in it.
	filesParsed  int
	langsSkipped map[string]int
	truncated    bool
}

func collectSymbols(b *Builder, root string, files *fileStats, modulePath string, opts Options, pr reporter) *symbolStats {
	engine := reachability.NewEngine()
	ctx := context.Background()

	st := &symbolStats{langsSkipped: map[string]int{}}
	if files == nil {
		return st
	}

	// Every path in the repo, so an import can be resolved to a file that actually exists
	// rather than to a plausible-looking guess.
	known := make(map[string]bool, len(files.files))
	for _, f := range files.files {
		known[f.Path] = true
	}

	symbolIDs := map[string]bool{}
	edgeIDs := map[string]bool{}

	for _, f := range files.files {
		if len(st.nodes) >= maxSymbolsPerRepo {
			st.truncated = true

			break
		}

		lang := treesitter.LanguageID(f.Language)
		query, ok := symbolQueries[lang]
		if !ok {
			st.langsSkipped[f.Language]++

			continue
		}

		src, err := os.ReadFile(filepath.Join(root, f.Path))
		if err != nil {
			continue
		}

		matches, err := engine.Run(ctx, lang, src, query)
		if err != nil {
			// A query that does not compile against this grammar is our bug, not the user's code
			// being wrong. Record it and move on rather than failing the scan.
			st.langsSkipped[f.Language]++

			continue
		}
		st.filesParsed++
		if st.filesParsed%100 == 0 {
			pr.Stage("Extracting symbols (" + plural(len(st.nodes), "symbol", "symbols") + ")")
		}

		fileNode := "file:" + f.Path

		for _, m := range matches {
			if src := m.Captures["import.source"]; src != "" {
				target := resolveImport(f.Path, src, known, lang, modulePath)
				if target == "" {
					continue
				}
				// A file can import the same target twice. That is one edge, not two.
				edgeID := fmt.Sprintf("e:imports:%s->%s", f.Path, target)
				if edgeIDs[edgeID] {
					continue
				}
				edgeIDs[edgeID] = true

				st.edges = append(st.edges, Edge{
					ID:   edgeID,
					Kind: "imports",
					From: fileNode,
					To:   "file:" + target,
					// An import that resolves to a file in this repository is a fact, not an
					// inference. The ones that do not resolve produce no edge at all, rather than a
					// guess with a confidence attached to it.
					Confidence: 1,
					Resolution: "exact",
				})

				continue
			}

			kind, name := symbolOf(m.Captures)
			if kind == "" || name == "" {
				continue
			}

			// Two symbols in one file can share a name. Go permits several `init()` per file;
			// methods on different receivers collide; overloaded methods collide in every language
			// that has them. The line number disambiguates them, which means a symbol id is not
			// stable across edits — the report schema says so, and nothing persists these as a
			// foreign key.
			id := fmt.Sprintf("%s:%s:%s", kind, f.Path, name)
			if symbolIDs[id] {
				id = fmt.Sprintf("%s#%d", id, m.StartLine)
			}
			symbolIDs[id] = true
			st.nodes = append(st.nodes, Node{
				ID:            id,
				Kind:          kind,
				Name:          name,
				QualifiedName: f.Path + "." + name,
				Path:          f.Path,
				StartLine:     m.StartLine,
				EndLine:       m.EndLine,
				Language:      f.Language,
				// Go's convention, and the only exported-ness we can read without semantic analysis.
				// Wrong for other languages, so it is only set where it is knowable.
				Exported: lang == treesitter.LangGo && isExportedGo(name),
			})
			st.edges = append(st.edges, Edge{
				ID:         "e:contains:" + id,
				Kind:       "contains",
				From:       fileNode,
				To:         id,
				Confidence: 1,
				Resolution: "exact",
			})
		}
	}

	emitSymbolMetrics(b, st, opts)

	return st
}

// symbolOf maps the unified capture tags to a node kind. This is the payoff of the shared
// vocabulary: one switch, no language branching, and adding a language is a query, not code.
func symbolOf(captures map[string]string) (kind, name string) {
	name = captures["name"]
	switch {
	case has(captures, "definition.function"):
		return "function", name
	case has(captures, "definition.method"):
		return "method", name
	case has(captures, "definition.class"):
		return "class", name
	case has(captures, "definition.interface"):
		return "interface", name
	}

	return "", ""
}

func has(m map[string]string, k string) bool {
	_, ok := m[k]

	return ok
}

var quoted = regexp.MustCompile(`^["'` + "`" + `](.*)["'` + "`" + `]$`)

// resolveImport turns an import string into a path in this repository, or returns "".
//
// Only imports we can resolve *exactly* produce an edge. A relative import names a path we can
// check. A Go import that starts with this module's own path names a directory we can check.
// An import of `lodash` names a package, not a file in this repo, and never will — so it
// produces no edge rather than a guess. A graph full of edges to things that do not exist is
// worse than a graph with fewer edges.
func resolveImport(from, spec string, known map[string]bool, lang treesitter.LanguageID, modulePath string) string {
	if m := quoted.FindStringSubmatch(spec); m != nil {
		spec = m[1]
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}

	// Go does not have relative imports. Everything is a module path — so an import of this
	// module's own path is an internal import, and it names a directory. Without this, a Go
	// repository resolves exactly zero internal imports, which is not a graph, it is a list.
	if lang == treesitter.LangGo && modulePath != "" && strings.HasPrefix(spec, modulePath+"/") {
		dir := strings.TrimPrefix(spec, modulePath+"/")

		// The import names a package (a directory). Any Go file in it is a valid target; pick the
		// first deterministically so two runs agree.
		best := ""
		for p := range known {
			if path.Dir(p) == dir && strings.HasSuffix(p, ".go") {
				if best == "" || p < best {
					best = p
				}
			}
		}

		return best
	}

	if !strings.HasPrefix(spec, ".") {
		return ""
	}

	dir := path.Dir(from)
	base := path.Clean(path.Join(dir, spec))

	// The import may name the file, the file without its extension, or a directory with an
	// index/init file in it. Try each, and accept only what exists.
	candidates := []string{base}
	for _, ext := range extensionsFor(lang) {
		candidates = append(candidates,
			base+ext,
			path.Join(base, "index"+ext),
			path.Join(base, "__init__"+ext),
			path.Join(base, "mod"+ext),
		)
	}

	for _, c := range candidates {
		if known[c] {
			return c
		}
	}

	return ""
}

func extensionsFor(lang treesitter.LanguageID) []string {
	return treesitter.Extensions(lang)
}

func isExportedGo(name string) bool {
	if name == "" {
		return false
	}
	r := rune(name[0])

	return r >= 'A' && r <= 'Z'
}

func emitSymbolMetrics(b *Builder, st *symbolStats, opts Options) {
	byKind := map[string][]EvidenceRef{}
	for _, n := range st.nodes {
		// The node is already in the graph; the evidence points at it rather than duplicating
		// it. Two copies of the same fact are two facts that can disagree.
		ref := b.AddRecord("sym-"+safeID(n.ID), &GraphElementRecord{
			ID:        "sym-" + safeID(n.ID),
			Type:      "graph_element",
			ElementID: n.ID,
			Element:   "node",
		})
		byKind[n.Kind] = append(byKind[n.Kind], ref)
	}

	all := make([]EvidenceRef, 0, len(st.nodes))
	for _, kind := range sortedKeys(byKind) {
		all = append(all, byKind[kind]...)
	}

	m := Metric{
		ID: "graph.symbols.total", Family: "graph", Name: "Symbols",
		Definition: "Functions, methods, classes and interfaces defined in this repository, extracted with tree-sitter. Languages with no extraction query are excluded, not counted as zero.",
	}
	if st.truncated {
		b.CountTruncated(m, all, 1, fmt.Sprintf(
			"symbol extraction stopped at the cap of %d; the remaining symbols were not read", maxSymbolsPerRepo))
	} else {
		b.Count(m, all)
	}

	for _, kind := range sortedKeys(byKind) {
		b.Count(Metric{
			ID:         "graph.symbols." + kind,
			Family:     "graph",
			Name:       strings.ToUpper(kind[:1]) + kind[1:] + "s",
			Definition: "Definitions of kind " + kind + " found in this repository's source.",
		}, byKind[kind])
	}

	// Each resolved import is evidenced by the edge it produced, so "142 internal imports"
	// opens into the 142 edges rather than asking to be believed.
	importRefs := []EvidenceRef{}
	for _, e := range st.edges {
		if e.Kind != "imports" {
			continue
		}
		id := "imp-" + safeID(e.ID)
		importRefs = append(importRefs, b.AddRecord(id, &GraphElementRecord{
			ID:        id,
			Type:      "graph_element",
			ElementID: e.ID,
			Element:   "edge",
		}))
	}

	b.Count(Metric{
		ID: "graph.imports.resolved", Family: "graph", Name: "Resolved internal imports",
		Definition: "Import statements that resolve to a file within this repository. Imports of external packages are dependency edges, not import edges — and an import that resolves to nothing produces no edge at all, rather than a guess with a confidence attached to it.",
	}, importRefs)

	if len(st.langsSkipped) > 0 {
		names := sortedKeys(st.langsSkipped)
		b.Diagnose(Diagnostic{
			Level: "note", Collector: "symbols",
			Message: "No symbol-extraction query for: " + strings.Join(names, ", ") +
				". Files in these languages contribute no symbols to the graph — which is not the same as having none.",
		})
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)

	return out
}
