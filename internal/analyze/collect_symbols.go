package analyze

// The structural code graph: symbols, imports and calls.
//
// Functions, classes, methods, interfaces, the file that contains each, imports between files
// in this repository, and call edges that can be resolved to those local symbols. Definitions
// and imports are facts. Calls are static inferences, so unresolved or ambiguous call sites do
// not produce graph edges.
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

// callQueries extract local call sites. They deliberately use the same capture vocabulary
// across languages: `@call.name` and, when the grammar exposes it cleanly, `@call.receiver`.
// Resolution is done below against symbols already found in the repository.
var callQueries = map[treesitter.LanguageID]string{
	treesitter.LangGo: `
		(call_expression function: (identifier) @call.name)
		(call_expression function: (selector_expression operand: (identifier) @call.receiver field: (field_identifier) @call.name))
	`,
	treesitter.LangPython: `
		(call function: (identifier) @call.name)
		(call function: (attribute object: (identifier) @call.receiver attribute: (identifier) @call.name))
	`,
	treesitter.LangJavaScript: `
		(call_expression function: (identifier) @call.name)
		(call_expression function: (member_expression object: (identifier) @call.receiver property: (property_identifier) @call.name))
		(new_expression constructor: (identifier) @call.name)
	`,
	treesitter.LangTypeScript: `
		(call_expression function: (identifier) @call.name)
		(call_expression function: (member_expression object: (identifier) @call.receiver property: (property_identifier) @call.name))
		(new_expression constructor: (identifier) @call.name)
	`,
	treesitter.LangJava: `
		(method_invocation name: (identifier) @call.name)
		(method_invocation object: (identifier) @call.receiver name: (identifier) @call.name)
	`,
	treesitter.LangRust: `
		(call_expression function: (identifier) @call.name)
		(call_expression function: (field_expression field: (field_identifier) @call.name))
	`,
	treesitter.LangCSharp: `
		(invocation_expression function: (identifier) @call.name)
		(invocation_expression function: (member_access_expression expression: (identifier) @call.receiver name: (identifier) @call.name))
	`,
	treesitter.LangPHP: `
		(function_call_expression function: (name) @call.name)
	`,
}

// maxSymbolsPerRepo bounds the graph. A monorepo has hundreds of thousands of symbols and
// nobody is going to look at them all; when the cap bites, the graph says so rather than
// presenting a partial picture as a whole one.
const maxSymbolsPerRepo = 20000

// maxCallEdgesPerRepo bounds static call relationships. Calls can be much denser than
// symbols; a capped graph is useful and honest, while a payload too large to persist helps no
// one. Multiple call sites between the same two symbols are collapsed into one edge.
const maxCallEdgesPerRepo = 20000

const maxCallSitesPerEdge = 5

type symbolStats struct {
	nodes []Node
	edges []Edge

	// filesParsed and langsSkipped exist so the report can say what it could not read. A
	// language with no query produces no symbols — which must not look like a language with
	// no code in it.
	filesParsed      int
	langsSkipped     map[string]int
	callLangsSkipped map[string]int
	truncated        bool
	callTruncated    bool
}

type callSite struct {
	file     string
	line     int
	name     string
	receiver string
}

func collectSymbols(b *Builder, root string, files *fileStats, modulePath string, opts Options, pr reporter) *symbolStats {
	engine := reachability.NewEngine()
	ctx := context.Background()

	st := &symbolStats{
		langsSkipped:     map[string]int{},
		callLangsSkipped: map[string]int{},
	}
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
	callSites := []callSite{}

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

		callQuery, ok := callQueries[lang]
		if !ok {
			st.callLangsSkipped[f.Language]++

			continue
		}
		callMatches, err := engine.Run(ctx, lang, src, callQuery)
		if err != nil {
			st.callLangsSkipped[f.Language]++

			continue
		}
		for _, m := range callMatches {
			name := strings.TrimSpace(m.Captures["call.name"])
			if name == "" {
				continue
			}
			callSites = append(callSites, callSite{
				file:     f.Path,
				line:     m.StartLine,
				name:     name,
				receiver: strings.TrimSpace(m.Captures["call.receiver"]),
			})
		}
	}

	st.edges = append(st.edges, resolveCallEdges(st, callSites, edgeIDs)...)
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

func resolveCallEdges(st *symbolStats, calls []callSite, edgeIDs map[string]bool) []Edge {
	if st == nil || len(st.nodes) == 0 || len(calls) == 0 {
		return nil
	}

	symbolsByFile := map[string][]Node{}
	targetsByFileAndName := map[string]map[string][]Node{}
	for _, n := range st.nodes {
		if n.Path == "" {
			continue
		}
		symbolsByFile[n.Path] = append(symbolsByFile[n.Path], n)
		if !isCallableTarget(n.Kind) {
			continue
		}
		byName := targetsByFileAndName[n.Path]
		if byName == nil {
			byName = map[string][]Node{}
			targetsByFileAndName[n.Path] = byName
		}
		byName[n.Name] = append(byName[n.Name], n)
	}
	for p := range symbolsByFile {
		sort.SliceStable(symbolsByFile[p], func(i, j int) bool {
			a, b := symbolsByFile[p][i], symbolsByFile[p][j]
			if a.StartLine == b.StartLine {
				return symbolRange(a) < symbolRange(b)
			}

			return a.StartLine < b.StartLine
		})
	}

	importsByFile := map[string][]string{}
	for _, e := range st.edges {
		if e.Kind != "imports" {
			continue
		}
		from, okFrom := strings.CutPrefix(e.From, "file:")
		to, okTo := strings.CutPrefix(e.To, "file:")
		if !okFrom || !okTo || from == "" || to == "" {
			continue
		}
		importsByFile[from] = append(importsByFile[from], to)
	}
	for p := range importsByFile {
		sort.Strings(importsByFile[p])
	}

	out := []Edge{}
	edgeIndex := map[string]int{}
	for _, site := range calls {
		if len(out) >= maxCallEdgesPerRepo {
			st.callTruncated = true

			break
		}
		caller := containingCallable(symbolsByFile[site.file], site.line)
		if caller == nil {
			continue
		}
		target, resolution, confidence := resolveCallTarget(site, targetsByFileAndName, importsByFile)
		if target == nil || target.ID == caller.ID {
			continue
		}

		id := fmt.Sprintf("e:calls:%s->%s", caller.ID, target.ID)
		if edgeIDs[id] {
			continue
		}
		if idx, ok := edgeIndex[id]; ok {
			mergeCallEdge(&out[idx], site, confidence)

			continue
		}

		edge := Edge{
			ID:         id,
			Kind:       "calls",
			From:       caller.ID,
			To:         target.ID,
			Confidence: confidence,
			Resolution: resolution,
			Properties: map[string]any{
				"callName": site.name,
				"count":    1,
				"sites":    []map[string]any{callSiteProperty(site)},
			},
		}
		edgeIndex[id] = len(out)
		edgeIDs[id] = true
		out = append(out, edge)
	}

	return out
}

func resolveCallTarget(site callSite, targets map[string]map[string][]Node, imports map[string][]string) (*Node, string, float64) {
	if site.name == "" {
		return nil, "", 0
	}

	if site.receiver == "" {
		if target := uniqueTarget(targets[site.file][site.name]); target != nil {
			return target, "lexical", 0.9
		}
		if target := uniqueImportedTarget(site, targets, imports, false); target != nil {
			return target, "import", 0.78
		}

		return nil, "", 0
	}

	if target := uniqueImportedTarget(site, targets, imports, true); target != nil {
		return target, "import", 0.72
	}
	if target := uniqueTarget(targets[site.file][site.name]); target != nil {
		return target, "heuristic", 0.55
	}

	return nil, "", 0
}

func uniqueImportedTarget(site callSite, targets map[string]map[string][]Node, imports map[string][]string, receiverMustMatch bool) *Node {
	candidates := []Node{}
	for _, imported := range imports[site.file] {
		if receiverMustMatch && !receiverMatchesImport(site.receiver, imported) {
			continue
		}
		candidates = append(candidates, targets[imported][site.name]...)
	}

	return uniqueTarget(candidates)
}

func receiverMatchesImport(receiver, imported string) bool {
	receiver = strings.TrimSpace(receiver)
	if receiver == "" || imported == "" {
		return false
	}
	dir := path.Base(path.Dir(imported))
	base := strings.TrimSuffix(path.Base(imported), path.Ext(imported))

	return receiver == dir || receiver == base
}

func uniqueTarget(candidates []Node) *Node {
	if len(candidates) != 1 {
		return nil
	}

	return &candidates[0]
}

func containingCallable(symbols []Node, line int) *Node {
	var best *Node
	for i := range symbols {
		n := &symbols[i]
		if !isCallableCaller(n.Kind) || n.StartLine == 0 || line < n.StartLine {
			continue
		}
		if n.EndLine != 0 && line > n.EndLine {
			continue
		}
		if best == nil || symbolRange(*n) < symbolRange(*best) {
			best = n
		}
	}

	return best
}

func isCallableCaller(kind string) bool {
	return kind == "function" || kind == "method"
}

func isCallableTarget(kind string) bool {
	return kind == "function" || kind == "method" || kind == "class"
}

func symbolRange(n Node) int {
	if n.StartLine == 0 || n.EndLine == 0 || n.EndLine < n.StartLine {
		return 1 << 30
	}

	return n.EndLine - n.StartLine
}

func mergeCallEdge(edge *Edge, site callSite, confidence float64) {
	if confidence > edge.Confidence {
		edge.Confidence = confidence
	}
	if edge.Properties == nil {
		edge.Properties = map[string]any{}
	}
	count, _ := edge.Properties["count"].(int)
	edge.Properties["count"] = count + 1

	sites, _ := edge.Properties["sites"].([]map[string]any)
	if len(sites) < maxCallSitesPerEdge {
		sites = append(sites, callSiteProperty(site))
		edge.Properties["sites"] = sites
	}
}

func callSiteProperty(site callSite) map[string]any {
	out := map[string]any{
		"path": site.file,
		"line": site.line,
		"name": site.name,
	}
	if site.receiver != "" {
		out["receiver"] = site.receiver
	}

	return out
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

	callRefs := []EvidenceRef{}
	for _, e := range st.edges {
		if e.Kind != "calls" {
			continue
		}
		id := "call-" + safeID(e.ID)
		callRefs = append(callRefs, b.AddRecord(id, &GraphElementRecord{
			ID:        id,
			Type:      "graph_element",
			ElementID: e.ID,
			Element:   "edge",
		}))
	}

	callMetric := Metric{
		ID: "graph.calls.resolved", Family: "graph", Name: "Resolved local calls",
		Definition: "Static call sites resolved to functions, methods or classes defined in this repository. Ambiguous and external calls are omitted rather than guessed; repeated call sites between the same two symbols are collapsed into one edge with a count.",
	}
	if st.callTruncated || st.truncated {
		b.CountTruncated(callMetric, callRefs, 1, fmt.Sprintf(
			"call extraction stopped at the cap of %d call edges, or because symbol extraction was capped", maxCallEdgesPerRepo))
	} else {
		b.Count(callMetric, callRefs)
	}

	if len(st.langsSkipped) > 0 {
		names := sortedKeys(st.langsSkipped)
		b.Diagnose(Diagnostic{
			Level: "note", Collector: "symbols",
			Message: "No symbol-extraction query for: " + strings.Join(names, ", ") +
				". Files in these languages contribute no symbols to the graph — which is not the same as having none.",
		})
	}
	if len(st.callLangsSkipped) > 0 {
		names := sortedKeys(st.callLangsSkipped)
		b.Diagnose(Diagnostic{
			Level: "note", Collector: "symbols",
			Message: "No call-extraction query for: " + strings.Join(names, ", ") +
				". Files in these languages contribute symbols but no call edges.",
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
