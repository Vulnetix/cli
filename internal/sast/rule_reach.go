package sast

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Rule reach: what a rule module's findings can depend on.
//
// Most rules report a finding from one file's text: a findings body iterates
// input.file_contents once and everything else it calls works on that file's
// lines. Such a rule can be evaluated a batch of files at a time, and its
// findings for an unchanged file can be kept from an earlier run, without
// changing what it reports. A rule that reads a second file (a config value, a
// constant declared elsewhere, the Java call graph) cannot, and runs once over
// every file in its scope.
//
// The analysis is on parsed, uncompiled modules and errs towards "reads other
// files": anything it cannot place (a parse error, the whole input document, a
// literal path) keeps the rule on the whole-tree path.
type moduleReach struct {
	// perFile is true when every finding depends on the text of one file.
	perFile bool
	// usesTree is true when a finding can also depend on the rest of the scan
	// input: the file list, the language directories or the scan root. Those
	// change when any file is added, so these findings are never cached
	// per file.
	usesTree bool
	// volatile is true when a finding can depend on something other than the
	// scan input: the clock, a network lookup, a random number. Its findings
	// are never cached at all.
	volatile bool
}

// ruleFacts is what one rule (one definition of a name) reads.
type ruleFacts struct {
	fcAll     int  // references to input.file_contents anywhere in the rule
	fcTop     int  // of those, outside comprehensions
	fcLiteral bool // input.file_contents["a/literal/path"]
	tree      bool // input.file_set, dirs_by_language, scan_root, or input itself
	volatile  bool // calls a builtin whose result is not a function of its arguments
	deps      []string
}

// reachIndex holds the facts for every rule name in a module set, keyed by
// "<package path>.<name>" so a call into a shared helper resolves to it.
type reachIndex struct {
	facts    map[string][]ruleFacts
	fcMemo   map[string]bool
	treeMemo map[string]bool
	volMemo  map[string]bool
}

// classifyReach returns the reach of every rule module (package
// vulnetix.rules.*) in modules. A module that does not parse is left out,
// which callers treat as whole-tree.
func classifyReach(modules map[string]string) map[string]moduleReach {
	return indexModules(modules).reach
}

// moduleIndex is what the engine learns from parsing a module set once: each
// rule module's reach, and which packages each module refers to.
type moduleIndex struct {
	reach map[string]moduleReach
	pkg   map[string]string   // module name → package path ("data.vulnetix.helpers")
	refs  map[string][]string // module name → data paths it imports or names
}

func indexModules(modules map[string]string) *moduleIndex {
	parsed := make(map[string]*ast.Module, len(modules))
	for name, src := range modules {
		mod, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err == nil {
			parsed[name] = mod
		}
	}
	mi := &moduleIndex{pkg: map[string]string{}, refs: map[string][]string{}}
	for name, mod := range parsed {
		mi.pkg[name] = mod.Package.Path.String()
		mi.refs[name] = dataRefs(mod)
	}

	// Names defined per package, across files: helpers.rego and
	// helpers_flow.rego share package vulnetix.helpers.
	defined := map[string]map[string]bool{}
	for _, mod := range parsed {
		pkg := mod.Package.Path.String()
		if defined[pkg] == nil {
			defined[pkg] = map[string]bool{}
		}
		for _, r := range mod.Rules {
			defined[pkg][ruleName(r)] = true
		}
	}

	idx := &reachIndex{facts: map[string][]ruleFacts{}, fcMemo: map[string]bool{}, treeMemo: map[string]bool{}, volMemo: map[string]bool{}}
	for _, mod := range parsed {
		pkg := mod.Package.Path.String()
		aliases := importAliases(mod)
		for _, r := range mod.Rules {
			id := pkg + "." + ruleName(r)
			idx.facts[id] = append(idx.facts[id], factsOf(r, pkg, defined[pkg], aliases))
		}
	}

	out := make(map[string]moduleReach, len(parsed))
	for name, mod := range parsed {
		pkg := mod.Package.Path.String()
		if !strings.HasPrefix(pkg, "data.vulnetix.rules.") {
			continue
		}
		reach := moduleReach{perFile: true}
		seen := false
		for _, f := range idx.facts[pkg+".findings"] {
			seen = true
			if f.fcAll != 1 || f.fcTop != 1 || f.fcLiteral {
				reach.perFile = false
			}
			if f.tree {
				reach.usesTree = true
			}
			if f.volatile {
				reach.volatile = true
			}
			for _, d := range f.deps {
				if idx.readsFiles(d) {
					reach.perFile = false
				}
				if idx.readsTree(d) {
					reach.usesTree = true
				}
				if idx.isVolatile(d) {
					reach.volatile = true
				}
			}
		}
		if !seen {
			reach.perFile = false
		}
		out[name] = reach
	}
	mi.reach = out
	return mi
}

// dataRefs is every data path a module imports or names, cut at the first
// part that is not a constant (data.lib[x] is data.lib).
func dataRefs(mod *ast.Module) []string {
	seen := map[string]bool{}
	add := func(ref ast.Ref) {
		if len(ref) > 0 && ref[0].Equal(ast.DefaultRootDocument) {
			seen[ref.GroundPrefix().String()] = true
		}
	}
	for _, imp := range mod.Imports {
		if ref, ok := imp.Path.Value.(ast.Ref); ok {
			add(ref)
		}
	}
	for _, r := range mod.Rules {
		ast.WalkRefs(r, func(ref ast.Ref) bool { add(ref); return false })
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}

// sharedFor is the part of shared that rules can reach: the shared modules
// whose package a rule refers to, and what those refer to in turn. Every
// unit used to compile all of them, including the libraries of external rule
// packs whose rules the kind filter had dropped. A module that did not parse
// is kept, since what it needs is unknown.
func (mi *moduleIndex) sharedFor(shared, rules map[string]string) map[string]string {
	var frontier []string
	for name := range rules {
		refs, ok := mi.refs[name]
		if !ok {
			return shared
		}
		frontier = append(frontier, refs...)
	}
	keep := map[string]string{}
	for name, src := range shared {
		if _, ok := mi.pkg[name]; !ok {
			keep[name] = src
		}
	}
	for len(frontier) > 0 {
		var next []string
		for name, src := range shared {
			if _, kept := keep[name]; kept {
				continue
			}
			pkg := mi.pkg[name]
			for _, ref := range frontier {
				if ref == pkg || strings.HasPrefix(ref, pkg+".") || strings.HasPrefix(pkg, ref+".") {
					keep[name] = src
					next = append(next, mi.refs[name]...)
					break
				}
			}
		}
		frontier = next
	}
	return keep
}

// readsFiles reports whether rule id, or anything it calls, reads
// input.file_contents.
func (x *reachIndex) readsFiles(id string) bool {
	return x.walk(id, x.fcMemo, func(f ruleFacts) bool { return f.fcAll > 0 })
}

// readsTree reports whether rule id, or anything it calls, reads the input
// beyond file_contents.
func (x *reachIndex) readsTree(id string) bool {
	return x.walk(id, x.treeMemo, func(f ruleFacts) bool { return f.tree })
}

// isVolatile reports whether rule id, or anything it calls, calls a builtin
// whose result is not a function of its arguments.
func (x *reachIndex) isVolatile(id string) bool {
	return x.walk(id, x.volMemo, func(f ruleFacts) bool { return f.volatile })
}

// clockBuiltins read the current time without OPA marking them
// nondeterministic: they check a token's or certificate's validity period.
var clockBuiltins = map[string]bool{
	"io.jwt.decode_verify":                                   true,
	"crypto.x509.parse_and_verify_certificates":              true,
	"crypto.x509.parse_and_verify_certificates_with_options": true,
}

// volatileCall reports whether ref names a builtin whose result can change
// between two evaluations of the same input.
func volatileCall(ref ast.Ref) bool {
	name := ref.String()
	if clockBuiltins[name] {
		return true
	}
	b, ok := ast.BuiltinMap[name]
	return ok && b.IsNondeterministic()
}

func (x *reachIndex) walk(id string, memo map[string]bool, direct func(ruleFacts) bool) bool {
	if v, ok := memo[id]; ok {
		return v
	}
	memo[id] = false // Rego forbids recursion; this only guards a malformed set
	for _, f := range x.facts[id] {
		if direct(f) {
			memo[id] = true
			return true
		}
		for _, d := range f.deps {
			if x.walk(d, memo, direct) {
				memo[id] = true
				return true
			}
		}
	}
	return false
}

func ruleName(r *ast.Rule) string {
	if v, ok := r.Head.Ref()[0].Value.(ast.Var); ok {
		return string(v)
	}
	return r.Head.Ref()[0].String()
}

func importAliases(mod *ast.Module) map[string]string {
	out := map[string]string{}
	for _, imp := range mod.Imports {
		ref, ok := imp.Path.Value.(ast.Ref)
		if !ok || len(ref) < 2 || !ref[0].Equal(ast.DefaultRootDocument) {
			continue
		}
		alias := string(imp.Alias)
		if alias == "" {
			s, ok := ref[len(ref)-1].Value.(ast.String)
			if !ok {
				continue
			}
			alias = string(s)
		}
		out[alias] = ref.String()
	}
	return out
}

var (
	inputVar        = ast.InputRootDocument.Value.(ast.Var)
	fileContentsStr = ast.String("file_contents")
)

func factsOf(r *ast.Rule, pkg string, local map[string]bool, aliases map[string]string) ruleFacts {
	var f ruleFacts
	ast.WalkRefs(r, func(ref ast.Ref) bool {
		countInputRef(ref, &f, &f.fcAll)
		if volatileCall(ref) {
			f.volatile = true
		}
		f.deps = appendDep(f.deps, ref, aliases)
		return false
	})
	inClosures := 0
	ast.WalkClosures(r, func(x any) bool {
		ast.WalkRefs(x, func(ref ast.Ref) bool {
			var scratch ruleFacts
			countInputRef(ref, &scratch, &inClosures)
			return false
		})
		return true // count each closure once, at its outermost level
	})
	f.fcTop = f.fcAll - inClosures

	self := ruleName(r)
	ast.WalkVars(r, func(v ast.Var) bool {
		if name := string(v); local[name] && name != self {
			f.deps = append(f.deps, pkg+"."+name)
		}
		return false
	})
	return f
}

// countInputRef classifies one reference to the input document.
func countInputRef(ref ast.Ref, f *ruleFacts, fc *int) {
	if len(ref) == 0 || ref[0].Value.Compare(inputVar) != 0 {
		return
	}
	if len(ref) == 1 {
		f.tree = true // the whole input document
		return
	}
	key, ok := ref[1].Value.(ast.String)
	switch {
	case !ok:
		f.tree = true // input[x]
	case key == fileContentsStr:
		*fc++
		if len(ref) > 2 {
			if _, lit := ref[2].Value.(ast.String); lit {
				f.fcLiteral = true
			}
		}
	default:
		f.tree = true
	}
}

// appendDep records a call into another package: through an import alias
// (helpers.is_comment_line) or a data reference.
func appendDep(deps []string, ref ast.Ref, aliases map[string]string) []string {
	if len(ref) < 2 {
		return deps
	}
	name, ok := ref[1].Value.(ast.String)
	if !ok {
		return deps
	}
	head, ok := ref[0].Value.(ast.Var)
	if !ok {
		return deps
	}
	if head == ast.DefaultRootDocument.Value.(ast.Var) {
		// data.vulnetix.helpers.x: the longest prefix that is a package is not
		// known here, so record every prefix; unknown ids have no facts.
		for i := 2; i <= len(ref); i++ {
			deps = append(deps, ref[:i].String())
		}
		return deps
	}
	if pkg, ok := aliases[string(head)]; ok {
		deps = append(deps, pkg+"."+string(name))
	}
	return deps
}
