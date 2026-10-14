package sast

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// File scoping. A rule is a claim about the source it understands, and many of
// the embedded rules match on a line substring without ever looking at the
// file's type. The result was a scanner that reported itself and its own
// documentation: the `.rego` files and the pages that quote a vulnerable
// pattern to explain it matched the rule they describe, a README snippet
// showing `curl | sh` was a vulnerability, and a Java rule fired on a JSON
// schema that lists "3DES" as an example value.
//
// Three facts about files drive the scoping, none of them specific to a rule:
//
//   - Prose and policy text (Markdown, reStructuredText, Rego) is not
//     executable code in any language. A source-code rule never applies to it.
//     The one exception is a rule that is about documentation, which says so
//     with the `documentation` tag.
//   - A rule that declares languages is claiming those languages. A file whose
//     language is known and disjoint from the claim is not what the rule was
//     written for.
//   - JSON is data, and it is code only for the JavaScript tooling that reads
//     it (package.json, tsconfig) and for .NET configuration. A Java, Python or
//     Go rule firing on a JSON file is looking at a value, not a call.
//
// Everything else fails open: a rule with no languages, `generic`, or a
// language this table does not model; a file type the table does not claim;
// and markup or template files that host other languages inline.

// proseExtensions are files that describe code rather than being code.
var proseExtensions = []string{".md", ".markdown", ".rst", ".adoc", ".rego"}

// embeddingExtensions are files whose language is a host for others:
// JavaScript in a <script> block, SQL in a JSP, PHP in HTML.
var embeddingExtensions = []string{
	".html", ".htm", ".xhtml", ".vue", ".svelte", ".astro", ".erb", ".ejs",
	".jsp", ".jspx", ".php", ".phtml", ".twig", ".tpl", ".hbs", ".mustache",
	".cshtml", ".razor", ".gohtml", ".tmpl", ".njk", ".liquid", ".mdx",
}

// jsonHosts are the canonical languages for which a JSON file is configuration
// that the rule may legitimately read.
var jsonHosts = []string{"javascript", "csharp"}

func isProsePath(path string) bool {
	lower := strings.ToLower(filepath.Base(path))
	for _, ext := range proseExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// ruleAppliesToFile reports whether a finding from a rule with the given
// declared languages may be reported against path.
func ruleAppliesToFile(languages []string, path string) bool {
	if len(languages) == 0 {
		return true
	}
	known := make([]string, 0, len(languages))
	for _, l := range languages {
		switch strings.ToLower(l) {
		case "generic", "all", "any":
			return true
		}
		if !knownLanguage(l) {
			return true // fail open on anything this table does not model
		}
		known = append(known, canonicalLang(l))
	}

	if isProsePath(path) {
		return false
	}

	lower := strings.ToLower(filepath.Base(path))

	for _, ext := range embeddingExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	if strings.HasSuffix(lower, ".json") && !slices.ContainsFunc(known, func(l string) bool { return slices.Contains(jsonHosts, l) }) {
		return false
	}

	fileLangs := LanguagesForPath(path)
	if len(fileLangs) == 0 {
		return true // a type this table does not claim (yaml, toml, properties, ...)
	}
	for _, l := range known {
		if fileLangs[l] {
			return true
		}
	}
	return false
}

// findingApplies is the engine's per-finding scope check.
func findingApplies(m *RuleMetadata, path, snippet string) bool {
	if strings.EqualFold(m.Kind, "sast") {
		if isProsePath(path) && !slices.Contains(m.Tags, "documentation") {
			return false
		}
		if isCommentSnippet(snippet) && !slices.Contains(m.Tags, "comments") && !slices.Contains(m.Tags, "documentation") {
			return false
		}
	}
	return ruleAppliesToFile(m.Languages, path)
}

// isCommentSnippet reports whether a matched line is nothing but a comment.
// A vulnerable-looking call named inside a comment is not executed: it is
// prose about code (or code that was removed, which VNX-1054 reports on its
// own). C preprocessor lines and shebangs start with '#' but are code.
func isCommentSnippet(s string) bool {
	t := strings.TrimSpace(s)
	switch {
	case t == "":
		return false
	case strings.HasPrefix(t, "//"):
		return true
	case strings.HasPrefix(t, "/*"):
		// `/* note */ return eval(x);` is code with a comment in front of it.
		if i := strings.LastIndex(t, "*/"); i >= 0 && strings.TrimSpace(t[i+2:]) != "" {
			return false
		}
		return true
	case strings.HasPrefix(t, "* "), strings.HasPrefix(t, "*/"), t == "*":
		return true
	case strings.HasPrefix(t, "#"):
		for _, code := range []string{"#include", "#define", "#undef", "#if", "#else", "#elif", "#endif", "#pragma", "#error", "#warning", "#line", "#!", "#import", "#region", "#endregion"} {
			if strings.HasPrefix(t, code) {
				return false
			}
		}
		return true
	}
	return false
}

// FindingApplies exposes the engine's per-finding scope check to tools that
// evaluate rules outside the engine (the efficacy profiler), so their counts
// match what a scan would report.
func FindingApplies(m *RuleMetadata, path, snippet string) bool {
	return findingApplies(m, path, snippet)
}

// ruleScope is the part of a rule's metadata that decides which files it may
// report on: the same inputs findingApplies reads, except the snippet.
type ruleScope struct {
	languages []string
	sastKind  bool
	docs      bool
}

func (s ruleScope) key() string {
	return fmt.Sprintf("%v|%v|%v", s.languages, s.sastKind, s.docs)
}

// allows reports whether a file is in scope: findingApplies without the
// comment-line test, which depends on the line, not the file.
func (s ruleScope) allows(path string) bool {
	if s.sastKind && !s.docs && isProsePath(path) {
		return false
	}
	return ruleAppliesToFile(s.languages, path)
}

var (
	kindRe     = regexp.MustCompile(`"kind"\s*:\s*"([a-z]+)"`)
	tagsDocsRe = regexp.MustCompile(`"tags"\s*:\s*\[[^\]]*"documentation"`)
)

// scopeOf reads a rule module's scope from its source, before compilation.
func scopeOf(src string) ruleScope {
	langs, _ := ruleLanguages(src)
	sorted := append([]string(nil), langs...)
	sort.Strings(sorted)
	kind := "sast"
	if m := kindRe.FindStringSubmatch(src); m != nil {
		kind = m[1]
	}
	return ruleScope{languages: sorted, sastKind: kind == "sast", docs: tagsDocsRe.MatchString(src)}
}

type scopeGroup struct {
	scope ruleScope
	rules map[string]string
}

// groupByScope partitions rule modules by scope, largest group first.
func groupByScope(rules map[string]string) []scopeGroup {
	by := map[string]*scopeGroup{}
	for name, src := range rules {
		s := scopeOf(src)
		g := by[s.key()]
		if g == nil {
			g = &scopeGroup{scope: s, rules: map[string]string{}}
			by[s.key()] = g
		}
		g.rules[name] = src
	}
	out := make([]scopeGroup, 0, len(by))
	for _, g := range by {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].rules) != len(out[j].rules) {
			return len(out[i].rules) > len(out[j].rules)
		}
		return out[i].scope.key() < out[j].scope.key()
	})
	return out
}

// scopedInput returns a shallow copy of in whose FileContents holds only the
// files the scope allows. A universal scope gets the input itself.
func scopedInput(in *ScanInput, s ruleScope) *ScanInput {
	if len(s.languages) == 0 && !s.sastKind {
		return in
	}
	out := *in
	out.FileContents = make(map[string]string, len(in.FileContents))
	for p, c := range in.FileContents {
		if s.allows(p) {
			out.FileContents[p] = c
		}
	}
	return &out
}
