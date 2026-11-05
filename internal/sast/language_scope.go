package sast

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// A language scope narrows `vulnetix sast` to the files of some languages, so a
// repository can run one job per language. Every file has exactly one owner, so
// the legs of a scope never overlap, and `--not-language` with every language
// the other legs named picks up the rest: the union of the legs is the findings
// of an unscoped scan. Findings on a file with no owner, and rules that declare
// no language, land on the leg that owns the file they report, which for a file
// no language claims is the rest leg.

// scopeOwners is the order in which a file claimed by several languages picks
// its owner. A `.h` is c and cpp, an `.erb` ruby and html, a `.tpl` go and php:
// source languages come before the markup and query languages that host them.
var scopeOwners = []string{
	"go", "python", "javascript", "java", "kotlin", "c-cpp", "csharp", "php",
	"ruby", "rust", "swift", "shell", "terraform", "docker", "sql", "graphql", "html",
}

// scopeNames folds the language pre-filter's canonical labels onto scope names.
var scopeNames = map[string]string{
	"c": "c-cpp", "cpp": "c-cpp", "android": "kotlin", "bash": "shell",
}

// ScopeLanguages lists the names --language accepts.
func ScopeLanguages() []string { return slices.Clone(scopeOwners) }

// scopeLanguage resolves a user-written language to its scope name.
func scopeLanguage(name string) (string, bool) {
	l := strings.ToLower(strings.TrimSpace(name))
	if l == "c-cpp" {
		return l, true
	}
	l = canonicalLang(l)
	if s, ok := scopeNames[l]; ok {
		l = s
	}
	return l, slices.Contains(scopeOwners, l)
}

// OwnerLanguage returns the one language that owns path, or "" when no language
// claims it (yaml, toml, plain text).
func OwnerLanguage(path string) string {
	claims := map[string]bool{}
	for l := range LanguagesForPath(path) {
		if s, ok := scopeNames[l]; ok {
			l = s
		}
		claims[l] = true
	}
	for _, l := range scopeOwners {
		if claims[l] {
			return l
		}
	}
	return ""
}

// LanguageScope is a resolved --language / --not-language pair. The zero value
// scopes nothing.
type LanguageScope struct {
	only, not []string
}

// NewLanguageScope validates the flags. Naming both is refused: a leg is either
// some languages or everything but some languages.
func NewLanguageScope(only, not []string) (LanguageScope, error) {
	if len(only) > 0 && len(not) > 0 {
		return LanguageScope{}, fmt.Errorf("--language and --not-language cannot be combined")
	}
	resolve := func(flag string, names []string) ([]string, error) {
		var out []string
		for _, n := range names {
			l, ok := scopeLanguage(n)
			if !ok {
				return nil, fmt.Errorf("%s: unknown language %q (want one of %s)", flag, n, strings.Join(scopeOwners, ", "))
			}
			if !slices.Contains(out, l) {
				out = append(out, l)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	o, err := resolve("--language", only)
	if err != nil {
		return LanguageScope{}, err
	}
	n, err := resolve("--not-language", not)
	if err != nil {
		return LanguageScope{}, err
	}
	return LanguageScope{only: o, not: n}, nil
}

// Active reports whether the scope narrows anything.
func (s LanguageScope) Active() bool { return len(s.only) > 0 || len(s.not) > 0 }

// Allows reports whether a file's findings belong to this leg.
func (s LanguageScope) Allows(path string) bool {
	switch {
	case len(s.only) > 0:
		return slices.Contains(s.only, OwnerLanguage(path))
	case len(s.not) > 0:
		return !slices.Contains(s.not, OwnerLanguage(path))
	}
	return true
}

// Slug names the leg in file names, the code scanning category and the tool
// name, so each leg keeps its own history. Empty when the scope is inactive.
func (s LanguageScope) Slug() string { return ScopeSlug(s.only, s.not) }

// ScopeSlug joins sorted scope names: "python", "go-python", "not-go-python".
func ScopeSlug(only, not []string) string {
	switch {
	case len(only) > 0:
		return strings.Join(only, "-")
	case len(not) > 0:
		return "not-" + strings.Join(not, "-")
	}
	return ""
}

// narrow applies a scope to a report's findings.
func (s LanguageScope) narrow(findings []Finding) []Finding {
	if !s.Active() {
		return findings
	}
	kept := findings[:0]
	for _, f := range findings {
		if s.Allows(f.ArtifactURI) {
			kept = append(kept, f)
		}
	}
	return kept
}

// files returns the file set the language pre-filter should read. A --language
// leg can drop the rules of languages none of its files are written in. A
// --not-language leg cannot: a language's rules also report on the file types no
// language claims (VNX-JAVA-002 on application.properties), and those files are
// this leg's.
func (s LanguageScope) files(fileSet map[string]bool) map[string]bool {
	if len(s.only) == 0 {
		return fileSet
	}
	set := make(map[string]bool, len(fileSet))
	for p := range fileSet {
		if s.Allows(p) {
			set[p] = true
		}
	}
	return set
}

// narrowContents drops the text of out-of-scope files. in.FileSet stays
// complete, so a rule asking whether a path exists sees what it sees in an
// unscoped scan.
func (s LanguageScope) narrowContents(in *ScanInput) {
	if !s.Active() {
		return
	}
	for p := range in.FileContents {
		if !s.Allows(p) {
			delete(in.FileContents, p)
		}
	}
}
