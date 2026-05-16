// Package treesitter wires the vdb-manager language identifiers used in
// x_treeSitterQueries.language to concrete tree-sitter grammars bundled
// via github.com/smacker/go-tree-sitter.
//
// The CLI links every supported grammar statically through CGo. Cross-
// compilation requires a C toolchain capable of targeting each GOOS/GOARCH
// (see justfile: `zig cc`).
package treesitter

import (
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/bash"
	tsc "github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/lua"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/ruby"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/scala"
	"github.com/smacker/go-tree-sitter/swift"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// LanguageID is the canonical identifier emitted by vdb-manager in the
// TreeSitterQuery.Language field. The set is fixed; new languages must
// be added in both vdb-manager and here.
type LanguageID string

const (
	LangJavaScript LanguageID = "javascript"
	LangTypeScript LanguageID = "typescript"
	LangTSX        LanguageID = "tsx"
	LangPython     LanguageID = "python"
	LangGo         LanguageID = "go"
	LangJava       LanguageID = "java"
	LangRuby       LanguageID = "ruby"
	LangRust       LanguageID = "rust"
	LangC          LanguageID = "c"
	LangCPP        LanguageID = "cpp"
	LangCSharp     LanguageID = "c-sharp"
	LangPHP        LanguageID = "php"
	LangSwift      LanguageID = "swift"
	LangKotlin     LanguageID = "kotlin"
	LangScala      LanguageID = "scala"
	LangBash       LanguageID = "bash"
	LangLua        LanguageID = "lua"
)

// Grammar resolves a vdb-manager language identifier to a tree-sitter
// grammar. Returns nil if the language is not bundled.
func Grammar(id LanguageID) *sitter.Language {
	switch id {
	case LangJavaScript:
		return javascript.GetLanguage()
	case LangTypeScript:
		return typescript.GetLanguage()
	case LangTSX:
		return tsx.GetLanguage()
	case LangPython:
		return python.GetLanguage()
	case LangGo:
		return golang.GetLanguage()
	case LangJava:
		return java.GetLanguage()
	case LangRuby:
		return ruby.GetLanguage()
	case LangRust:
		return rust.GetLanguage()
	case LangC:
		return tsc.GetLanguage()
	case LangCPP:
		return cpp.GetLanguage()
	case LangCSharp:
		return csharp.GetLanguage()
	case LangPHP:
		return php.GetLanguage()
	case LangSwift:
		return swift.GetLanguage()
	case LangKotlin:
		return kotlin.GetLanguage()
	case LangScala:
		return scala.GetLanguage()
	case LangBash:
		return bash.GetLanguage()
	case LangLua:
		return lua.GetLanguage()
	}
	return nil
}

// Extensions returns the file extensions associated with a language. The
// dot is included (e.g. ".py"). Returned slices must not be mutated.
func Extensions(id LanguageID) []string {
	switch id {
	case LangJavaScript:
		return []string{".js", ".mjs", ".cjs", ".jsx"}
	case LangTypeScript:
		return []string{".ts", ".mts", ".cts"}
	case LangTSX:
		return []string{".tsx"}
	case LangPython:
		return []string{".py", ".pyi"}
	case LangGo:
		return []string{".go"}
	case LangJava:
		return []string{".java"}
	case LangRuby:
		return []string{".rb", ".rake", ".gemspec"}
	case LangRust:
		return []string{".rs"}
	case LangC:
		return []string{".c", ".h"}
	case LangCPP:
		return []string{".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"}
	case LangCSharp:
		return []string{".cs"}
	case LangPHP:
		return []string{".php", ".phtml"}
	case LangSwift:
		return []string{".swift"}
	case LangKotlin:
		return []string{".kt", ".kts"}
	case LangScala:
		return []string{".scala", ".sc"}
	case LangBash:
		return []string{".sh", ".bash"}
	case LangLua:
		return []string{".lua"}
	}
	return nil
}

// All returns every bundled language identifier in declaration order.
func All() []LanguageID {
	return []LanguageID{
		LangJavaScript, LangTypeScript, LangTSX, LangPython, LangGo,
		LangJava, LangRuby, LangRust, LangC, LangCPP, LangCSharp,
		LangPHP, LangSwift, LangKotlin, LangScala, LangBash, LangLua,
	}
}

var extToLang = func() map[string]LanguageID {
	m := make(map[string]LanguageID, 64)
	for _, id := range All() {
		for _, ext := range Extensions(id) {
			if _, exists := m[ext]; !exists {
				m[ext] = id
			}
		}
	}
	return m
}()

// LanguageForPath returns the language ID a path's extension maps to,
// or empty if no bundled grammar handles it. Casing is normalised.
func LanguageForPath(path string) LanguageID {
	ext := strings.ToLower(filepath.Ext(path))
	return extToLang[ext]
}

// Normalise accepts user/server identifiers in any of the several
// spellings used in the wild (golang vs go, c-sharp vs csharp, etc.)
// and returns the canonical LanguageID, or empty if unknown.
func Normalise(raw string) LanguageID {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "javascript", "js", "ecmascript":
		return LangJavaScript
	case "typescript", "ts":
		return LangTypeScript
	case "tsx":
		return LangTSX
	case "python", "py":
		return LangPython
	case "go", "golang":
		return LangGo
	case "java":
		return LangJava
	case "ruby", "rb":
		return LangRuby
	case "rust", "rs":
		return LangRust
	case "c":
		return LangC
	case "cpp", "c++", "cxx":
		return LangCPP
	case "c-sharp", "csharp", "c#":
		return LangCSharp
	case "php":
		return LangPHP
	case "swift":
		return LangSwift
	case "kotlin", "kt":
		return LangKotlin
	case "scala":
		return LangScala
	case "bash", "sh", "shell":
		return LangBash
	case "lua":
		return LangLua
	}
	return ""
}
