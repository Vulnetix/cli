package treesitter

import (
	"testing"
)

func TestGrammar_AllLanguagesReturnNonNil(t *testing.T) {
	// Grammar requires CGo (tree-sitter). Skip if CGo is disabled.
	for _, id := range All() {
		g := Grammar(id)
		if g == nil {
			t.Fatalf("Grammar(%q) returned nil", id)
		}
	}
}

func TestGrammar_UnknownReturnsNil(t *testing.T) {
	if g := Grammar("fortran"); g != nil {
		t.Fatal("expected nil for unknown language")
	}
	if g := Grammar(""); g != nil {
		t.Fatal("expected nil for empty language")
	}
}

func TestExtensions_AllLanguagesReturnNonEmpty(t *testing.T) {
	for _, id := range All() {
		exts := Extensions(id)
		if len(exts) == 0 {
			t.Fatalf("Extensions(%q) returned empty", id)
		}
		for _, ext := range exts {
			if len(ext) == 0 || ext[0] != '.' {
				t.Fatalf("Extensions(%q) has invalid extension %q (must start with '.')", id, ext)
			}
		}
	}
}

func TestExtensions_UnknownReturnsNil(t *testing.T) {
	if exts := Extensions("fortran"); exts != nil {
		t.Fatalf("expected nil for unknown language, got %v", exts)
	}
}

func TestExtensions_SpecificLanguages(t *testing.T) {
	tests := []struct {
		id       LanguageID
		expected []string
	}{
		{LangJavaScript, []string{".js", ".mjs", ".cjs", ".jsx"}},
		{LangGo, []string{".go"}},
		{LangPython, []string{".py", ".pyi"}},
		{LangRust, []string{".rs"}},
		{LangBash, []string{".sh", ".bash"}},
		{LangLua, []string{".lua"}},
	}
	for _, tc := range tests {
		exts := Extensions(tc.id)
		if len(exts) != len(tc.expected) {
			t.Fatalf("Extensions(%q): expected %d, got %d: %v", tc.id, len(tc.expected), len(exts), exts)
		}
		for i, e := range tc.expected {
			if i >= len(exts) || exts[i] != e {
				t.Fatalf("Extensions(%q)[%d]: expected %q, got %q", tc.id, i, e, exts[i])
			}
		}
	}
}

func TestAll_Count(t *testing.T) {
	all := All()
	if len(all) != 17 {
		t.Fatalf("expected 17 languages, got %d", len(all))
	}
}

func TestAll_ContainsExpectedLanguages(t *testing.T) {
	all := All()
	ids := make(map[LanguageID]bool)
	for _, id := range all {
		ids[id] = true
	}
	expected := []LanguageID{
		LangJavaScript, LangTypeScript, LangTSX, LangPython, LangGo,
		LangJava, LangRuby, LangRust, LangC, LangCPP, LangCSharp,
		LangPHP, LangSwift, LangKotlin, LangScala, LangBash, LangLua,
	}
	for _, id := range expected {
		if !ids[id] {
			t.Fatalf("All() missing %q", id)
		}
	}
}

func TestLanguageForPath_MatchingExtensions(t *testing.T) {
	tests := []struct {
		path     string
		expected LanguageID
	}{
		{"main.go", LangGo},
		{"src/app.ts", LangTypeScript},
		{"components/Button.tsx", LangTSX},
		{"script.py", LangPython},
		{"lib/utils.js", LangJavaScript},
		{"module.mjs", LangJavaScript},
		{"test.cjs", LangJavaScript},
		{"App.jsx", LangJavaScript},
		{"Main.java", LangJava},
		{"app.rb", LangRuby},
		{"lib.rs", LangRust},
		{"src/main.c", LangC},
		{"include/header.h", LangC},
		{"src/core.cpp", LangCPP},
		{"module.cs", LangCSharp},
		{"index.php", LangPHP},
		{"app.swift", LangSwift},
		{"Main.kt", LangKotlin},
		{"build.kts", LangKotlin},
		{"test.scala", LangScala},
		{"script.sh", LangBash},
		{"setup.bash", LangBash},
		{"init.lua", LangLua},
	}
	for _, tc := range tests {
		result := LanguageForPath(tc.path)
		if result != tc.expected {
			t.Fatalf("LanguageForPath(%q): expected %q, got %q", tc.path, tc.expected, result)
		}
	}
}

func TestLanguageForPath_CaseInsensitive(t *testing.T) {
	if id := LanguageForPath("MAIN.GO"); id != LangGo {
		t.Fatalf("expected Go, got %q", id)
	}
	if id := LanguageForPath("App.PY"); id != LangPython {
		t.Fatalf("expected Python, got %q", id)
	}
}

func TestLanguageForPath_NoExtension(t *testing.T) {
	if id := LanguageForPath("README"); id != "" {
		t.Fatalf("expected empty for no extension, got %q", id)
	}
	if id := LanguageForPath(""); id != "" {
		t.Fatalf("expected empty for empty path, got %q", id)
	}
}

func TestLanguageForPath_UnknownExtension(t *testing.T) {
	if id := LanguageForPath("file.xyz"); id != "" {
		t.Fatalf("expected empty for unknown extension, got %q", id)
	}
}

func TestNormalise_CanonicalAliases(t *testing.T) {
	tests := []struct {
		input    string
		expected LanguageID
	}{
		{"go", LangGo},
		{"golang", LangGo},
		{"python", LangPython},
		{"py", LangPython},
		{"javascript", LangJavaScript},
		{"js", LangJavaScript},
		{"ecmascript", LangJavaScript},
		{"typescript", LangTypeScript},
		{"ts", LangTypeScript},
		{"tsx", LangTSX},
		{"java", LangJava},
		{"ruby", LangRuby},
		{"rb", LangRuby},
		{"rust", LangRust},
		{"rs", LangRust},
		{"c", LangC},
		{"cpp", LangCPP},
		{"c++", LangCPP},
		{"cxx", LangCPP},
		{"c-sharp", LangCSharp},
		{"csharp", LangCSharp},
		{"c#", LangCSharp},
		{"php", LangPHP},
		{"swift", LangSwift},
		{"kotlin", LangKotlin},
		{"kt", LangKotlin},
		{"scala", LangScala},
		{"bash", LangBash},
		{"sh", LangBash},
		{"shell", LangBash},
		{"lua", LangLua},
	}
	for _, tc := range tests {
		result := Normalise(tc.input)
		if result != tc.expected {
			t.Fatalf("Normalise(%q): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

func TestNormalise_CaseInsensitive(t *testing.T) {
	if id := Normalise("GO"); id != LangGo {
		t.Fatalf("expected Go, got %q", id)
	}
	if id := Normalise("PYTHON"); id != LangPython {
		t.Fatalf("expected Python, got %q", id)
	}
	if id := Normalise("TypeScript"); id != LangTypeScript {
		t.Fatalf("expected TypeScript, got %q", id)
	}
}

func TestNormalise_TrimsSpaces(t *testing.T) {
	if id := Normalise("  go  "); id != LangGo {
		t.Fatalf("expected Go, got %q", id)
	}
}

func TestNormalise_UnknownReturnsEmpty(t *testing.T) {
	if id := Normalise("fortran"); id != "" {
		t.Fatalf("expected empty for unknown, got %q", id)
	}
	if id := Normalise(""); id != "" {
		t.Fatalf("expected empty for empty, got %q", id)
	}
}
