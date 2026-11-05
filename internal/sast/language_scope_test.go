package sast

import (
	"slices"
	"testing"
)

func TestOwnerLanguageHasOneOwner(t *testing.T) {
	cases := map[string]string{
		"a.go": "go", "go.mod": "go", "a.py": "python", "pyproject.toml": "python",
		"a.ts": "javascript", "a.tsx": "javascript", "package.json": "javascript",
		"a.h": "c-cpp", "a.c": "c-cpp", "a.cpp": "c-cpp", "a.kt": "kotlin", "A.java": "java",
		"a.sh": "shell", "Makefile": "shell", "a.cs": "csharp", "a.rs": "rust",
		"a.rb": "ruby", "a.php": "php", "a.tf": "terraform", "Dockerfile": "docker",
		"a.erb": "ruby", "a.html": "html", "a.yaml": "", "README.txt": "",
	}
	for p, want := range cases {
		if got := OwnerLanguage(p); got != want {
			t.Errorf("OwnerLanguage(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestLanguageScopeNames(t *testing.T) {
	for in, want := range map[string]string{"typescript": "javascript", "TS": "javascript", "c++": "c-cpp", "c": "c-cpp", "c-cpp": "c-cpp", "sh": "shell", "shell": "shell", "golang": "go", "c#": "csharp", "android": "kotlin"} {
		s, err := NewLanguageScope([]string{in}, nil)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if s.Slug() != want {
			t.Errorf("%s: slug %q, want %q", in, s.Slug(), want)
		}
	}
	if _, err := NewLanguageScope([]string{"cobol"}, nil); err == nil {
		t.Error("an unknown language must be refused")
	}
	if _, err := NewLanguageScope([]string{"go"}, []string{"python"}); err == nil {
		t.Error("--language with --not-language must be refused")
	}
	s, _ := NewLanguageScope(nil, []string{"python", "go", "golang"})
	if s.Slug() != "not-go-python" {
		t.Errorf("rest slug = %q", s.Slug())
	}
}

// The legs of a scope partition the files: each path is in the rest leg or in
// exactly one language leg, so no finding is lost or reported twice.
func TestLanguageLegsPartitionFiles(t *testing.T) {
	paths := []string{"a.go", "b.py", "c.ts", "d.h", "e.yaml", "Dockerfile", "f.tpl", "g.inc", "h.gql", "i.erb", "j.kts", "build.gradle", "k.txt", ""}
	languages := []string{"go", "python", "javascript"}
	var legs []LanguageScope
	for _, l := range languages {
		s, err := NewLanguageScope([]string{l}, nil)
		if err != nil {
			t.Fatal(err)
		}
		legs = append(legs, s)
	}
	rest, err := NewLanguageScope(nil, languages)
	if err != nil {
		t.Fatal(err)
	}
	legs = append(legs, rest)
	for _, p := range paths {
		n := 0
		for _, s := range legs {
			if s.Allows(p) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%q is in %d legs, want 1", p, n)
		}
	}
}

func TestScopedKind(t *testing.T) {
	if got := ScopedKind("sast", "python"); got != "sast/python" {
		t.Errorf("ScopedKind = %q", got)
	}
	if got := AutomationID(ScopedKind("sast", "python")); got != "vulnetix/sast/python/" {
		t.Errorf("AutomationID = %q", got)
	}
	if got := ScopedKind("sast", ""); got != "sast" {
		t.Errorf("unscoped ScopedKind = %q", got)
	}
}

// A scoped run keeps its category through the split even though each result
// says it is plain sast.
func TestSplitByKindKeepsScope(t *testing.T) {
	l := &SARIFLog{Version: "2.1.0", Runs: []SARIFRun{{Results: []SARIFResult{{RuleID: "R", Properties: map[string]any{"vulnetix/kind": "sast"}}}}}}
	SetCategory(l, "sast/python")
	got := SplitByKind(l)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	if !slices.Equal(keys, []string{"sast/python"}) {
		t.Fatalf("split keys = %v", keys)
	}
	if id := got["sast/python"].Runs[0].AutomationDetails.ID; id != "vulnetix/sast/python/" {
		t.Errorf("automation id = %q", id)
	}
}

// The pre-filter must keep every language's rules on a rest leg, or a rule that
// reports on a file no language claims is lost from the union of the legs.
func TestScopeFilesForThePreFilter(t *testing.T) {
	all := map[string]bool{"a.java": true, "b.py": true, "app.properties": true}
	only, _ := NewLanguageScope([]string{"python"}, nil)
	if got := only.files(all); len(got) != 1 || !got["b.py"] {
		t.Errorf("--language keeps its own files, got %v", got)
	}
	rest, _ := NewLanguageScope(nil, []string{"java", "python"})
	if got := rest.files(all); len(got) != len(all) {
		t.Errorf("--not-language must leave the set whole, got %v", got)
	}
}
