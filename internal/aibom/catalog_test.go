package aibom

import "testing"

func TestDefaultCatalogCompiles(t *testing.T) {
	cat, err := DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	if len(cat.Tools) < 40 {
		t.Errorf("want >= 40 tool entries, got %d", len(cat.Tools))
	}
	if len(cat.Libraries) < 25 {
		t.Errorf("want >= 25 library entries, got %d", len(cat.Libraries))
	}
	if len(cat.Families) == 0 {
		t.Error("expected model family hints")
	}
	if cat.Version == "" {
		t.Error("catalog has no version")
	}
	// Compile validates every regex/glob and every extractor capture group.
	if _, err := cat.Compile(); err != nil {
		t.Fatalf("catalog failed validation: %v", err)
	}
}

func TestGlobToRegexp(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{".claude/agents/**", ".claude/agents/foo.md", true},
		{".claude/agents/**", ".claude/agents/sub/bar.md", true},
		{".claude/agents/**", ".claude/settings.json", false},
		{"**/AGENTS.md", "AGENTS.md", true},
		{"**/AGENTS.md", "pkg/sub/AGENTS.md", true},
		{"**/AGENTS.md", "AGENTS.md.bak", false},
		{"*.md", "a.md", true},
		{"*.md", "dir/a.md", false},
		{"CLAUDE_CODE_*", "CLAUDE_CODE_TOKEN", true},
		{"CLAUDE_CODE_*", "CLAUDE", false},
	}
	for _, c := range cases {
		re, err := globToRegexp(c.glob)
		if err != nil {
			t.Fatalf("globToRegexp(%q): %v", c.glob, err)
		}
		if got := re.MatchString(c.path); got != c.want {
			t.Errorf("glob %q vs %q = %v, want %v (re=%s)", c.glob, c.path, got, c.want, re.String())
		}
	}
}

func TestClassifyModelUnknownStillReturned(t *testing.T) {
	cc, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := cc.Compile()
	if err != nil {
		t.Fatal(err)
	}
	// A future GPT name matches the family prefix.
	if p, f, known := compiled.classifyModel("gpt-9-zeta-2099", "OpenAI"); !known || p != "OpenAI" || f != "GPT" {
		t.Errorf("classify future gpt = (%q,%q,%v), want (OpenAI,GPT,true)", p, f, known)
	}
	// A totally unknown literal falls back to the SDK provider and Known=false.
	if p, _, known := compiled.classifyModel("acme-megamind-v0", "Acme"); known || p != "Acme" {
		t.Errorf("classify unknown = (%q,_,%v), want (Acme,_,false)", p, known)
	}
}
