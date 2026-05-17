package reachability

import (
	"context"
	"testing"

	"github.com/vulnetix/cli/v3/internal/treesitter"
)

func TestEngineRunsJavaScriptQuery(t *testing.T) {
	engine := NewEngine()
	src := []byte(`
const _ = require('lodash');
function render(input) {
    return _.template(input);
}
`)
	// Match any call_expression whose callee is a member_expression.
	query := `(call_expression function: (member_expression) @callee)`
	matches, err := engine.Run(context.Background(), treesitter.LangJavaScript, src, query)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("expected at least one match, got 0")
	}
	for _, m := range matches {
		if m.StartLine < 1 || m.EndLine < m.StartLine {
			t.Errorf("invalid range %d:%d", m.StartLine, m.EndLine)
		}
	}
}

func TestEngineUnsupportedLanguage(t *testing.T) {
	engine := NewEngine()
	_, err := engine.Run(context.Background(), treesitter.LanguageID("klingon"), []byte("x = 1"), `(identifier) @x`)
	if err == nil {
		t.Fatal("expected error for unsupported language, got nil")
	}
}

func TestEngineMalformedQuery(t *testing.T) {
	engine := NewEngine()
	_, err := engine.Run(context.Background(), treesitter.LangPython, []byte("x = 1"), `(this is not a valid query)`)
	if err == nil {
		t.Fatal("expected error for malformed query, got nil")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":           ModeBoth,
		"both":       ModeBoth,
		"direct":     ModeDirect,
		"transitive": ModeTransitive,
		"off":        ModeOff,
		"none":       ModeOff,
		"false":      ModeOff,
		"0":          ModeOff,
	}
	for in, want := range cases {
		got, ok := ParseMode(in)
		if !ok {
			t.Errorf("ParseMode(%q) failed", in)
			continue
		}
		if got != want {
			t.Errorf("ParseMode(%q) = %q, want %q", in, got, want)
		}
	}
	if _, ok := ParseMode("garbage"); ok {
		t.Error("ParseMode(\"garbage\") should fail")
	}
}

func TestModeIncludes(t *testing.T) {
	if !ModeBoth.Includes(ModeDirect) {
		t.Error("both should include direct")
	}
	if !ModeBoth.Includes(ModeTransitive) {
		t.Error("both should include transitive")
	}
	if ModeOff.Includes(ModeDirect) {
		t.Error("off should not include direct")
	}
	if ModeDirect.Includes(ModeTransitive) {
		t.Error("direct should not include transitive")
	}
}
