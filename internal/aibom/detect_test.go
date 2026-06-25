package aibom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
)

func compiledCatalog(t *testing.T) *CompiledCatalog {
	t.Helper()
	cat, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	cc, err := cat.Compile()
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

func mustWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func toolIDs(det cdx.AIDetections) map[string]bool {
	m := map[string]bool{}
	for _, t := range det.Tools {
		m[t.ID] = true
	}
	return m
}

func libIDs(det cdx.AIDetections) map[string]bool {
	m := map[string]bool{}
	for _, l := range det.Libraries {
		m[l.ID] = true
	}
	return m
}

func findModel(det cdx.AIDetections, name string) *cdx.AIModel {
	for i := range det.Models {
		if det.Models[i].Name == name {
			return &det.Models[i]
		}
	}
	return nil
}

func TestDetectEnvRecordsNamesNotValues(t *testing.T) {
	cc := compiledCatalog(t)
	dir := t.TempDir()
	det, err := Detect(Options{
		Root:    dir,
		Catalog: cc,
		ScanEnv: true,
		Environ: []string{"OPENAI_API_KEY=sk-supersecret-leak-123", "PATH=/usr/bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !toolIDs(det)["openai-api"] {
		t.Fatal("OPENAI_API_KEY should detect the openai-api service")
	}
	// The secret VALUE must never appear anywhere in the detections.
	for _, tl := range det.Tools {
		for _, e := range tl.Evidence {
			if strings.Contains(e.Locator, "supersecret") || strings.Contains(e.Snippet, "supersecret") {
				t.Fatalf("env value leaked into evidence: %+v", e)
			}
		}
	}
}

func TestDetectFilesPrimaryVsShared(t *testing.T) {
	cc := compiledCatalog(t)
	dir := t.TempDir()
	mustWrite(t, dir, ".claude/settings.json", `{"model":"claude-sonnet-4-6"}`)
	mustWrite(t, dir, "CLAUDE.md", "# project instructions")
	mustWrite(t, dir, ".cursorrules", "be concise")
	mustWrite(t, dir, ".aiderignore", "secrets/")
	mustWrite(t, dir, "AGENTS.md", "# shared agent instructions")

	det, err := Detect(Options{Root: dir, Catalog: cc})
	if err != nil {
		t.Fatal(err)
	}
	ids := toolIDs(det)
	for _, want := range []string{"claude-code", "cursor", "aider", "agents-md"} {
		if !ids[want] {
			t.Errorf("expected tool %q to be detected", want)
		}
	}
	// zed lists AGENTS.md/.rules as instructions but has no zed-specific file
	// here; the shared AGENTS.md must NOT establish it.
	if ids["zed"] {
		t.Error("zed falsely reported from a shared AGENTS.md")
	}
	// The model in .claude/settings.json should be extracted via the config extractor.
	if findModel(det, "claude-sonnet-4-6") == nil {
		t.Error("expected claude-sonnet-4-6 extracted from .claude/settings.json")
	}
}

func TestDetectSourceExtractsUnknownModel(t *testing.T) {
	cc := compiledCatalog(t)
	dir := t.TempDir()
	mustWrite(t, dir, "main.py", strings.Join([]string{
		"from openai import OpenAI",
		"client = OpenAI()",
		`resp = client.chat.completions.create(model="gpt-9-zeta-2099")`,
	}, "\n"))
	mustWrite(t, dir, "requirements.txt", "openai\n")

	det, err := Detect(Options{Root: dir, Catalog: cc, ScanSource: true})
	if err != nil {
		t.Fatal(err)
	}
	if !libIDs(det)["openai-python"] {
		t.Fatal("expected openai-python SDK detected")
	}
	m := findModel(det, "gpt-9-zeta-2099")
	if m == nil {
		t.Fatal("future/unknown model literal was not extracted")
	}
	if m.Provider != "OpenAI" || m.Family != "GPT" || !m.Known {
		t.Errorf("model classify = provider=%q family=%q known=%v, want OpenAI/GPT/true", m.Provider, m.Family, m.Known)
	}
	if m.ViaSDK != "openai-python" {
		t.Errorf("via-sdk = %q, want openai-python", m.ViaSDK)
	}
}

func TestDetectMultiSDKAttribution(t *testing.T) {
	cc := compiledCatalog(t)
	dir := t.TempDir()
	mustWrite(t, dir, "app.py", strings.Join([]string{
		"from openai import OpenAI",
		"import anthropic",
		`OpenAI().chat.completions.create(model="gpt-4o")`,
		`anthropic.Anthropic().messages.create(model="claude-sonnet-4-6")`,
	}, "\n"))

	det, err := Detect(Options{Root: dir, Catalog: cc, ScanSource: true})
	if err != nil {
		t.Fatal(err)
	}
	claude := findModel(det, "claude-sonnet-4-6")
	if claude == nil {
		t.Fatal("claude model not found")
	}
	// Even though the generic openai `model=` pattern also matches the line,
	// attribution should prefer the SDK whose provider matches the model, and
	// the occurrence must be counted once (deduped by source location).
	if claude.ViaSDK != "anthropic-python" {
		t.Errorf("claude via-sdk = %q, want anthropic-python", claude.ViaSDK)
	}
	if claude.Occurrences != 1 {
		t.Errorf("claude occurrences = %d, want 1", claude.Occurrences)
	}
}
