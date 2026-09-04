package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func claudeHost(t *testing.T, dir string) Host {
	t.Helper()
	return Host{
		ID: "test-claude", Name: "Test Claude",
		SkillDirs:   []string{"~/.claude/skills"},
		HookDialect: DialectClaudeCode,
		HookConfig:  filepath.Join(dir, "settings.json"),
	}
}

func readDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return doc
}

func TestInstallHooksCreatesConfig(t *testing.T) {
	dir := t.TempDir()
	h := claudeHost(t, dir)

	res := InstallHooks(h, InstallOptions{Hooks: true})
	if res.Err != nil {
		t.Fatalf("install: %v", res.Err)
	}
	if !res.Changed {
		t.Fatal("first install should report a change")
	}

	doc := readDoc(t, h.HookConfig)
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("no hooks object: %v", doc)
	}
	if _, ok := hooks["PreToolUse"].([]any); !ok {
		t.Fatalf("no PreToolUse entries: %v", hooks)
	}
}

// TestInstallHooksIsIdempotent is what makes the installer safe to re-run,
// which is how anyone upgrading will use it.
func TestInstallHooksIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	h := claudeHost(t, dir)

	if res := InstallHooks(h, InstallOptions{Hooks: true}); res.Err != nil {
		t.Fatalf("first install: %v", res.Err)
	}
	before, err := os.ReadFile(h.HookConfig)
	if err != nil {
		t.Fatal(err)
	}

	res := InstallHooks(h, InstallOptions{Hooks: true})
	if res.Err != nil {
		t.Fatalf("second install: %v", res.Err)
	}
	if res.Changed {
		t.Fatal("second install reported a change; it should be a no-op")
	}

	after, err := os.ReadFile(h.HookConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("file changed on a no-op install:\nbefore: %s\nafter:  %s", before, after)
	}
}

// TestInstallHooksPreservesEverythingElse is the property that decides whether
// people trust the installer with a settings file they have edited by hand.
func TestInstallHooksPreservesEverythingElse(t *testing.T) {
	dir := t.TempDir()
	h := claudeHost(t, dir)

	original := `{
  "model": "opus",
  "env": {"FOO": "bar"},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/somebody-elses-hook"}]}
    ],
    "Stop": [
      {"matcher": "", "hooks": [{"type": "command", "command": "notify-send done"}]}
    ]
  }
}`
	if err := os.WriteFile(h.HookConfig, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if res := InstallHooks(h, InstallOptions{Hooks: true}); res.Err != nil {
		t.Fatalf("install: %v", res.Err)
	}

	doc := readDoc(t, h.HookConfig)
	if doc["model"] != "opus" {
		t.Errorf("model setting lost: %v", doc["model"])
	}
	if env, ok := doc["env"].(map[string]any); !ok || env["FOO"] != "bar" {
		t.Errorf("env setting lost: %v", doc["env"])
	}

	hooks := doc["hooks"].(map[string]any)
	if _, ok := hooks["Stop"].([]any); !ok {
		t.Error("unrelated Stop hook lost")
	}
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse has %d entries, want the existing one plus ours", len(pre))
	}
	first := pre[0].(map[string]any)
	if groupIsOurs(first) {
		t.Error("our entry displaced the existing hook rather than being appended")
	}
}

func TestUninstallLeavesOtherHooksAlone(t *testing.T) {
	dir := t.TempDir()
	h := claudeHost(t, dir)

	original := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other"}]}]}}`
	if err := os.WriteFile(h.HookConfig, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := InstallHooks(h, InstallOptions{Hooks: true}); res.Err != nil {
		t.Fatal(res.Err)
	}

	res := Uninstall(h, InstallOptions{})
	if res.Err != nil {
		t.Fatalf("uninstall: %v", res.Err)
	}
	if !res.Changed {
		t.Fatal("uninstall should report removing our entry")
	}

	doc := readDoc(t, h.HookConfig)
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("PreToolUse has %d entries, want only the pre-existing one", len(pre))
	}
	if groupIsOurs(pre[0].(map[string]any)) {
		t.Error("our entry survived uninstall")
	}
}

// TestInstallHooksRefusesToOverwriteUnparseableConfig protects the case where
// somebody is mid-edit: losing their work to fix a problem they did not have is
// worse than declining.
func TestInstallHooksRefusesToOverwriteUnparseableConfig(t *testing.T) {
	dir := t.TempDir()
	h := claudeHost(t, dir)

	broken := `{"hooks": {`
	if err := os.WriteFile(h.HookConfig, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	res := InstallHooks(h, InstallOptions{Hooks: true})
	if res.Err == nil {
		t.Fatal("expected an error rather than an overwrite")
	}

	after, err := os.ReadFile(h.HookConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != broken {
		t.Fatalf("file was modified: %s", after)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	h := claudeHost(t, dir)

	res := InstallHooks(h, InstallOptions{Hooks: true, DryRun: true})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if !res.Changed {
		t.Fatal("dry run should still report that a change is needed")
	}
	if _, err := os.Stat(h.HookConfig); !os.IsNotExist(err) {
		t.Fatal("dry run created the file")
	}
}

// TestUnverifiedHostSaysSo keeps the installer honest: promising a hook surface
// that has never been run against a host is how the previous documentation came
// to advertise a directory Codex does not read.
func TestUnverifiedHostSaysSo(t *testing.T) {
	h := Host{ID: "x", Name: "Example", SkillDirs: []string{"~/.agents/skills"}}
	res := InstallHooks(h, InstallOptions{Hooks: true})
	if len(res.Wired) != 0 {
		t.Fatalf("wired %v for a host with no verified dialect", res.Wired)
	}
	if len(res.Notes) == 0 {
		t.Fatal("expected a note explaining why hooks were not configured")
	}
}

func TestCodexDialectNestsUnderHooksWithADescription(t *testing.T) {
	// Verified against codex 0.149.1: an event at the document root is rejected
	// with `unknown field PreToolUse, expected description or hooks`.
	dir := t.TempDir()
	h := Host{
		ID: "test-codex", Name: "Test Codex",
		HookDialect: DialectCodex,
		HookConfig:  filepath.Join(dir, "hooks.json"),
	}
	if res := InstallHooks(h, InstallOptions{Hooks: true}); res.Err != nil {
		t.Fatal(res.Err)
	}

	doc := readDoc(t, h.HookConfig)
	if _, ok := doc["description"].(string); !ok {
		t.Error("codex config needs a description")
	}
	if _, ok := doc["PreToolUse"]; ok {
		t.Error("event must not sit at the document root")
	}
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("no hooks object: %v", doc)
	}
	entries := hooks["PreToolUse"].([]any)
	group := entries[0].(map[string]any)
	if group["matcher"] != "*" {
		t.Errorf("codex matcher = %v, want * so the binary decides", group["matcher"])
	}
}
