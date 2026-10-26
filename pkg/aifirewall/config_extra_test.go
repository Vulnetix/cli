package aifirewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestShellFile(t *testing.T) {
	o := testOptions(t, "openai", "anthropic")
	path, block, err := ShellFile(o)
	if err != nil {
		t.Fatalf("ShellFile: %v", err)
	}
	if path == "" {
		t.Error("expected a shell config path")
	}
	for _, want := range []string{
		Markers.Start,
		Markers.End,
		"OPENAI_BASE_URL",
		"ANTHROPIC_BASE_URL",
		"$" + VulnetixKeyEnv,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("block missing %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, testKey) {
		t.Error("block should not contain literal key unless --embed-key")
	}
}

func TestEnvKeys(t *testing.T) {
	o := testOptions(t, "openai", "anthropic")
	keys := EnvKeys(o)
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	for _, want := range []string{"OPENAI_BASE_URL", "OPENAI_API_BASE", "ANTHROPIC_BASE_URL", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN"} {
		if !seen[want] {
			t.Errorf("missing %q in %v", want, keys)
		}
	}
}

func TestShellBlock(t *testing.T) {
	o := testOptions(t, "mistral")
	block := ShellBlock(o, "sh")
	if !strings.Contains(block, "VULNETIX_AIFW_MISTRAL_BASE_URL") {
		t.Errorf("snippet-only provider should produce info var:\n%s", block)
	}
}

func TestProjectEnvFiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env", ".envrc", "Makefile"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("# existing\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	o := testOptions(t, "openai")
	o.Root = root
	files := ProjectEnvFiles(o)
	if len(files) != 3 {
		t.Fatalf("expected 3 env files, got %d: %+v", len(files), files)
	}

	seen := map[string]bool{}
	for _, f := range files {
		seen[f.Path] = true
		want := "OPENAI_BASE_URL"
		if !strings.Contains(f.Content, want) {
			t.Errorf("%s missing %q", f.Path, want)
		}
	}
	for _, name := range []string{".env", ".envrc", "Makefile"} {
		if !seen[filepath.Join(root, name)] {
			t.Errorf("missing %s in output", name)
		}
	}
}

func TestProjectEnvFilesNoRoot(t *testing.T) {
	o := testOptions(t, "openai")
	o.Root = ""
	if files := ProjectEnvFiles(o); len(files) != 0 {
		t.Errorf("expected no files when Root is empty, got %d", len(files))
	}
}

func TestProjectEnvFilesSyntax(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env", ".envrc", "Makefile"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	o := testOptions(t, "openai")
	o.Root = root
	for _, f := range ProjectEnvFiles(o) {
		base := filepath.Base(f.Path)
		switch base {
		case ".envrc":
			if !strings.HasPrefix(f.Content, "export OPENAI_BASE_URL=\"") {
				t.Errorf(".envrc syntax wrong: %s", f.Content)
			}
		case "Makefile":
			if !strings.HasPrefix(f.Content, "export OPENAI_BASE_URL=") {
				t.Errorf("Makefile syntax wrong: %s", f.Content)
			}
		case ".env":
			if !strings.HasPrefix(f.Content, "OPENAI_BASE_URL=") {
				t.Errorf(".env syntax wrong: %s", f.Content)
			}
		}
	}
}

func TestCreateProjectEnv(t *testing.T) {
	root := t.TempDir()
	o := testOptions(t, "openai", "anthropic")
	o.Root = root
	f := CreateProjectEnv(o)
	if f.Path != filepath.Join(root, ".env") {
		t.Errorf("path = %q, want %q", f.Path, filepath.Join(root, ".env"))
	}
	for _, want := range []string{"OPENAI_BASE_URL=", "ANTHROPIC_BASE_URL="} {
		if !strings.Contains(f.Content, want) {
			t.Errorf("content missing %q: %s", want, f.Content)
		}
	}
	if strings.Contains(f.Content, testKey) {
		t.Error("project .env should not contain the literal key")
	}
}

func TestHasTarget(t *testing.T) {
	o := testOptions(t, "openai")
	if !o.HasTarget("openai") {
		t.Error("expected openai targeted")
	}
	if o.HasTarget("anthropic") {
		t.Error("did not expect anthropic targeted")
	}
}

func TestScopeOrDefault(t *testing.T) {
	o := testOptions(t, "openai")
	if got := o.ScopeOrDefault(ScopeProject); got != ScopeProject {
		t.Errorf("default scope = %q, want %q", got, ScopeProject)
	}
	o.Scope = ScopeUser
	if got := o.ScopeOrDefault(ScopeProject); got != ScopeUser {
		t.Errorf("explicit scope = %q, want %q", got, ScopeUser)
	}
}

func TestClaudeCodeFileWithoutAnthropicTarget(t *testing.T) {
	o := testOptions(t, "openai")
	if _, ok := ClaudeCodeFile(o); ok {
		t.Error("claude-code file should only exist when anthropic is targeted")
	}
}

func TestContinueJSONMergeAndStrip(t *testing.T) {
	o := testOptions(t, "openai")
	o.Model = "gpt-5"
	path := filepath.Join(t.TempDir(), "continue.json")
	f := continueJSONFile(o, path)

	out, err := f.Merge("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"title": "Vulnetix AI Firewall (openai)"`) {
		t.Errorf("merge did not create entry:\n%s", out)
	}

	out2, err := f.Merge(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, `"model": "gpt-5"`) {
		t.Errorf("merge did not update entry:\n%s", out2)
	}

	stripped, ok := f.Strip("", out2)
	if !ok {
		t.Fatal("strip did not remove entry")
	}
	if strings.Contains(stripped, "Vulnetix AI Firewall") {
		t.Errorf("strip left the entry behind:\n%s", stripped)
	}

	// Invalid JSON is rejected.
	if _, err := f.Merge("not json"); err == nil {
		t.Error("merge should reject invalid JSON")
	}
}

func TestMergeJSONEnv(t *testing.T) {
	merge := mergeJSONEnv(map[string]string{"OPENAI_API_KEY": "vlx_test", "OTHER": "x"}, nil)
	out, err := merge("")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	env, ok := doc["env"].(map[string]any)
	if !ok {
		t.Fatalf("env not an object: %v", doc)
	}
	if env["OPENAI_API_KEY"] != "vlx_test" {
		t.Errorf("key not set: %v", env)
	}
}

func TestStripJSONEnv(t *testing.T) {
	strip := stripJSONEnv([]string{"OPENAI_API_KEY"})
	body := `{"env":{"OPENAI_API_KEY":"x","OTHER":"y"}}`
	out, ok := strip("", body)
	if !ok {
		t.Fatal("expected a change")
	}
	if strings.Contains(out, "OPENAI_API_KEY") {
		t.Errorf("key not removed: %s", out)
	}
	if !strings.Contains(out, "OTHER") {
		t.Errorf("other key removed: %s", out)
	}

	// A document without the env block is unchanged.
	if _, ok := strip("", `{"other":"y"}`); ok {
		t.Error("a document without env should not report a change")
	}
}

func TestSecretSafeAndChmod600(t *testing.T) {
	// git check-ignore only matches paths inside a repository, so the ignored
	// path has to live under the package dir; the **/*.log rule covers it.
	logFile, err := filepath.Abs("secret-safe-test-coverage.log")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logFile, []byte("k"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(logFile) })

	if err := SecretSafe(logFile); err != nil {
		t.Errorf("ignored .log path rejected: %v", err)
	}

	// A path outside the repository cannot be ignored, so it must be refused.
	if err := SecretSafe(filepath.Join(t.TempDir(), "key")); err == nil {
		t.Error("a non-ignored path must be refused")
	}

	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte("k"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Chmod600(f); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestYAMLHelpersRoundTrip(t *testing.T) {
	merge := mergeYAMLKeys(map[string]any{"openai-api-base": "https://gw.example.com/v1", "model": "gpt-4o"})
	out, err := merge("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "openai-api-base:") {
		t.Errorf("yaml merge did not create keys:\n%s", out)
	}

	mergeList := mergeYAMLListEntry("models", "name", "test", map[string]any{"name": "test", "model": "gpt-4o"})
	out, err = mergeList("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "- name: test") && !strings.Contains(out, "- model: gpt-4o") {
		t.Errorf("yaml list merge failed:\n%s", out)
	}

	stripList := stripYAMLListEntry("models", "name", "test")
	stripped, ok := stripList("", out)
	if !ok {
		t.Fatal("expected strip to remove the list entry")
	}
	if strings.Contains(stripped, "gpt-4o") {
		t.Errorf("yaml list strip failed:\n%s", stripped)
	}
}

func TestLoadYAMLDocInvalid(t *testing.T) {
	_, _, err := loadYAMLDoc("a: [unterminated")
	if err == nil {
		t.Error("expected invalid YAML to fail")
	}
	_, _, err = loadYAMLDoc("[a, b]")
	if err == nil {
		t.Error("expected non-mapping top level to fail")
	}
}

func TestMapHelpers(t *testing.T) {
	doc, root, err := loadYAMLDoc("")
	if err != nil {
		t.Fatal(err)
	}
	node := &yaml.Node{}
	_ = node.Encode("v1")
	mapSet(root, "k1", node)
	if got, _ := mapGet(root, "k1"); got == nil || got.Value != "v1" {
		t.Errorf("mapGet(k1) = %v", got)
	}
	mapDelete(root, "k1")
	if got, _ := mapGet(root, "k1"); got != nil {
		t.Errorf("k1 should be deleted, got %v", got)
	}
	renderYAMLDoc(doc)
}
