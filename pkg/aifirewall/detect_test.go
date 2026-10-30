package aifirewall

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		baseURL     string
		gatewayHost string
		want        State
	}{
		{"", "", StateNotWired},
		{"", "guardrails.vulnetix.com", StateNotWired},
		{"https://api.openai.com/v1", "guardrails.vulnetix.com", StateElsewhere},
		{"https://guardrails.vulnetix.com/openai/org", "guardrails.vulnetix.com", StateWired},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.baseURL, tt.gatewayHost), func(t *testing.T) {
			if got := classify(tt.baseURL, tt.gatewayHost); got != tt.want {
				t.Errorf("classify(%q, %q) = %q, want %q", tt.baseURL, tt.gatewayHost, got, tt.want)
			}
		})
	}
}

func TestDetectReturnsOneEntryPerClient(t *testing.T) {
	root := t.TempDir()
	o := Options{Home: root, Root: root}
	got := Detect(o, "")
	if len(got) != len(Clients()) {
		t.Fatalf("expected %d detected clients, got %d", len(Clients()), len(got))
	}
	seen := map[string]bool{}
	for _, d := range got {
		if seen[d.Client.ID] {
			t.Errorf("duplicate client %q in output", d.Client.ID)
		}
		seen[d.Client.ID] = true
	}
}

// clearProviderEnv blanks every variable Detect reads from the environment, so
// a base URL or key exported in the developer's own shell cannot change the
// verdict under test.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, p := range Providers() {
		if p.APIKeyEnv != "" {
			t.Setenv(p.APIKeyEnv, "")
		}
		for _, k := range p.BaseURLEnv {
			t.Setenv(k, "")
		}
	}
}

func TestDetectShellState(t *testing.T) {
	root := t.TempDir()
	clearProviderEnv(t)
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("OPENAI_BASE_URL", GatewayURL(DefaultGatewayURL, "openai", testOrg))

	got := Detect(Options{Home: root, Root: root}, GatewayHostOrFatal(t))

	shell, ok := findDetected(got, "shell")
	if !ok {
		t.Fatalf("expected shell entry, got %+v", got)
	}
	if shell.State != StateWired {
		t.Errorf("shell state = %q, want %q", shell.State, StateWired)
	}
	if !shell.KeyEnvSet["OPENAI_API_KEY"] {
		t.Error("expected OPENAI_API_KEY tracked")
	}
	if !shell.WiredProviders["openai"] {
		t.Error("expected openai in WiredProviders")
	}

	t.Setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
	got = Detect(Options{Home: root, Root: root}, GatewayHostOrFatal(t))
	shell, _ = findDetected(got, "shell")
	if shell.State != StateElsewhere {
		t.Errorf("shell state = %q, want %q", shell.State, StateElsewhere)
	}
}

func TestDetectShellMixedWiring(t *testing.T) {
	root := t.TempDir()
	clearProviderEnv(t)
	t.Setenv("OPENAI_BASE_URL", GatewayURL(DefaultGatewayURL, "openai", testOrg))
	t.Setenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")

	got := Detect(Options{Home: root, Root: root}, GatewayHostOrFatal(t))
	shell, _ := findDetected(got, "shell")
	if shell.State != StateElsewhere {
		t.Errorf("mixed wiring state = %q, want %q", shell.State, StateElsewhere)
	}
	if !shell.WiredProviders["openai"] {
		t.Error("openai should still be reported as wired")
	}
}

func TestEnvAssignment(t *testing.T) {
	tests := []struct {
		body string
		key  string
		want string
	}{
		{"OPENAI_BASE_URL=https://x", "OPENAI_BASE_URL", "https://x"},
		{"export OPENAI_BASE_URL=https://x", "OPENAI_BASE_URL", "https://x"},
		{"OPENAI_BASE_URL=\"https://x\"", "OPENAI_BASE_URL", "https://x"},
		{"# OPENAI_BASE_URL=https://x", "OPENAI_BASE_URL", ""},
		{"OTHER=https://x", "OPENAI_BASE_URL", ""},
		{"export\tOPENAI_BASE_URL  =  https://x # comment", "OPENAI_BASE_URL", "https://x"},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			if got := envAssignment(tt.body, tt.key); got != tt.want {
				t.Errorf("envAssignment(%q, %q) = %q, want %q", tt.body, tt.key, got, tt.want)
			}
		})
	}
}

func TestDetectProjectEnv(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("OPENAI_BASE_URL="+GatewayURL(DefaultGatewayURL, "openai", testOrg)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got := Detect(Options{Home: root, Root: root}, GatewayHostOrFatal(t))
	env, ok := findDetected(got, "env")
	if !ok {
		t.Fatalf("expected env entry, got %+v", got)
	}
	if env.State != StateWired {
		t.Errorf("env state = %q, want %q", env.State, StateWired)
	}
	if env.Path != filepath.Join(root, ".env") {
		t.Errorf("env path = %q, want %q", env.Path, filepath.Join(root, ".env"))
	}
}

func TestDetectProjectEnvElsewhere(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("OPENAI_BASE_URL=https://api.openai.com/v1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got := Detect(Options{Home: root, Root: root}, GatewayHostOrFatal(t))
	env, _ := findDetected(got, "env")
	if env.State != StateElsewhere {
		t.Errorf("env state = %q, want %q", env.State, StateElsewhere)
	}
}

func TestReadClaudeCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	body := `{"env":{"ANTHROPIC_BASE_URL":"https://x","ANTHROPIC_MODEL":"claude-sonnet-4"}}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	base, model := readClaudeCode(path)
	if base != "https://x" {
		t.Errorf("base = %q, want %q", base, "https://x")
	}
	if model != "claude-sonnet-4" {
		t.Errorf("model = %q, want %q", model, "claude-sonnet-4")
	}

	if base, model := readClaudeCode(filepath.Join(dir, "missing")); base != "" || model != "" {
		t.Error("missing file should return empty values")
	}

	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if base, model := readClaudeCode(path); base != "" || model != "" {
		t.Error("invalid JSON should return empty values")
	}
}

func TestReadCodex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	body := `
model = "gpt-5"
model_provider = "vulnetix-openai"

[model_providers.vulnetix-openai]
base_url = "https://guardrails.vulnetix.com/openai/org/v1"
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	base, model := readCodex(path)
	if want := "https://guardrails.vulnetix.com/openai/org/v1"; base != want {
		t.Errorf("base = %q, want %q", base, want)
	}
	if model != "gpt-5" {
		t.Errorf("model = %q, want %q", model, "gpt-5")
	}

	if err := os.WriteFile(path, []byte("not valid toml =="), 0644); err != nil {
		t.Fatal(err)
	}
	if base, model := readCodex(path); base != "" || model != "" {
		t.Error("invalid TOML should return empty values")
	}

	noProvider := `model = "o3"`
	if err := os.WriteFile(path, []byte(noProvider), 0644); err != nil {
		t.Fatal(err)
	}
	base, model = readCodex(path)
	if base != "" {
		t.Errorf("without model_provider base should be empty, got %q", base)
	}
	if model != "o3" {
		t.Errorf("model = %q, want %q", model, "o3")
	}
}

func TestReadContinueYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// The owned entry comes second: readContinue must prefer it over the first
	// entry that merely sets a base URL.
	body := `models:
  - name: Local Ollama
    apiBase: http://localhost:11434
    model: llama3
  - name: Vulnetix AI Firewall (openai)
    apiBase: https://guardrails.vulnetix.com/openai/org/v1
    model: gpt-4o
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	base, model := readContinue(path)
	if want := "https://guardrails.vulnetix.com/openai/org/v1"; base != want {
		t.Errorf("base = %q, want %q", base, want)
	}
	if model != "gpt-4o" {
		t.Errorf("model = %q, want %q", model, "gpt-4o")
	}
}

func TestReadContinueJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	body := `{"models":[{"title":"Vulnetix AI Firewall (openai)","apiBase":"https://guardrails.vulnetix.com/openai/org/v1","model":"gpt-4o"}]}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	base, model := readContinue(path)
	if want := "https://guardrails.vulnetix.com/openai/org/v1"; base != want {
		t.Errorf("base = %q, want %q", base, want)
	}
	if model != "gpt-4o" {
		t.Errorf("model = %q, want %q", model, "gpt-4o")
	}
}

func TestReadContinueFallsBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	body := `models:
  - name: Other
    apiBase: https://api.openai.com/v1
    model: gpt-3.5
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	base, model := readContinue(path)
	if base != "https://api.openai.com/v1" {
		t.Errorf("base = %q, want %q", base, "https://api.openai.com/v1")
	}
	if model != "gpt-3.5" {
		t.Errorf("model = %q, want %q", model, "gpt-3.5")
	}
}

func TestReadAider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aider.conf.yml")

	body := `openai-api-base: https://guardrails.vulnetix.com/openai/org/v1
model: gpt-4o
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	base, model := readAider(path)
	if want := "https://guardrails.vulnetix.com/openai/org/v1"; base != want {
		t.Errorf("base = %q, want %q", base, want)
	}
	if model != "gpt-4o" {
		t.Errorf("model = %q, want %q", model, "gpt-4o")
	}

	if err := os.WriteFile(path, []byte("not: valid: ["), 0644); err != nil {
		t.Fatal(err)
	}
	if base, model := readAider(path); base != "" || model != "" {
		t.Error("invalid YAML should return empty values")
	}
}

func findDetected(got []Detected, id string) (Detected, bool) {
	for _, d := range got {
		if d.Client.ID == id {
			return d, true
		}
	}
	return Detected{}, false
}

func TestDetectManualClients(t *testing.T) {
	root := t.TempDir()
	// Their config directories make both clients installed, so the verdict does
	// not depend on whether this machine happens to have them.
	for _, dir := range []string{".cursor", ".windsurf"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	got := Detect(Options{Home: root, Root: root}, GatewayHostOrFatal(t))
	for _, id := range []string{"cursor", "windsurf"} {
		d, ok := findDetected(got, id)
		if !ok {
			t.Fatalf("expected %s entry", id)
		}
		if d.State != StateManual {
			t.Errorf("%s state = %q, want %q", id, d.State, StateManual)
		}
	}
}

func TestDetectInstalled(t *testing.T) {
	root := t.TempDir()
	claudeDir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatal(err)
	}

	got := Detect(Options{Home: root, Root: root}, GatewayHostOrFatal(t))
	claude, _ := findDetected(got, "claude-code")
	// Installed, but with no settings.json there is no base URL to classify.
	if claude.State != StateNotWired {
		t.Errorf("claude-code state = %q, want %q", claude.State, StateNotWired)
	}
}

func GatewayHostOrFatal(t *testing.T) string {
	t.Helper()
	host, err := GatewayHost(DefaultGatewayURL)
	if err != nil {
		t.Fatal(err)
	}
	return host
}
