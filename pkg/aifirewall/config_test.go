package aifirewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/vulnetix/cli/v3/internal/managedfile"
	"gopkg.in/yaml.v3"
)

const testOrg = "6f2a1c3e-0000-0000-0000-000000000001"
const testKey = "vlx_live_abcdefghijklmnop"

func testOptions(t *testing.T, targets ...string) Options {
	t.Helper()
	var ps []Provider
	for _, slug := range targets {
		p, ok := ProviderBySlug(slug)
		if !ok {
			t.Fatalf("unknown provider %q", slug)
		}
		ps = append(ps, p)
	}
	dir := t.TempDir()
	return Options{
		Gateway: DefaultGatewayURL,
		OrgUUID: testOrg,
		APIKey:  testKey,
		Targets: ps,
		Home:    dir,
		Root:    dir,
	}
}

func TestGatewayURL(t *testing.T) {
	got := GatewayURL("https://guardrails.vulnetix.com", "openai", testOrg)
	want := "https://guardrails.vulnetix.com/openai/" + testOrg + "/v1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Anthropic omits the version segment — see
	// TestAnthropicBaseURLOmitsTheVersionSegment.
	if got := GatewayURL("https://gw.example.com/", "anthropic", testOrg); got != "https://gw.example.com/anthropic/"+testOrg {
		t.Errorf("trailing slash not handled: %q", got)
	}
	if got := GatewayURL("", "openai", testOrg); !strings.HasPrefix(got, DefaultGatewayURL) {
		t.Errorf("empty gateway should fall back to the default: %q", got)
	}
}

// The OpenAI and Anthropic SDKs disagree about who owns the "/v1", and getting
// it wrong yields a request to a path containing "/v1/v1/" — a 404 that looks
// like the gateway is broken rather than like a config bug.
func TestAnthropicBaseURLOmitsTheVersionSegment(t *testing.T) {
	// The Anthropic SDK appends /v1/messages to base_url itself.
	got := GatewayURL(DefaultGatewayURL, "anthropic", testOrg)
	want := DefaultGatewayURL + "/anthropic/" + testOrg
	if got != want {
		t.Errorf("anthropic base URL is %q; the SDK appends /v1/messages, so a trailing /v1 here produces /v1/v1/messages", got)
	}

	// The OpenAI SDK's base_url includes the version; it appends only
	// /chat/completions or /responses.
	if got := GatewayURL(DefaultGatewayURL, "openai", testOrg); !strings.HasSuffix(got, "/v1") {
		t.Errorf("openai base URL must end in /v1, got %q", got)
	}
}

// The env writers must carry the same asymmetry through to the shell block.
func TestAnthropicEnvVarOmitsTheVersionSegment(t *testing.T) {
	o := testOptions(t, "anthropic")
	for _, v := range EnvVars(o, "shell") {
		if v.Key != "ANTHROPIC_BASE_URL" {
			continue
		}
		if strings.HasSuffix(v.Value, "/v1") {
			t.Fatalf("ANTHROPIC_BASE_URL is %q; Claude Code would POST to /v1/v1/messages", v.Value)
		}
		return
	}
	t.Fatal("ANTHROPIC_BASE_URL was not written")
}

// The single most consequential fact in this package: we must not invent
// base-URL environment variables. A variable that looks like an SDK setting but
// is read by nothing would leave a user believing their traffic was proxied
// while it went straight to the provider.
func TestOnlyRealBaseURLEnvVarsAreClaimed(t *testing.T) {
	envWired := map[string][]string{
		"openai":    {"OPENAI_BASE_URL", "OPENAI_API_BASE"},
		"anthropic": {"ANTHROPIC_BASE_URL"},
		"groq":      {"GROQ_BASE_URL"},
	}
	for _, p := range Providers() {
		want, ok := envWired[p.Slug]
		if !ok {
			if p.EnvWired() {
				t.Errorf("%s claims base-URL env vars %v, but no SDK reads one for it", p.Slug, p.BaseURLEnv)
			}
			continue
		}
		if strings.Join(p.BaseURLEnv, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %v, want %v", p.Slug, p.BaseURLEnv, want)
		}
	}
}

// ANTHROPIC_API_KEY is sent as x-api-key; the gateway wants Bearer. Getting this
// wrong produces a 401 that looks like a bad key.
func TestAnthropicUsesAuthToken(t *testing.T) {
	p, _ := ProviderBySlug("anthropic")
	if p.APIKeyEnv != "ANTHROPIC_AUTH_TOKEN" {
		t.Errorf("anthropic key env is %q; ANTHROPIC_API_KEY would be sent as x-api-key, which the gateway does not accept", p.APIKeyEnv)
	}
}

func TestEnvVarsReferenceTheKeyRatherThanInliningIt(t *testing.T) {
	o := testOptions(t, "openai")
	vars := EnvVars(o, "shell")

	var sawKey bool
	for _, v := range vars {
		if strings.Contains(v.Value, testKey) {
			t.Fatalf("the API key was inlined into %s without --embed-key", v.Key)
		}
		if v.Key == "OPENAI_API_KEY" {
			sawKey = true
			if v.Value != "$"+VulnetixKeyEnv {
				t.Errorf("OPENAI_API_KEY should reference $%s, got %q", VulnetixKeyEnv, v.Value)
			}
		}
	}
	if !sawKey {
		t.Error("OPENAI_API_KEY was not set")
	}

	o.EmbedKey = true
	for _, v := range EnvVars(o, "shell") {
		if v.Key == "OPENAI_API_KEY" && v.Value != testKey {
			t.Errorf("--embed-key should write the literal, got %q", v.Value)
		}
	}
}

// A provider with no base-URL variable gets an informational one, never a
// plausible-looking fake.
func TestSnippetOnlyProviderGetsInfoVarOnly(t *testing.T) {
	o := testOptions(t, "mistral")
	vars := EnvVars(o, "shell")
	if len(vars) != 1 {
		t.Fatalf("expected exactly one informational var, got %v", vars)
	}
	if vars[0].Key != "VULNETIX_AIFW_MISTRAL_BASE_URL" {
		t.Errorf("got %q; MISTRAL_BASE_URL is not read by any SDK and must not be written", vars[0].Key)
	}
	if !strings.Contains(vars[0].Value, "/mistral/") {
		t.Errorf("info var should carry the gateway URL: %q", vars[0].Value)
	}
}

// --- Claude Code ---

func TestClaudeCodeMergePreservesEverythingElse(t *testing.T) {
	o := testOptions(t, "anthropic")
	o.Model = "claude-sonnet-4-5"

	existing := `{
  "permissions": {
    "allow": ["Bash(git:*)"]
  },
  "env": {
    "MY_OWN_VAR": "keep me"
  },
  "hooks": {"Stop": []}
}`
	f, ok := ClaudeCodeFile(o)
	if !ok {
		t.Fatal("expected a claude-code file")
	}
	got, err := f.Merge(existing)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("produced invalid JSON: %v\n%s", err, got)
	}
	if _, ok := doc["permissions"]; !ok {
		t.Error("permissions were dropped")
	}
	if _, ok := doc["hooks"]; !ok {
		t.Error("hooks were dropped")
	}
	env := doc["env"].(map[string]any)
	if env["MY_OWN_VAR"] != "keep me" {
		t.Error("an unrelated env var was dropped")
	}
	// No /v1: Claude Code appends /v1/messages to ANTHROPIC_BASE_URL itself.
	if got := env["ANTHROPIC_BASE_URL"].(string); !strings.HasSuffix(got, "/anthropic/"+testOrg) {
		t.Errorf("base URL not set: %v", got)
	}
	if env["ANTHROPIC_MODEL"] != "claude-sonnet-4-5" {
		t.Errorf("model not pinned: %v", env["ANTHROPIC_MODEL"])
	}

	// settings.json is routinely committed: the credential must not be in it.
	if strings.Contains(got, testKey) {
		t.Fatal("the API key was written into settings.json, which is commonly committed")
	}

	// And the strip puts it back exactly.
	back, changed := f.Strip(f.Path, got)
	if !changed {
		t.Fatal("strip found nothing to remove")
	}
	var doc2 map[string]any
	if err := json.Unmarshal([]byte(back), &doc2); err != nil {
		t.Fatal(err)
	}
	env2 := doc2["env"].(map[string]any)
	if _, ok := env2["ANTHROPIC_BASE_URL"]; ok {
		t.Error("our var survived the strip")
	}
	if env2["MY_OWN_VAR"] != "keep me" {
		t.Error("strip removed a var that was not ours")
	}
	if _, ok := doc2["permissions"]; !ok {
		t.Error("strip dropped permissions")
	}
}

func TestClaudeCodeRefusesInvalidJSON(t *testing.T) {
	o := testOptions(t, "anthropic")
	f, _ := ClaudeCodeFile(o)
	if _, err := f.Merge("{ not json"); err == nil {
		t.Fatal("expected a refusal rather than clobbering a file we cannot parse")
	}
}

// --- Codex ---

func TestCodexMergePreservesCommentsAndOtherProviders(t *testing.T) {
	o := testOptions(t, "openai")
	o.Model = "gpt-5"

	existing := `# my codex config
model = "o3"
approval_policy = "on-request"

# a provider I set up myself
[model_providers.my-own]
name = "Mine"
base_url = "https://example.com/v1"
`
	f, ok := CodexFile(o)
	if !ok {
		t.Fatal("expected a codex file")
	}
	got, err := f.Merge(existing)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"# my codex config",
		"# a provider I set up myself",
		"[model_providers.my-own]",
		`approval_policy = "on-request"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q from the user's config:\n%s", want, got)
		}
	}

	var doc struct {
		Model          string `toml:"model"`
		ModelProvider  string `toml:"model_provider"`
		ModelProviders map[string]struct {
			BaseURL string `toml:"base_url"`
			WireAPI string `toml:"wire_api"`
			EnvKey  string `toml:"env_key"`
		} `toml:"model_providers"`
	}
	if _, err := toml.Decode(got, &doc); err != nil {
		t.Fatalf("produced invalid TOML: %v\n%s", err, got)
	}
	if doc.ModelProvider != CodexProviderName {
		t.Errorf("model_provider not pointed at us: %q", doc.ModelProvider)
	}
	if doc.Model != "gpt-5" {
		t.Errorf("model not replaced: %q", doc.Model)
	}
	ours := doc.ModelProviders[CodexProviderName]
	if !strings.Contains(ours.BaseURL, "/openai/"+testOrg+"/v1") {
		t.Errorf("base_url wrong: %q", ours.BaseURL)
	}
	// Codex only accepts wire_api = "responses".
	if ours.WireAPI != WireResponses {
		t.Errorf("wire_api is %q; Codex only accepts %q", ours.WireAPI, WireResponses)
	}
	if ours.EnvKey != VulnetixKeyEnv {
		t.Errorf("env_key is %q, want %q", ours.EnvKey, VulnetixKeyEnv)
	}
	if _, ok := doc.ModelProviders["my-own"]; !ok {
		t.Error("the user's own provider was dropped")
	}

	back, changed := f.Strip(f.Path, got)
	if !changed {
		t.Fatal("strip found nothing")
	}
	if strings.Contains(back, CodexProviderName) {
		t.Errorf("our provider survived the strip:\n%s", back)
	}
	if !strings.Contains(back, "[model_providers.my-own]") {
		t.Errorf("strip removed the user's provider:\n%s", back)
	}
}

// A root key must go above the comment block that introduces the first table,
// not between the comment and the table it describes — otherwise the user's
// comment ends up annotating our line.
func TestCodexRootKeyDoesNotSplitACommentFromItsTable(t *testing.T) {
	o := testOptions(t, "openai")
	existing := `# header
approval_policy = "on-request"

# a provider I set up myself
[model_providers.my-own]
name = "Mine"
`
	f, _ := CodexFile(o)
	got, err := f.Merge(existing)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(got, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "[model_providers.my-own]" {
			continue
		}
		if i == 0 {
			t.Fatal("the user's table lost its comment")
		}
		if prev := strings.TrimSpace(lines[i-1]); prev != "# a provider I set up myself" {
			t.Errorf("the comment above the user's table is now %q — we inserted between a comment and the table it describes:\n%s", prev, got)
		}
		return
	}
	t.Fatalf("the user's table vanished:\n%s", got)
}

func TestCodexRefusesToWriteUnparseableTOML(t *testing.T) {
	o := testOptions(t, "openai")
	f, _ := CodexFile(o)
	if _, err := f.Merge("this = = broken\n"); err == nil {
		t.Fatal("expected a refusal rather than leaving Codex with a config it cannot load")
	}
}

// --- Continue ---

func TestContinueMergeKeepsOtherModelsAndComments(t *testing.T) {
	o := testOptions(t, "openai")
	dir := filepath.Join(o.Home, ".continue")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("models: []\n"), 0644); err != nil {
		t.Fatal(err)
	}

	existing := `# my continue config
name: my-assistant
models:
  - name: Local Ollama
    provider: ollama
    model: llama3
`
	f, ok := ContinueFile(o)
	if !ok {
		t.Fatal("expected a continue file")
	}
	got, err := f.Merge(existing)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got, "# my continue config") {
		t.Errorf("comment lost:\n%s", got)
	}
	var doc struct {
		Name   string `yaml:"name"`
		Models []struct {
			Name    string `yaml:"name"`
			APIBase string `yaml:"apiBase"`
			APIKey  string `yaml:"apiKey"`
		} `yaml:"models"`
	}
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, got)
	}
	if doc.Name != "my-assistant" {
		t.Error("unrelated key dropped")
	}
	if len(doc.Models) != 2 {
		t.Fatalf("expected the user's model plus ours, got %d", len(doc.Models))
	}
	var ours bool
	for _, m := range doc.Models {
		if m.Name == ContinueModelName {
			ours = true
			if !strings.Contains(m.APIBase, "/openai/"+testOrg+"/v1") {
				t.Errorf("apiBase wrong: %q", m.APIBase)
			}
			// Continue cannot read the shell environment: it resolves this from
			// ~/.continue/.env.
			if !strings.Contains(m.APIKey, "secrets."+VulnetixKeyEnv) {
				t.Errorf("apiKey should be a secrets reference, got %q", m.APIKey)
			}
		}
	}
	if !ours {
		t.Error("our model entry was not added")
	}

	// Re-running replaces our entry rather than adding a second.
	twice, err := f.Merge(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(twice, ContinueModelName) != 1 {
		t.Errorf("our entry was duplicated:\n%s", twice)
	}

	back, changed := f.Strip(f.Path, got)
	if !changed {
		t.Fatal("strip found nothing")
	}
	if strings.Contains(back, ContinueModelName) {
		t.Error("our entry survived the strip")
	}
	if !strings.Contains(back, "Local Ollama") {
		t.Error("strip removed the user's model")
	}
}

// --- aider ---

func TestAiderMergeKeepsUnrelatedKeys(t *testing.T) {
	o := testOptions(t, "openai")
	o.Model = "gpt-4o"

	existing := "auto-commits: false\ndark-mode: true\n"
	f, ok := AiderFile(o)
	if !ok {
		t.Fatal("expected an aider file")
	}
	got, err := f.Merge(existing)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["auto-commits"] != false || doc["dark-mode"] != true {
		t.Errorf("unrelated keys lost: %v", doc)
	}
	base, _ := doc["openai-api-base"].(string)
	if !strings.Contains(base, "/openai/"+testOrg+"/v1") {
		t.Errorf("base not set: %v", doc["openai-api-base"])
	}
	if doc["model"] != "openai/gpt-4o" {
		t.Errorf("model should be namespaced for aider: %v", doc["model"])
	}
	// aider reads the key from the environment; it must not be in the file.
	if strings.Contains(got, testKey) {
		t.Fatal("the API key was written into .aider.conf.yml")
	}

	back, changed := f.Strip(f.Path, got)
	if !changed {
		t.Fatal("strip found nothing")
	}
	var doc2 map[string]any
	if err := yaml.Unmarshal([]byte(back), &doc2); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc2["openai-api-base"]; ok {
		t.Error("our key survived the strip")
	}
	if doc2["auto-commits"] != false {
		t.Error("strip removed the user's setting")
	}
}

// --- round trip ---

// Install then uninstall must leave every file byte-for-byte as it was.
func TestInstallUninstallRoundTrip(t *testing.T) {
	o := testOptions(t, "openai", "anthropic")
	o.Model = "gpt-4o"

	originals := map[string]string{
		filepath.Join(o.Home, ".codex", "config.toml"):    "# mine\nmodel = \"o3\"\n\n[model_providers.my-own]\nbase_url = \"https://example.com\"\n",
		filepath.Join(o.Home, ".claude", "settings.json"): "{\n  \"env\": {\n    \"KEEP\": \"1\"\n  }\n}\n",
		filepath.Join(o.Home, ".continue", "config.yaml"): "models:\n  - name: Local\n    provider: ollama\n",
		filepath.Join(o.Root, ".aider.conf.yml"):          "auto-commits: false\n",
	}
	for path, body := range originals {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Claude Code writes to the project scope by default.
	o.Scope = ScopeUser

	files := []managedfile.File{}
	if f, ok := ClaudeCodeFile(o); ok {
		files = append(files, f)
	}
	if f, ok := CodexFile(o); ok {
		files = append(files, f)
	}
	if f, ok := ContinueFile(o); ok {
		files = append(files, f)
	}
	if f, ok := AiderFile(o); ok {
		files = append(files, f)
	}

	for _, f := range files {
		if _, err := managedfile.UpsertFile(f, Markers, false); err != nil {
			t.Fatalf("install %s: %v", f.Path, err)
		}
	}
	host, _ := GatewayHost(o.Gateway)
	for _, f := range files {
		if _, err := managedfile.RemoveFile(f, Markers, host, false); err != nil {
			t.Fatalf("uninstall %s: %v", f.Path, err)
		}
	}

	for path, want := range originals {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s was deleted by uninstall: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s not restored:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
		}
	}
}

func TestSecretFilesAreOnlyTheOnesThatMustBe(t *testing.T) {
	o := testOptions(t, "openai")
	f, ok := ContinueSecretsFile(o)
	if !ok {
		t.Fatal("expected a continue secrets file")
	}
	if !strings.Contains(f.Content, testKey) {
		t.Error("Continue's .env must hold the literal key — an IDE extension cannot read the shell environment")
	}

	// Claude Code's secrets file only exists with --embed-key.
	if _, ok := ClaudeCodeSecretsFile(o); ok {
		t.Error("no key should be written for claude-code without --embed-key")
	}
	o.EmbedKey = true
	o.Targets = []Provider{mustProvider(t, "anthropic")}
	sf, ok := ClaudeCodeSecretsFile(o)
	if !ok {
		t.Fatal("expected a secrets file with --embed-key")
	}
	if !strings.HasSuffix(sf.Path, "settings.local.json") {
		t.Errorf("the key must go to the git-ignored settings.local.json, not %s", sf.Path)
	}
}

func mustProvider(t *testing.T, slug string) Provider {
	t.Helper()
	p, ok := ProviderBySlug(slug)
	if !ok {
		t.Fatalf("unknown provider %q", slug)
	}
	return p
}

// --- wire capability gate ---

func TestWireGate(t *testing.T) {
	codex, _ := ClientByID("codex")
	claude, _ := ClientByID("claude-code")
	aider, _ := ClientByID("aider")

	// No advertisement: refuse to wire the clients that need a non-chat wire,
	// rather than writing a config that 404s at request time.
	if ok, why := SupportsWire(nil, codex, "openai"); ok {
		t.Error("codex should not be wired when the gateway's capabilities are unknown")
	} else if !strings.Contains(why, "responses") {
		t.Errorf("the reason should name the wire it needs: %q", why)
	}
	if ok, _ := SupportsWire(nil, claude, "anthropic"); ok {
		t.Error("claude-code should not be wired when capabilities are unknown")
	}
	// A chat client is fine either way.
	if ok, _ := SupportsWire(nil, aider, "openai"); !ok {
		t.Error("aider only needs chat, which is the safe assumption")
	}

	gw := &Gateway{WireAPIs: map[string][]string{
		"openai":    {"chat", "responses"},
		"anthropic": {"chat"},
	}}
	if ok, _ := SupportsWire(gw, codex, "openai"); !ok {
		t.Error("codex should be wired when the gateway serves responses")
	}
	if ok, why := SupportsWire(gw, claude, "anthropic"); ok {
		t.Error("claude-code needs messages, which this gateway does not serve")
	} else if !strings.Contains(why, "messages") {
		t.Errorf("the reason should name the missing wire: %q", why)
	}
}
