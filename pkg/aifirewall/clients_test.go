package aifirewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClientsRegistry(t *testing.T) {
	c := Clients()
	if len(c) == 0 {
		t.Fatal("expected a non-empty client registry")
	}
	seen := map[string]bool{}
	for _, client := range c {
		if seen[client.ID] {
			t.Errorf("duplicate client id %q", client.ID)
		}
		seen[client.ID] = true
	}

	must := []string{"shell", "env", "claude-code", "codex", "continue", "aider", "cursor", "windsurf"}
	for _, id := range must {
		_, ok := seen[id]
		if !ok {
			t.Errorf("expected client %q in registry", id)
		}
	}

	frozen := clients
	if len(c) != len(frozen) {
		t.Fatalf("Clients() returned %d clients, expected %d", len(c), len(frozen))
	}
	c[0].ID = "mutated"
	if frozen[0].ID == "mutated" {
		t.Error("Clients() returned a reference to the internal slice")
	}
}

func TestClientByID(t *testing.T) {
	tests := []struct {
		id     string
		wantOK bool
		manual bool
		wire   string
	}{
		{"claude-code", true, false, WireMessages},
		{"codex", true, false, WireResponses},
		{"aider", true, false, WireChat},
		{"cursor", true, true, WireChat},
		{"unknown", false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			c, ok := ClientByID(tt.id)
			if ok != tt.wantOK {
				t.Fatalf("ClientByID(%q) ok = %v, want %v", tt.id, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if c.ID != tt.id {
				t.Errorf("id = %q, want %q", c.ID, tt.id)
			}
			if c.Manual != tt.manual {
				t.Errorf("manual = %v, want %v", c.Manual, tt.manual)
			}
			if c.Wire != tt.wire {
				t.Errorf("wire = %q, want %q", c.Wire, tt.wire)
			}
		})
	}
}

func TestClientPaths(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()

	tests := []struct {
		id      string
		scope   Scope
		wantCfg string
	}{
		{"claude-code", ScopeUser, filepath.Join(home, ".claude", "settings.json")},
		{"claude-code", ScopeProject, filepath.Join(root, ".claude", "settings.json")},
		{"codex", ScopeUser, filepath.Join(home, ".codex", "config.toml")},
		{"continue", ScopeUser, filepath.Join(home, ".continue", "config.yaml")},
		{"aider", ScopeProject, filepath.Join(root, ".aider.conf.yml")},
	}
	for _, tt := range tests {
		t.Run(tt.id+"/"+string(tt.scope), func(t *testing.T) {
			c, _ := ClientByID(tt.id)
			p := ClientPaths(c, tt.scope, home, root)
			if p.Config != tt.wantCfg {
				t.Errorf("Config = %q, want %q", p.Config, tt.wantCfg)
			}
		})
	}
}

func TestClientPathsAiderFallsBack(t *testing.T) {
	home := t.TempDir()
	p := ClientPaths(Client{ID: "aider"}, ScopeProject, home, "")
	if p.Config != filepath.Join(home, ".aider.conf.yml") {
		t.Errorf("aider user config path = %q, want %q", p.Config, filepath.Join(home, ".aider.conf.yml"))
	}
}

func TestClientPathsEnvNoRoot(t *testing.T) {
	p := ClientPaths(Client{ID: "env"}, ScopeProject, t.TempDir(), "")
	if p.Config != "" || len(p.Detect) != 0 {
		t.Errorf("env without root should return empty paths, got %+v", p)
	}
}

func TestInstalled(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()

	if !Installed(Client{ID: "shell"}, ScopeUser, home, root) {
		t.Error("shell should always report installed")
	}
	if Installed(Client{ID: "env"}, ScopeProject, home, "") {
		t.Error("env without root should not be installed")
	}
	if !Installed(Client{ID: "env"}, ScopeProject, home, root) {
		t.Error("env with root should report installed")
	}

	claudeDir := filepath.Join(home, ".claude")
	if err := createDir(claudeDir); err != nil {
		t.Fatal(err)
	}
	claude, _ := ClientByID("claude-code")
	if !Installed(claude, ScopeUser, home, root) {
		t.Error("claude-code should be installed when its directory exists")
	}
	config := filepath.Join(home, ".codex", "config.toml")
	if err := createFile(config); err != nil {
		t.Fatal(err)
	}
	codex, _ := ClientByID("codex")
	if !Installed(codex, ScopeUser, home, root) {
		t.Error("codex should be installed when its config exists")
	}
}

func TestBinaryName(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"codex", "codex"},
		{"aider", "aider"},
		{"claude-code", "claude"},
		{"cursor", "cursor"},
		{"windsurf", "windsurf"},
		{"shell", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := binaryName(tt.id); got != tt.want {
				t.Errorf("binaryName(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestSupportsWire(t *testing.T) {
	codex, _ := ClientByID("codex")
	claude, _ := ClientByID("claude-code")

	gw := &Gateway{WireAPIs: map[string][]string{
		"openai":    {"chat"},
		"anthropic": {"messages"},
	}}
	if ok, why := SupportsWire(gw, codex, "openai"); ok {
		t.Errorf("codex should need responses on openai: %s", why)
	}
	if ok, why := SupportsWire(gw, claude, "anthropic"); !ok || why != "" {
		t.Errorf("claude should be supported for messages: ok=%v why=%q", ok, why)
	}

	gwWithResponses := &Gateway{WireAPIs: map[string][]string{"openai": {"chat", "responses"}}}
	if ok, _ := SupportsWire(gwWithResponses, codex, "openai"); !ok {
		t.Error("codex should be supported when responses is advertised")
	}
}

func createDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func createFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(""), 0644)
}
