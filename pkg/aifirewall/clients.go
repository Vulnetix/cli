package aifirewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Scope is where a client's config lives.
type Scope string

const (
	ScopeUser    Scope = "user"    // under $HOME, applies everywhere
	ScopeProject Scope = "project" // under the git root, applies to this repo
)

// Client is a local consumer of an AI API that can be pointed at the gateway.
type Client struct {
	ID          string
	DisplayName string

	// Manual clients have no user-editable config for the API base URL — the
	// setting lives in application state. We detect them and tell the user where
	// to paste the URL; we never write. Fabricating a config file for these would
	// produce a file the application ignores, and a status check that lies.
	Manual bool

	// Wire is the request format this client speaks. A client can only be wired
	// if the gateway proxies this wire for the target provider: Codex speaks the
	// OpenAI Responses API (its config no longer accepts any other wire_api), and
	// Claude Code speaks the Anthropic Messages API. Empty means the client is
	// happy with whatever the provider's SDK speaks.
	Wire string

	// Providers restricts the client to these provider slugs. Empty means every
	// provider that can be wired by environment variable.
	Providers []string

	// DefaultScope is used when --scope is not given.
	DefaultScope Scope
}

var clients = []Client{
	{
		ID: "shell", DisplayName: "Shell environment",
		DefaultScope: ScopeUser,
	},
	{
		ID: "env", DisplayName: "Project env files",
		DefaultScope: ScopeProject,
	},
	{
		ID: "claude-code", DisplayName: "Claude Code",
		Wire: WireMessages, Providers: []string{"anthropic"},
		DefaultScope: ScopeProject,
	},
	{
		ID: "codex", DisplayName: "Codex",
		Wire: WireResponses, Providers: []string{"openai"},
		DefaultScope: ScopeUser,
	},
	{
		ID: "continue", DisplayName: "Continue",
		Wire: WireChat, Providers: []string{"openai"},
		DefaultScope: ScopeUser,
	},
	{
		ID: "aider", DisplayName: "aider",
		Wire: WireChat, Providers: []string{"openai"},
		DefaultScope: ScopeProject,
	},
	{
		ID: "cursor", DisplayName: "Cursor", Manual: true,
		Wire: WireChat, Providers: []string{"openai"},
		DefaultScope: ScopeUser,
	},
	{
		ID: "windsurf", DisplayName: "Windsurf", Manual: true,
		Wire: WireChat, Providers: []string{"openai"},
		DefaultScope: ScopeUser,
	},
}

// Clients returns the client registry.
func Clients() []Client {
	out := make([]Client, len(clients))
	copy(out, clients)
	return out
}

// ClientByID looks up a client by its subcommand name.
func ClientByID(id string) (Client, bool) {
	for _, c := range clients {
		if c.ID == id {
			return c, true
		}
	}
	return Client{}, false
}

// Paths locates a client's config for a scope. home is $HOME; root is the git
// root ("" when not in a repository). The returned paths may not exist.
type Paths struct {
	// Config is the file we write, or would write.
	Config string
	// Secrets is a second file that must hold the API key, when the client cannot
	// read it from the environment. Empty for every client that can.
	Secrets string
	// Detect are additional paths whose presence means the client is installed,
	// even when Config does not exist yet.
	Detect []string
}

// ClientPaths resolves where a client keeps its configuration.
func ClientPaths(c Client, scope Scope, home, root string) Paths {
	switch c.ID {
	case "shell":
		path, _, err := shellConfigPath()
		if err != nil {
			return Paths{}
		}
		return Paths{Config: path}

	case "env":
		if root == "" {
			return Paths{}
		}
		// Only files that already exist are touched, so Config is whichever of
		// these is present; the writer re-checks.
		return Paths{Detect: []string{
			filepath.Join(root, ".env"),
			filepath.Join(root, ".envrc"),
			filepath.Join(root, "Makefile"),
		}}

	case "claude-code":
		dir := filepath.Join(home, ".claude")
		if scope == ScopeProject && root != "" {
			dir = filepath.Join(root, ".claude")
		}
		return Paths{
			Config: filepath.Join(dir, "settings.json"),
			// settings.local.json is git-ignored by convention, which is where a
			// literal key goes when --embed-key is used.
			Secrets: filepath.Join(dir, "settings.local.json"),
			Detect:  []string{dir, filepath.Join(home, ".claude")},
		}

	case "codex":
		dir := filepath.Join(home, ".codex")
		return Paths{Config: filepath.Join(dir, "config.toml"), Detect: []string{dir}}

	case "continue":
		dir := filepath.Join(home, ".continue")
		cfg := filepath.Join(dir, "config.yaml")
		if !exists(cfg) && exists(filepath.Join(dir, "config.json")) {
			cfg = filepath.Join(dir, "config.json")
		}
		return Paths{
			Config: cfg,
			// Continue is an IDE extension: it cannot read the shell environment,
			// and resolves ${{ secrets.X }} from this file. It is the one place a
			// literal key is unavoidable.
			Secrets: filepath.Join(dir, ".env"),
			Detect:  []string{dir},
		}

	case "aider":
		if root == "" {
			return Paths{Config: filepath.Join(home, ".aider.conf.yml")}
		}
		return Paths{
			Config: filepath.Join(root, ".aider.conf.yml"),
			Detect: []string{filepath.Join(home, ".aider.conf.yml")},
		}

	case "cursor":
		return Paths{Detect: []string{
			filepath.Join(home, ".cursor"),
			filepath.Join(root, ".cursor"),
		}}

	case "windsurf":
		return Paths{Detect: []string{
			filepath.Join(home, ".codeium", "windsurf"),
			filepath.Join(home, ".windsurf"),
		}}
	}
	return Paths{}
}

// Installed reports whether a client appears to be present on this machine: its
// config directory exists, or its binary is on PATH.
func Installed(c Client, scope Scope, home, root string) bool {
	p := ClientPaths(c, scope, home, root)
	if p.Config != "" && exists(p.Config) {
		return true
	}
	for _, d := range p.Detect {
		if d != "" && exists(d) {
			return true
		}
	}
	// The shell is always present; a repo always has an environment to configure.
	switch c.ID {
	case "shell":
		return true
	case "env":
		return root != ""
	}
	if bin := binaryName(c.ID); bin != "" {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
	}
	return false
}

func binaryName(clientID string) string {
	switch clientID {
	case "codex":
		return "codex"
	case "aider":
		return "aider"
	case "claude-code":
		return "claude"
	case "cursor":
		return "cursor"
	case "windsurf":
		return "windsurf"
	}
	return ""
}

// SupportsWire reports whether the gateway can serve the wire this client
// speaks, for the given provider. An absent capability advertisement means the
// server is older than this check: assume chat only, and refuse to write a
// config for a client that needs something else, rather than writing one that
// fails at request time with a 404 the user has to reverse-engineer.
func SupportsWire(gw *Gateway, c Client, providerSlug string) (bool, string) {
	if c.Wire == "" || c.Wire == WireChat {
		return true, ""
	}
	if gw == nil || len(gw.WireAPIs) == 0 {
		return false, c.DisplayName + " needs the " + c.Wire + " API, and this server does not advertise the gateway's capabilities — skipping rather than writing a config that would fail at request time"
	}
	for _, w := range gw.WireAPIs[providerSlug] {
		if w == c.Wire {
			return true, ""
		}
	}
	return false, c.DisplayName + " needs the " + c.Wire + " API, which the gateway does not proxy for " + providerSlug + " (it serves: " + strings.Join(gw.WireAPIs[providerSlug], ", ") + ")"
}

// Gateway is the capability advertisement, mirrored from the API response so
// this package does not depend on the vdb client.
type Gateway struct {
	BaseURL  string
	WireAPIs map[string][]string
}

func exists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
