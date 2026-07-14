package aifirewall

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// State is what we found on disk for one client.
type State string

const (
	StateWired State = "wired" // points at this org's gateway
	// StateElsewhere is the finding that matters: the client is configured with a
	// base URL, and it is not ours. Traffic that the user believes is being
	// screened is going straight to the provider.
	StateElsewhere State = "points elsewhere"
	StateNotWired  State = "not wired"
	StateManual    State = "manual"        // no config file exists to write
	StateAbsent    State = "not installed" // the client is not on this machine
)

// Detected is one client's local configuration.
type Detected struct {
	Client  Client
	Scope   Scope
	Path    string
	State   State
	BaseURL string // whatever base URL the client is configured with, if any
	Model   string // the model it has pinned, if any
	// KeyEnvSet records, per provider API-key variable, whether the environment
	// holds a value. Only names and set/unset are recorded — never the value.
	KeyEnvSet map[string]bool
	// WiredProviders holds the providers this client actually points at the
	// gateway for. The shell can be wired for one provider and not another, and a
	// provider nobody has wired must not produce findings about its key.
	WiredProviders map[string]bool
}

// Detect inspects every client and reports how it is configured.
func Detect(o Options, gatewayHost string) []Detected {
	var out []Detected
	for _, c := range Clients() {
		scope := o.scope(c.DefaultScope)
		d := Detected{Client: c, Scope: scope, State: StateAbsent}

		if !Installed(c, scope, o.Home, o.Root) {
			out = append(out, d)
			continue
		}

		p := ClientPaths(c, scope, o.Home, o.Root)
		d.Path = p.Config

		switch c.ID {
		case "shell":
			d.Path, d.BaseURL, d.State, d.KeyEnvSet, d.WiredProviders = detectShell(gatewayHost)
		case "env":
			d.Path, d.BaseURL, d.State = detectProjectEnv(o, gatewayHost)
		case "claude-code":
			d.BaseURL, d.Model = readClaudeCode(p.Config)
			d.State = classify(d.BaseURL, gatewayHost)
		case "codex":
			d.BaseURL, d.Model = readCodex(p.Config)
			d.State = classify(d.BaseURL, gatewayHost)
		case "continue":
			d.BaseURL, d.Model = readContinue(p.Config)
			d.State = classify(d.BaseURL, gatewayHost)
		case "aider":
			d.BaseURL, d.Model = readAider(p.Config)
			d.State = classify(d.BaseURL, gatewayHost)
		case "cursor", "windsurf":
			// The base URL lives in application state, not a file we can read.
			// Reporting these as "not wired" would be a guess; "manual" is the truth.
			d.State = StateManual
		}
		out = append(out, d)
	}
	return out
}

func classify(baseURL, gatewayHost string) State {
	switch {
	case baseURL == "":
		return StateNotWired
	case gatewayHost != "" && strings.Contains(baseURL, gatewayHost):
		return StateWired
	default:
		return StateElsewhere
	}
}

// detectShell reads the process environment rather than parsing the rc file: the
// rc file is what we wrote, but the environment is what the SDKs will actually
// see, which is the thing that decides whether traffic is proxied.
func detectShell(gatewayHost string) (path, baseURL string, state State, keys, wiredProviders map[string]bool) {
	path, _, err := shellConfigPath()
	if err != nil {
		path = ""
	}
	keys = map[string]bool{}
	wiredProviders = map[string]bool{}
	state = StateNotWired

	for _, p := range Providers() {
		if p.APIKeyEnv != "" {
			keys[p.APIKeyEnv] = os.Getenv(p.APIKeyEnv) != ""
		}
		for _, envKey := range p.BaseURLEnv {
			v := os.Getenv(envKey)
			if v == "" {
				continue
			}
			if baseURL == "" {
				baseURL = v
			}
			switch classify(v, gatewayHost) {
			case StateWired:
				wiredProviders[p.Slug] = true
				if state != StateElsewhere {
					state = StateWired
				}
			case StateElsewhere:
				// One provider pointing away from the gateway is enough to matter:
				// report the whole shell as bypassing, not the optimistic reading.
				state = StateElsewhere
				baseURL = v
			}
		}
	}
	return path, baseURL, state, keys, wiredProviders
}

func detectProjectEnv(o Options, gatewayHost string) (path, baseURL string, state State) {
	for _, f := range ProjectEnvFiles(o) {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}
		body := string(data)
		for _, p := range Providers() {
			for _, envKey := range p.BaseURLEnv {
				if v := envAssignment(body, envKey); v != "" {
					s := classify(v, gatewayHost)
					if s == StateElsewhere {
						return f.Path, v, StateElsewhere
					}
					if path == "" {
						path, baseURL, state = f.Path, v, s
					}
				}
			}
		}
	}
	if path == "" {
		return "", "", StateNotWired
	}
	return path, baseURL, state
}

var envLineRe = regexp.MustCompile(`(?m)^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*"?([^"\n#]*)"?`)

func envAssignment(body, key string) string {
	for _, m := range envLineRe.FindAllStringSubmatch(body, -1) {
		if m[1] == key {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

func readClaudeCode(path string) (baseURL, model string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return "", ""
	}
	return doc.Env["ANTHROPIC_BASE_URL"], doc.Env["ANTHROPIC_MODEL"]
}

func readCodex(path string) (baseURL, model string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var doc struct {
		Model          string `toml:"model"`
		ModelProvider  string `toml:"model_provider"`
		ModelProviders map[string]struct {
			BaseURL string `toml:"base_url"`
		} `toml:"model_providers"`
	}
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return "", ""
	}
	if doc.ModelProvider == "" {
		return "", doc.Model
	}
	return doc.ModelProviders[doc.ModelProvider].BaseURL, doc.Model
}

func readContinue(path string) (baseURL, model string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	type entry struct {
		Name    string `yaml:"name" json:"name"`
		Title   string `yaml:"title" json:"title"`
		Model   string `yaml:"model" json:"model"`
		APIBase string `yaml:"apiBase" json:"apiBase"`
	}
	var doc struct {
		Models []entry `yaml:"models" json:"models"`
	}
	if strings.HasSuffix(path, ".json") {
		if json.Unmarshal(data, &doc) != nil {
			return "", ""
		}
	} else if yaml.Unmarshal(data, &doc) != nil {
		return "", ""
	}
	// Prefer the entry we own; fall back to the first that sets a base URL, so a
	// user pointing Continue at some other proxy is still reported.
	for _, e := range doc.Models {
		if e.Name == ContinueModelName || e.Title == ContinueModelName {
			return e.APIBase, e.Model
		}
	}
	for _, e := range doc.Models {
		if e.APIBase != "" {
			return e.APIBase, e.Model
		}
	}
	return "", ""
}

func readAider(path string) (baseURL, model string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var doc struct {
		OpenAIAPIBase string `yaml:"openai-api-base"`
		Model         string `yaml:"model"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return "", ""
	}
	return doc.OpenAIAPIBase, doc.Model
}
