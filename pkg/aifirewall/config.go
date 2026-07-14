package aifirewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/vulnetix/cli/v3/internal/managedfile"
	"gopkg.in/yaml.v3"
)

// Markers fence the AI Firewall's managed blocks. They differ from the Package
// Firewall's on purpose: both write the same shell rc, and each uninstall must
// strip only its own block.
var Markers = managedfile.Markers{
	Start: "# Vulnetix AI Firewall",
	End:   "# End Vulnetix AI Firewall",
}

// providerRef is the name of the Continue/Codex config entry we own. Anything
// with this name is ours to rewrite or remove; anything else in the file is the
// user's and is preserved.
const configEntryPrefix = "vulnetix-"

// Options is everything a writer needs to render a client's config.
type Options struct {
	Gateway string // https://guardrails.vulnetix.com
	OrgUUID string
	APIKey  string // the Vulnetix API key; only written when EmbedKey

	// Targets are the providers to wire, already filtered to those the org has a
	// BYOK key for.
	Targets []Provider

	// Model pins a default model in the agent configs that take one.
	Model string

	// EmbedKey writes the literal API key instead of a reference to
	// $VULNETIX_API_KEY. Opt-in, because it puts a credential in a file.
	EmbedKey bool

	Home  string
	Root  string // git root, "" when not in a repository
	Scope Scope
}

// keyRef is what a config should contain for the API key: a reference to the
// environment variable, unless the caller opted into embedding the literal.
func (o Options) keyRef(syntax string) string {
	if o.EmbedKey && o.APIKey != "" {
		return o.APIKey
	}
	switch syntax {
	case "brace": // .env, Continue
		return "${" + VulnetixKeyEnv + "}"
	default: // shell
		return "$" + VulnetixKeyEnv
	}
}

// BaseURL is the gateway URL for one provider.
func (o Options) BaseURL(slug string) string {
	return GatewayURL(o.Gateway, slug, o.OrgUUID)
}

func shellConfigPath() (path, kind string, err error) {
	return managedfile.ShellConfigPath()
}

// EnvVars renders the environment variables that wire the targeted providers.
//
// A provider with no base-URL variable that any SDK reads still gets an
// informational VULNETIX_AIFW_<P>_BASE_URL: nothing consumes it, but it records
// the gateway URL for that provider so `status` can see the intent and so the
// value is to hand when writing base_url into code. It is deliberately NOT
// named MISTRAL_BASE_URL or similar — a variable that looks like an SDK setting
// but is read by nothing would leave the user believing their traffic was
// proxied when it went straight to the provider.
func EnvVars(o Options, valueSyntax string) []managedfile.KV {
	var out []managedfile.KV
	for _, p := range o.Targets {
		base := o.BaseURL(p.Slug)
		if !p.EnvWired() {
			out = append(out, managedfile.KV{Key: InfoBaseURLEnv(p.Slug), Value: base})
			continue
		}
		for _, key := range p.BaseURLEnv {
			out = append(out, managedfile.KV{Key: key, Value: base})
		}
		out = append(out, managedfile.KV{Key: p.APIKeyEnv, Value: o.keyRef(valueSyntax)})
	}
	return out
}

// EnvKeys is every variable name EnvVars can produce for the targets, which is
// what uninstall must remove.
func EnvKeys(o Options) []string {
	var out []string
	for _, p := range o.Targets {
		if !p.EnvWired() {
			out = append(out, InfoBaseURLEnv(p.Slug))
			continue
		}
		out = append(out, p.BaseURLEnv...)
		out = append(out, p.APIKeyEnv)
	}
	return out
}

// ShellBlock renders the managed block for the user's shell rc.
func ShellBlock(o Options, kind string) string {
	return managedfile.EnvBlock(kind, Markers, EnvVars(o, "shell"))
}

// ShellFile locates the shell rc and renders its block.
func ShellFile(o Options) (path string, block string, err error) {
	path, kind, err := shellConfigPath()
	if err != nil {
		return "", "", err
	}
	return path, ShellBlock(o, kind), nil
}

// ProjectEnvFiles returns the project env files that exist at the git root, with
// the block to splice into each. Files that do not exist are not created: a .env
// this tool invented would not be loaded by anything the project already runs.
func ProjectEnvFiles(o Options) []managedfile.File {
	if o.Root == "" {
		return nil
	}
	var out []managedfile.File
	for _, spec := range []struct {
		name   string
		syntax string
	}{
		{name: ".env", syntax: "brace"},
		{name: ".envrc", syntax: "shell"},
		{name: "Makefile", syntax: "brace"},
	} {
		path := filepath.Join(o.Root, spec.name)
		if !exists(path) {
			continue
		}
		lines := make([]string, 0)
		for _, v := range EnvVars(o, spec.syntax) {
			switch spec.name {
			case ".envrc":
				lines = append(lines, "export "+v.Key+"=\""+v.Value+"\"")
			case "Makefile":
				lines = append(lines, "export "+v.Key+"="+v.Value)
			default: // .env
				lines = append(lines, v.Key+"="+v.Value)
			}
		}
		out = append(out, managedfile.File{Path: path, Content: strings.Join(lines, "\n")})
	}
	return out
}

// CreateProjectEnv renders a .env from scratch, for --create-env.
func CreateProjectEnv(o Options) managedfile.File {
	vars := EnvVars(o, "brace")
	lines := make([]string, 0, len(vars))
	for _, v := range vars {
		lines = append(lines, v.Key+"="+v.Value)
	}
	return managedfile.File{
		Path:    filepath.Join(o.Root, ".env"),
		Content: strings.Join(lines, "\n"),
	}
}

// ClaudeCodeFile writes the Anthropic base URL (and the pinned model) into the
// `env` object of a Claude Code settings.json, folding into whatever else the
// file holds.
//
// The auth token is not written here: settings.json is routinely committed, and
// a credential in it would be published with the repo. It comes from the shell
// block instead — or, with --embed-key, from settings.local.json, which is
// git-ignored by convention.
func ClaudeCodeFile(o Options) (managedfile.File, bool) {
	p, ok := ProviderBySlug("anthropic")
	if !ok || !o.targeting("anthropic") {
		return managedfile.File{}, false
	}
	env := map[string]string{"ANTHROPIC_BASE_URL": o.BaseURL(p.Slug)}
	if o.Model != "" {
		env["ANTHROPIC_MODEL"] = o.Model
	}
	keys := []string{"ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL"}

	paths := ClientPaths(Client{ID: "claude-code"}, o.scope(ScopeProject), o.Home, o.Root)
	return managedfile.File{
		Path:  paths.Config,
		Merge: mergeJSONEnv(env, keys),
		Strip: stripJSONEnv(keys),
	}, true
}

// ClaudeCodeSecretsFile holds the literal token, for --embed-key only.
func ClaudeCodeSecretsFile(o Options) (managedfile.File, bool) {
	if !o.EmbedKey || o.APIKey == "" || !o.targeting("anthropic") {
		return managedfile.File{}, false
	}
	p, _ := ProviderBySlug("anthropic")
	env := map[string]string{p.APIKeyEnv: o.APIKey}
	keys := []string{p.APIKeyEnv}
	paths := ClientPaths(Client{ID: "claude-code"}, o.scope(ScopeProject), o.Home, o.Root)
	return managedfile.File{
		Path:  paths.Secrets,
		Merge: mergeJSONEnv(env, keys),
		Strip: stripJSONEnv(keys),
	}, true
}

// mergeJSONEnv folds keys into the top-level "env" object of a JSON settings
// file, preserving every other key in the document — and every other variable in
// `env` — byte-for-byte where the encoder allows.
func mergeJSONEnv(set map[string]string, _ []string) func(string) (string, error) {
	return func(existing string) (string, error) {
		doc := map[string]json.RawMessage{}
		if strings.TrimSpace(existing) != "" {
			if err := json.Unmarshal([]byte(existing), &doc); err != nil {
				return "", fmt.Errorf("refusing to rewrite a settings file that is not valid JSON: %w", err)
			}
		}
		env := map[string]json.RawMessage{}
		if raw, ok := doc["env"]; ok {
			if err := json.Unmarshal(raw, &env); err != nil {
				return "", fmt.Errorf("refusing to rewrite a settings file whose \"env\" is not an object: %w", err)
			}
		}
		for k, v := range set {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			env[k] = b
		}
		envRaw, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return "", err
		}
		doc["env"] = envRaw
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return "", err
		}
		return string(out) + "\n", nil
	}
}

// stripJSONEnv removes only the variables we set, leaving the rest of `env` and
// the rest of the document alone. An `env` we emptied is removed entirely, so an
// uninstall leaves no vestigial key behind.
func stripJSONEnv(keys []string) func(string, string) (string, bool) {
	return func(_, existing string) (string, bool) {
		doc := map[string]json.RawMessage{}
		if json.Unmarshal([]byte(existing), &doc) != nil {
			return existing, false
		}
		raw, ok := doc["env"]
		if !ok {
			return existing, false
		}
		env := map[string]json.RawMessage{}
		if json.Unmarshal(raw, &env) != nil {
			return existing, false
		}
		changed := false
		for _, k := range keys {
			if _, ok := env[k]; ok {
				delete(env, k)
				changed = true
			}
		}
		if !changed {
			return existing, false
		}
		if len(env) == 0 {
			delete(doc, "env")
		} else {
			envRaw, err := json.MarshalIndent(env, "", "  ")
			if err != nil {
				return existing, false
			}
			doc["env"] = envRaw
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return existing, false
		}
		return string(out) + "\n", true
	}
}

// CodexProviderName is the [model_providers.<name>] table we own.
const CodexProviderName = configEntryPrefix + "openai"

// CodexFile folds a model provider into ~/.codex/config.toml.
//
// The file is edited as text, never round-tripped through a TOML encoder: the
// encoder drops comments and reorders tables, so a user with a commented,
// hand-ordered config would get it silently rearranged. The result is parsed
// before it is written, so we never leave behind a config Codex cannot load.
func CodexFile(o Options) (managedfile.File, bool) {
	if !o.targeting("openai") {
		return managedfile.File{}, false
	}
	base := o.BaseURL("openai")
	block := strings.Join([]string{
		"[model_providers." + CodexProviderName + "]",
		`name = "Vulnetix AI Firewall (openai)"`,
		`base_url = "` + base + `"`,
		`env_key = "` + VulnetixKeyEnv + `"`,
		`wire_api = "` + WireResponses + `"`,
	}, "\n")

	root := map[string]string{"model_provider": `"` + CodexProviderName + `"`}
	if o.Model != "" {
		root["model"] = `"` + o.Model + `"`
	}

	paths := ClientPaths(Client{ID: "codex"}, ScopeUser, o.Home, o.Root)
	return managedfile.File{
		Path: paths.Config,
		Merge: func(existing string) (string, error) {
			next := managedfile.Upsert(existing, managedfile.Block(Markers, block), Markers)
			next = upsertTOMLRootKeys(next, root)
			var probe map[string]any
			if _, err := toml.Decode(next, &probe); err != nil {
				return "", fmt.Errorf("refusing to write a config.toml that does not parse: %w", err)
			}
			return next, nil
		},
		Strip: func(_, existing string) (string, bool) {
			next, changed := managedfile.Remove(existing, Markers)
			next2, changed2 := removeTOMLRootKeys(next, CodexProviderName)
			return next2, changed || changed2
		},
	}, true
}

// upsertTOMLRootKeys sets top-level scalars line-by-line, before the first
// table header (where root keys must live), leaving comments intact.
func upsertTOMLRootKeys(existing string, set map[string]string) string {
	lines := strings.Split(existing, "\n")
	seen := map[string]bool{}
	firstTable := len(lines)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && firstTable == len(lines) {
			firstTable = i
		}
		for key, val := range set {
			if firstTable <= i {
				continue
			}
			if tomlRootKey(trimmed) == key {
				lines[i] = key + " = " + val
				seen[key] = true
			}
		}
	}
	var add []string
	for key, val := range set {
		if !seen[key] {
			add = append(add, key+" = "+val)
		}
	}
	if len(add) == 0 {
		return strings.Join(lines, "\n")
	}
	sortStrings(add)

	// Root keys must precede the first table, but the lines immediately above that
	// table are usually its comment. Inserting directly against the header would
	// leave the user's comment describing our key instead of their table, so back
	// up over the comment block first.
	at := firstTable
	for at > 0 {
		prev := strings.TrimSpace(lines[at-1])
		if prev == "" || strings.HasPrefix(prev, "#") {
			at--
			continue
		}
		break
	}

	out := append([]string{}, lines[:at]...)
	out = append(out, add...)
	out = append(out, lines[at:]...)
	return strings.Join(out, "\n")
}

// removeTOMLRootKeys drops the root scalars we set, but only when they still
// point at our provider — a user who has since pointed model_provider at
// something else keeps their setting.
func removeTOMLRootKeys(existing string, ours string) (string, bool) {
	lines := strings.Split(existing, "\n")
	var kept []string
	changed := false
	inTable := false
	dropModel := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inTable = true
		}
		if !inTable && tomlRootKey(trimmed) == "model_provider" {
			if strings.Contains(trimmed, ours) {
				changed = true
				dropModel = true
				continue
			}
		}
		kept = append(kept, line)
	}
	if !dropModel {
		return strings.Join(kept, "\n"), changed
	}
	// The pinned model only made sense alongside our provider.
	var final []string
	inTable = false
	for _, line := range kept {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inTable = true
		}
		if !inTable && tomlRootKey(trimmed) == "model" {
			changed = true
			continue
		}
		final = append(final, line)
	}
	return strings.Join(final, "\n"), changed
}

func tomlRootKey(line string) string {
	if i := strings.Index(line, "="); i > 0 {
		return strings.TrimSpace(line[:i])
	}
	return ""
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ContinueModelName is the models[] entry we own.
const ContinueModelName = "Vulnetix AI Firewall (openai)"

// ContinueFile folds a model entry into ~/.continue/config.yaml.
//
// Edited through the yaml Node API so comments and key order survive; a
// map[string]any round-trip would silently discard both.
func ContinueFile(o Options) (managedfile.File, bool) {
	if !o.targeting("openai") {
		return managedfile.File{}, false
	}
	paths := ClientPaths(Client{ID: "continue"}, ScopeUser, o.Home, o.Root)
	if strings.HasSuffix(paths.Config, ".json") {
		return continueJSONFile(o, paths.Config), true
	}
	model := o.Model
	if model == "" {
		model = "gpt-4o"
	}
	entry := map[string]any{
		"name":     ContinueModelName,
		"provider": "openai",
		"model":    model,
		"apiBase":  o.BaseURL("openai"),
		// Continue resolves this from ~/.continue/.env, not the shell.
		"apiKey": "${{ secrets." + VulnetixKeyEnv + " }}",
		"roles":  []any{"chat", "edit", "apply"},
	}
	return managedfile.File{
		Path:  paths.Config,
		Merge: mergeYAMLListEntry("models", "name", ContinueModelName, entry),
		Strip: stripYAMLListEntry("models", "name", ContinueModelName),
	}, true
}

func continueJSONFile(o Options, path string) managedfile.File {
	model := o.Model
	if model == "" {
		model = "gpt-4o"
	}
	entry := map[string]any{
		"title":    ContinueModelName,
		"provider": "openai",
		"model":    model,
		"apiBase":  o.BaseURL("openai"),
		"apiKey":   "${{ secrets." + VulnetixKeyEnv + " }}",
	}
	return managedfile.File{
		Path:  path,
		Merge: mergeJSONListEntry("models", "title", ContinueModelName, entry),
		Strip: stripJSONListEntry("models", "title", ContinueModelName),
	}
}

// ContinueSecretsFile is the one place a literal key is unavoidable: Continue
// runs inside an IDE and cannot read the shell environment.
func ContinueSecretsFile(o Options) (managedfile.File, bool) {
	if o.APIKey == "" || !o.targeting("openai") {
		return managedfile.File{}, false
	}
	paths := ClientPaths(Client{ID: "continue"}, ScopeUser, o.Home, o.Root)
	return managedfile.File{
		Path:    paths.Secrets,
		Content: VulnetixKeyEnv + "=" + o.APIKey,
	}, true
}

// AiderFile writes the OpenAI base URL and default model into .aider.conf.yml.
// The key is not written: aider reads OPENAI_API_KEY from the environment, which
// the shell and project-env writers already set.
func AiderFile(o Options) (managedfile.File, bool) {
	if !o.targeting("openai") {
		return managedfile.File{}, false
	}
	set := map[string]any{"openai-api-base": o.BaseURL("openai")}
	keys := []string{"openai-api-base"}
	if o.Model != "" {
		set["model"] = "openai/" + strings.TrimPrefix(o.Model, "openai/")
		keys = append(keys, "model")
	}
	paths := ClientPaths(Client{ID: "aider"}, o.scope(ScopeProject), o.Home, o.Root)
	return managedfile.File{
		Path:  paths.Config,
		Merge: mergeYAMLKeys(set),
		Strip: stripYAMLKeys(keys),
	}, true
}

// HasTarget reports whether a provider is among those being wired.
func (o Options) HasTarget(slug string) bool { return o.targeting(slug) }

// ScopeOrDefault is the requested scope, or the client's default.
func (o Options) ScopeOrDefault(def Scope) Scope { return o.scope(def) }

func (o Options) targeting(slug string) bool {
	for _, p := range o.Targets {
		if p.Slug == slug {
			return true
		}
	}
	return false
}

func (o Options) scope(def Scope) Scope {
	if o.Scope == "" {
		return def
	}
	return o.Scope
}

// --- YAML helpers (Node API: comments and key order survive) ---

func loadYAMLDoc(existing string) (*yaml.Node, *yaml.Node, error) {
	var doc yaml.Node
	if strings.TrimSpace(existing) == "" {
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
		return &doc, root, nil
	}
	if err := yaml.Unmarshal([]byte(existing), &doc); err != nil {
		return nil, nil, fmt.Errorf("refusing to rewrite a config that is not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{root}
		return &doc, root, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("refusing to rewrite a config whose top level is not a mapping")
	}
	return &doc, root, nil
}

func renderYAMLDoc(doc *yaml.Node) (string, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func mapGet(root *yaml.Node, key string) (*yaml.Node, int) {
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i+1], i
		}
	}
	return nil, -1
}

func mapSet(root *yaml.Node, key string, val *yaml.Node) {
	if _, i := mapGet(root, key); i >= 0 {
		root.Content[i+1] = val
		return
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		val,
	)
}

func mapDelete(root *yaml.Node, key string) bool {
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			root.Content = append(root.Content[:i], root.Content[i+2:]...)
			return true
		}
	}
	return false
}

func mergeYAMLKeys(set map[string]any) func(string) (string, error) {
	return func(existing string) (string, error) {
		doc, root, err := loadYAMLDoc(existing)
		if err != nil {
			return "", err
		}
		for k, v := range set {
			node := &yaml.Node{}
			if err := node.Encode(v); err != nil {
				return "", err
			}
			mapSet(root, k, node)
		}
		return renderYAMLDoc(doc)
	}
}

func stripYAMLKeys(keys []string) func(string, string) (string, bool) {
	return func(_, existing string) (string, bool) {
		doc, root, err := loadYAMLDoc(existing)
		if err != nil {
			return existing, false
		}
		changed := false
		for _, k := range keys {
			if mapDelete(root, k) {
				changed = true
			}
		}
		if !changed {
			return existing, false
		}
		out, err := renderYAMLDoc(doc)
		if err != nil {
			return existing, false
		}
		return out, true
	}
}

// mergeYAMLListEntry upserts one entry of a list of mappings, matched on idKey ==
// idVal. Every other entry in the list is left exactly as it was.
func mergeYAMLListEntry(listKey, idKey, idVal string, entry map[string]any) func(string) (string, error) {
	return func(existing string) (string, error) {
		doc, root, err := loadYAMLDoc(existing)
		if err != nil {
			return "", err
		}
		node := &yaml.Node{}
		if err := node.Encode(entry); err != nil {
			return "", err
		}
		list, _ := mapGet(root, listKey)
		if list == nil || list.Kind != yaml.SequenceNode {
			list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			mapSet(root, listKey, list)
		}
		for i, item := range list.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			if v, _ := mapGet(item, idKey); v != nil && v.Value == idVal {
				list.Content[i] = node
				return renderYAMLDoc(doc)
			}
		}
		list.Content = append(list.Content, node)
		return renderYAMLDoc(doc)
	}
}

func stripYAMLListEntry(listKey, idKey, idVal string) func(string, string) (string, bool) {
	return func(_, existing string) (string, bool) {
		doc, root, err := loadYAMLDoc(existing)
		if err != nil {
			return existing, false
		}
		list, _ := mapGet(root, listKey)
		if list == nil || list.Kind != yaml.SequenceNode {
			return existing, false
		}
		changed := false
		var kept []*yaml.Node
		for _, item := range list.Content {
			if item.Kind == yaml.MappingNode {
				if v, _ := mapGet(item, idKey); v != nil && v.Value == idVal {
					changed = true
					continue
				}
			}
			kept = append(kept, item)
		}
		if !changed {
			return existing, false
		}
		if len(kept) == 0 {
			mapDelete(root, listKey)
		} else {
			list.Content = kept
		}
		out, err := renderYAMLDoc(doc)
		if err != nil {
			return existing, false
		}
		return out, true
	}
}

// --- JSON list helpers (legacy Continue config.json) ---

func mergeJSONListEntry(listKey, idKey, idVal string, entry map[string]any) func(string) (string, error) {
	return func(existing string) (string, error) {
		doc := map[string]json.RawMessage{}
		if strings.TrimSpace(existing) != "" {
			if err := json.Unmarshal([]byte(existing), &doc); err != nil {
				return "", fmt.Errorf("refusing to rewrite a config that is not valid JSON: %w", err)
			}
		}
		var list []map[string]any
		if raw, ok := doc[listKey]; ok {
			if err := json.Unmarshal(raw, &list); err != nil {
				return "", fmt.Errorf("refusing to rewrite a config whose %q is not a list: %w", listKey, err)
			}
		}
		replaced := false
		for i, item := range list {
			if s, _ := item[idKey].(string); s == idVal {
				list[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			list = append(list, entry)
		}
		raw, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return "", err
		}
		doc[listKey] = raw
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return "", err
		}
		return string(out) + "\n", nil
	}
}

func stripJSONListEntry(listKey, idKey, idVal string) func(string, string) (string, bool) {
	return func(_, existing string) (string, bool) {
		doc := map[string]json.RawMessage{}
		if json.Unmarshal([]byte(existing), &doc) != nil {
			return existing, false
		}
		raw, ok := doc[listKey]
		if !ok {
			return existing, false
		}
		var list []map[string]any
		if json.Unmarshal(raw, &list) != nil {
			return existing, false
		}
		var kept []map[string]any
		changed := false
		for _, item := range list {
			if s, _ := item[idKey].(string); s == idVal {
				changed = true
				continue
			}
			kept = append(kept, item)
		}
		if !changed {
			return existing, false
		}
		if len(kept) == 0 {
			delete(doc, listKey)
		} else {
			b, err := json.MarshalIndent(kept, "", "  ")
			if err != nil {
				return existing, false
			}
			doc[listKey] = b
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return existing, false
		}
		return string(out) + "\n", true
	}
}

// SecretSafe reports whether it is safe to write a literal credential to path:
// the file must be covered by the repository's ignore rules. A key written to a
// tracked file is a key that gets committed.
func SecretSafe(path string) error {
	if managedfile.GitIgnored(path) {
		return nil
	}
	if _, err := managedfile.GitRoot(); err != nil {
		// Not in a repository: nothing can be committed from here.
		return nil
	}
	return fmt.Errorf("%s is not git-ignored; writing the API key there would commit it. Add it to .gitignore, or drop --embed-key and let the client read $%s from the environment", filepath.Base(path), VulnetixKeyEnv)
}

// Chmod600 tightens a file that holds a credential.
func Chmod600(path string) error {
	return os.Chmod(path, 0600)
}
