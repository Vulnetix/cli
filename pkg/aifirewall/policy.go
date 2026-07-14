package aifirewall

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPolicyPath is where the declarative policy lives in a repository.
const DefaultPolicyPath = ".vulnetix/ai-firewall.yaml"

// PolicyAPIVersion / PolicyKind identify the document.
const (
	PolicyAPIVersion = "vulnetix.com/v1"
	PolicyKind       = "AiFirewallPolicy"
)

// PolicyFile is the declarative form of the org's AI Firewall policy.
type PolicyFile struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   PolicyMetadata `yaml:"metadata,omitempty"`
	Spec       PolicySpec     `yaml:"spec"`
}

type PolicyMetadata struct {
	// Org guards against applying one org's policy to another — the commonest way
	// to do real damage with a config file. Apply refuses on a mismatch.
	Org string `yaml:"org,omitempty"`
}

type PolicySpec struct {
	// Prune lets apply delete server objects this file does not mention. Off by
	// default: a CLI apply must not silently destroy guardrails someone created
	// in the dashboard.
	Prune bool `yaml:"prune,omitempty"`

	Settings   *SettingsSpec   `yaml:"settings,omitempty"`
	Baseline   *BaselineSpec   `yaml:"baseline,omitempty"`
	Providers  []ProviderSpec  `yaml:"providers,omitempty"`
	Models     []ModelSpec     `yaml:"models,omitempty"`
	Guardrails []GuardrailSpec `yaml:"guardrails,omitempty"`
}

type SettingsSpec struct {
	LogsEnabled *bool `yaml:"logsEnabled,omitempty"`
}

type BaselineSpec struct {
	Enabled bool     `yaml:"enabled"`
	Ref     string   `yaml:"ref,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"` // baseline guardrail ids
}

type ProviderSpec struct {
	Slug   string         `yaml:"slug"`
	Action string         `yaml:"action"` // allow | deny | default
	Key    *KeySourceSpec `yaml:"key,omitempty"`
}

// KeySourceSpec names where the provider key comes from. Never the key itself: a
// credential in a file that lives in a repository is a credential that gets
// committed.
type KeySourceSpec struct {
	FromEnv  string `yaml:"fromEnv,omitempty"`
	FromFile string `yaml:"fromFile,omitempty"`
}

type ModelSpec struct {
	Slug        string `yaml:"slug"`
	Provider    string `yaml:"provider,omitempty"`
	AnyProvider bool   `yaml:"anyProvider,omitempty"`
	Action      string `yaml:"action"` // allow | deny
}

type GuardrailSpec struct {
	Name       string `yaml:"name"`
	BaselineID string `yaml:"baselineId,omitempty"`
	RuleType   string `yaml:"ruleType"`
	Action     string `yaml:"action"`
	Pattern    string `yaml:"pattern"`
	Priority   int    `yaml:"priority,omitempty"`
	Enabled    *bool  `yaml:"enabled,omitempty"`
}

// IsEnabled defaults to true: a guardrail you wrote down is one you meant.
func (g GuardrailSpec) IsEnabled() bool {
	return g.Enabled == nil || *g.Enabled
}

var (
	validProviderActions  = map[string]bool{"allow": true, "deny": true, "default": true}
	validModelActions     = map[string]bool{"allow": true, "deny": true}
	validRuleTypes        = map[string]bool{"blocked_pattern": true, "max_messages": true, "pii_redact": true}
	validGuardrailActions = map[string]bool{"block": true, "redact": true, "flag": true}
)

// LoadPolicyFile reads and validates a policy document.
func LoadPolicyFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := pf.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &pf, nil
}

// Validate rejects a document the gateway would refuse, or silently misapply.
func (pf *PolicyFile) Validate() error {
	if pf.APIVersion != PolicyAPIVersion {
		return fmt.Errorf("apiVersion must be %q, got %q", PolicyAPIVersion, pf.APIVersion)
	}
	if pf.Kind != PolicyKind {
		return fmt.Errorf("kind must be %q, got %q", PolicyKind, pf.Kind)
	}

	for _, p := range pf.Spec.Providers {
		if p.Slug == "" {
			return fmt.Errorf("providers: slug is required")
		}
		if !validProviderActions[p.Action] {
			return fmt.Errorf("providers[%s]: action must be allow, deny, or default", p.Slug)
		}
		if p.Key != nil && p.Key.FromEnv == "" && p.Key.FromFile == "" {
			return fmt.Errorf("providers[%s].key: set fromEnv or fromFile", p.Slug)
		}
	}

	for _, m := range pf.Spec.Models {
		if m.Slug == "" {
			return fmt.Errorf("models: slug is required")
		}
		if !validModelActions[m.Action] {
			return fmt.Errorf("models[%s]: action must be allow or deny", m.Slug)
		}
		if (m.Provider == "") == !m.AnyProvider {
			return fmt.Errorf("models[%s]: set exactly one of provider or anyProvider", m.Slug)
		}
	}

	// Guardrails are reconciled by name, so a duplicate name makes the desired
	// state ambiguous — refuse rather than pick one arbitrarily.
	seen := map[string]bool{}
	for _, g := range pf.Spec.Guardrails {
		if g.Name == "" {
			return fmt.Errorf("guardrails: name is required")
		}
		if seen[g.Name] {
			return fmt.Errorf("guardrails[%s]: duplicate name — guardrails are reconciled by name, so names must be unique", g.Name)
		}
		seen[g.Name] = true
		if err := ValidateGuardrail(g.Name, g.RuleType, g.Action, g.Pattern); err != nil {
			return err
		}
	}
	return nil
}

// ValidateGuardrail checks one rule against what the gateway can enforce.
func ValidateGuardrail(name, ruleType, action, pattern string) error {
	if !validRuleTypes[ruleType] {
		return fmt.Errorf("guardrails[%s]: ruleType must be blocked_pattern, max_messages, or pii_redact", name)
	}
	if !validGuardrailActions[action] {
		return fmt.Errorf("guardrails[%s]: action must be block, redact, or flag", name)
	}
	switch ruleType {
	case "max_messages":
		n, err := strconv.Atoi(strings.TrimSpace(pattern))
		if err != nil || n <= 0 {
			return fmt.Errorf("guardrails[%s]: max_messages needs a positive integer pattern, got %q", name, pattern)
		}
	case "blocked_pattern":
		if strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("guardrails[%s]: blocked_pattern needs a pattern", name)
		}
		if err := compileRE2(name, pattern); err != nil {
			return err
		}
	case "pii_redact":
		// An empty pattern selects the built-in email/card/SSN/phone detectors.
		if strings.TrimSpace(pattern) != "" {
			if err := compileRE2(name, pattern); err != nil {
				return err
			}
		}
	}
	return nil
}

// compileRE2 rejects a pattern the gateway cannot run. A rule with a bad pattern
// is skipped at request time, so it sits in the dashboard looking enforced while
// enforcing nothing — catching it here is the whole point.
func compileRE2(name, pattern string) error {
	if _, err := regexp.Compile(pattern); err != nil {
		msg := fmt.Sprintf("guardrails[%s]: pattern does not compile: %v", name, err)
		if strings.Contains(pattern, "(?=") || strings.Contains(pattern, "(?!") || strings.Contains(pattern, "(?<") {
			msg += "\n  Go uses RE2, which has no lookahead or lookbehind. Drop it — `orgUuid=\\S+` blocks the same requests as `(?<=orgUuid=)\\S+`."
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// --- planning ---

// Op is what a Change does to the server.
type Op string

const (
	OpCreate Op = "create"
	OpUpdate Op = "update"
	OpDelete Op = "delete"
	OpDrift  Op = "drift" // present on the server, absent from the file, not pruned
)

// Kind is which policy object a Change touches.
type Kind string

const (
	KindGuardrail Kind = "guardrail"
	KindModel     Kind = "model"
	KindProvider  Kind = "provider"
	KindKey       Kind = "key"
	KindSettings  Kind = "settings"
)

// Change is one server mutation apply intends to make.
type Change struct {
	Kind   Kind   `json:"kind"`
	Op     Op     `json:"op"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`

	// Populated for execution.
	Guardrail *GuardrailSpec `json:"-"`
	Model     *ModelSpec     `json:"-"`
	Provider  *ProviderSpec  `json:"-"`
	UUID      string         `json:"-"`
	Enable    *bool          `json:"-"`
}

// ServerState is the current policy, in the shape the planner needs.
type ServerState struct {
	Providers   map[string]string // slug -> action ("" = default)
	HasKey      map[string]bool
	Models      map[string]string // "provider/model" -> action
	Guardrails  map[string]ServerGuardrail
	LogsEnabled bool
}

type ServerGuardrail struct {
	UUID     string
	RuleType string
	Action   string
	Pattern  string
	Priority int
	Enabled  bool
}

// Plan diffs desired against current and returns the changes in execution order.
//
// Guardrails go first, then models, then providers, then keys, then settings. A
// policy that is being tightened must never pass through a state where a provider
// is enabled and the guardrails that constrain it are not yet in place.
func Plan(desired PolicyFile, server ServerState) []Change {
	var changes []Change

	// Guardrails, keyed by name.
	for _, g := range desired.Spec.Guardrails {
		cur, exists := server.Guardrails[g.Name]
		if !exists {
			g := g
			changes = append(changes, Change{
				Kind: KindGuardrail, Op: OpCreate, Target: g.Name,
				Detail:    fmt.Sprintf("%s / %s, priority %d", g.RuleType, g.Action, g.Priority),
				Guardrail: &g,
			})
			continue
		}
		if cur.RuleType != g.RuleType || cur.Action != g.Action || cur.Pattern != g.Pattern ||
			cur.Priority != g.Priority || cur.Enabled != g.IsEnabled() {
			g := g
			changes = append(changes, Change{
				Kind: KindGuardrail, Op: OpUpdate, Target: g.Name,
				Detail:    guardrailDiff(cur, g),
				Guardrail: &g, UUID: cur.UUID,
			})
		}
	}
	if desired.Spec.Prune {
		for name, cur := range server.Guardrails {
			if !hasGuardrail(desired.Spec.Guardrails, name) {
				changes = append(changes, Change{
					Kind: KindGuardrail, Op: OpDelete, Target: name, UUID: cur.UUID,
				})
			}
		}
	} else {
		for name := range server.Guardrails {
			if !hasGuardrail(desired.Spec.Guardrails, name) {
				changes = append(changes, Change{
					Kind: KindGuardrail, Op: OpDrift, Target: name,
					Detail: "on the server, not in this file (pass --prune to delete)",
				})
			}
		}
	}

	// Models, keyed by provider+slug. anyProvider is expanded server-side, so it
	// is planned as a single change and its effect is not diffable here.
	for _, m := range desired.Spec.Models {
		m := m
		if m.AnyProvider {
			changes = append(changes, Change{
				Kind: KindModel, Op: OpUpdate, Target: m.Slug,
				Detail: m.Action + " across every provider listing this model",
				Model:  &m,
			})
			continue
		}
		key := m.Provider + "/" + m.Slug
		if server.Models[key] == m.Action {
			continue
		}
		op := OpCreate
		if _, ok := server.Models[key]; ok {
			op = OpUpdate
		}
		changes = append(changes, Change{
			Kind: KindModel, Op: op, Target: key,
			Detail: m.Action, Model: &m,
		})
	}

	// Providers.
	for _, p := range desired.Spec.Providers {
		p := p
		want := p.Action
		if want == "default" {
			want = ""
		}
		if server.Providers[p.Slug] != want {
			changes = append(changes, Change{
				Kind: KindProvider, Op: OpUpdate, Target: p.Slug,
				Detail: p.Action, Provider: &p,
			})
		}
		if p.Key != nil {
			src := p.Key.FromEnv
			if src == "" {
				src = p.Key.FromFile
			}
			changes = append(changes, Change{
				Kind: KindKey, Op: OpUpdate, Target: p.Slug,
				Detail: "from " + src, Provider: &p,
			})
		}
	}

	// Settings.
	if s := desired.Spec.Settings; s != nil && s.LogsEnabled != nil && *s.LogsEnabled != server.LogsEnabled {
		v := *s.LogsEnabled
		changes = append(changes, Change{
			Kind: KindSettings, Op: OpUpdate, Target: "logsEnabled",
			Detail: fmt.Sprintf("%v", v), Enable: &v,
		})
	}

	sortChanges(changes)
	return changes
}

// sortChanges puts the changes in execution order, stably within each kind.
func sortChanges(changes []Change) {
	order := map[Kind]int{
		KindGuardrail: 0, KindModel: 1, KindProvider: 2, KindKey: 3, KindSettings: 4,
	}
	sort.SliceStable(changes, func(i, j int) bool {
		return order[changes[i].Kind] < order[changes[j].Kind]
	})
}

func hasGuardrail(gs []GuardrailSpec, name string) bool {
	for _, g := range gs {
		if g.Name == name {
			return true
		}
	}
	return false
}

func guardrailDiff(cur ServerGuardrail, want GuardrailSpec) string {
	var parts []string
	if cur.RuleType != want.RuleType {
		parts = append(parts, fmt.Sprintf("ruleType %s -> %s", cur.RuleType, want.RuleType))
	}
	if cur.Action != want.Action {
		parts = append(parts, fmt.Sprintf("action %s -> %s", cur.Action, want.Action))
	}
	if cur.Pattern != want.Pattern {
		parts = append(parts, "pattern changed")
	}
	if cur.Priority != want.Priority {
		parts = append(parts, fmt.Sprintf("priority %d -> %d", cur.Priority, want.Priority))
	}
	if cur.Enabled != want.IsEnabled() {
		parts = append(parts, fmt.Sprintf("enabled %v -> %v", cur.Enabled, want.IsEnabled()))
	}
	return strings.Join(parts, ", ")
}

// Mutating reports whether the plan actually changes anything on the server.
func Mutating(changes []Change) []Change {
	var out []Change
	for _, c := range changes {
		if c.Op != OpDrift {
			out = append(out, c)
		}
	}
	return out
}

// --- export ---

// Export renders the server's current policy as a policy file. It never writes a
// key: the server does not return one, and a file in a repository is the last
// place a credential should be.
func Export(org string, server ServerState, providerCatalog []string) ([]byte, error) {
	pf := PolicyFile{
		APIVersion: PolicyAPIVersion,
		Kind:       PolicyKind,
		Metadata:   PolicyMetadata{Org: org},
		Spec: PolicySpec{
			Settings: &SettingsSpec{LogsEnabled: boolPtr(server.LogsEnabled)},
		},
	}

	slugs := append([]string{}, providerCatalog...)
	sort.Strings(slugs)
	for _, slug := range slugs {
		action := server.Providers[slug]
		if action == "" {
			continue // default-allow: nothing to record
		}
		pf.Spec.Providers = append(pf.Spec.Providers, ProviderSpec{Slug: slug, Action: action})
	}

	var modelKeys []string
	for k := range server.Models {
		modelKeys = append(modelKeys, k)
	}
	sort.Strings(modelKeys)
	for _, k := range modelKeys {
		provider, slug, ok := strings.Cut(k, "/")
		if !ok {
			continue
		}
		pf.Spec.Models = append(pf.Spec.Models, ModelSpec{
			Slug: slug, Provider: provider, Action: server.Models[k],
		})
	}

	var names []string
	for name := range server.Guardrails {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		g := server.Guardrails[name]
		pf.Spec.Guardrails = append(pf.Spec.Guardrails, GuardrailSpec{
			Name: name, RuleType: g.RuleType, Action: g.Action,
			Pattern: g.Pattern, Priority: g.Priority, Enabled: boolPtr(g.Enabled),
		})
	}

	body, err := yaml.Marshal(pf)
	if err != nil {
		return nil, err
	}
	header := "# Vulnetix AI Firewall policy, exported from the org's current state.\n" +
		"# Provider keys are never exported: the server does not return them.\n" +
		"# Apply with: vulnetix ai-firewall apply\n"
	return append([]byte(header), body...), nil
}

func boolPtr(b bool) *bool { return &b }
