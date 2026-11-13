package aifirewall

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Property tests for Plan and ValidateGuardrail. The example tests in
// policy_test.go pin particular plans; these check the invariants every plan
// must keep, over generated policies and server states.

var planQuickConfig = &quick.Config{MaxCount: 2000}

// Small vocabularies, so a generated file and a generated server overlap often
// enough to exercise create, update, unchanged, drift and delete together.
var (
	propGuardrailNames = []string{"g1", "g2", "g3", "g4", "g5"}
	propRuleTypes      = []string{"blocked_pattern", "pii_redact", "tool_deny", "mcp_allow"}
	propActions        = []string{"block", "flag", "redact", "strip"}
	propPatterns       = []string{"secret", "", "mcp__github__*"}
	propProviders      = []string{"openai", "anthropic", "groq", "mistral"}
	propProviderActs   = []string{"allow", "deny", "default"}
	propModels         = []string{"m1", "m2", "m3"}
	propModelActs      = []string{"allow", "deny"}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

// planCase is one generated (desired, server) pair. Names are unique within
// the file, as Validate requires. Provider keys and anyProvider models are not
// generated: both are re-sent on every apply by design (a key is write-only and
// an anyProvider entry is expanded server-side), so they are not expected to
// converge and are covered by the example tests instead.
type planCase struct {
	Desired PolicyFile
	Server  ServerState
}

func (planCase) Generate(r *rand.Rand, _ int) reflect.Value {
	var c planCase
	c.Desired.Spec.Prune = r.Intn(2) == 0

	for _, name := range propGuardrailNames {
		if r.Intn(2) == 0 {
			g := GuardrailSpec{
				Name: name, RuleType: pick(r, propRuleTypes), Action: pick(r, propActions),
				Pattern: pick(r, propPatterns), Priority: r.Intn(3),
			}
			if r.Intn(3) == 0 {
				g.Enabled = boolPtr(r.Intn(2) == 0)
			}
			c.Desired.Spec.Guardrails = append(c.Desired.Spec.Guardrails, g)
		}
	}
	for _, p := range propProviders {
		for _, m := range propModels {
			if r.Intn(3) == 0 {
				c.Desired.Spec.Models = append(c.Desired.Spec.Models,
					ModelSpec{Provider: p, Slug: m, Action: pick(r, propModelActs)})
			}
		}
	}
	for _, p := range propProviders {
		if r.Intn(2) == 0 {
			c.Desired.Spec.Providers = append(c.Desired.Spec.Providers,
				ProviderSpec{Slug: p, Action: pick(r, propProviderActs)})
		}
	}
	if r.Intn(2) == 0 {
		c.Desired.Spec.Settings = &SettingsSpec{LogsEnabled: boolPtr(r.Intn(2) == 0)}
	}

	c.Server = ServerState{
		Providers:   map[string]string{},
		Models:      map[string]string{},
		Guardrails:  map[string]ServerGuardrail{},
		LogsEnabled: r.Intn(2) == 0,
	}
	for i, name := range propGuardrailNames {
		if r.Intn(2) == 0 {
			c.Server.Guardrails[name] = ServerGuardrail{
				UUID: fmt.Sprintf("uuid-%d", i), RuleType: pick(r, propRuleTypes), Action: pick(r, propActions),
				Pattern: pick(r, propPatterns), Priority: r.Intn(3), Enabled: r.Intn(2) == 0,
			}
		}
	}
	for _, p := range propProviders {
		if r.Intn(2) == 0 {
			c.Server.Providers[p] = pick(r, []string{"", "allow", "deny"})
		}
		for _, m := range propModels {
			if r.Intn(3) == 0 {
				c.Server.Models[p+"/"+m] = pick(r, propModelActs)
			}
		}
	}
	return reflect.ValueOf(c)
}

var kindOrder = map[Kind]int{KindGuardrail: 0, KindModel: 1, KindProvider: 2, KindKey: 3, KindSettings: 4}

// TestPlanRunsInKindOrder: guardrails, then models, then providers, then keys,
// then settings, whatever the input. Tightening must never pass through a state
// where a provider is open before the guardrails that constrain it exist.
func TestPlanRunsInKindOrder(t *testing.T) {
	prop := func(c planCase) bool {
		changes := Plan(c.Desired, c.Server)
		for i := 1; i < len(changes); i++ {
			if kindOrder[changes[i-1].Kind] > kindOrder[changes[i].Kind] {
				t.Logf("%s before %s in %+v", changes[i-1].Kind, changes[i].Kind, changes)
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, planQuickConfig); err != nil {
		t.Error(err)
	}
}

// TestPlanIsDeterministic: equal inputs give the same plan, in the same order,
// every time. The server state arrives as maps, whose iteration order changes
// from run to run; a plan that followed it would print and apply its drift and
// deletes in a different order on every apply.
func TestPlanIsDeterministic(t *testing.T) {
	prop := func(c planCase) bool {
		first := Plan(c.Desired, c.Server)
		for range 5 {
			if again := Plan(c.Desired, c.Server); !reflect.DeepEqual(first, again) {
				t.Logf("plans differ:\n%+v\n%+v", first, again)
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, planQuickConfig); err != nil {
		t.Error(err)
	}
}

// applyPlan does to a copy of the server what apply would do with the plan's
// mutating changes.
func applyPlan(server ServerState, changes []Change) ServerState {
	out := ServerState{
		Providers:   map[string]string{},
		Models:      map[string]string{},
		Guardrails:  map[string]ServerGuardrail{},
		LogsEnabled: server.LogsEnabled,
	}
	for k, v := range server.Providers {
		out.Providers[k] = v
	}
	for k, v := range server.Models {
		out.Models[k] = v
	}
	for k, v := range server.Guardrails {
		out.Guardrails[k] = v
	}
	for _, c := range Mutating(changes) {
		switch c.Kind {
		case KindGuardrail:
			if c.Op == OpDelete {
				delete(out.Guardrails, c.Target)
				continue
			}
			g := c.Guardrail
			out.Guardrails[c.Target] = ServerGuardrail{
				UUID: c.UUID, RuleType: g.RuleType, Action: g.Action,
				Pattern: g.Pattern, Priority: g.Priority, Enabled: g.IsEnabled(),
			}
		case KindModel:
			if c.Op == OpDelete {
				delete(out.Models, c.Target)
				continue
			}
			out.Models[c.Model.Provider+"/"+c.Model.Slug] = c.Model.Action
		case KindProvider:
			action := c.Provider.Action
			if action == "default" {
				action = ""
			}
			out.Providers[c.Target] = action
		case KindSettings:
			out.LogsEnabled = *c.Enable
		}
	}
	return out
}

// TestPlanConverges: once a plan's mutating changes are applied, planning the
// same file again has nothing left to change. A plan that never converges would
// rewrite the same objects on every apply and could never be clean.
func TestPlanConverges(t *testing.T) {
	prop := func(c planCase) bool {
		after := applyPlan(c.Server, Plan(c.Desired, c.Server))
		if rest := Mutating(Plan(c.Desired, after)); len(rest) != 0 {
			t.Logf("still mutating after apply: %+v", rest)
			return false
		}
		return true
	}
	if err := quick.Check(prop, planQuickConfig); err != nil {
		t.Error(err)
	}
}

// TestValidateGuardrailAcceptsExactlyTheEnforceablePairs walks every rule type
// and action the gateway knows, with a pattern valid for the rule type, and
// checks the verdict against the pairs the gateway can enforce.
func TestValidateGuardrailAcceptsExactlyTheEnforceablePairs(t *testing.T) {
	patterns := map[string]string{
		"blocked_pattern": "secret", "max_messages": "50", "pii_redact": "", "delimiter_integrity": "",
		"tool_allow": "Bash", "tool_deny": "Bash", "mcp_allow": "mcp__github__*", "mcp_deny": "mcp__github__*",
		"skill_allow": "review", "skill_deny": "review", "client_allow": "cursor", "client_deny": "cursor",
	}
	allowed := map[string][]string{
		"blocked_pattern":     {"block", "redact", "flag"},
		"max_messages":        {"block", "redact", "flag"},
		"pii_redact":          {"block", "redact", "flag"},
		"delimiter_integrity": {"block", "flag"},
		"tool_allow":          {"block", "flag", "strip"},
		"tool_deny":           {"block", "flag", "strip"},
		"mcp_allow":           {"block", "flag", "strip"},
		"mcp_deny":            {"block", "flag", "strip"},
		"skill_allow":         {"block", "flag"},
		"skill_deny":          {"block", "flag"},
		"client_allow":        {"block", "flag"},
		"client_deny":         {"block", "flag"},
	}
	if len(allowed) != len(contentRuleTypes)+len(capabilityRuleTypes) {
		t.Fatalf("the table covers %d rule types, the vocabulary has %d", len(allowed), len(contentRuleTypes)+len(capabilityRuleTypes))
	}
	for ruleType, ok := range allowed {
		for action := range validGuardrailActions {
			want := false
			for _, a := range ok {
				want = want || a == action
			}
			err := ValidateGuardrail("g", ruleType, action, patterns[ruleType])
			if (err == nil) != want {
				t.Errorf("ValidateGuardrail(%s, %s) = %v, want accepted=%v", ruleType, action, err, want)
			}
		}
	}
}

// TestValidateGuardrailIsTotal: any strings give an answer, never a panic, and
// a rule type or action outside the vocabulary is always refused.
func TestValidateGuardrailIsTotal(t *testing.T) {
	prop := func(name, ruleType, action, pattern string) bool {
		err := ValidateGuardrail(name, ruleType, action, pattern)
		known := (contentRuleTypes[ruleType] || capabilityRuleTypes[ruleType]) && validGuardrailActions[action]
		return known || err != nil
	}
	if err := quick.Check(prop, planQuickConfig); err != nil {
		t.Error(err)
	}
	// Known vocabulary with arbitrary patterns: still an answer, never a panic.
	var types []string
	for k := range contentRuleTypes {
		types = append(types, k)
	}
	for k := range capabilityRuleTypes {
		types = append(types, k)
	}
	r := rand.New(rand.NewSource(1))
	known := func(pattern string) bool {
		action := []string{"block", "redact", "flag", "strip"}[r.Intn(4)]
		_ = ValidateGuardrail("g", types[r.Intn(len(types))], action, pattern)
		return true
	}
	if err := quick.Check(known, planQuickConfig); err != nil {
		t.Error(err)
	}
}
