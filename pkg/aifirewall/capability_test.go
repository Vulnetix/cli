package aifirewall

import (
	"strings"
	"testing"
)

// Capability rules govern what a request can DO — the tools it offers the
// model, the MCP servers wired into the session, the skills it exposes, and
// which client is calling. They share the guardrail table and the guardrail
// CRUD with content rules, but they take a GLOB rather than a regex and they
// accept a different set of actions.
//
// Validating here matters because the alternative failure is silent: a rule the
// gateway cannot run is stored, reported as enabled, and enforces nothing.

func TestCapabilityRuleTypesAccepted(t *testing.T) {
	for _, rt := range []string{
		"tool_allow", "tool_deny", "mcp_allow", "mcp_deny",
		"skill_allow", "skill_deny", "client_allow", "client_deny",
	} {
		if err := ValidateGuardrail("r", rt, "flag", "Bash"); err != nil {
			t.Errorf("%s should be a valid rule type: %v", rt, err)
		}
		if !IsCapabilityRuleType(rt) {
			t.Errorf("%s should classify as a capability rule", rt)
		}
		if IsContentRuleType(rt) {
			t.Errorf("%s must not classify as a content rule", rt)
		}
	}
}

func TestUnknownRuleTypeRejected(t *testing.T) {
	err := ValidateGuardrail("r", "tool_maybe", "flag", "Bash")
	if err == nil {
		t.Fatal("an unknown rule type must be refused")
	}
	// The message lists the vocabulary, because someone who mistyped one needs
	// to see the whole set rather than guess again.
	if !strings.Contains(err.Error(), "tool_deny") || !strings.Contains(err.Error(), "blocked_pattern") {
		t.Errorf("message should list both planes, got %q", err.Error())
	}
}

func TestStripOnlyOnStrippableFamilies(t *testing.T) {
	for _, rt := range []string{"tool_deny", "tool_allow", "mcp_deny", "mcp_allow"} {
		if err := ValidateGuardrail("r", rt, "strip", "Bash"); err != nil {
			t.Errorf("strip should be valid on %s: %v", rt, err)
		}
	}
	// A skill is a value inside another tool's schema and a client is a header,
	// so neither has an entry to remove. Accepting strip there would store a
	// rule that does nothing.
	for _, rt := range []string{"skill_deny", "client_deny"} {
		if err := ValidateGuardrail("r", rt, "strip", "deploy"); err == nil {
			t.Errorf("strip must be refused on %s", rt)
		}
	}
	for _, rt := range []string{"blocked_pattern", "pii_redact", "max_messages"} {
		pattern := "x"
		if rt == "max_messages" {
			pattern = "10"
		}
		if err := ValidateGuardrail("r", rt, "strip", pattern); err == nil {
			t.Errorf("strip must be refused on the content rule %s", rt)
		}
	}
}

func TestRedactOnlyOnContentRules(t *testing.T) {
	if err := ValidateGuardrail("r", "pii_redact", "redact", ""); err != nil {
		t.Errorf("redact should be valid on pii_redact: %v", err)
	}
	if err := ValidateGuardrail("r", "tool_deny", "redact", "Bash"); err == nil {
		t.Error("redact rewrites content, so it must be refused on a tool rule")
	}
}

func TestCapabilityPatternIsRequired(t *testing.T) {
	// Unlike pii_redact, a capability rule has no useful default: an empty
	// pattern names nothing.
	for _, p := range []string{"", "   "} {
		if err := ValidateGuardrail("r", "tool_deny", "flag", p); err == nil {
			t.Errorf("an empty capability pattern (%q) must be refused", p)
		}
	}
}

func TestCapabilityPatternIsAGlobNotARegex(t *testing.T) {
	// mcp__github__* is a VALID regex in which `_*` is a quantifier, so a regex
	// validator would pass it while it matched something else entirely. The
	// glob validator has to accept it as a prefix match.
	if err := ValidateGuardrail("r", "tool_deny", "flag", "mcp__github__*"); err != nil {
		t.Errorf("a prefix glob should be valid: %v", err)
	}
	if err := ValidateGuardrail("r", "tool_deny", "flag", "*__delete_*"); err != nil {
		t.Errorf("an inner glob should be valid: %v", err)
	}

	// Anchors are implied. Someone porting a regex would write ^Bash$ and get a
	// rule matching a tool literally named that, which is never what they meant.
	err := ValidateGuardrail("r", "tool_deny", "flag", "^Bash$")
	if err == nil {
		t.Fatal("^Bash$ should be refused with an explanation, not silently accepted")
	}
	if !strings.Contains(err.Error(), "glob") {
		t.Errorf("message should explain the syntax, got %q", err.Error())
	}
}

func TestPolicyFileAcceptsCapabilityRules(t *testing.T) {
	pf := &PolicyFile{
		APIVersion: PolicyAPIVersion,
		Kind:       PolicyKind,
	}
	pf.Spec.Guardrails = []GuardrailSpec{
		{Name: "no-jira", RuleType: "tool_deny", Action: "strip", Pattern: "mcp__jira__*"},
		{Name: "no-secrets", RuleType: "blocked_pattern", Action: "block", Pattern: `sk-live-\w+`},
	}

	if err := pf.Validate(); err != nil {
		t.Fatalf("a policy file mixing both planes should validate: %v", err)
	}
}

func TestPolicyFileRejectsBadCapabilityRule(t *testing.T) {
	pf := &PolicyFile{APIVersion: PolicyAPIVersion, Kind: PolicyKind}
	pf.Spec.Guardrails = []GuardrailSpec{
		{Name: "broken", RuleType: "tool_deny", Action: "strip", Pattern: ""},
	}

	if err := pf.Validate(); err == nil {
		t.Fatal("a capability rule with no pattern must fail the whole file, so it never reaches the API")
	}
}
