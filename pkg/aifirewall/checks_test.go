package aifirewall

import (
	"strings"
	"testing"
)

func policyWith(t *testing.T, mutate func(*Policy)) Policy {
	t.Helper()
	p := Policy{
		ProviderAction: map[string]string{"openai": "", "anthropic": ""},
		ProviderHasKey: map[string]bool{"openai": true, "anthropic": true},
		ModelAction:    map[string]string{},
		AllowlistMode:  map[string]bool{},
		Gateway:        &Gateway{WireAPIs: map[string][]string{"openai": {"chat", "responses"}, "anthropic": {"messages"}}},
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func wired(clientID, model string) Detected {
	c, _ := ClientByID(clientID)
	return Detected{
		Client:  c,
		State:   StateWired,
		BaseURL: "https://guardrails.vulnetix.com/openai/org/v1",
		Model:   model,
	}
}

func findCheck(checks []Check, id string) (Check, bool) {
	for _, c := range checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

func TestCheckDeniedProvider(t *testing.T) {
	pol := policyWith(t, func(p *Policy) { p.ProviderAction["openai"] = "deny" })
	checks := RunChecks(pol, []Detected{wired("aider", "")}, "guardrails.vulnetix.com")

	c, ok := findCheck(checks, "provider_denied")
	if !ok {
		t.Fatalf("expected provider_denied, got %+v", checks)
	}
	if c.Severity != SeverityError {
		t.Errorf("a denied provider means every request 403s; that is an error, not a warning")
	}
}

func TestCheckMissingKey(t *testing.T) {
	pol := policyWith(t, func(p *Policy) { p.ProviderHasKey["openai"] = false })
	checks := RunChecks(pol, []Detected{wired("aider", "")}, "guardrails.vulnetix.com")

	c, ok := findCheck(checks, "provider_key_missing")
	if !ok {
		t.Fatalf("expected provider_key_missing, got %+v", checks)
	}
	if !strings.Contains(c.Message, "key set openai") {
		t.Errorf("the message should say how to fix it: %q", c.Message)
	}
}

func TestCheckDeniedModel(t *testing.T) {
	pol := policyWith(t, func(p *Policy) { p.ModelAction["openai/gpt-4o"] = "deny" })
	checks := RunChecks(pol, []Detected{wired("aider", "gpt-4o")}, "guardrails.vulnetix.com")
	if _, ok := findCheck(checks, "model_denied"); !ok {
		t.Fatalf("expected model_denied, got %+v", checks)
	}
}

// The allowlist flip: one allow entry turns the provider allowlist-only, so a
// model that was never denied starts failing.
func TestCheckAllowlistModeRefusesUnlistedModel(t *testing.T) {
	pol := policyWith(t, func(p *Policy) {
		p.ModelAction["openai/gpt-4o-mini"] = "allow"
		p.AllowlistMode["openai"] = true
	})
	checks := RunChecks(pol, []Detected{wired("aider", "gpt-4o")}, "guardrails.vulnetix.com")

	c, ok := findCheck(checks, "model_not_allowed")
	if !ok {
		t.Fatalf("expected model_not_allowed, got %+v", checks)
	}
	if !strings.Contains(c.Message, "allowlist mode") {
		t.Errorf("the message should explain the flip: %q", c.Message)
	}

	// A model that IS on the list passes.
	checks = RunChecks(pol, []Detected{wired("aider", "gpt-4o-mini")}, "guardrails.vulnetix.com")
	if _, ok := findCheck(checks, "model_not_allowed"); ok {
		t.Error("an allowed model must not be flagged")
	}
}

// The finding that earns the command: a client whose traffic is not being
// screened at all, and which never errors to tell you.
func TestCheckBypass(t *testing.T) {
	c, _ := ClientByID("aider")
	d := Detected{Client: c, State: StateElsewhere, BaseURL: "https://api.openai.com/v1"}

	checks := RunChecks(policyWith(t, nil), []Detected{d}, "guardrails.vulnetix.com")
	got, ok := findCheck(checks, "bypasses_firewall")
	if !ok {
		t.Fatalf("expected bypasses_firewall, got %+v", checks)
	}
	if !strings.Contains(got.Message, "not screened") {
		t.Errorf("the message must say the traffic is unscreened: %q", got.Message)
	}
}

func TestCheckGuardrailPatternDoesNotCompile(t *testing.T) {
	pol := policyWith(t, func(p *Policy) {
		p.Guardrails = []Guardrail{
			{Name: "lookbehind", RuleType: "blocked_pattern", Pattern: `(?<=orgUuid=)\S+`, Enabled: true},
		}
	})
	checks := RunChecks(pol, nil, "guardrails.vulnetix.com")

	c, ok := findCheck(checks, "guardrail_pattern_invalid")
	if !ok {
		t.Fatalf("expected guardrail_pattern_invalid, got %+v", checks)
	}
	if !strings.Contains(c.Message, "NOT being enforced") {
		t.Errorf("the message must say the rule is silently inert: %q", c.Message)
	}
	if !strings.Contains(c.Message, "no lookahead or lookbehind") {
		t.Errorf("the message should explain RE2 and give the rewrite: %q", c.Message)
	}
}

func TestCheckDisabledGuardrailPatternIsNotFlagged(t *testing.T) {
	pol := policyWith(t, func(p *Policy) {
		p.Guardrails = []Guardrail{
			{Name: "off", RuleType: "blocked_pattern", Pattern: `(?<=x)y`, Enabled: false},
		}
	})
	if checks := RunChecks(pol, nil, "guardrails.vulnetix.com"); len(checks) != 0 {
		t.Errorf("a disabled guardrail is not a policy hole: %+v", checks)
	}
}

// A provider nobody wired must not produce findings. The shell is wired for
// openai only; warning that $ANTHROPIC_AUTH_TOKEN is unset would be noise about
// a provider this machine does not use.
func TestKeyEnvUnsetOnlyFiresForWiredProviders(t *testing.T) {
	shell, _ := ClientByID("shell")
	d := Detected{
		Client:  shell,
		State:   StateWired,
		BaseURL: "https://guardrails.vulnetix.com/openai/org/v1",
		KeyEnvSet: map[string]bool{
			"OPENAI_API_KEY":       true,
			"ANTHROPIC_AUTH_TOKEN": false, // unset, but anthropic is not wired
			"GROQ_API_KEY":         false, // likewise
		},
		WiredProviders: map[string]bool{"openai": true},
	}

	checks := RunChecks(policyWith(t, nil), []Detected{d}, "guardrails.vulnetix.com")
	for _, c := range checks {
		if c.ID == "key_env_unset" {
			t.Errorf("warned about a provider that is not wired: %q", c.Message)
		}
	}

	// But once anthropic IS wired and its token is missing, it must fire.
	d.WiredProviders["anthropic"] = true
	checks = RunChecks(policyWith(t, nil), []Detected{d}, "guardrails.vulnetix.com")
	c, ok := findCheck(checks, "key_env_unset")
	if !ok {
		t.Fatalf("expected key_env_unset for the wired provider, got %+v", checks)
	}
	if !strings.Contains(c.Message, "ANTHROPIC_AUTH_TOKEN") {
		t.Errorf("should name the missing variable: %q", c.Message)
	}
}

func TestCheckWireGate(t *testing.T) {
	// A gateway that serves only chat for openai cannot serve Codex, which
	// requires the Responses API.
	pol := policyWith(t, func(p *Policy) {
		p.Gateway = &Gateway{WireAPIs: map[string][]string{"openai": {"chat"}}}
	})
	checks := RunChecks(pol, []Detected{wired("codex", "")}, "guardrails.vulnetix.com")
	if _, ok := findCheck(checks, "wire_unsupported"); !ok {
		t.Fatalf("expected wire_unsupported, got %+v", checks)
	}
}

func TestNoChecksWhenEverythingLinesUp(t *testing.T) {
	pol := policyWith(t, nil)
	checks := RunChecks(pol, []Detected{wired("aider", "gpt-4o")}, "guardrails.vulnetix.com")
	if len(checks) != 0 {
		t.Errorf("a correctly wired client should produce no findings: %+v", checks)
	}
	if Errors(checks) != 0 || Warnings(checks) != 0 {
		t.Error("counts should be zero")
	}
}

func TestAbsentClientsAreNotChecked(t *testing.T) {
	c, _ := ClientByID("codex")
	d := Detected{Client: c, State: StateAbsent}
	if checks := RunChecks(policyWith(t, nil), []Detected{d}, "guardrails.vulnetix.com"); len(checks) != 0 {
		t.Errorf("a client that is not installed is not a problem: %+v", checks)
	}
}

func TestErrorAndWarningCounts(t *testing.T) {
	pol := policyWith(t, func(p *Policy) {
		p.ProviderAction["openai"] = "deny"
		p.Guardrails = []Guardrail{{Name: "bad", RuleType: "blocked_pattern", Pattern: "(", Enabled: true}}
	})
	checks := RunChecks(pol, []Detected{wired("aider", "")}, "guardrails.vulnetix.com")
	if Errors(checks) != 1 {
		t.Errorf("want 1 error, got %d: %+v", Errors(checks), checks)
	}
	if Warnings(checks) != 1 {
		t.Errorf("want 1 warning, got %d: %+v", Warnings(checks), checks)
	}
}
