package aifirewall

import (
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func basePolicy() PolicyFile {
	return PolicyFile{APIVersion: PolicyAPIVersion, Kind: PolicyKind}
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*PolicyFile)
		wantErr string
	}{
		{
			name:    "wrong apiVersion",
			mutate:  func(p *PolicyFile) { p.APIVersion = "v1" },
			wantErr: "apiVersion must be",
		},
		{
			name:    "wrong kind",
			mutate:  func(p *PolicyFile) { p.Kind = "Policy" },
			wantErr: "kind must be",
		},
		{
			name: "bad provider action",
			mutate: func(p *PolicyFile) {
				p.Spec.Providers = []ProviderSpec{{Slug: "openai", Action: "block"}}
			},
			wantErr: "action must be allow, deny, or default",
		},
		{
			name: "model with neither provider nor anyProvider",
			mutate: func(p *PolicyFile) {
				p.Spec.Models = []ModelSpec{{Slug: "gpt-4o", Action: "allow"}}
			},
			wantErr: "exactly one of provider or anyProvider",
		},
		{
			name: "model with both",
			mutate: func(p *PolicyFile) {
				p.Spec.Models = []ModelSpec{{Slug: "gpt-4o", Provider: "openai", AnyProvider: true, Action: "allow"}}
			},
			wantErr: "exactly one of provider or anyProvider",
		},
		{
			name: "duplicate guardrail names",
			mutate: func(p *PolicyFile) {
				p.Spec.Guardrails = []GuardrailSpec{
					{Name: "dup", RuleType: "blocked_pattern", Action: "block", Pattern: "x"},
					{Name: "dup", RuleType: "blocked_pattern", Action: "block", Pattern: "y"},
				}
			},
			wantErr: "duplicate name",
		},
		{
			name: "unknown rule type",
			mutate: func(p *PolicyFile) {
				p.Spec.Guardrails = []GuardrailSpec{{Name: "g", RuleType: "regex", Action: "block", Pattern: "x"}}
			},
			wantErr: "ruleType must be",
		},
		{
			name: "max_messages needs an integer",
			mutate: func(p *PolicyFile) {
				p.Spec.Guardrails = []GuardrailSpec{{Name: "cap", RuleType: "max_messages", Action: "block", Pattern: "lots"}}
			},
			wantErr: "positive integer",
		},
		{
			name: "lookbehind is rejected with the rewrite",
			mutate: func(p *PolicyFile) {
				p.Spec.Guardrails = []GuardrailSpec{
					{Name: "g", RuleType: "blocked_pattern", Action: "block", Pattern: `(?<=orgUuid=)\S+`},
				}
			},
			wantErr: "no lookahead or lookbehind",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePolicy()
			tt.mutate(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("expected an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidPolicyPasses(t *testing.T) {
	p := basePolicy()
	p.Spec.Providers = []ProviderSpec{{Slug: "openai", Action: "allow"}}
	p.Spec.Models = []ModelSpec{{Slug: "gpt-4o", Provider: "openai", Action: "allow"}}
	p.Spec.Guardrails = []GuardrailSpec{
		{Name: "aws", RuleType: "blocked_pattern", Action: "block", Pattern: `(?i)AKIA[0-9A-Z]{16}`, Priority: 10},
		{Name: "pii", RuleType: "pii_redact", Action: "redact", Pattern: "", Priority: 20},
		{Name: "cap", RuleType: "max_messages", Action: "block", Pattern: "50", Priority: 50},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPlanCreatesUpdatesAndReportsDrift(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Guardrails = []GuardrailSpec{
		{Name: "new", RuleType: "blocked_pattern", Action: "block", Pattern: "x", Priority: 10},
		{Name: "changed", RuleType: "blocked_pattern", Action: "block", Pattern: "new", Priority: 20},
		{Name: "same", RuleType: "blocked_pattern", Action: "block", Pattern: "same", Priority: 30},
	}
	server := ServerState{
		Providers: map[string]string{},
		Models:    map[string]string{},
		HasKey:    map[string]bool{},
		Guardrails: map[string]ServerGuardrail{
			"changed":     {UUID: "u1", RuleType: "blocked_pattern", Action: "block", Pattern: "old", Priority: 20, Enabled: true},
			"same":        {UUID: "u2", RuleType: "blocked_pattern", Action: "block", Pattern: "same", Priority: 30, Enabled: true},
			"only-server": {UUID: "u3", RuleType: "blocked_pattern", Action: "flag", Pattern: "z", Priority: 40, Enabled: true},
		},
	}

	changes := Plan(desired, server)
	byTarget := map[string]Change{}
	for _, c := range changes {
		byTarget[c.Target] = c
	}

	if got := byTarget["new"].Op; got != OpCreate {
		t.Errorf("new guardrail: got %s, want create", got)
	}
	if got := byTarget["changed"].Op; got != OpUpdate {
		t.Errorf("changed guardrail: got %s, want update", got)
	}
	if byTarget["changed"].UUID != "u1" {
		t.Error("an update must carry the server's uuid")
	}
	if _, ok := byTarget["same"]; ok {
		t.Error("an identical guardrail should produce no change")
	}
	// Without --prune, a guardrail authored in the dashboard is reported, never
	// deleted.
	if got := byTarget["only-server"].Op; got != OpDrift {
		t.Errorf("server-only guardrail: got %s, want drift", got)
	}
	if len(Mutating(changes)) != 2 {
		t.Errorf("drift must not count as a mutation: %v", Mutating(changes))
	}
}

func TestPlanPruneDeletes(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Prune = true
	server := ServerState{
		Providers: map[string]string{}, Models: map[string]string{}, HasKey: map[string]bool{},
		Guardrails: map[string]ServerGuardrail{
			"only-server": {UUID: "u3", RuleType: "blocked_pattern", Action: "flag", Pattern: "z"},
		},
	}
	changes := Plan(desired, server)
	if len(changes) != 1 || changes[0].Op != OpDelete || changes[0].UUID != "u3" {
		t.Fatalf("expected a single delete carrying the uuid, got %+v", changes)
	}
}

// Guardrails must be applied before providers: tightening a policy must never
// pass through a state where a provider is live and its guardrails are not.
func TestPlanOrdersGuardrailsBeforeProviders(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Providers = []ProviderSpec{{Slug: "openai", Action: "allow"}}
	desired.Spec.Models = []ModelSpec{{Slug: "gpt-4o", Provider: "openai", Action: "allow"}}
	desired.Spec.Guardrails = []GuardrailSpec{
		{Name: "g", RuleType: "blocked_pattern", Action: "block", Pattern: "x", Priority: 1},
	}
	desired.Spec.Settings = &SettingsSpec{LogsEnabled: boolPtr(true)}

	changes := Plan(desired, ServerState{
		Providers: map[string]string{}, Models: map[string]string{},
		HasKey: map[string]bool{}, Guardrails: map[string]ServerGuardrail{},
	})

	var order []Kind
	for _, c := range changes {
		order = append(order, c.Kind)
	}
	want := []Kind{KindGuardrail, KindModel, KindProvider, KindSettings}
	if len(order) != len(want) {
		t.Fatalf("got %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("execution order is %v, want %v", order, want)
		}
	}
}

func TestPlanProviderDefaultClearsAssociation(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Providers = []ProviderSpec{{Slug: "openai", Action: "default"}}
	server := ServerState{
		Providers:  map[string]string{"openai": "deny"},
		Models:     map[string]string{},
		HasKey:     map[string]bool{},
		Guardrails: map[string]ServerGuardrail{},
	}
	changes := Plan(desired, server)
	if len(changes) != 1 || changes[0].Kind != KindProvider {
		t.Fatalf("expected one provider change, got %+v", changes)
	}
	// An org already at default produces no change at all.
	server.Providers["openai"] = ""
	if got := Plan(desired, server); len(got) != 0 {
		t.Errorf("already at default should be a no-op, got %+v", got)
	}
}

// Export -> apply -> export must be a fixpoint, or the file drifts every run.
func TestExportApplyExportIsStable(t *testing.T) {
	server := ServerState{
		Providers: map[string]string{"openai": "allow", "openrouter": "deny", "groq": ""},
		HasKey:    map[string]bool{"openai": true},
		Models:    map[string]string{"openai/gpt-4o": "allow"},
		Guardrails: map[string]ServerGuardrail{
			"aws": {UUID: "u1", RuleType: "blocked_pattern", Action: "block", Pattern: `AKIA[0-9A-Z]{16}`, Priority: 10, Enabled: true},
		},
		LogsEnabled: true,
	}
	catalog := []string{"openai", "openrouter", "groq"}

	body, err := Export(testOrg, server, catalog)
	if err != nil {
		t.Fatal(err)
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(body, &pf); err != nil {
		t.Fatalf("export produced a file we cannot read back: %v\n%s", err, body)
	}
	if err := pf.Validate(); err != nil {
		t.Fatalf("export produced a file that fails validation: %v\n%s", err, body)
	}
	// A default-allow provider is not recorded: it has no association.
	for _, p := range pf.Spec.Providers {
		if p.Slug == "groq" {
			t.Error("a provider with no association should not be exported")
		}
	}
	// Applying what we exported changes nothing.
	if changes := Mutating(Plan(pf, server)); len(changes) != 0 {
		t.Errorf("export -> apply should be a no-op, got %+v", changes)
	}
	// And nothing that looks like a key came out.
	if strings.Contains(string(body), "fromEnv") || strings.Contains(string(body), "apiKey") {
		t.Errorf("export must never emit a key source:\n%s", body)
	}
}

// --- baseline ---

func TestBaselineCompileRejectsBadPatternWholesale(t *testing.T) {
	b := Baseline{Guardrails: []BaselineGuardrail{
		{ID: "ok", Name: "OK", RuleType: "blocked_pattern", Action: "block", Pattern: "AKIA"},
		{ID: "bad", Name: "Bad", RuleType: "blocked_pattern", Action: "block", Pattern: `(?<=x)y`},
	}}
	err := b.Compile()
	if err == nil {
		t.Fatal("a baseline with an uncompilable pattern must be rejected")
	}
	if !strings.Contains(err.Error(), "lookahead or lookbehind") {
		t.Errorf("the error should explain RE2: %v", err)
	}

	b2 := Baseline{Guardrails: []BaselineGuardrail{
		{ID: "dup", Name: "A", RuleType: "pii_redact", Action: "redact"},
		{ID: "dup", Name: "B", RuleType: "pii_redact", Action: "redact"},
	}}
	if err := b2.Compile(); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("duplicate ids must be rejected (they are the key for excludes): %v", err)
	}
}

func TestComposeGuardrailsPrecedence(t *testing.T) {
	local := []GuardrailSpec{
		{Name: "PII email redaction", RuleType: "pii_redact", Action: "flag", Pattern: "", Priority: 5},
	}
	baseline := &Baseline{Guardrails: []BaselineGuardrail{
		{ID: "pii-email", Name: "PII email redaction", RuleType: "pii_redact", Action: "redact", Priority: 20, Enabled: true},
		{ID: "pii-phone", Name: "PII phone redaction", RuleType: "pii_redact", Action: "redact", Priority: 21, Enabled: true},
		{ID: "prompt-injection", Name: "Prompt injection", RuleType: "blocked_pattern", Action: "flag", Pattern: "(?i)ignore (all|any) previous instructions", Priority: 30, Enabled: true},
	}}

	got := ComposeGuardrails(local, baseline, []string{"pii-phone"})

	byName := map[string]GuardrailSpec{}
	for _, g := range got {
		byName[g.Name] = g
	}
	if len(got) != 2 {
		t.Fatalf("expected the local rule plus one baseline rule, got %d: %+v", len(got), got)
	}
	// The file wins: the org downgraded this rule to flag on purpose.
	if byName["PII email redaction"].Action != "flag" {
		t.Errorf("a local guardrail must beat the baseline entry with the same name: %+v", byName["PII email redaction"])
	}
	if _, ok := byName["PII phone redaction"]; ok {
		t.Error("an excluded baseline id must be dropped")
	}
	pi := byName["Prompt injection"]
	if pi.BaselineID != "prompt-injection" {
		t.Error("a composed baseline rule should record its id, so export can round-trip it")
	}
}

// --- model reconciliation ---

// A model row on the server that the file does not mention must be pruned with
// --prune, exactly as a guardrail is. Leaving it means a policy file is not a
// complete description of what the org allows.
func TestPlanPrunesModelRows(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Prune = true
	desired.Spec.Models = []ModelSpec{{Slug: "gpt-4o", Provider: "openai", Action: "allow"}}
	server := ServerState{
		Providers: map[string]string{}, HasKey: map[string]bool{},
		Guardrails: map[string]ServerGuardrail{},
		Models: map[string]string{
			"openai/gpt-4o":             "allow",
			"openai/gpt-4o-mini":        "allow",
			"anthropic/claude-sonnet-5": "deny",
		},
	}

	var deleted []string
	for _, c := range Plan(desired, server) {
		if c.Kind != KindModel {
			continue
		}
		if c.Op != OpDelete {
			t.Fatalf("unexpected model change %+v", c)
		}
		if c.Model == nil || c.Model.Action != "remove" {
			t.Fatalf("a model delete must carry the remove verb the API expects: %+v", c.Model)
		}
		deleted = append(deleted, c.Target)
	}
	sort.Strings(deleted)
	want := []string{"anthropic/claude-sonnet-5", "openai/gpt-4o-mini"}
	if len(deleted) != len(want) {
		t.Fatalf("got %v, want %v", deleted, want)
	}
	for i := range want {
		if deleted[i] != want[i] {
			t.Fatalf("got %v, want %v", deleted, want)
		}
	}
}

// Without --prune the same rows are reported, never removed, and never counted
// as a mutation.
func TestPlanReportsModelDriftWithoutPrune(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Models = []ModelSpec{{Slug: "gpt-4o", Provider: "openai", Action: "allow"}}
	server := ServerState{
		Providers: map[string]string{}, HasKey: map[string]bool{},
		Guardrails: map[string]ServerGuardrail{},
		Models:     map[string]string{"openai/gpt-4o": "allow", "openai/gpt-4o-mini": "allow"},
	}

	changes := Plan(desired, server)
	if got := len(Mutating(changes)); got != 0 {
		t.Fatalf("an unmentioned model must not mutate anything without --prune: %+v", Mutating(changes))
	}
	var drift []Change
	for _, c := range changes {
		if c.Kind == KindModel && c.Op == OpDrift {
			drift = append(drift, c)
		}
	}
	if len(drift) != 1 || drift[0].Target != "openai/gpt-4o-mini" {
		t.Fatalf("expected drift for openai/gpt-4o-mini, got %+v", drift)
	}
}

// anyProvider is expanded server-side into one row per provider. Those rows are
// mentioned by the file, so prune must not delete what the same apply created.
func TestPlanPruneKeepsAnyProviderModels(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Prune = true
	desired.Spec.Models = []ModelSpec{{Slug: "gpt-4o", AnyProvider: true, Action: "deny"}}
	server := ServerState{
		Providers: map[string]string{}, HasKey: map[string]bool{},
		Guardrails: map[string]ServerGuardrail{},
		Models: map[string]string{
			"openai/gpt-4o":     "deny",
			"openrouter/gpt-4o": "deny",
			"openai/o3":         "allow",
		},
	}

	for _, c := range Plan(desired, server) {
		if c.Kind == KindModel && c.Op == OpDelete && c.Target != "openai/o3" {
			t.Fatalf("prune deleted a row anyProvider covers: %+v", c)
		}
	}
}

// --- baseline default ---

// The apply flags advertise the baseline as on by default (--no-baseline turns
// it off), so a file that says nothing about it must still get it.
func TestBaselineRequestedDefaultsOn(t *testing.T) {
	pf := basePolicy()
	if !pf.Spec.BaselineRequested() {
		t.Error("a policy file with no baseline block must still request the baseline")
	}

	pf.Spec.Baseline = &BaselineSpec{Enabled: false}
	if pf.Spec.BaselineRequested() {
		t.Error("spec.baseline.enabled: false must opt out")
	}

	pf.Spec.Baseline = &BaselineSpec{Enabled: true, Ref: "strict"}
	if !pf.Spec.BaselineRequested() || pf.Spec.BaselineRef() != "strict" {
		t.Error("an explicit baseline block must be honoured, ref included")
	}
}

// An exported snapshot is the org's current state, so re-applying it must not
// suddenly compose in a baseline the org never had.
func TestExportPinsBaselineOff(t *testing.T) {
	body, err := Export(testOrg, ServerState{
		Providers: map[string]string{}, HasKey: map[string]bool{},
		Models: map[string]string{}, Guardrails: map[string]ServerGuardrail{},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(body, &pf); err != nil {
		t.Fatal(err)
	}
	if pf.Spec.BaselineRequested() {
		t.Errorf("an export must pin the baseline off so a round-trip is a no-op:\n%s", body)
	}
}

// A provider association absent from the file must surface as drift and never as
// a delete: clearing a provider row drops a "deny", which opens access rather
// than closing it. Before this, an unmentioned provider was silently invisible.
func TestPlanReportsProviderDriftAndNeverPrunesIt(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Prune = true
	desired.Spec.Providers = []ProviderSpec{{Slug: "openai", Action: "deny"}}
	server := ServerState{
		Providers: map[string]string{
			"openai": "deny", // mentioned
			"xai":    "deny", // unmentioned, has an association
			"groq":   "",     // unmentioned, default — nothing to report
		},
		HasKey:     map[string]bool{},
		Models:     map[string]string{},
		Guardrails: map[string]ServerGuardrail{},
	}

	var drift []string
	for _, c := range Plan(desired, server) {
		if c.Kind != KindProvider {
			continue
		}
		if c.Op == OpDelete {
			t.Fatalf("prune must never delete a provider association: %+v", c)
		}
		if c.Op == OpDrift {
			drift = append(drift, c.Target)
		}
	}
	if len(drift) != 1 || drift[0] != "xai" {
		t.Fatalf("expected drift for xai alone, got %v", drift)
	}
}
