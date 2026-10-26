package aifirewall

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestLoadBaselineFileJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	body := `{"version":"1","guardrails":[{"id":"pii","name":"PII","ruleType":"pii_redact","action":"redact","enabled":true}]}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaselineFile(path)
	if err != nil {
		t.Fatalf("LoadBaselineFile: %v", err)
	}
	if b.Version != "1" {
		t.Errorf("version = %q, want %q", b.Version, "1")
	}
	if b.Ref != "local" {
		t.Errorf("ref = %q, want %q (unpinned baseline defaults to local)", b.Ref, "local")
	}
	if len(b.Guardrails) != 1 || b.Guardrails[0].ID != "pii" {
		t.Fatalf("guardrails not parsed: %+v", b.Guardrails)
	}
}

func TestLoadBaselineFileYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	body := "version: \"1\"\nguardrails:\n  - id: pii\n    name: PII\n    ruleType: pii_redact\n    action: redact\n    enabled: true\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaselineFile(path)
	if err != nil {
		t.Fatalf("LoadBaselineFile: %v", err)
	}
	if b.Ref != "local" {
		t.Errorf("ref = %q, want %q", b.Ref, "local")
	}
	if len(b.Guardrails) != 1 {
		t.Fatalf("guardrails not parsed: %+v", b.Guardrails)
	}
}

func TestLoadBaselineFileErrors(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadBaselineFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaselineFile(badJSON); err == nil {
		t.Error("expected error for invalid JSON")
	}

	badYAML := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badYAML, []byte(":\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaselineFile(badYAML); err == nil {
		t.Error("expected error for invalid YAML")
	}

	// A compiled baseline with an invalid guardrail fails and names the path.
	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("guardrails:\n  - id: g\n    name: G\n    ruleType: regex\n    action: block\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaselineFile(invalid); err == nil || !strings.Contains(err.Error(), "invalid.yaml") {
		t.Errorf("expected compile error naming the file, got %v", err)
	}
}

func TestBaselineCompileEmptyIDAndName(t *testing.T) {
	b := Baseline{Guardrails: []BaselineGuardrail{
		{ID: "", Name: "NoID", RuleType: "pii_redact", Action: "redact"},
	}}
	if err := b.Compile(); err == nil || !strings.Contains(err.Error(), "id is required") {
		t.Errorf("expected id required error, got %v", err)
	}

	b = Baseline{Guardrails: []BaselineGuardrail{
		{ID: "x", Name: "", RuleType: "pii_redact", Action: "redact"},
	}}
	if err := b.Compile(); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Errorf("expected name required error, got %v", err)
	}
}

func TestComposeGuardrailsNilBaseline(t *testing.T) {
	spec := []GuardrailSpec{{Name: "local", RuleType: "pii_redact", Action: "redact"}}
	got := ComposeGuardrails(spec, nil, nil)
	if !reflect.DeepEqual(got, spec) {
		t.Errorf("nil baseline should return spec unchanged: %+v", got)
	}
}

func TestRuleTypeList(t *testing.T) {
	s := ruleTypeList()
	for _, want := range []string{"blocked_pattern", "max_messages", "pii_redact", "delimiter_integrity", "tool_allow", "client_deny"} {
		if !strings.Contains(s, want) {
			t.Errorf("ruleTypeList missing %q", want)
		}
	}
}

func TestLoadPolicyFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "policy.yaml")
	if _, err := LoadPolicyFile(missing); err == nil {
		t.Fatal("missing file should error")
	}

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("invalid: ["), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(bad); err == nil {
		t.Fatal("invalid yaml must error")
	}

	valid := filepath.Join(dir, "valid.yaml")
	body := `apiVersion: vulnetix.com/v1
kind: AiFirewallPolicy
spec:
  providers:
    - slug: openai
      action: allow
`
	if err := os.WriteFile(valid, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	pf, err := LoadPolicyFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(pf.Spec.Providers) != 1 {
		t.Fatalf("providers not parsed: %+v", pf)
	}
}

func TestBaselineExclude(t *testing.T) {
	var s PolicySpec
	if got := s.BaselineExclude(); got != nil {
		t.Errorf("nil baseline exclude = %v, want nil", got)
	}
	s.Baseline = &BaselineSpec{Exclude: []string{"x"}}
	if got := s.BaselineExclude(); len(got) != 1 || got[0] != "x" {
		t.Errorf("exclude = %v", got)
	}
}

func TestSortedKeys(t *testing.T) {
	got := sortedKeys(map[string]string{"b": "1", "a": "2", "c": "3"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sortedKeys = %v, want %v", got, want)
	}
}

func TestMutatingFiltersDrift(t *testing.T) {
	changes := []Change{
		{Kind: KindGuardrail, Op: OpDrift, Target: "a"},
		{Kind: KindGuardrail, Op: OpCreate, Target: "b"},
	}
	got := Mutating(changes)
	if len(got) != 1 || got[0].Op != OpCreate {
		t.Errorf("Mutating = %+v, want only the create", got)
	}
}

func TestBoolPtr(t *testing.T) {
	p := boolPtr(true)
	if p == nil || !*p {
		t.Error("boolPtr(true) should return a true pointer")
	}
	p = boolPtr(false)
	if p == nil || *p {
		t.Error("boolPtr(false) should return a false pointer")
	}
}

func TestMentionsModel(t *testing.T) {
	models := []ModelSpec{
		{Slug: "gpt-4o", Provider: "openai", Action: "allow"},
		{Slug: "claude-sonnet", AnyProvider: true, Action: "deny"},
	}
	tests := []struct {
		key  string
		want bool
	}{
		{"openai/gpt-4o", true},
		{"openai/claude-sonnet", true},
		{"anthropic/claude-sonnet", true},
		{"openai/other", false},
		{"no-slash", false},
	}
	for _, tt := range tests {
		if got := mentionsModel(models, tt.key); got != tt.want {
			t.Errorf("mentionsModel(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestHasGuardrailAndProvider(t *testing.T) {
	gs := []GuardrailSpec{{Name: "g1"}}
	if !hasGuardrail(gs, "g1") {
		t.Error("expected g1 present")
	}
	if hasGuardrail(gs, "g2") {
		t.Error("expected g2 absent")
	}

	ps := []ProviderSpec{{Slug: "openai"}}
	if !hasProvider(ps, "openai") {
		t.Error("expected openai present")
	}
	if hasProvider(ps, "anthropic") {
		t.Error("expected anthropic absent")
	}
}

func TestSortChangesOrder(t *testing.T) {
	changes := []Change{
		{Kind: KindSettings, Target: "s"},
		{Kind: KindKey, Target: "k"},
		{Kind: KindGuardrail, Target: "g"},
		{Kind: KindModel, Target: "m"},
		{Kind: KindProvider, Target: "p"},
	}
	sortChanges(changes)
	want := []Kind{KindGuardrail, KindModel, KindProvider, KindKey, KindSettings}
	var got []Kind
	for _, c := range changes {
		got = append(got, c.Kind)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestExportErrorBranches(t *testing.T) {
	// A provider slug with an association is exported; empty action is skipped.
	server := ServerState{
		Providers:   map[string]string{"openai": "deny", "groq": ""},
		HasKey:      map[string]bool{},
		Models:      map[string]string{},
		Guardrails:  map[string]ServerGuardrail{},
		LogsEnabled: true,
	}
	body, err := Export(testOrg, server, []string{"openai", "groq", "openrouter"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "slug: openai") {
		t.Error("openai provider not exported")
	}
	if strings.Contains(s, "slug: groq") {
		t.Error("groq has no association and should not be exported")
	}
}

func TestPlanModelKeyWithoutSlash(t *testing.T) {
	// A malformed model key is skipped during prune, never a panic or a change.
	desired := basePolicy()
	desired.Spec.Prune = true
	server := ServerState{
		Providers:  map[string]string{},
		HasKey:     map[string]bool{},
		Models:     map[string]string{"malformed": "allow"},
		Guardrails: map[string]ServerGuardrail{},
	}
	changes := Plan(desired, server)
	for _, c := range changes {
		if c.Kind == KindModel && c.Target == "malformed" {
			t.Errorf("malformed key produced a change: %+v", c)
		}
	}
}

func TestPlanExportRoundTripWithoutKeys(t *testing.T) {
	server := ServerState{
		Providers:  map[string]string{"openai": "allow"},
		HasKey:     map[string]bool{"openai": true},
		Models:     map[string]string{"openai/gpt-4o": "allow"},
		Guardrails: map[string]ServerGuardrail{},
	}
	body, err := Export(testOrg, server, []string{"openai"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "fromEnv") || strings.Contains(string(body), "apiKey") {
		t.Errorf("export must never emit a key source:\n%s", body)
	}
}

func TestGuardrailDiff(t *testing.T) {
	cur := ServerGuardrail{RuleType: "blocked_pattern", Action: "block", Pattern: "a", Priority: 1, Enabled: true}
	want := GuardrailSpec{Name: "g", RuleType: "pii_redact", Action: "redact", Pattern: "b", Priority: 2}
	diff := guardrailDiff(cur, want)
	for _, part := range []string{"ruleType blocked_pattern -> pii_redact", "action block -> redact", "pattern changed", "priority 1 -> 2"} {
		if !strings.Contains(diff, part) {
			t.Errorf("guardrailDiff missing %q in %q", part, diff)
		}
	}
}

func TestPlanAnyProviderModel(t *testing.T) {
	desired := basePolicy()
	desired.Spec.Models = []ModelSpec{{Slug: "gpt-4o", AnyProvider: true, Action: "allow"}}
	server := ServerState{
		Providers:  map[string]string{},
		HasKey:     map[string]bool{},
		Models:     map[string]string{},
		Guardrails: map[string]ServerGuardrail{},
	}
	changes := Plan(desired, server)
	if len(changes) != 1 || changes[0].Kind != KindModel || changes[0].Op != OpUpdate {
		t.Fatalf("expected one anyProvider update, got %+v", changes)
	}
}

var _ = sort.Strings
